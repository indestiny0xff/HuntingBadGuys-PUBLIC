"""APK analysis service.

Extracts:
- AndroidManifest.xml (binary XML parser — no external deps)
- .so files (ELF header info + hex_dump for radare2/DDV)
- JADX decompiled Java/Kotlin sources (if jadx is in PATH)
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
from typing import Any

from .efa_svc import _analyse_strings, _build_hex_dump, _parse_elf, _strings_ascii

log = logging.getLogger(__name__)

_SO_HEX_CAP = 2 * 1024 * 1024  # 2 MB cap per .so hex dump
_JADX_TIMEOUT = 120  # seconds
_MAX_CLASSES = 60  # max decompiled class files to store
_MAX_SRC_BYTES = 60_000  # max source bytes per class
_MAX_SO_FILES = 20  # max .so files to deeply analyse
_MAX_ENTRY_BYTES = 64 * 1024 * 1024  # refuse to inflate any single entry above this


# ── Binary XML (AXML) parser ─────────────────────────────────────────────────
# Android stores AndroidManifest.xml in a proprietary binary format.
# We parse it from scratch — no third-party deps needed.


class _AXMLParser:
    """Parse Android binary XML (AXML) into a manifest info dict."""

    _CHUNK_XML = 0x0003
    _CHUNK_STRPOOL = 0x0001
    _CHUNK_RESMAP = 0x0180
    _CHUNK_START_NS = 0x0100
    _CHUNK_END_NS = 0x0101
    _CHUNK_START_EL = 0x0102
    _CHUNK_END_EL = 0x0103

    # Res_value dataType codes (ResourceTypes.h)
    _T_NULL = 0x00
    _T_REF = 0x01
    _T_ATTR = 0x02
    _T_STRING = 0x03
    _T_FLOAT = 0x04
    _T_INTDEC = 0x10
    _T_INTHEX = 0x11
    _T_INTBOOL = 0x12

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.strings: list[str] = []

    # ── Low-level reads ───────────────────────────────────────────────────────

    def _u8(self, p: int) -> int:
        return self.data[p]

    def _u16(self, p: int) -> int:
        return struct.unpack_from("<H", self.data, p)[0]

    def _u32(self, p: int) -> int:
        return struct.unpack_from("<I", self.data, p)[0]

    def _str(self, idx: int) -> str:
        if idx == 0xFFFFFFFF or idx < 0 or idx >= len(self.strings):
            return ""
        return self.strings[idx]

    # ── String pool ───────────────────────────────────────────────────────────

    def _parse_string_pool(self, chunk_start: int) -> None:
        d = self.data
        self._u32(chunk_start + 4)
        hdr_size = self._u16(chunk_start + 2)
        string_count = self._u32(chunk_start + 8)
        flags = self._u32(chunk_start + 16)
        strings_start = self._u32(chunk_start + 20)  # relative to chunk start
        is_utf8 = bool(flags & 0x100)

        offsets_base = chunk_start + hdr_size
        strings_base = chunk_start + strings_start

        self.strings = []
        for i in range(string_count):
            if offsets_base + i * 4 + 4 > len(d):
                self.strings.append("")
                continue
            off = self._u32(offsets_base + i * 4)
            p = strings_base + off
            if p >= len(d):
                self.strings.append("")
                continue
            try:
                self.strings.append(self._decode_str(p, is_utf8))
            except Exception:
                self.strings.append("")

    def _decode_str(self, p: int, is_utf8: bool) -> str:
        d = self.data
        if is_utf8:
            char_len = d[p]
            p += 1
            if char_len & 0x80:
                char_len = ((char_len & 0x7F) << 8) | d[p]
                p += 1
            byte_len = d[p]
            p += 1
            if byte_len & 0x80:
                byte_len = ((byte_len & 0x7F) << 8) | d[p]
                p += 1
            return d[p : p + byte_len].decode("utf-8", errors="replace")
        else:
            char_len = self._u16(p)
            p += 2
            if char_len & 0x8000:
                char_len = ((char_len & 0x7FFF) << 16) | self._u16(p)
                p += 2
            return d[p : p + char_len * 2].decode("utf-16-le", errors="replace")

    # ── Attribute value ───────────────────────────────────────────────────────

    def _attr_val(self, raw_idx: int, dtype: int, ddata: int) -> Any:
        if dtype == self._T_STRING:
            return self._str(ddata)
        if dtype in (self._T_INTDEC, self._T_INTHEX):
            return ddata
        if dtype == self._T_INTBOOL:
            return bool(ddata)
        if dtype == self._T_REF:
            return f"@0x{ddata:08x}"
        if raw_idx != 0xFFFFFFFF:
            return self._str(raw_idx)
        return ddata

    # ── Main parse ────────────────────────────────────────────────────────────

    def parse(self) -> dict:
        d = self.data
        if len(d) < 8 or self._u16(0) != self._CHUNK_XML:
            return {"error": "Not a valid binary XML file"}

        result: dict[str, Any] = {
            "package": "",
            "version_name": "",
            "version_code": 0,
            "min_sdk": 0,
            "target_sdk": 0,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "application": {"label": "", "debuggable": False},
        }

        pos = 8  # skip file header
        while pos + 8 <= len(d):
            ctype = self._u16(pos)
            chdr = self._u16(pos + 2)
            csz = self._u32(pos + 4)
            if csz < 8 or pos + csz > len(d):
                break

            if ctype == self._CHUNK_STRPOOL:
                self._parse_string_pool(pos)

            elif ctype == self._CHUNK_START_EL and chdr >= 16:
                # node header: 8 bytes header + 4 line_num + 4 comment
                # ResXMLTree_attrExt starts at offset 16:
                #   ns(4), name(4), attrStart(2), attrSize(2), attrCount(2), ...
                if pos + 36 > len(d):
                    pos += csz
                    continue
                name_idx = self._u32(pos + 20)
                attr_start = self._u16(pos + 24)  # offset from attrExt (pos+16)
                attr_size = self._u16(pos + 26)  # bytes per attribute (usually 20)
                attr_count = self._u16(pos + 28)
                name = self._str(name_idx)

                # Attributes base = pos + 16 (node hdr) + attr_start (from attrExt)
                ab = pos + 16 + attr_start
                attrs: dict[str, Any] = {}
                for i in range(attr_count):
                    ap = ab + i * attr_size
                    if ap + attr_size > len(d):
                        break
                    a_name = self._u32(ap + 4)
                    a_raw = self._u32(ap + 8)
                    v_type = self._u8(ap + 15)
                    v_data = self._u32(ap + 16)
                    key = self._str(a_name)
                    if key:
                        attrs[key] = self._attr_val(a_raw, v_type, v_data)

                self._process_el(name, attrs, result)

            pos += csz

        # Deduplicate lists
        for key in ("permissions", "activities", "services", "receivers", "providers"):
            result[key] = sorted(set(result[key]))
        return result

    def _process_el(self, name: str, attrs: dict, result: dict) -> None:
        if name == "manifest":
            result["package"] = str(attrs.get("package", ""))
            result["version_name"] = str(attrs.get("versionName", ""))
            vc = attrs.get("versionCode", 0)
            try:
                result["version_code"] = int(vc)
            except (TypeError, ValueError):
                result["version_code"] = 0
        elif name == "uses-sdk":
            for key, dst in (("minSdkVersion", "min_sdk"), ("targetSdkVersion", "target_sdk")):
                v = attrs.get(key, 0)
                try:
                    result[dst] = int(v)
                except (TypeError, ValueError):
                    pass
        elif name == "uses-permission":
            n = str(attrs.get("name", "") or attrs.get("android:name", ""))
            if (n and "android.permission" in n) or "." in n:
                result["permissions"].append(n)
        elif name == "activity":
            n = str(attrs.get("name", ""))
            if n:
                result["activities"].append(n)
        elif name == "service":
            n = str(attrs.get("name", ""))
            if n:
                result["services"].append(n)
        elif name == "receiver":
            n = str(attrs.get("name", ""))
            if n:
                result["receivers"].append(n)
        elif name == "provider":
            n = str(attrs.get("name", ""))
            if n:
                result["providers"].append(n)
        elif name == "application":
            result["application"]["label"] = str(attrs.get("label", ""))
            result["application"]["debuggable"] = bool(attrs.get("debuggable", False))


def _parse_manifest(data: bytes) -> dict:
    """Parse AndroidManifest.xml bytes (binary XML or plaintext XML fallback)."""
    # Binary XML starts with 0x0300
    if len(data) >= 4 and data[:2] == b"\x03\x00":
        try:
            return _AXMLParser(data).parse()
        except Exception as exc:
            log.debug("Binary XML parse error: %s", exc)
    # Fallback: try as plain-text XML (some tools repack as text)
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(data.decode("utf-8", errors="replace"))
        ns = "http://schemas.android.com/apk/res/android"
        result: dict[str, Any] = {
            "package": root.attrib.get("package", ""),
            "version_name": root.attrib.get(f"{{{ns}}}versionName", ""),
            "version_code": 0,
            "min_sdk": 0,
            "target_sdk": 0,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "application": {"label": "", "debuggable": False},
        }
        vc = root.attrib.get(f"{{{ns}}}versionCode", "0")
        try:
            result["version_code"] = int(vc)
        except ValueError:
            pass
        sdk_el = root.find("uses-sdk")
        if sdk_el is not None:
            for attr, dst in (
                (f"{{{ns}}}minSdkVersion", "min_sdk"),
                (f"{{{ns}}}targetSdkVersion", "target_sdk"),
            ):
                v = sdk_el.attrib.get(attr, "")
                try:
                    result[dst] = int(v)
                except ValueError:
                    pass
        for tag in root.iter("uses-permission"):
            n = tag.attrib.get(f"{{{ns}}}name", "")
            if n:
                result["permissions"].append(n)
        for comp, lst in (
            ("activity", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers"),
        ):
            for el in root.iter(comp):
                n = el.attrib.get(f"{{{ns}}}name", "")
                if n:
                    result[lst].append(n)
        for key in ("permissions", "activities", "services", "receivers", "providers"):
            result[key] = sorted(set(result[key]))
        return result
    except Exception as exc:
        log.debug("Plaintext manifest parse error: %s", exc)
        return {"error": "Failed to parse AndroidManifest.xml"}


# ── .so file analysis ─────────────────────────────────────────────────────────


def _analyse_so_file(path: str, data: bytes) -> dict[str, Any]:
    """ELF header info + hex_dump + strings for a .so file."""
    capped = data[:_SO_HEX_CAP]
    entry: dict[str, Any] = {
        "path": path,
        "size": len(data),
        **_build_hex_dump(capped),
    }
    if capped[:4] == b"\x7fELF":
        entry["elf"] = _parse_elf(capped)
    strs = _strings_ascii(capped)
    entry["strings_ascii"] = strs[:100]
    entry["artifacts"] = _analyse_strings(strs)
    return entry


# ── JADX ─────────────────────────────────────────────────────────────────────


def jadx_available() -> bool:
    return shutil.which("jadx") is not None


def _run_jadx_sync(apk_path: str) -> dict[str, Any]:
    """Run JADX on the APK and return collected sources. asyncio.to_thread target."""
    tmpdir = tempfile.mkdtemp(prefix="jadx_")
    try:
        result = subprocess.run(
            ["jadx", "-d", tmpdir, "--no-res", "--log-level", "ERROR", apk_path],
            capture_output=True,
            text=True,
            timeout=_JADX_TIMEOUT,
        )
        classes: list[dict] = []
        total = 0
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, tmpdir).replace(os.sep, "/")
                total += 1
                if len(classes) >= _MAX_CLASSES:
                    continue
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        src = f.read(_MAX_SRC_BYTES)
                    classes.append({"path": rel, "source": src})
                except Exception:
                    pass
        # Sort: shorter paths (top-level classes) first
        classes.sort(key=lambda c: c["path"].count("/"))
        return {
            "status": "ok",
            "total_classes": total,
            "classes": classes[:_MAX_CLASSES],
            "stderr": result.stderr[:2000] if result.returncode != 0 else "",
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "total_classes": 0, "classes": []}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "total_classes": 0, "classes": []}
    finally:
        import shutil as _sh

        _sh.rmtree(tmpdir, ignore_errors=True)


def _read_entry(zf: zipfile.ZipFile, name: str) -> bytes:
    """Read a zip member, refusing entries whose declared size is excessive
    (decompression bombs) or whose real size exceeds the declared size."""
    info = zf.getinfo(name)
    if info.file_size > _MAX_ENTRY_BYTES:
        raise ValueError(f"{name}: entry too large ({info.file_size} bytes)")
    with zf.open(info) as fh:
        data = fh.read(_MAX_ENTRY_BYTES + 1)
    if len(data) > _MAX_ENTRY_BYTES:
        raise ValueError(f"{name}: entry inflates beyond the allowed size")
    return data


def _run_apk_sync(data: bytes) -> dict[str, Any]:
    """Full APK analysis: extract + parse manifest + .so files + JADX.
    asyncio.to_thread target.
    """
    result: dict[str, Any] = {
        "manifest": {},
        "dex_files": [],
        "so_files": [],
        "jadx": {"status": "not_available", "total_classes": 0, "classes": []},
        "asset_count": 0,
        "all_files": [],
    }

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"error": "Not a valid ZIP/APK file"}

    entries = zf.infolist()
    result["all_files"] = [
        {"name": e.filename, "size": e.file_size, "csize": e.compress_size} for e in entries[:300]
    ]

    # ── AndroidManifest.xml ───────────────────────────────────────────────────
    if "AndroidManifest.xml" in zf.namelist():
        try:
            manifest_bytes = _read_entry(zf, "AndroidManifest.xml")
            result["manifest"] = _parse_manifest(manifest_bytes)
        except Exception as exc:
            result["manifest"] = {"error": str(exc)}

    # ── DEX files ─────────────────────────────────────────────────────────────
    result["dex_files"] = [e.filename for e in entries if e.filename.endswith(".dex")]

    # ── .so files ─────────────────────────────────────────────────────────────
    so_entries = [e for e in entries if e.filename.endswith(".so")]
    for e in so_entries[:_MAX_SO_FILES]:
        try:
            so_data = _read_entry(zf, e.filename)
            result["so_files"].append(_analyse_so_file(e.filename, so_data))
        except Exception as exc:
            result["so_files"].append({"path": e.filename, "size": e.file_size, "error": str(exc)})

    # ── Asset count ───────────────────────────────────────────────────────────
    result["asset_count"] = sum(1 for e in entries if e.filename.startswith("assets/"))

    # ── JADX ─────────────────────────────────────────────────────────────────
    if jadx_available():
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".apk")
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(data)
            result["jadx"] = _run_jadx_sync(tmp_path)
        except Exception as exc:
            result["jadx"] = {
                "status": "error",
                "error": str(exc),
                "total_classes": 0,
                "classes": [],
            }
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    else:
        result["jadx"] = {"status": "not_available", "total_classes": 0, "classes": []}

    return result


async def analyse(data: bytes) -> dict[str, Any]:
    """Full APK analysis (async entry point)."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_apk_sync, data),
            timeout=_JADX_TIMEOUT + 30,
        )
    except TimeoutError:
        return {"error": f"APK analysis timed out after {_JADX_TIMEOUT + 30}s"}
    except Exception as exc:
        return {"error": str(exc)}
