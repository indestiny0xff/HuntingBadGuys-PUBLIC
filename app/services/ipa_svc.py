"""IPA analysis service.

Extracts:
- Info.plist (bundle ID, version, min OS, supported devices)
- Linked frameworks and dylibs (Mach-O load commands)
- Entitlements (embedded in code signature)
- Main binary metadata (Mach-O header) + hex_dump for radare2/DDV
"""

from __future__ import annotations

import asyncio
import io
import logging
import plistlib
import re
import struct
import zipfile
from typing import Any

from .efa_svc import _analyse_strings, _build_hex_dump, _strings_ascii

log = logging.getLogger(__name__)

_MACHO_HEX_CAP = 4 * 1024 * 1024  # 4 MB hex dump for DDV
_MAX_FRAMEWORKS = 80
_MAX_ENTRY_BYTES = 64 * 1024 * 1024  # zip-bomb guard


# ── Mach-O parser ─────────────────────────────────────────────────────────────

_MACHO_MAGIC = {
    0xFEEDFACE: ("big", 32),
    0xCEFAEDFE: ("little", 32),
    0xFEEDFACF: ("big", 64),
    0xCFFAEDFE: ("little", 64),
}

_CPU_TYPES = {
    0x0000000C: "arm",
    0x0100000C: "arm64",
    0x00000007: "x86",
    0x01000007: "x86_64",
    0x00000012: "ppc",
    0x01000012: "ppc64",
}

_MH_FILETYPES = {
    0x01: "relocatable",
    0x02: "execute",
    0x03: "fvmlib",
    0x04: "core",
    0x05: "preload",
    0x06: "dylib",
    0x07: "dylinker",
    0x08: "bundle",
    0x0A: "dylib_stub",
    0x0B: "dsym",
}

# LC_ codes we care about
_LC_LOAD_DYLIB = 0x0000000C
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_RPATH = 0x8000001C
_LC_UUID = 0x0000001B
_LC_ENCRYPTION_INFO = 0x00000021
_LC_ENCRYPTION_INFO_64 = 0x0000002C
_LC_SOURCE_VERSION = 0x0000002A


def _parse_macho(data: bytes) -> dict[str, Any]:
    """Parse Mach-O binary headers and load commands."""
    result: dict[str, Any] = {}
    if len(data) < 8:
        return result

    magic = struct.unpack_from(">I", data, 0)[0]

    # Fat binary — list architectures, pick arm64 or first slice
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        endian = ">" if magic == 0xCAFEBABE else "<"
        nfat = struct.unpack_from(endian + "I", data, 4)[0]
        archs = []
        for i in range(min(nfat, 8)):
            base = 8 + i * 20
            if base + 20 > len(data):
                break
            cputype = struct.unpack_from(endian + "i", data, base)[0]
            offset = struct.unpack_from(endian + "I", data, base + 8)[0]
            size = struct.unpack_from(endian + "I", data, base + 12)[0]
            archs.append(
                {
                    "cpu": _CPU_TYPES.get(cputype & 0x01FFFFFF, f"0x{cputype:08x}"),
                    "offset": offset,
                    "size": size,
                }
            )
        result["fat"] = True
        result["architectures"] = [a["cpu"] for a in archs]
        # Recurse into arm64 slice if present
        arm64 = next((a for a in archs if a["cpu"] == "arm64"), archs[0] if archs else None)
        if arm64:
            sl = data[arm64["offset"] : arm64["offset"] + arm64["size"]]
            inner = _parse_macho(sl)
            inner["fat"] = True
            inner["architectures"] = result["architectures"]
            return inner
        return result

    # Thin binary
    endian_str, bits_info = _MACHO_MAGIC.get(magic, (None, None))
    if not endian_str:
        return {"error": f"Unknown Mach-O magic 0x{magic:08x}"}

    fmt = "<" if endian_str == "little" else ">"
    cputype = struct.unpack_from(fmt + "i", data, 4)[0]
    struct.unpack_from(fmt + "i", data, 8)[0]
    filetype = struct.unpack_from(fmt + "I", data, 12)[0]
    ncmds = struct.unpack_from(fmt + "I", data, 16)[0]
    flags = struct.unpack_from(fmt + "I", data, 24)[0]
    hdr_size = 32 if bits_info == 64 else 28

    result["bits"] = bits_info
    result["endian"] = endian_str
    result["arch"] = _CPU_TYPES.get(cputype & 0x01FFFFFF, f"0x{cputype:08x}")
    result["filetype"] = _MH_FILETYPES.get(filetype, f"0x{filetype:x}")
    result["is_pie"] = bool(flags & 0x200000)
    result["is_encrypted"] = False

    dylibs: list[str] = []
    rpaths: list[str] = []

    pos = hdr_size
    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(data):
            break
        cmd = struct.unpack_from(fmt + "I", data, pos)[0]
        cmd_sz = struct.unpack_from(fmt + "I", data, pos + 4)[0]
        if cmd_sz < 8 or pos + cmd_sz > len(data):
            break

        if cmd in (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB):
            # dylib_command: cmd(4)+size(4)+dylib(16: name_offset(4)+ts(4)+cv(4)+cv(4))
            if cmd_sz >= 24:
                name_off = struct.unpack_from(fmt + "I", data, pos + 8)[0]
                name_abs = pos + name_off
                if name_abs < len(data):
                    end = data.find(b"\x00", name_abs)
                    if end < 0:
                        end = min(name_abs + 256, len(data))
                    dylibs.append(data[name_abs:end].decode("utf-8", errors="replace"))
        elif cmd == _LC_RPATH:
            if cmd_sz >= 12:
                path_off = struct.unpack_from(fmt + "I", data, pos + 8)[0]
                path_abs = pos + path_off
                if path_abs < len(data):
                    end = data.find(b"\x00", path_abs)
                    if end < 0:
                        end = min(path_abs + 256, len(data))
                    rpaths.append(data[path_abs:end].decode("utf-8", errors="replace"))
        elif cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
            crypt_id = struct.unpack_from(fmt + "I", data, pos + 16)[0]
            result["is_encrypted"] = crypt_id != 0

        pos += cmd_sz

    result["dylibs"] = dylibs[:_MAX_FRAMEWORKS]
    result["rpaths"] = rpaths
    return result


# ── Entitlement extraction ────────────────────────────────────────────────────

_PLIST_PATTERN = re.compile(
    rb"<\?xml[^>]+\?>\s*<!DOCTYPE plist[^>]*>\s*<plist[^>]*>.*?</plist>",
    re.DOTALL | re.IGNORECASE,
)


def _extract_entitlements(data: bytes) -> dict:
    """Search binary for embedded plist entitlements (code signature)."""
    for m in _PLIST_PATTERN.finditer(data):
        try:
            return plistlib.loads(m.group(0))
        except Exception:
            continue
    return {}


# ── Main IPA analysis ─────────────────────────────────────────────────────────


def _read_entry(zf: zipfile.ZipFile, name: str) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > _MAX_ENTRY_BYTES:
        raise ValueError(f"{name}: entry too large")
    with zf.open(info) as fh:
        data = fh.read(_MAX_ENTRY_BYTES + 1)
    if len(data) > _MAX_ENTRY_BYTES:
        raise ValueError(f"{name}: entry inflates beyond the allowed size")
    return data


def _find_app_binary(zf: zipfile.ZipFile) -> tuple[str, bytes] | None:
    """Find the main executable binary in Payload/*.app/.

    Returns (name, bytes) or None.
    """
    names = zf.namelist()
    # Find Info.plist to get CFBundleExecutable name
    plist_paths = [n for n in names if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)]
    for pp in plist_paths:
        try:
            raw = _read_entry(zf, pp)
            pl = plistlib.loads(raw)
            exe = pl.get("CFBundleExecutable", "")
            if exe:
                app_dir = pp.rsplit("/", 1)[0]  # Payload/MyApp.app
                bin_path = f"{app_dir}/{exe}"
                if bin_path in names:
                    return bin_path, _read_entry(zf, bin_path)
        except Exception:
            continue
    # Fallback: look for a Mach-O file in Payload/*.app/ (not in Frameworks)
    for name in names:
        if not re.match(r"^Payload/[^/]+\.app/[^/]+$", name):
            continue
        if "." in name.rsplit("/", 1)[-1]:
            continue  # skip files with extensions (dylibs, plists, etc.)
        try:
            data = _read_entry(zf, name)
            if data[:4] in (
                b"\xfe\xed\xfa\xce",
                b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe",
                b"\xbe\xba\xfe\xca",
            ):
                return name, data
        except Exception:
            continue
    return None


def _run_ipa_sync(data: bytes) -> dict[str, Any]:
    """Full IPA analysis. asyncio.to_thread target."""
    result: dict[str, Any] = {
        "bundle_id": "",
        "display_name": "",
        "version": "",
        "build_version": "",
        "min_os_version": "",
        "platform": "",
        "supported_devices": [],
        "frameworks": [],
        "entitlements": {},
        "main_binary": None,
        "info_plist": {},
    }

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"error": "Not a valid ZIP/IPA file"}

    names = zf.namelist()

    # ── Info.plist ────────────────────────────────────────────────────────────
    plist_paths = [n for n in names if re.match(r"^Payload/[^/]+\.app/Info\.plist$", n)]
    info: dict = {}
    if plist_paths:
        try:
            info = plistlib.loads(_read_entry(zf, plist_paths[0]))
        except Exception as exc:
            log.debug("IPA Info.plist parse error: %s", exc)

    result["bundle_id"] = info.get("CFBundleIdentifier", "")
    result["display_name"] = info.get("CFBundleDisplayName") or info.get("CFBundleName", "")
    result["version"] = info.get("CFBundleShortVersionString", "")
    result["build_version"] = info.get("CFBundleVersion", "")
    result["min_os_version"] = info.get("MinimumOSVersion", "")
    result["platform"] = info.get("DTPlatformName", "")
    result["supported_devices"] = info.get("UISupportedInterfaceOrientations", [])

    # Key fields for info_plist summary (not the full blob)
    safe_keys = (
        "CFBundleIdentifier",
        "CFBundleDisplayName",
        "CFBundleName",
        "CFBundleShortVersionString",
        "CFBundleVersion",
        "MinimumOSVersion",
        "DTPlatformName",
        "DTSDKName",
        "UIRequiredDeviceCapabilities",
        "LSApplicationQueriesSchemes",
        "NSAppTransportSecurity",
        "NSLocationWhenInUseUsageDescription",
        "NSCameraUsageDescription",
        "NSMicrophoneUsageDescription",
        "UIBackgroundModes",
    )
    result["info_plist"] = {k: info[k] for k in safe_keys if k in info}

    # ── Frameworks from Payload/*.app/Frameworks/ ─────────────────────────────
    fw_set: set[str] = set()
    for n in names:
        m = re.match(r"^Payload/[^/]+\.app/Frameworks/([^/]+\.(?:framework|dylib))/", n)
        if m:
            fw_set.add(m.group(1))
    result["frameworks"] = sorted(fw_set)[:_MAX_FRAMEWORKS]

    # ── Main binary ───────────────────────────────────────────────────────────
    bin_result = _find_app_binary(zf)
    if bin_result:
        bin_path, bin_data = bin_result
        capped = bin_data[:_MACHO_HEX_CAP]
        macho = _parse_macho(capped)
        strs = _strings_ascii(capped)
        # Merge dylibs from Mach-O with framework list
        for lib in macho.get("dylibs", []):
            fw_name = lib.rsplit("/", 1)[-1]
            if fw_name.endswith(".dylib") or ".framework/" in lib:
                fw_set.add(fw_name)
        # Deduplicate frameworks
        result["frameworks"] = sorted(fw_set)[:_MAX_FRAMEWORKS]

        entitlements = _extract_entitlements(capped)
        result["entitlements"] = entitlements

        result["main_binary"] = {
            "path": bin_path,
            "size": len(bin_data),
            "macho": macho,
            **_build_hex_dump(capped),
            "strings_ascii": strs[:100],
            "artifacts": _analyse_strings(strs),
        }

    return result


async def analyse(data: bytes) -> dict[str, Any]:
    """Full IPA analysis (async entry point)."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_ipa_sync, data),
            timeout=90,
        )
    except TimeoutError:
        return {"error": "IPA analysis timed out after 90s"}
    except Exception as exc:
        return {"error": str(exc)}
