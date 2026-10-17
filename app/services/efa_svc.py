"""EFA — Extracted File Analysis: static content analysis of crawled files."""

from __future__ import annotations

import io
import logging
import math
import os
import re
import struct
import zipfile
from typing import Any

import httpx

from ..config import settings
from ..security import ssrf_request_hook

log = logging.getLogger(__name__)

_MAX_FILE_BYTES = 100 * 1024 * 1024
_FETCH_CAP = min(settings.max_file_bytes, 2 * 1024 * 1024)  # 2 MB cap (scripts, configs…)
# APK/IPA are ZIP archives — Python's zipfile needs the central directory which sits at the
# END of the file.  Truncating the download makes the file unreadable.  Use a generous fixed
# cap (50 MB) that is NOT tied to settings.max_file_bytes (the crawler cap for small files).
_APK_IPA_FETCH_CAP = 50 * 1024 * 1024  # 50 MB fixed — independent of global crawler cap
_PREVIEW_BYTES = 5 * 1024 * 1024
_STRINGS_MIN_LEN = 4
_STRINGS_MAX = 500

_TEXT_EXT = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".py",
        ".rb",
        ".pl",
        ".sh",
        ".bash",
        ".zsh",
        ".vbs",
        ".vba",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".html",
        ".htm",
        ".xhtml",
        ".css",
        ".scss",
        ".xml",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".conf",
        ".config",
        ".env",
        ".cfg",
        ".txt",
        ".log",
        ".md",
        ".rst",
        ".csv",
        ".sql",
        ".asp",
        ".aspx",
        ".jsp",
        ".jspx",
        ".htaccess",
        ".htpasswd",
        ".lua",
        ".go",
        ".java",
        ".c",
        ".cpp",
        ".h",
    }
)
_ZIP_EXT = frozenset({".zip", ".jar", ".war", ".ear"})  # .apk/.ipa handled separately
_APK_EXT = frozenset({".apk"})
_IPA_EXT = frozenset({".ipa"})
_PDF_EXT = frozenset({".pdf"})
_LNK_EXT = frozenset({".lnk"})
_EXEC_EXT = frozenset({".exe", ".dll", ".sys", ".drv", ".ocx", ".scr", ".pif", ".com"})
_ELF_EXT = frozenset({".elf", ".so", ".bin", ".out"})
_OFFICE_EXT = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"})


def _ext(path: str) -> str:
    return os.path.splitext(path.lower())[1]


def _is_text_ct(ct: str | None) -> bool:
    if not ct:
        return False
    ct = ct.lower().split(";")[0].strip()
    return any(
        ct.startswith(p)
        for p in (
            "text/",
            "application/javascript",
            "application/json",
            "application/xml",
            "application/x-sh",
            "application/x-python",
        )
    )


# ── Magic byte detection ──────────────────────────────────────────────────────

_MAGIC: list[tuple[bytes, str]] = [
    (b"MZ", "PE/Windows Executable"),
    (b"\x7fELF", "ELF Binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"\xca\xfe\xba\xbe", "Mach-O Fat Binary"),
    (b"PK\x03\x04", "ZIP Archive"),
    (b"Rar!\x1a\x07", "RAR Archive"),
    (b"\x1f\x8b", "GZip Archive"),
    (b"BZh", "BZip2 Archive"),
    (b"\xfd7zXZ", "XZ Archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"%PDF", "PDF Document"),
    (b"\xd0\xcf\x11\xe0", "OLE2 / MS Office (legacy)"),
    (b"\x4c\x00\x00\x00", "Windows LNK Shortcut"),
    (b"MSCF", "Cabinet / CAB Archive"),
    (b"#!/", "Shell Script"),
    (b"#!", "Script (shebang)"),
    (b"\x89PNG", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"GIF8", "GIF Image"),
]


def _detect_magic(data: bytes) -> str:
    for magic, label in _MAGIC:
        if data[: len(magic)] == magic:
            return label
    return f"Unknown (0x{data[:4].hex()})"


# ── Entropy ───────────────────────────────────────────────────────────────────


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _entropy_label(e: float) -> str:
    if e < 3.5:
        return "low (plaintext / sparse)"
    if e < 6.0:
        return "medium (compiled code)"
    if e < 7.2:
        return "high (compressed data)"
    return "very high — likely packed / encrypted"


# ── String extraction ─────────────────────────────────────────────────────────


def _strings_ascii(data: bytes) -> list[str]:
    pat = re.compile(rb"[ -~]{" + str(_STRINGS_MIN_LEN).encode() + rb",}")
    return [m.group(0).decode("ascii", errors="replace") for m in pat.finditer(data)][:_STRINGS_MAX]


def _strings_utf16(data: bytes) -> list[str]:
    """UTF-16 LE — equivalent to strings -el."""
    try:
        decoded = data.decode("utf-16-le", errors="ignore")
        results, current = [], []
        for ch in decoded:
            if ch.isprintable() and ch != "\x00":
                current.append(ch)
            else:
                if len(current) >= _STRINGS_MIN_LEN:
                    results.append("".join(current))
                current = []
        if len(current) >= _STRINGS_MIN_LEN:
            results.append("".join(current))
        return results[:_STRINGS_MAX]
    except Exception:
        return []


# ── Artifact analysis of extracted strings ────────────────────────────────────

_ARTIFACT_PATS: dict[str, str] = {
    # Registry
    "registry_keys": r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKU|HKCR)\\[^\s\"'<>]{4,200}",
    # DLLs / system files
    "dll_names": r"\b[a-zA-Z0-9_\-]{2,40}\.(?:dll|sys|drv|ocx)\b",
    # Windows API / suspicious calls
    "winapi_calls": r"\b(?:VirtualAlloc|VirtualProtect|CreateRemoteThread|WriteProcessMemory|ReadProcessMemory|NtUnmapViewOfSection|RtlDecompressBuffer|IsDebuggerPresent|CheckRemoteDebuggerPresent|CreateProcess|ShellExecute(?:Ex)?|WinExec|LoadLibrary(?:Ex)?|GetProcAddress|RegOpenKey(?:Ex)?|RegSetValue(?:Ex)?|InternetOpen|InternetConnect|HttpSendRequest|WSAStartup|connect|recv|send|socket)\b",
    # Windows paths / environment vars
    "windows_paths": r"(?:%(?:APPDATA|TEMP|USERPROFILE|PROGRAMDATA|SYSTEMROOT|WINDIR|PUBLIC|COMMONPROGRAMFILES|PROGRAMFILES(?:x86)?)%|[Cc]:\\(?:Windows|Users|ProgramData|Program Files|AppData|Temp)[\\\/][^\s\"'<>]{3,200})",
    # Scheduled tasks / services
    "services_tasks": r"(?:sc\s+(?:create|config|start|stop|delete)|schtasks\s+/(?:create|run|delete)|net\s+(?:start|stop|user|localgroup))[^\n]{0,200}",
    # PowerShell / cmd suspicious
    "suspicious_cmds": r"(?:powershell(?:\.exe)?\s+(?:-[eE]nc(?:odedCommand)?|-[wW]indowStyle\s+[hH]idden|-[bB]ypass|-[nN]oprofile|-[eE]xec(?:utionPolicy)?\s+[bB]ypass)[^\n]{0,300}|cmd(?:\.exe)?\s+/[cCkK]\s+[^\n]{3,200}|mshta(?:\.exe)?\s+[^\s]{5,}|wscript(?:\.exe)?\s+[^\s]{5,}|cscript(?:\.exe)?\s+[^\s]{5,}|regsvr32(?:\.exe)?[^\n]{0,200}|rundll32(?:\.exe)?[^\n]{0,200}|certutil\s+(?:-decode|-urlcache)[^\n]{0,200}|bitsadmin\s+/transfer[^\n]{0,200})",
    # URLs / IPs in strings
    "urls": r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>]{0,200})?",
    "ip_port": r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b",
    # Mutex names (common malware pattern)
    "mutex_names": r"(?:Global|Local)\\[a-zA-Z0-9_\-\.\{\}]{6,64}",
    # Named pipes
    "named_pipes": r"\\\\.\\pipe\\[a-zA-Z0-9_\-]{4,64}",
    # Interesting file extensions in paths
    "dropped_files": r"[a-zA-Z0-9_\-]{3,40}\.(?:exe|dll|bat|ps1|vbs|js|hta|jar|tmp|dat|bin|cfg|log)\b",
    # Base64 blobs (potential encoded payload)
    "base64_blobs": r"(?:[A-Za-z0-9+/]{40,}={0,2})",
}

_MAX_ARTIFACTS = 30


def _analyse_strings(strings: list[str]) -> dict[str, list[str]]:
    """Run artifact patterns over extracted strings."""
    combined = "\n".join(strings)
    if not combined:
        return {}
    out: dict[str, list[str]] = {}
    for cat, pat in _ARTIFACT_PATS.items():
        matches = {m.group(0).strip() for m in re.finditer(pat, combined, re.IGNORECASE)}
        if matches:
            # Filter noise for some categories
            if cat == "dll_names":
                # Skip very common/benign DLLs
                skip = {
                    "ntdll.dll",
                    "kernel32.dll",
                    "user32.dll",
                    "gdi32.dll",
                    "advapi32.dll",
                    "msvcrt.dll",
                    "ole32.dll",
                    "oleaut32.dll",
                    "shell32.dll",
                    "comctl32.dll",
                    "comdlg32.dll",
                    "ws2_32.dll",
                }
                matches = {m for m in matches if m.lower() not in skip}
            if cat == "base64_blobs":
                # Only keep if looks like actual b64 (length divisible by 4 roughly)
                matches = {m for m in matches if len(m) >= 60}
            if matches:
                out[cat] = sorted(matches)[:_MAX_ARTIFACTS]
    return out


# ── PE header parser ──────────────────────────────────────────────────────────


def _parse_pe(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        if len(data) < 64 or data[:2] != b"MZ":
            return result
        pe_offset = struct.unpack_from("<I", data, 60)[0]
        if pe_offset + 24 > len(data):
            return result
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return result

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        ts = struct.unpack_from("<I", data, pe_offset + 8)[0]
        n_sec = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_sz = struct.unpack_from("<H", data, pe_offset + 20)[0]
        chars = struct.unpack_from("<H", data, pe_offset + 22)[0]

        machine_map = {
            0x014C: "x86",
            0x8664: "x86-64",
            0x01C0: "ARM",
            0xAA64: "ARM64",
            0x0200: "IA-64",
        }
        result["arch"] = machine_map.get(machine, f"0x{machine:04x}")
        result["timestamp"] = ts
        result["is_dll"] = bool(chars & 0x2000)
        result["is_aslr"] = bool(chars & 0x0040)
        result["sections"] = n_sec

        opt_base = pe_offset + 24
        magic = struct.unpack_from("<H", data, opt_base)[0] if opt_base + 2 <= len(data) else 0
        result["pe_type"] = "PE32+" if magic == 0x20B else "PE32"

        # Section names
        sec_base = opt_base + opt_sz
        sections = []
        for i in range(min(n_sec, 32)):
            off = sec_base + i * 40
            if off + 40 > len(data):
                break
            name = data[off : off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            v_size = struct.unpack_from("<I", data, off + 8)[0]
            raw_sz = struct.unpack_from("<I", data, off + 16)[0]
            sections.append({"name": name, "vsize": v_size, "rsize": raw_sz})
        result["section_names"] = sections

        # Imported DLLs via string scan
        dll_pat = re.compile(rb"[a-zA-Z0-9_\-]{2,30}\.(?:dll|exe|sys)\x00", re.IGNORECASE)
        dlls = list(
            {
                m.group(0)[:-1].decode("ascii", errors="replace").lower()
                for m in dll_pat.finditer(data[: 512 * 1024])
            }
        )
        result["imported_dlls"] = sorted(dlls)[:60]

    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


# ── ELF header parser ─────────────────────────────────────────────────────────


def _parse_elf(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        if len(data) < 16 or data[:4] != b"\x7fELF":
            return result
        ei_class = data[4]
        ei_data = data[5]
        fmt = "<H" if ei_data == 1 else ">H"
        e_type = struct.unpack_from(fmt, data, 16)[0]
        e_machine = struct.unpack_from(fmt, data, 18)[0]

        result["bits"] = 64 if ei_class == 2 else 32
        result["endian"] = "little" if ei_data == 1 else "big"
        result["type"] = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}.get(
            e_type, f"0x{e_type:04x}"
        )
        result["machine"] = {
            0x02: "SPARC",
            0x03: "x86",
            0x08: "MIPS",
            0x14: "PowerPC",
            0x28: "ARM",
            0x3E: "x86-64",
            0xB7: "AArch64",
            0xF3: "RISC-V",
        }.get(e_machine, f"0x{e_machine:04x}")

        so_pat = re.compile(rb"lib[a-zA-Z0-9_\-]{1,30}\.so(?:\.\d+)*\x00")
        libs = [
            m.group(0)[:-1].decode("ascii", errors="replace")
            for m in so_pat.finditer(data[: 512 * 1024])
        ]
        result["shared_libs"] = sorted(set(libs))[:40]
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


# ── PDF ───────────────────────────────────────────────────────────────────────


def _extract_pdf_text(data: bytes) -> str:
    texts: list[str] = []
    for block in re.finditer(rb"BT(.*?)ET", data, re.DOTALL):
        for m in re.finditer(rb"\(([^)]{1,500})\)\s*Tj", block.group(1)):
            try:
                texts.append(m.group(1).decode("latin-1", errors="replace"))
            except Exception:
                pass
    return "\n".join(texts)[:10000]


# ── ZIP / Office ──────────────────────────────────────────────────────────────


def _analyse_zip(data: bytes, ext: str = ".zip") -> dict[str, Any]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        entries = [
            {"name": zi.filename, "size": zi.file_size, "csize": zi.compress_size}
            for zi in zf.infolist()[:200]
        ]
        result: dict[str, Any] = {
            "file_type": ext.lstrip(".") or "zip",
            "entry_count": len(zf.infolist()),
            "entries": entries,
        }
        if ext in (".docx", ".xlsx", ".pptx"):
            xml_names = [
                n
                for n in zf.namelist()
                if n.endswith(".xml")
                and ("word/document" in n or "xl/shared" in n or "ppt/slides" in n)
            ]
            texts = []
            for name in xml_names[:3]:
                if zf.getinfo(name).file_size > 8 * 1024 * 1024:
                    continue
                raw = zf.read(name).decode("utf-8", errors="replace")
                texts.append(re.sub(r"<[^>]+>", " ", raw)[:3000])
            if texts:
                result["text_preview"] = "\n".join(texts)[:5000]
        return result
    except zipfile.BadZipFile:
        return {"file_type": ext.lstrip(".") or "zip", "error": "not a valid archive"}
    except Exception as exc:
        return {"file_type": ext.lstrip(".") or "zip", "error": str(exc)}


# ── Hex dump ──────────────────────────────────────────────────────────────────

_HEX_BYTES_PER_LINE = 32
_HEX_GROUP_SIZE = 8


def _build_hex_dump(data: bytes) -> dict:
    rows: list[str] = []
    for i in range(0, len(data), _HEX_BYTES_PER_LINE):
        row = data[i : i + _HEX_BYTES_PER_LINE]
        groups = [
            " ".join(f"{b:02X}" for b in row[g : g + _HEX_GROUP_SIZE])
            for g in range(0, len(row), _HEX_GROUP_SIZE)
        ]
        hex_str = "  ".join(f"{g:<23}" for g in groups)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        rows.append(f"{i:08X}  {hex_str}  |{asc}|")
    return {
        "hex_dump": "\n".join(rows),
        "hex_size": len(data),
    }


# ── Main analyser ─────────────────────────────────────────────────────────────


async def analyse(
    url: str,
    path: str,
    content_type: str | None,
    size: int | None,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Fetch `url` and return a static analysis dict.

    Pass proxy='socks5://127.0.0.1:9050' for .onion targets.
    """
    if size is not None and size > _MAX_FILE_BYTES:
        return {
            "file_type": "skipped",
            "error": f"File too large ({size // 1024 // 1024} MB > 100 MB limit)",
        }

    ext = _ext(path)

    # APK and IPA use a higher fetch cap (up to 50 MB)
    is_mobile = ext in _APK_EXT or ext in _IPA_EXT
    fetch_cap = _APK_IPA_FETCH_CAP if is_mobile else _FETCH_CAP

    client_kwargs: dict = dict(verify=False, follow_redirects=True, timeout=settings.timeout)
    if proxy:
        client_kwargs["proxy"] = proxy
    else:
        client_kwargs["event_hooks"] = {"request": [ssrf_request_hook]}

    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {"file_type": "fetch_error", "error": f"HTTP {resp.status_code}"}
            data = resp.content[:fetch_cap]
            ct = content_type or resp.headers.get("content-type", "")
    except Exception as exc:
        return {"file_type": "fetch_error", "error": str(exc)}

    if not data:
        return {"file_type": "empty", "error": "Empty response"}

    magic_str = _detect_magic(data)
    ent = _entropy(data[:65536])
    base: dict[str, Any] = {
        "magic": magic_str,
        "entropy": round(ent, 3),
        "entropy_label": _entropy_label(ent),
        "size_fetched": len(data),
        **_build_hex_dump(data),
    }

    # ── APK — Android Package ─────────────────────────────────────────────────
    if ext in _APK_EXT or _looks_apk(data):
        from . import apk_svc

        apk = await apk_svc.analyse(data)
        return {**base, "file_type": "apk", "apk": apk}

    # ── IPA — iOS App Archive ─────────────────────────────────────────────────
    if ext in _IPA_EXT:
        from . import ipa_svc

        ipa = await ipa_svc.analyse(data)
        return {**base, "file_type": "ipa", "ipa": ipa}

    # ── PDF ───────────────────────────────────────────────────────────────────
    if ext in _PDF_EXT or data[:4] == b"%PDF":
        text = _extract_pdf_text(data)
        return {
            **base,
            "file_type": "pdf",
            "text_preview": text[:_PREVIEW_BYTES],
            "truncated": len(text) > _PREVIEW_BYTES,
        }

    # ── Office Open XML ───────────────────────────────────────────────────────
    if ext in _OFFICE_EXT:
        return {**base, **_analyse_zip(data, ext)}

    # ── ZIP / JAR ─────────────────────────────────────────────────────────────
    if ext in _ZIP_EXT or data[:4] == b"PK\x03\x04":
        return {**base, **_analyse_zip(data, ext or ".zip")}

    # ── LNK ───────────────────────────────────────────────────────────────────
    if ext in _LNK_EXT or data[:4] == b"\x4c\x00\x00\x00":
        ascii_s = _strings_ascii(data)
        utf16_s = _strings_utf16(data)
        return {
            **base,
            "file_type": "lnk",
            "strings_ascii": ascii_s,
            "strings_utf16": utf16_s,
            "artifacts": _analyse_strings(ascii_s + utf16_s),
        }

    # ── Windows PE ────────────────────────────────────────────────────────────
    if ext in _EXEC_EXT or data[:2] == b"MZ":
        ascii_s = _strings_ascii(data)
        utf16_s = _strings_utf16(data)
        return {
            **base,
            "file_type": "pe",
            "pe": _parse_pe(data),
            "strings_ascii": ascii_s,
            "strings_utf16": utf16_s,
            "artifacts": _analyse_strings(ascii_s + utf16_s),
        }

    # ── ELF ───────────────────────────────────────────────────────────────────
    if ext in _ELF_EXT or data[:4] == b"\x7fELF":
        ascii_s = _strings_ascii(data)
        return {
            **base,
            "file_type": "elf",
            "elf": _parse_elf(data),
            "strings_ascii": ascii_s,
            "artifacts": _analyse_strings(ascii_s),
        }

    # ── Text / source code ────────────────────────────────────────────────────
    if ext in _TEXT_EXT or _is_text_ct(ct) or _looks_text(data):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        truncated = len(text) > _PREVIEW_BYTES
        nt = _extract_network_traffic(text, ext, ct)
        result: dict[str, Any] = {
            **base,
            "file_type": "text",
            "language": _guess_lang(ext, ct),
            "content": text[:_PREVIEW_BYTES],
            "truncated": truncated,
            "total_lines": text.count("\n"),
        }
        if nt:
            result["nt"] = nt
        return result

    # ── Generic binary fallback ───────────────────────────────────────────────
    ascii_s = _strings_ascii(data)
    utf16_s = _strings_utf16(data)
    return {
        **base,
        "file_type": "binary",
        "strings_ascii": ascii_s,
        "strings_utf16": utf16_s,
        "artifacts": _analyse_strings(ascii_s + utf16_s),
    }


_NT_MAX = 30

# ── Network-traffic extraction regexes ───────────────────────────────────────

_NT_FETCH = re.compile(r"""fetch\s*\(\s*['"`]([^'"`\n]{3,200})['"`]""", re.IGNORECASE)
_NT_FETCH_METHOD = re.compile(r"""method\s*:\s*['"]([A-Z]+)['"]""", re.IGNORECASE)
_NT_XHR = re.compile(
    r"""\.open\s*\(\s*['"]([A-Z]+)['"]\s*,\s*['"`]([^'"`\n]{2,200})['"`]""", re.IGNORECASE
)
_NT_AXIOS_M = re.compile(
    r"""axios\.(get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`\n]{2,200})['"`]""",
    re.IGNORECASE,
)
_NT_AXIOS_CFG = re.compile(
    r"""axios\s*\(\s*\{(?:[^}]{0,500}?)url\s*:\s*['"`]([^'"`\n]{2,200})['"`]""", re.IGNORECASE
)
_NT_AXIOS_TYPE = re.compile(r"""method\s*:\s*['"]([a-zA-Z]+)['"]""", re.IGNORECASE)
_NT_JQ_SIMPLE = re.compile(
    r"""\$\.(get|post|getJSON|getScript)\s*\(\s*['"`]([^'"`\n]{2,200})['"`]""", re.IGNORECASE
)
_NT_JQ_AJAX = re.compile(
    r"""\$\.ajax\s*\(\s*\{(?:[^}]{0,600}?)url\s*:\s*['"`]([^'"`\n]{2,200})['"`]""", re.IGNORECASE
)
_NT_JQ_TYPE = re.compile(r"""(?:type|method)\s*:\s*['"]([A-Z]+)['"]""", re.IGNORECASE)
_NT_WS = re.compile(
    r"""['"`](wss?://[a-zA-Z0-9\-\.]+(?::\d+)?(?:/[^\s'"`]{0,120})?)['"`]""", re.IGNORECASE
)
_NT_FORM = re.compile(r"""<form\b[^>]{0,400}>""", re.IGNORECASE | re.DOTALL)
_NT_FORM_ACTION = re.compile(r"""\baction\s*=\s*['"]([^'"]{1,200})['"]""", re.IGNORECASE)
_NT_FORM_METHOD = re.compile(r"""\bmethod\s*=\s*['"]([a-zA-Z]+)['"]""", re.IGNORECASE)
_NT_API_BASE = re.compile(
    r"""(?:API_URL|API_BASE|BASE_URL|ENDPOINT|baseUrl|baseURL|apiUrl|apiBase|endpoint|host)\s*[=:]\s*['"`](https?://[^'"`\s]{4,200})['"`]""",
    re.IGNORECASE,
)
_NT_PHP_FGC = re.compile(r"""file_get_contents\s*\(\s*['"]([^'"]{4,200})['"]""", re.IGNORECASE)
_NT_PHP_CURL = re.compile(r"""curl_init\s*\(\s*['"]([^'"]{4,200})['"]""", re.IGNORECASE)
_NT_PHP_CURL_OPT = re.compile(r"""CURLOPT_URL\s*,\s*['"]([^'"]{4,200})['"]""", re.IGNORECASE)
_NT_GQL_EP = re.compile(r"""['"]([^'"]{1,200}graphql[^'"]{0,100})['"]""", re.IGNORECASE)
_NT_GQL_OP = re.compile(
    r"""\bgql\s*`[^`]{0,30}(?:query|mutation)\s+([a-zA-Z][a-zA-Z0-9_]{0,60})""", re.IGNORECASE
)
_NT_BEACON_TIMER = re.compile(r"""(?:setInterval|setTimeout)\s*\(""", re.IGNORECASE)
_NT_BEACON_NET = re.compile(r"""\bfetch\s*\(|\bnew\s+XMLHttpRequest\b|\.open\s*\(""", re.IGNORECASE)
_NT_BEACON_DELAY = re.compile(r""",\s*(\d{3,7})\s*\)""")

_PHP_EXT = frozenset({".php", ".php3", ".php4", ".php5", ".phtml"})


def _extract_network_traffic(text: str, ext: str, ct: str) -> dict[str, Any]:
    """Extract network-traffic patterns from text/script content — static analysis only."""
    if not text:
        return {}

    nt: dict[str, Any] = {}

    # ── fetch() ──────────────────────────────────────────────────────────────
    # Only scan inside the options object {…} immediately following the URL so we
    # don't pick up the method from a different fetch call further down the file.
    seen: set[str] = set()
    for m in _NT_FETCH.finditer(text):
        url = m.group(1).strip()
        after = text[m.end() : min(len(text), m.end() + 8)]
        method = "GET"
        if re.match(r"\s*,\s*\{", after):
            brace = text.find("{", m.end())
            if brace != -1:
                depth, end = 0, brace
                for i, ch in enumerate(text[brace : brace + 400]):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = brace + i
                            break
                mm = _NT_FETCH_METHOD.search(text[brace:end])
                if mm:
                    method = mm.group(1).upper()
        key = f"{method}:{url}"
        if key not in seen:
            seen.add(key)
            nt.setdefault("fetch_calls", []).append({"url": url, "method": method})

    # ── XMLHttpRequest.open() ─────────────────────────────────────────────────
    seen.clear()
    for m in _NT_XHR.finditer(text):
        method = m.group(1).upper()
        url = m.group(2).strip()
        key = f"{method}:{url}"
        if key not in seen:
            seen.add(key)
            nt.setdefault("xhr_calls", []).append({"url": url, "method": method})

    # ── axios ────────────────────────────────────────────────────────────────
    seen.clear()
    for m in _NT_AXIOS_M.finditer(text):
        method = m.group(1).upper()
        url = m.group(2).strip()
        key = f"{method}:{url}"
        if key not in seen:
            seen.add(key)
            nt.setdefault("axios_calls", []).append({"url": url, "method": method})
    for m in _NT_AXIOS_CFG.finditer(text):
        url = m.group(1).strip()
        ctx = text[max(0, m.start()) : min(len(text), m.end() + 80)]
        mm = _NT_AXIOS_TYPE.search(ctx)
        method = mm.group(1).upper() if mm else "GET"
        key = f"{method}:{url}"
        if key not in seen:
            seen.add(key)
            nt.setdefault("axios_calls", []).append({"url": url, "method": method})

    # ── jQuery ───────────────────────────────────────────────────────────────
    seen.clear()
    for m in _NT_JQ_SIMPLE.finditer(text):
        verb = m.group(1).lower()
        method = "GET" if verb in ("get", "getjson", "getscript") else "POST"
        url = m.group(2).strip()
        key = f"{method}:{url}"
        if key not in seen:
            seen.add(key)
            nt.setdefault("jquery_calls", []).append({"url": url, "method": method})
    for m in _NT_JQ_AJAX.finditer(text):
        url = m.group(1).strip()
        ctx = text[max(0, m.start()) : min(len(text), m.end() + 80)]
        mm = _NT_JQ_TYPE.search(ctx)
        method = mm.group(1).upper() if mm else "POST"
        key = f"{method}:{url}"
        if key not in seen:
            seen.add(key)
            nt.setdefault("jquery_calls", []).append({"url": url, "method": method})

    # ── WebSockets ────────────────────────────────────────────────────────────
    seen.clear()
    for m in _NT_WS.finditer(text):
        url = m.group(1).strip()
        if url not in seen:
            seen.add(url)
            nt.setdefault("websockets", []).append(url)

    # ── HTML form actions ─────────────────────────────────────────────────────
    seen.clear()
    for m in _NT_FORM.finditer(text):
        tag = m.group(0)
        am = _NT_FORM_ACTION.search(tag)
        if am:
            action = am.group(1).strip()
            mm = _NT_FORM_METHOD.search(tag)
            method = mm.group(1).upper() if mm else "GET"
            key = f"{method}:{action}"
            if key not in seen:
                seen.add(key)
                nt.setdefault("form_actions", []).append({"action": action, "method": method})

    # ── API base-URL constants ────────────────────────────────────────────────
    seen.clear()
    for m in _NT_API_BASE.finditer(text):
        url = m.group(1).strip()
        if url not in seen:
            seen.add(url)
            nt.setdefault("api_bases", []).append(url)

    # ── PHP outbound HTTP calls ───────────────────────────────────────────────
    if ext in _PHP_EXT or "php" in ct.lower():
        seen.clear()
        for pat, fn in (
            (_NT_PHP_FGC, "file_get_contents"),
            (_NT_PHP_CURL, "curl_init"),
            (_NT_PHP_CURL_OPT, "curl_setopt"),
        ):
            for m in pat.finditer(text):
                url = m.group(1).strip()
                if url not in seen:
                    seen.add(url)
                    nt.setdefault("php_http", []).append({"url": url, "fn": fn})

    # ── GraphQL ───────────────────────────────────────────────────────────────
    seen.clear()
    for m in _NT_GQL_EP.finditer(text):
        ep = m.group(1).strip()
        if ep not in seen:
            seen.add(ep)
            nt.setdefault("graphql", []).append(ep)
    for m in _NT_GQL_OP.finditer(text):
        name = f"op:{m.group(1)}"
        if name not in seen:
            seen.add(name)
            nt.setdefault("graphql", []).append(name)

    # ── Beacon / C2 heartbeat patterns ───────────────────────────────────────
    seen.clear()
    for m in _NT_BEACON_TIMER.finditer(text):
        ctx = text[m.start() : min(len(text), m.start() + 600)]
        if _NT_BEACON_NET.search(ctx):
            snippet = ctx[:140].replace("\n", " ").strip()
            if snippet not in seen:
                seen.add(snippet)
                dm = _NT_BEACON_DELAY.search(ctx)
                delay = int(dm.group(1)) if dm else None
                nt.setdefault("beacons", []).append({"snippet": snippet, "delay_ms": delay})

    # Cap each list and drop empty categories
    return {k: v[:_NT_MAX] for k, v in nt.items() if v}


def _looks_apk(data: bytes) -> bool:
    """Heuristic: ZIP file that likely contains AndroidManifest.xml."""
    if data[:4] != b"PK\x03\x04":
        return False
    try:
        import io as _io
        import zipfile as _zf

        with _zf.ZipFile(_io.BytesIO(data)) as z:
            return "AndroidManifest.xml" in z.namelist()
    except Exception:
        return False


def _looks_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:1024]
    non_printable = sum(1 for b in sample if b < 9 or (14 <= b <= 31))
    return non_printable / len(sample) < 0.30


def _guess_lang(ext: str, ct: str) -> str:
    ct = (ct or "").lower()
    m = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".php": "php",
        ".py": "python",
        ".rb": "ruby",
        ".pl": "perl",
        ".sh": "bash",
        ".bash": "bash",
        ".zsh": "bash",
        ".vbs": "vbscript",
        ".vba": "vbscript",
        ".bat": "batch",
        ".cmd": "batch",
        ".ps1": "powershell",
        ".psm1": "powershell",
        ".html": "html",
        ".htm": "html",
        ".xhtml": "html",
        ".css": "css",
        ".scss": "css",
        ".sass": "css",
        ".xml": "xml",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".sql": "sql",
        ".lua": "lua",
        ".go": "go",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".asp": "asp",
        ".aspx": "asp",
        ".jsp": "jsp",
    }
    if ext in m:
        return m[ext]
    if "javascript" in ct:
        return "javascript"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    if "json" in ct:
        return "json"
    return "text"
