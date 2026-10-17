"""DDV — Disassembly + Decompilation View: radare2-backed binary analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any

log = logging.getLogger(__name__)

_MAX_FUNCTIONS = 30  # per-function analysis cap (2 × aaa is slow; 30 is plenty)
_MAX_OPS = 300  # instructions per function cap
_R2_TIMEOUT = 180  # seconds (2 × aaa can take ~60 s for large binaries)

# /tmp is Docker tmpfs; r2pipe.open() (os.path.exists) sees files as missing.
# /app/tmp is the container overlay layer — always visible to all processes.
_TMP_DIR = "/app/tmp"

# ─────────────────────────────────────────────────────────────────────────────
# Batch-mode approach: use r2 -q -c 'cmds' file, which is proven to work
# (no interactive protocol, no r2pipe, no null-byte issues).
# ─────────────────────────────────────────────────────────────────────────────

_MARKER = "===DDV_FUNC_"  # prefix for per-function pdg separator
_MARKER_END = "==="  # suffix


def _hex_dump_to_bytes(hex_dump: str) -> bytes:
    """Reconstruct raw bytes from the _build_hex_dump() format."""
    out = bytearray()
    for line in hex_dump.split("\n"):
        if len(line) < 12:
            continue
        pipe = line.find("|")
        if pipe < 10:
            continue
        hex_part = line[10:pipe].rstrip()
        for tok in hex_part.split():
            if len(tok) == 2:
                try:
                    out.append(int(tok, 16))
                except ValueError:
                    pass
    return bytes(out)


def r2_available() -> bool:
    return shutil.which("r2") is not None


def _run_diec(tmp: str) -> list[dict]:
    """Run diec (Detect-It-Easy) and return its detects list."""
    if not shutil.which("diec"):
        return []
    try:
        result = subprocess.run(
            ["diec", "-j", tmp],
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = result.stdout
        # diec may print "[!] ..." warning lines before the JSON — skip them
        json_start = stdout.find("{")
        if json_start < 0:
            return []
        data = json.loads(stdout[json_start:])
        return data.get("detects", [])
    except Exception:
        return []


def _r2_batch(cmds: str, tmp: str, timeout: int) -> str:
    """Run r2 -A -q -c cmds file and return stdout. -A triggers analysis at startup."""
    result = subprocess.run(
        ["r2", "-A", "-q", "-c", cmds, tmp],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout


def _parse_line_jsons(text: str) -> list[Any]:
    """Parse a block of text that may contain one or more JSON values per line."""
    objects: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return objects


def _run_r2_sync(data: bytes) -> dict[str, Any]:
    """Two-pass batch radare2 analysis — asyncio.to_thread target."""
    os.makedirs(_TMP_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".bin", dir=_TMP_DIR)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
    except Exception as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return {"error": f"Failed to write analysis file: {exc}"}

    try:
        # ── Pass 1: arch info + function list ─────────────────────────────
        # Quick; no per-function work.
        out1 = _r2_batch("ij; aflj", tmp, timeout=75)

        info: dict = {}
        funcs_raw: list = []
        for obj in _parse_line_jsons(out1):
            if isinstance(obj, list):
                funcs_raw = obj
            elif isinstance(obj, dict) and "bin" in obj and "core" in obj:
                info = obj

        b_info = info.get("bin") or {}
        arch = b_info.get("arch", "unknown")
        bits = b_info.get("bits", 64)
        entry = (info.get("core") or {}).get("entry")
        entry_str = f"0x{entry:08x}" if isinstance(entry, int) else (str(entry) if entry else "")

        fn_list = funcs_raw[:_MAX_FUNCTIONS]
        if not fn_list:
            return {"arch": arch, "bits": bits, "entry": entry_str, "functions": []}

        # ── Pass 2: per-function disassembly + decompilation ──────────────
        # Build one big -c command string.  For each function:
        #   s addr; pdfj          → JSON disassembly line
        #   s addr; ?e MARKER_addr; pdg  → Ghidra decompile block preceded by marker
        parts = ["e scr.color=0"]
        for fn in fn_list:
            addr = fn.get("offset") or fn.get("addr") or 0
            parts.append(f"s {addr}; pdfj")
            parts.append(f"s {addr}; ?e {_MARKER}{addr}{_MARKER_END}; pdg")

        out2 = _r2_batch("; ".join(parts), tmp, timeout=90)

        # ── Parse pass-2 output ───────────────────────────────────────────
        pdf_by_addr: dict[int, dict] = {}
        pdg_by_addr: dict[int, str] = {}
        cur_pdc_addr: int | None = None
        cur_pdc_lines: list[str] = []

        def _flush_pdc() -> None:
            nonlocal cur_pdc_addr, cur_pdc_lines
            if cur_pdc_addr is not None and cur_pdc_lines:
                text = "\n".join(cur_pdc_lines).strip()
                if len(text) > 10:
                    pdg_by_addr[cur_pdc_addr] = text
            cur_pdc_addr = None
            cur_pdc_lines = []

        for raw_line in out2.splitlines():
            stripped = raw_line.strip()

            # DDV marker: ===DDV_FUNC_<decimal_addr>===
            if stripped.startswith(_MARKER) and stripped.endswith(_MARKER_END):
                _flush_pdc()
                try:
                    cur_pdc_addr = int(stripped[len(_MARKER) : -len(_MARKER_END)])
                except ValueError:
                    cur_pdc_addr = None
                cur_pdc_lines = []

            # pdfj output (compact JSON line with "ops" key)
            elif stripped.startswith("{") and '"ops"' in stripped:
                _flush_pdc()
                try:
                    pdf = json.loads(stripped)
                    addr = pdf.get("addr") or pdf.get("offset")
                    if addr is not None:
                        pdf_by_addr[int(addr)] = pdf
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass

            # pdg content (Ghidra decompiler output)
            elif cur_pdc_addr is not None:
                cur_pdc_lines.append(raw_line)

        _flush_pdc()

        # ── Assemble result ───────────────────────────────────────────────
        functions: list[dict] = []
        for fn in fn_list:
            fn_offset = fn.get("offset") or fn.get("addr") or 0
            fn_name = fn.get("name", f"fcn.{fn_offset:08x}")
            fn_size = fn.get("size", 0)

            pdf = pdf_by_addr.get(fn_offset) or {}
            ops: list[dict] = []
            for op in (pdf.get("ops") or [])[:_MAX_OPS]:
                ops.append(
                    {
                        "addr": f"0x{op.get('offset', 0):08x}",
                        "bytes": op.get("bytes", ""),
                        "op": op.get("disasm") or op.get("opcode", ""),
                        "type": op.get("type", ""),
                        "size": op.get("size", 0),
                    }
                )

            functions.append(
                {
                    "name": fn_name,
                    "addr": f"0x{fn_offset:08x}",
                    "size": fn_size,
                    "ops": ops,
                    "pseudo": pdg_by_addr.get(fn_offset),
                }
            )

        return {
            "arch": arch,
            "bits": bits,
            "entry": entry_str,
            "functions": functions,
            "die": _run_diec(tmp),
        }

    except subprocess.TimeoutExpired:
        return {"error": "radare2 timed out during analysis"}
    except Exception as exc:
        log.exception("r2 analysis failed: %s", exc)
        return {"error": str(exc)}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _run_die_sync(data: bytes) -> list[dict]:
    """Run diec on raw bytes — asyncio.to_thread target."""
    os.makedirs(_TMP_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".bin", dir=_TMP_DIR)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return _run_diec(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


async def analyse_die(hex_dump: str) -> list[dict]:
    """Run diec on binary data from hex_dump. Returns diec detects list."""
    if not shutil.which("diec"):
        return []
    data = _hex_dump_to_bytes(hex_dump)
    if len(data) < 4:
        return []
    return await asyncio.to_thread(_run_die_sync, data)


async def analyse(hex_dump: str, file_type: str = "binary") -> dict[str, Any]:
    """Disassemble and decompile binary from its hex_dump string (EFA format)."""
    if not r2_available():
        return {"error": "radare2 not found in PATH"}

    data = _hex_dump_to_bytes(hex_dump)
    if len(data) < 16:
        return {"error": "Binary data too small to analyse"}

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_r2_sync, data),
            timeout=_R2_TIMEOUT,
        )
    except TimeoutError:
        return {"error": f"radare2 timed out after {_R2_TIMEOUT}s"}
