"""EFI (IOC extraction), EFA (file analysis), disassembly and NT capture."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi import Query as QParam
from fastapi.responses import JSONResponse

from .. import db as _db_module
from ..auth import get_current_user
from ..browser import ensure_browser
from ..config import settings
from ..models import UserInDB
from ..security import is_safe_url, ssrf_request_hook
from ..services import efa_svc, efi_svc, nt_svc
from ..state import (
    _store_for,
)

log = logging.getLogger(__name__)
router = APIRouter()


def _proxy_for(result: dict) -> str | None:
    """Tor proxy for re-fetching a result's URLs: .onion targets and results
    that were scanned through Tor (random exit IP) must never be fetched directly."""
    target = str(result.get("target", "")).lower()
    if target.endswith(".onion") or result.get("via_tor"):
        return settings.tor_proxy
    return None


def _efi_texts_for_result(r: dict) -> list[str]:
    """Collect all text content from a result for EFI extraction."""
    texts: list[str] = []
    # DNS TXT records
    dns = r.get("dns") or {}
    texts.extend(dns.get("TXT") or [])
    # WHOIS
    w = r.get("whois") or {}
    if w.get("raw"):
        texts.append(w["raw"])
    texts.extend(w.get("emails") or [])
    # Final headers values
    for v in (r.get("final_headers") or {}).values():
        texts.append(v)
    # HTTP chain headers
    for hop in r.get("chain") or []:
        for v in (hop.get("response_headers") or {}).values():
            texts.append(v)
        texts.append(hop.get("url") or "")
    # Cert SANs / CNs
    for cert in r.get("certs") or []:
        texts.append(cert.get("common_name") or "")
        texts.extend(cert.get("san") or [])
    return [t for t in texts if t]


def _efi_texts_for_files(files: list[dict]) -> list[str]:
    """Return URL strings from file entries (path + url contain useful IOCs)."""
    texts = []
    for f in files:
        texts.append(f.get("path") or "")
        texts.append(f.get("url") or "")
        texts.append(f.get("content_type") or "")
    return [t for t in texts if t]


async def _run_efi_on_result(uid: str, result_id: str, path_filter: str | None = None) -> dict:
    """Extract EFI from all files in a result (or one file if path_filter is set).
    Returns the updated efi dict.
    """
    store = _store_for(uid)
    r = store.get(result_id)
    if not r:
        return {}

    existing = r.get("efi") or {}
    texts = _efi_texts_for_result(r)

    all_files = list(r.get("root_files") or []) + list(r.get("crawled_files") or [])
    if path_filter:
        all_files = [
            f for f in all_files if f.get("path") == path_filter or f.get("url") == path_filter
        ]

    fetch_proxy = _proxy_for(r)

    # Fetch text content from each file URL
    async def _fetch_text(f: dict) -> str:
        url = f.get("url") or ""
        if not url:
            return ""
        sz = f.get("size") or 0
        if sz > 100 * 1024 * 1024:
            return ""
        if not await is_safe_url(url):
            return ""
        try:
            import httpx as _httpx

            client_kwargs: dict = dict(
                verify=False, follow_redirects=True, timeout=settings.timeout
            )
            if fetch_proxy:
                client_kwargs["proxy"] = fetch_proxy
            else:
                client_kwargs["event_hooks"] = {"request": [ssrf_request_hook]}
            async with _httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text[: 5 * 1024 * 1024]
        except Exception:
            pass
        return ""

    # When scanning the whole result (no path filter), also fetch the main page HTML
    # so inline <script> content is included (where hardcoded keys/IOCs often live).
    fetch_targets = list(all_files)
    if not path_filter:
        main_url = r.get("final_url") or (
            f"https://{r['target']}" if r.get("target") and r.get("kind") == "domain" else None
        )
        if main_url:
            fetch_targets.append({"url": main_url, "size": 0})

    fetched = await asyncio.gather(*[_fetch_text(f) for f in fetch_targets], return_exceptions=True)
    for t in fetched:
        if isinstance(t, str) and t:
            texts.append(t)

    # Also include file path strings
    texts.extend(_efi_texts_for_files(all_files))

    new_iocs = efi_svc.extract(texts)
    merged = efi_svc.merge(existing, new_iocs)

    r["efi"] = merged
    asyncio.create_task(_db_module.get_db().patch_result(uid, result_id, {"efi": merged}))
    log.info(
        "[%s] EFI extracted for %s — %d categories", uid, r.get("target", result_id), len(merged)
    )
    return merged


# ── EFI endpoints ──────────────────────────────────────────────────────────────


@router.post("/results/{result_id}/efi")
async def run_efi(
    result_id: str,
    path: str | None = QParam(default=None),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Extract IOCs from a result's files. Optional `path` param limits to one file."""
    result = await _run_efi_on_result(current_user.id, result_id, path)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return JSONResponse(result)


@router.post("/cases/{case_id}/efi")
async def run_case_efi(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run EFI extraction for every result in a case."""
    store = _store_for(current_user.id)
    result_ids = [rid for rid, r in store.items() if r.get("case_id") == case_id]
    if not result_ids:
        raise HTTPException(status_code=404, detail="No results found for this case")
    await asyncio.gather(*[_run_efi_on_result(current_user.id, rid) for rid in result_ids])
    return JSONResponse({"status": "ok", "processed": len(result_ids)})


@router.delete("/results/{result_id}/efi/{category}")
async def delete_efi_item(
    result_id: str,
    category: str,
    value: str = QParam(...),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Remove a single value from an EFI category."""
    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    efi = efi_svc.delete_item(r.get("efi") or {}, category, value)
    r["efi"] = efi
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, result_id, {"efi": efi}))
    return JSONResponse(efi)


@router.get("/results/{result_id}/file-content")
async def get_file_content(
    result_id: str,
    path: str = QParam(...),
    current_user: UserInDB = Depends(get_current_user),
) -> Response:
    """Return raw text content of a scanned file, re-fetched on demand.
    Use path='/' to fetch the domain's main page HTML."""
    import httpx as _httpx

    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    if path == "/":
        url = r.get("final_url") or (f"https://{r['target']}" if r.get("target") else None)
    else:
        all_files = list(r.get("root_files") or []) + list(r.get("crawled_files") or [])
        f = next((x for x in all_files if x.get("path") == path), None)
        if not f:
            raise HTTPException(status_code=404, detail="File not found in result")
        url = f.get("url") or ""
    if not url:
        raise HTTPException(status_code=404, detail="No URL available")
    if not await is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL points to a private/internal address")
    proxy = _proxy_for(r)
    try:
        kwargs: dict = dict(verify=False, follow_redirects=True, timeout=settings.timeout)
        if proxy:
            kwargs["proxy"] = proxy
        else:
            kwargs["event_hooks"] = {"request": [ssrf_request_hook]}
        async with _httpx.AsyncClient(**kwargs) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Remote returned {resp.status_code}")
            return Response(resp.text[: 500 * 1024], media_type="text/plain; charset=utf-8")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ── EFA helpers ───────────────────────────────────────────────────────────────


async def _run_efa_on_result(uid: str, result_id: str, path_filter: str | None = None) -> list:
    """Analyse files in a result. Returns updated efa list."""
    store = _store_for(uid)
    r = store.get(result_id)
    if not r:
        return []

    existing_efa: list[dict] = list(r.get("efa") or [])
    existing_paths = {e["path"] for e in existing_efa}

    all_files = list(r.get("root_files") or []) + list(r.get("crawled_files") or [])
    if path_filter:
        all_files = [f for f in all_files if f.get("path") == path_filter]

    to_analyse = [
        f
        for f in all_files
        if f.get("url")
        and f.get("status_code") == 200
        and (path_filter or f.get("path") not in existing_paths)
    ]

    # When scanning the whole result, also analyse the main page HTML
    # (same as EFI — inline JS/content is not in root_files/crawled_files).
    # Skip when final_url itself is a binary/download file (e.g. the target was
    # a direct APK/IPA/ZIP link) — fetching it as "the main page" with the small
    # text fetch cap would just produce a BadZipFile / truncation error.
    _BINARY_EXTS = frozenset(
        {
            ".apk",
            ".ipa",
            ".exe",
            ".dll",
            ".zip",
            ".jar",
            ".so",
            ".bin",
            ".pdf",
            ".rar",
            ".7z",
            ".gz",
            ".tar",
            ".dmg",
            ".pkg",
            ".deb",
            ".rpm",
        }
    )
    if not path_filter and r.get("kind") == "domain":
        main_url = r.get("final_url") or (f"https://{r['target']}" if r.get("target") else None)
        if main_url and "/" not in existing_paths:
            import os.path as _osp

            _mu_ext = _osp.splitext(main_url.split("?")[0].lower())[1]
            if _mu_ext not in _BINARY_EXTS:
                to_analyse.append(
                    {
                        "url": main_url,
                        "path": "/",
                        "status_code": 200,
                        "content_type": "text/html",
                        "size": None,
                    }
                )

    tor_proxy = _proxy_for(r)

    async def _do(f: dict) -> dict | None:
        try:
            if not await is_safe_url(f["url"]):
                return None
            result = await efa_svc.analyse(
                url=f["url"],
                path=f.get("path", ""),
                content_type=f.get("content_type"),
                size=f.get("size"),
                proxy=tor_proxy,
            )
            return {"path": f.get("path", f["url"]), "url": f["url"], **result}
        except Exception as exc:
            log.warning("EFA analyse failed for %s: %s", f.get("url"), exc)
            return None

    results = await asyncio.gather(*[_do(f) for f in to_analyse])
    new_entries = [res for res in results if res is not None]

    # If path_filter: replace existing entry for that path
    if path_filter:
        efa = [e for e in existing_efa if e.get("path") != path_filter] + new_entries
    else:
        efa = existing_efa + new_entries

    r["efa"] = efa
    asyncio.create_task(_db_module.get_db().patch_result(uid, result_id, {"efa": efa}))
    log.info(
        "[%s] EFA done for %s — %d files analysed",
        uid,
        r.get("target", result_id),
        len(new_entries),
    )
    return efa


# ── EFA endpoints ─────────────────────────────────────────────────────────────


@router.post("/results/{result_id}/efa")
async def run_efa(
    result_id: str,
    path: str | None = QParam(default=None),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run static file analysis on a result's crawled files."""
    efa = await _run_efa_on_result(current_user.id, result_id, path)
    return JSONResponse(efa)


@router.post("/cases/{case_id}/efa")
async def run_case_efa(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run EFA for every result in a case."""
    store = _store_for(current_user.id)
    result_ids = [rid for rid, r in store.items() if r.get("case_id") == case_id]
    if not result_ids:
        raise HTTPException(status_code=404, detail="No results found for this case")
    await asyncio.gather(*[_run_efa_on_result(current_user.id, rid) for rid in result_ids])
    return JSONResponse({"status": "ok", "processed": len(result_ids)})


@router.delete("/results/{result_id}/efa")
async def delete_efa_entry(
    result_id: str,
    path: str = QParam(...),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Remove EFA analysis for a specific file path."""
    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    efa = [e for e in (r.get("efa") or []) if e.get("path") != path]
    r["efa"] = efa
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, result_id, {"efa": efa}))
    return JSONResponse({"status": "ok"})


@router.post("/results/{result_id}/efa/disasm")
async def run_efa_disasm(
    result_id: str,
    path: str = QParam(...),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run radare2 disassembly + decompilation on a binary EFA entry."""
    from ..services import disasm_svc

    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    efa: list = r.get("efa") or []
    entry = next((e for e in efa if e.get("path") == path), None)
    if not entry:
        raise HTTPException(status_code=404, detail="EFA entry not found for that path")
    hex_dump = entry.get("hex_dump", "")
    if not hex_dump:
        raise HTTPException(status_code=400, detail="No binary hex data available for disassembly")
    result = await disasm_svc.analyse(hex_dump, entry.get("file_type", "binary"))
    entry["disasm"] = result
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, result_id, {"efa": efa}))
    return JSONResponse(result)


@router.post("/results/{result_id}/efa/die")
async def run_efa_die(
    result_id: str,
    path: str = QParam(...),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run diec binary identification on an EFA entry."""
    from ..services import disasm_svc

    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    efa: list = r.get("efa") or []
    entry = next((e for e in efa if e.get("path") == path), None)
    if not entry:
        raise HTTPException(status_code=404, detail="EFA entry not found for that path")
    hex_dump = entry.get("hex_dump", "")
    if not hex_dump:
        raise HTTPException(status_code=400, detail="No binary data available")
    result = await disasm_svc.analyse_die(hex_dump)
    entry["die"] = result
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, result_id, {"efa": efa}))
    return JSONResponse(result)


# ── APK .so DDV — disassemble a native lib inside an APK EFA entry ────────────


@router.post("/results/{result_id}/efa/apk-disasm")
async def run_apk_so_disasm(
    result_id: str,
    path: str = QParam(..., description="EFA entry path (the .apk file)"),
    so_path: str = QParam(..., description="Path of the .so inside the APK"),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run radare2 + r2ghidra on a .so extracted from an APK EFA entry."""
    from ..services import disasm_svc

    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    efa: list = r.get("efa") or []
    entry = next((e for e in efa if e.get("path") == path), None)
    if not entry:
        raise HTTPException(status_code=404, detail="EFA entry not found for that path")
    so_files: list = (entry.get("apk") or {}).get("so_files") or []
    so_entry = next((s for s in so_files if s.get("path") == so_path), None)
    if not so_entry:
        raise HTTPException(status_code=404, detail=".so file not found in APK entry")
    hex_dump = so_entry.get("hex_dump", "")
    if not hex_dump:
        raise HTTPException(status_code=400, detail="No hex data available for this .so")
    result = await disasm_svc.analyse(hex_dump, "elf")
    so_entry["disasm"] = result
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, result_id, {"efa": efa}))
    log.info(
        "[%s] APK so-disasm: %s → %s (%d fn)",
        current_user.username,
        path,
        so_path,
        len(result.get("functions", [])),
    )
    return JSONResponse(result)


# ── IPA main binary DDV ────────────────────────────────────────────────────────


@router.post("/results/{result_id}/efa/ipa-disasm")
async def run_ipa_disasm(
    result_id: str,
    path: str = QParam(..., description="EFA entry path (the .ipa file)"),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run radare2 + r2ghidra on the main binary extracted from an IPA EFA entry."""
    from ..services import disasm_svc

    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    efa: list = r.get("efa") or []
    entry = next((e for e in efa if e.get("path") == path), None)
    if not entry:
        raise HTTPException(status_code=404, detail="EFA entry not found for that path")
    main_bin = (entry.get("ipa") or {}).get("main_binary") or {}
    hex_dump = main_bin.get("hex_dump", "")
    if not hex_dump:
        raise HTTPException(status_code=400, detail="No main binary hex data available")
    result = await disasm_svc.analyse(hex_dump, "binary")
    main_bin["disasm"] = result
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, result_id, {"efa": efa}))
    log.info(
        "[%s] IPA disasm: %s (%d fn)", current_user.username, path, len(result.get("functions", []))
    )
    return JSONResponse(result)


# ── NT endpoints ──────────────────────────────────────────────────────────────


@router.post("/results/{result_id}/nt")
async def run_nt(
    result_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Run dynamic network traffic capture for a domain result."""
    store = _store_for(current_user.id)
    r = store.get(result_id)
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    if r.get("kind") != "domain":
        raise HTTPException(
            status_code=400, detail="NT capture is only available for domain results"
        )
    url = r.get("final_url") or (f"https://{r['target']}" if r.get("target") else None)
    if not url:
        raise HTTPException(status_code=400, detail="No URL available for NT capture")
    if not await is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL points to a private/internal address")
    browser = await ensure_browser()
    if not browser:
        raise HTTPException(status_code=503, detail="Browser not available")
    tor_proxy = _proxy_for(r)
    nt_data = await nt_svc.capture(browser, url, proxy=tor_proxy)
    r["nt"] = nt_data or {}
    asyncio.create_task(
        _db_module.get_db().patch_result(current_user.id, result_id, {"nt": r["nt"]})
    )
    log.info("[%s] NT capture: %s", current_user.username, r.get("target", result_id))
    return JSONResponse(r["nt"])
