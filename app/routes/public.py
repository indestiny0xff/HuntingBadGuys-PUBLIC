"""Public (unauthenticated) results feed and the authenticated team feed."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Query as QParam
from fastapi.responses import HTMLResponse, JSONResponse

from .. import db as _db_module
from ..auth import get_current_user
from ..config import settings
from ..models import QueryRequest, UserInDB
from ..query.engine import filter_results
from ..query.engine import validate as query_validate
from ..state import (
    _stores,
    _user_cases,
    _user_folders,
)
from .pages import render_page

log = logging.getLogger(__name__)
router = APIRouter()

_SLIM_STRIP = frozenset({"screenshot"})


def _slim_result(item: dict[str, Any]) -> dict[str, Any]:
    """Strip heavy fields (screenshot bytes, raw whois, HE.net tables, per-hop
    headers) from a result dict for list-view payloads."""
    d = {k: v for k, v in item.items() if k not in _SLIM_STRIP}
    d["has_screenshot"] = bool(item.get("screenshot") or item.get("has_screenshot"))
    if isinstance(d.get("whois"), dict):
        d["whois"] = {k: v for k, v in d["whois"].items() if k != "raw"}
    if isinstance(d.get("bgp"), dict):
        d["bgp"] = {
            k: v for k, v in d["bgp"].items() if k not in ("he_dns_records", "he_search_results")
        }
    if isinstance(d.get("chain"), list):
        d["chain"] = [
            {k: v for k, v in hop.items() if k != "response_headers"} for hop in d["chain"]
        ]
    return d


def _list_result(item: dict[str, Any]) -> dict[str, Any]:
    """Minimal card/list-view projection of a result (~10x smaller than
    _slim_result). The full detail is fetched per item when a card is
    expanded, so the list payload only carries what the cards, client-side
    filters, text search and stats actually read."""
    chain = item.get("chain") or []
    d: dict[str, Any] = {
        "_id": item.get("_id"),
        "target": item.get("target"),
        "kind": item.get("kind"),
        "final_status": item.get("final_status"),
        "final_url": item.get("final_url"),
        "scanned_at": item.get("scanned_at"),
        "is_private": item.get("is_private", False),
        "has_screenshot": bool(item.get("screenshot") or item.get("has_screenshot")),
        "screenshot_phash": item.get("screenshot_phash"),
        "cf": bool(
            (item.get("final_headers") or {}).get("cf-ray")
            or any(
                (h.get("response_headers") or {}).get("cf-ray")
                for h in chain
                if isinstance(h, dict)
            )
        ),
        "certs_count": len(item.get("certs") or []),
    }
    whois = item.get("whois")
    if isinstance(whois, dict) and whois:
        d["whois"] = {"registrar": whois.get("registrar")}
    dns = item.get("dns")
    if isinstance(dns, dict) and dns.get("A"):
        d["dns"] = {"A": dns["A"]}
    bgp = item.get("bgp")
    if isinstance(bgp, dict):
        asn = bgp.get("asn") or {}
        if isinstance(asn, dict) and (asn.get("asn") or asn.get("asn_description")):
            d["bgp"] = {
                "asn": {"asn": asn.get("asn"), "asn_description": asn.get("asn_description")}
            }
    geo = item.get("geo")
    if isinstance(geo, dict) and (geo.get("country_iso") or geo.get("country_name")):
        d["geo"] = {"country_iso": geo.get("country_iso"), "country_name": geo.get("country_name")}
    seen_iso: dict[str, dict] = {}
    for g in item.get("geo_ips") or []:
        if isinstance(g, dict) and g.get("country_iso") and g["country_iso"] not in seen_iso:
            seen_iso[g["country_iso"]] = {
                "country_iso": g["country_iso"],
                "country_name": g.get("country_name"),
            }
    if seen_iso:
        d["geo_ips"] = list(seen_iso.values())
    # Names attached by the DB page query + pHash search metadata
    for k in ("_case_name", "_folder_name", "case_name", "folder_name", "_phash_distance"):
        if item.get(k) is not None:
            d[k] = item[k]
    return d


def _build_public_results(slim: bool = True, viewer_id: str | None = None) -> list[dict[str, Any]]:
    """Return results across all users, newest first.

    By default only non-private results are included (the public feed). When
    *viewer_id* is given, that user's own private results are also included —
    used by the authenticated Intel team feed."""
    out: list[dict[str, Any]] = []
    for uid, store in _stores.items():
        user_cases = _user_cases.get(uid, {})
        user_folders = _user_folders.get(uid, {})
        case_meta: dict[str, dict] = {}
        for cid, case in user_cases.items():
            folder_name = None
            if case.folder_id:
                fol = user_folders.get(case.folder_id)
                folder_name = fol.name if fol else None
            case_meta[cid] = {"case_name": case.name, "folder_name": folder_name}

        for item in store.values():
            if item.get("is_private", False) and uid != viewer_id:
                continue
            d: dict[str, Any] = _slim_result(item) if slim else dict(item)
            # Attach case/folder names for tag display
            cid = item.get("case_id")
            if cid and cid in case_meta:
                d["_case_name"] = case_meta[cid]["case_name"]
                d["_folder_name"] = case_meta[cid]["folder_name"]
            out.append(d)
    out.sort(key=lambda x: x.get("scanned_at") or "", reverse=True)
    return out


# Only the compact card projection may be requested in bulk; full documents
# are capped so an anonymous client cannot pull every multi-MB result at once.
_FULL_PAGE_CAP = 500


def _cap_limit(limit: int, fields: str | None) -> int:
    return limit if fields == "list" else min(limit, _FULL_PAGE_CAP)


# ── Public API (unauthenticated) ──────────────────────────────────────────────


@router.get("/public/results")
async def public_results(
    page: int = QParam(default=1, ge=1),
    limit: int = QParam(default=50000, le=50000),
    kind: str | None = QParam(default=None),
    slim: bool = QParam(default=True),
    fields: str | None = QParam(default=None),
) -> JSONResponse:
    limit = _cap_limit(limit, fields)
    offset = (page - 1) * limit
    # fields=list → compact card-view projection (~10x smaller payload),
    # built in SQL on the DB path so Python never parses the full jsonb.
    compact = fields == "list"
    proj = None if compact else (_slim_result if slim else None)
    # DB is the source of truth: the in-memory store can be empty or only
    # partially hydrated after a restart, which would otherwise blank the page.
    total, rows = await _db_module.get_db().get_public_results_page(
        limit=limit, offset=offset, kind=kind, compact=compact
    )
    if total or rows:
        results = [proj(r) for r in rows] if proj else rows
        return JSONResponse({"total": total, "page": page, "limit": limit, "results": results})
    # Fallback: no DB (local/dev NullDB) — serve from the in-memory store.
    items = _build_public_results(slim=slim)
    if kind:
        items = [r for r in items if r.get("kind") == kind]
    total = len(items)
    page_items = items[offset : offset + limit]
    if fields == "list":
        page_items = [_list_result(r) for r in page_items]
    return JSONResponse({"total": total, "page": page, "limit": limit, "results": page_items})


# ── Authenticated team feed (Intel page) ──────────────────────────────────────


def _feed_excluded_uids() -> list[str]:
    """User-ids whose results are hidden from the Intel feed (bulk ingest account)."""
    from ..auth import _username_index as _idx

    names = [u.strip() for u in settings.feed_exclude_usernames.split(",") if u.strip()]
    return [uid for n in names if (uid := _idx.get(n))]


@router.get("/feed/results")
async def feed_results(
    page: int = QParam(default=1, ge=1),
    limit: int = QParam(default=50000, le=50000),
    kind: str | None = QParam(default=None),
    slim: bool = QParam(default=True),
    fields: str | None = QParam(default=None),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Team feed for the Intel page: all users' non-private results plus the
    viewer's own (incl. private), minus the bulk ingest account. Keeps
    EFA/EFI/NT — the value-add over the public feed."""
    limit = _cap_limit(limit, fields)
    offset = (page - 1) * limit
    compact = fields == "list"
    proj = None if compact else (_slim_result if slim else None)
    excluded = _feed_excluded_uids()
    total, rows = await _db_module.get_db().get_feed_results_page(
        viewer_id=current_user.id,
        limit=limit,
        offset=offset,
        kind=kind,
        exclude_uids=excluded,
        compact=compact,
    )
    if total or rows:
        results = [proj(r) for r in rows] if proj else rows
        return JSONResponse({"total": total, "page": page, "limit": limit, "results": results})
    # Fallback: no DB (local/dev NullDB) — build from the in-memory stores.
    excluded_set = set(excluded)
    items: list[dict[str, Any]] = []
    for uid, store in _stores.items():
        if uid in excluded_set:
            continue
        user_cases = _user_cases.get(uid, {})
        user_folders = _user_folders.get(uid, {})
        for item in store.values():
            if item.get("is_private", False) and uid != current_user.id:
                continue
            d = _slim_result(item) if slim else dict(item)
            cid = item.get("case_id")
            case = user_cases.get(cid) if cid else None
            if case:
                d["_case_name"] = case.name
                fol = user_folders.get(case.folder_id) if case.folder_id else None
                d["_folder_name"] = fol.name if fol else None
            items.append(d)
    if kind:
        items = [r for r in items if r.get("kind") == kind]
    items.sort(key=lambda x: x.get("scanned_at") or "", reverse=True)
    total = len(items)
    page_items = items[offset : offset + limit]
    if fields == "list":
        page_items = [_list_result(r) for r in page_items]
    return JSONResponse({"total": total, "page": page, "limit": limit, "results": page_items})


@router.get("/public/r/{item_id}")
async def public_result_page(item_id: str):
    return HTMLResponse(
        render_page("public_result.html"),
        headers={
            "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
            "Cache-Control": "no-store",
        },
    )


@router.get("/feed/r/{item_id}")
async def feed_result_page(item_id: str):
    """Authed Intel-team viewer for a single result. Serves the same viewer as
    /public/r/ — the page detects the /feed/ path and loads the authed detail
    endpoint (/feed/results/{id}), so private-but-owned results are viewable."""
    return HTMLResponse(
        render_page("public_result.html"),
        headers={
            "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
            "Cache-Control": "no-store",
        },
    )


@router.get("/public/results/{item_id}")
async def public_result_detail(item_id: str) -> JSONResponse:
    """Return a single public result with full data (screenshot included)."""
    for store in _stores.values():
        item = store.get(item_id)
        if item and not item.get("is_private", False):
            # In-memory items have screenshot bytes stripped — fetch from DB if needed
            if item.get("has_screenshot") and not item.get("screenshot"):
                result = await _db_module.get_db().get_result(item_id)
                if result:
                    return JSONResponse(result)
            return JSONResponse(item)
    # Not in memory at all — fetch full data including screenshot from DB
    result = await _db_module.get_db().get_result(item_id)
    if result and not result.get("is_private", False):
        return JSONResponse(result)
    raise HTTPException(status_code=404, detail="Not found or private")


@router.get("/feed/results/{item_id}")
async def feed_result_detail(
    item_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Authed detail for the Intel page: full data (incl. screenshot) for any
    non-private result OR any result the viewer owns (incl. their private ones)."""
    for uid, store in _stores.items():
        item = store.get(item_id)
        if not item:
            continue
        if item.get("is_private", False) and uid != current_user.id:
            raise HTTPException(status_code=404, detail="Not found or private")
        if item.get("has_screenshot") and not item.get("screenshot"):
            result = await _db_module.get_db().get_result(item_id)
            if result:
                return JSONResponse(result)
        return JSONResponse(item)
    # Not in memory (e.g. after a restart) — fall back to DB with the same
    # visibility rule as the feed list: non-private to anyone, private only to
    # its owner. (Plain get_result would 404 the viewer's own private results.)
    result = await _db_module.get_db().get_result_for_viewer(item_id, current_user.id)
    if result:
        return JSONResponse(result)
    raise HTTPException(status_code=404, detail="Not found or private")


@router.post("/public/query")
async def public_query(req: QueryRequest) -> JSONResponse:
    """Run the query language against all public results. No auth required."""
    try:
        query_validate(req.query)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Query syntax error: {exc}")
    items = _build_public_results(slim=False)
    if req.ids:
        id_set = set(req.ids)
        items = [r for r in items if r.get("_id") in id_set]
    return JSONResponse(filter_results(req.query, items))


@router.get("/public/phash-search")
async def public_phash_search(
    phash: str = QParam(...),
    threshold: int = QParam(default=15, ge=0, le=40),
) -> JSONResponse:
    """Find public results whose screenshot pHash is within `threshold` Hamming bits."""
    phash = phash.lower().strip()
    if len(phash) != 16 or not all(c in "0123456789abcdef" for c in phash):
        raise HTTPException(status_code=400, detail="phash must be exactly 16 hex characters")

    def hamming(a: str, b: str) -> int:
        return bin(int(a, 16) ^ int(b, 16)).count("1")

    matches: list[dict] = []
    for store in _stores.values():
        for item in store.values():
            if item.get("is_private", False):
                continue
            stored = (item.get("screenshot_phash") or "").lower()
            if len(stored) != 16:
                continue
            dist = hamming(phash, stored)
            if dist <= threshold:
                d = {k: v for k, v in item.items() if k != "screenshot"}
                d["_phash_distance"] = dist
                matches.append(d)

    matches.sort(key=lambda x: x["_phash_distance"])
    return JSONResponse(matches[:100])


@router.post("/feed/query")
async def feed_query(
    req: QueryRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Query language over the authenticated team feed (non-private + viewer's own)."""
    try:
        query_validate(req.query)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Query syntax error: {exc}")
    items = _build_public_results(slim=False, viewer_id=current_user.id)
    if req.ids:
        id_set = set(req.ids)
        items = [r for r in items if r.get("_id") in id_set]
    return JSONResponse(filter_results(req.query, items))


@router.get("/feed/phash-search")
async def feed_phash_search(
    phash: str = QParam(...),
    threshold: int = QParam(default=15, ge=0, le=40),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """pHash similarity over the team feed (non-private + viewer's own)."""
    phash = phash.lower().strip()
    if len(phash) != 16 or not all(c in "0123456789abcdef" for c in phash):
        raise HTTPException(status_code=400, detail="phash must be exactly 16 hex characters")

    def hamming(a: str, b: str) -> int:
        return bin(int(a, 16) ^ int(b, 16)).count("1")

    matches: list[dict] = []
    for uid, store in _stores.items():
        for item in store.values():
            if item.get("is_private", False) and uid != current_user.id:
                continue
            stored = (item.get("screenshot_phash") or "").lower()
            if len(stored) != 16:
                continue
            dist = hamming(phash, stored)
            if dist <= threshold:
                d = {k: v for k, v in item.items() if k != "screenshot"}
                d["_phash_distance"] = dist
                matches.append(d)

    matches.sort(key=lambda x: x["_phash_distance"])
    return JSONResponse(matches[:100])
