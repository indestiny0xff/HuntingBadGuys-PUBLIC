"""Per-user result store, query endpoint, folders, cases and shared CTI reports."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Query as QParam
from fastapi.responses import JSONResponse

from .. import db as _db_module
from ..auth import get_current_user
from ..models import (
    Case,
    CaseCreate,
    CasePatch,
    Folder,
    FolderCreate,
    QueryRequest,
    ReportUpdate,
    ResultPatch,
    UserInDB,
)
from ..query.engine import filter_results
from ..query.engine import validate as query_validate
from ..security import sanitize_for_log
from ..state import (
    _cases_for,
    _folders_for,
    _index_for,
    _store_for,
    _stores,
    _user_cases,
)

log = logging.getLogger(__name__)
router = APIRouter()


@router.post("/query")
async def query_store(
    req: QueryRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    try:
        query_validate(req.query)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Query syntax error: {exc}")
    log.info("[%s] query: %s", current_user.username, sanitize_for_log(req.query))
    store = _store_for(current_user.id)
    pool = [store[i] for i in (req.ids or []) if i in store] if req.ids else list(store.values())
    if req.case_id:
        pool = [v for v in pool if v.get("case_id") == req.case_id]
    return JSONResponse(filter_results(req.query, pool))


# ── Store management ──────────────────────────────────────────────────────────


@router.get("/store")
async def list_store(
    case_id: str | None = QParam(default=None),
    saved_only: bool = QParam(default=False),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    store = _store_for(current_user.id)
    items = list(store.items())
    if case_id:
        items = [(k, v) for k, v in items if v.get("case_id") == case_id]
    if saved_only:
        items = [(k, v) for k, v in items if not v.get("is_private", False)]
    summary = [
        {
            "_id": k,
            "target": v.get("target"),
            "kind": v.get("kind"),
            "final_status": v.get("final_status"),
            "case_id": v.get("case_id"),
            "is_private": v.get("is_private", False),
            "scanned_at": v.get("scanned_at"),
        }
        for k, v in items
    ]
    return JSONResponse(summary)


@router.patch("/store/{item_id}")
async def patch_item(
    item_id: str,
    body: ResultPatch,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Partially update a result (is_private, case_id)."""
    store = _store_for(current_user.id)
    entry = store.get(item_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Result not found")
    updates = body.model_dump(exclude_unset=True)
    entry.update(updates)
    asyncio.create_task(_db_module.get_db().patch_result(current_user.id, item_id, updates))
    return JSONResponse({"status": "ok", **updates})


@router.delete("/store/{item_id}")
async def delete_item(
    item_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    store = _store_for(current_user.id)
    index = _index_for(current_user.id)
    entry = store.pop(item_id, None)
    if entry:
        index.pop(entry.get("target", ""), None)
        log.info("[%s] deleted item: %s", current_user.username, entry.get("target", item_id))
        asyncio.create_task(_db_module.get_db().delete_result(current_user.id, item_id))
    return {"status": "ok"}


@router.delete("/store")
async def clear_store(
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    _store_for(current_user.id).clear()
    _index_for(current_user.id).clear()
    asyncio.create_task(_db_module.get_db().clear_results(current_user.id))
    return {"status": "ok"}


# ── Folders ───────────────────────────────────────────────────────────────────


@router.get("/folders")
async def list_folders(
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    return JSONResponse([f.model_dump() for f in _folders_for(current_user.id).values()])


@router.post("/folders", status_code=201)
async def create_folder(
    req: FolderCreate,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    folder = Folder(
        id=str(uuid.uuid4()),
        name=req.name,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _folders_for(current_user.id)[folder.id] = folder
    await _db_module.get_db().save_folder(current_user.id, folder.model_dump())
    return JSONResponse(folder.model_dump(), status_code=201)


@router.delete("/folders/{folder_id}")
async def delete_folder(
    folder_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    _folders_for(current_user.id).pop(folder_id, None)
    # Unlink cases that belonged to this folder
    for case in _cases_for(current_user.id).values():
        if case.folder_id == folder_id:
            case.folder_id = None
            await _db_module.get_db().save_case(current_user.id, case.model_dump())
    await _db_module.get_db().delete_folder(current_user.id, folder_id)
    return {"status": "ok"}


# ── Cases ─────────────────────────────────────────────────────────────────────


@router.get("/cases")
async def list_cases(
    folder_id: str | None = QParam(default=None),
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    cases = _cases_for(current_user.id).values()
    if folder_id:
        cases = [c for c in cases if c.folder_id == folder_id]
    return JSONResponse([c.model_dump() for c in cases])


@router.post("/cases", status_code=201)
async def create_case(
    req: CaseCreate,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    case = Case(
        id=str(uuid.uuid4()),
        name=req.name,
        description=req.description,
        folder_id=req.folder_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _cases_for(current_user.id)[case.id] = case
    await _db_module.get_db().save_case(current_user.id, case.model_dump())
    return JSONResponse(case.model_dump(), status_code=201)


@router.patch("/cases/{case_id}")
async def patch_case(
    case_id: str,
    patch: CasePatch,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Update a case: move it to a folder, rename it, or edit its report."""
    case = _cases_for(current_user.id).get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    body = patch.model_dump(exclude_unset=True)
    if "folder_id" in body:
        case.folder_id = body["folder_id"]
    if "name" in body:
        case.name = body["name"]
    if "description" in body:
        case.description = body["description"]
    if "notes_md" in body:
        case.notes_md = body["notes_md"] or ""
        case.report_updated_at = datetime.now(timezone.utc).isoformat()
    if "report_title" in body:
        case.report_title = body["report_title"] or ""
    await _db_module.get_db().save_case(current_user.id, case.model_dump())
    return JSONResponse(case.model_dump())


@router.delete("/cases/{case_id}")
async def delete_case(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    _cases_for(current_user.id).pop(case_id, None)
    await _db_module.get_db().delete_case(current_user.id, case_id)
    return {"status": "ok"}


# ── CTI report (shared across the team — any connected user can read/edit) ─────


def _find_case(case_id: str) -> tuple[str | None, Case | None]:
    """Locate a case across ALL users' case stores (reports are team-shared)."""
    for uid, cases in _user_cases.items():
        if case_id in cases:
            return uid, cases[case_id]
    return None, None


@router.get("/cases/{case_id}/report")
async def get_case_report(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    owner, case = _find_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return JSONResponse(
        {
            "case_id": case_id,
            "case_name": case.name,
            "report_title": case.report_title or case.name,
            "notes_md": case.notes_md or "",
            "report_updated_at": case.report_updated_at,
        }
    )


@router.put("/cases/{case_id}/report")
async def save_case_report(
    case_id: str,
    update: ReportUpdate,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Any connected user can edit a case's report. Saved against the owner."""
    owner, case = _find_case(case_id)
    if not case or not owner:
        raise HTTPException(status_code=404, detail="Case not found")
    body = update.model_dump(exclude_unset=True)
    if "notes_md" in body:
        case.notes_md = body["notes_md"] or ""
        case.report_updated_at = datetime.now(timezone.utc).isoformat()
    if "report_title" in body:
        case.report_title = body["report_title"] or ""
    await _db_module.get_db().save_case(owner, case.model_dump())
    return JSONResponse({"status": "ok", "report_updated_at": case.report_updated_at})


@router.get("/cases/{case_id}/report-results")
async def case_report_results(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Full results for a case across ALL users' stores — powers the report's
    entity tables and @-autocomplete (incl. EFA file content)."""
    out: list[dict[str, Any]] = []
    for store in _stores.values():
        for item in store.values():
            if item.get("case_id") == case_id:
                out.append({k: v for k, v in item.items() if k != "screenshot"})
    return JSONResponse(out)


@router.get("/reports")
async def list_all_reports(
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Team-wide list of every case that has a report started, so anyone can
    open and edit it. Newest-edited first."""
    from ..auth import _users as _auth_users

    published: set[str] = set()
    try:
        for p in await _db_module.get_db().list_published_posts(limit=1000):
            if p.get("case_id"):
                published.add(p["case_id"])
    except Exception:
        pass
    out: list[dict[str, Any]] = []
    for uid, cases in _user_cases.items():
        owner = _auth_users.get(uid)
        owner_name = owner.username if owner else "—"
        for cid, case in cases.items():
            if not (getattr(case, "notes_md", "") or "").strip():
                continue
            out.append(
                {
                    "case_id": cid,
                    "title": case.report_title or case.name,
                    "owner": owner_name,
                    "mine": uid == current_user.id,
                    "updated_at": case.report_updated_at,
                    "published": cid in published,
                }
            )
    out.sort(key=lambda x: x.get("updated_at") or "", reverse=True)
    return JSONResponse({"reports": out})
