"""Admin console API: logs, accounts, user export/import, changelog."""

from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from .. import __version__, apikeys
from .. import db as _db_module
from ..auth import (
    _hash_password,
    _save_users,
    _username_index,
    _users,
    add_user,
    get_admin_usernames,
    initial_password_file,
    initial_password_pending,
    is_admin,
    is_env_admin,
    is_weak_admin_password,
    rebuild_username_index,
    require_admin,
)
from ..config import settings
from ..logbuffer import log_buffer
from ..models import AdminUserCreate, AdminUserUpdate, UserInDB
from ..services import blog_svc
from ..state import (
    _stores,
    _target_indexes,
    _user_alerts,
    _user_cases,
)
from .pages import page_response

log = logging.getLogger(__name__)
router = APIRouter()

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
_CHANGELOG = pathlib.Path(__file__).resolve().parent.parent.parent / "CHANGELOG.md"


@router.get("/admin")
async def admin_page(_: UserInDB = Depends(require_admin)) -> HTMLResponse:
    return page_response("admin.html")


@router.get("/admin/api/info")
async def admin_info(_: UserInDB = Depends(require_admin)) -> JSONResponse:
    """Version and non-sensitive runtime facts for the console header."""
    return JSONResponse(
        {
            "app_name": settings.app_name,
            "version": __version__,
            "theme": settings.theme,
            "database": "postgres" if settings.db_dsn else "memory",
            "sso_enabled": settings.sso_enabled,
            "registration_enabled": settings.registration_enabled,
            "feed_ingest": settings.feed_ingest,
            "weak_admin_password": is_weak_admin_password(),
            "initial_password_pending": initial_password_pending(),
        }
    )


@router.get("/admin/api/changelog")
async def admin_changelog(_: UserInDB = Depends(require_admin)) -> JSONResponse:
    """CHANGELOG.md rendered to sanitised HTML, plus the raw markdown."""
    try:
        raw = _CHANGELOG.read_text(encoding="utf-8")
    except FileNotFoundError:
        raw = "# Changelog\n\nNo changelog file found."
    return JSONResponse(
        {
            "version": __version__,
            "markdown": raw,
            "html": blog_svc.render_md(raw, hard_breaks=False),
        }
    )


@router.get("/admin/api/logs")
async def admin_get_logs(_: UserInDB = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(list(log_buffer))


@router.get("/admin/api/admins")
async def admin_get_admins(_: UserInDB = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(get_admin_usernames())


def _user_row(u: UserInDB) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "created_at": u.created_at,
        "email": u.email,
        "auth_provider": u.auth_provider,
        "is_admin": is_admin(u),
        "env_admin": is_env_admin(u),
    }


@router.get("/admin/api/users")
async def admin_get_users(_: UserInDB = Depends(require_admin)) -> JSONResponse:
    return JSONResponse([_user_row(u) for u in _users.values()])


@router.post("/admin/api/users", status_code=201)
async def admin_create_user(
    req: AdminUserCreate,
    current_admin: UserInDB = Depends(require_admin),
) -> JSONResponse:
    """Create a local account with a password chosen by the administrator."""
    if req.username in _username_index:
        raise HTTPException(status_code=409, detail="Username already taken")
    user = UserInDB(
        id=str(uuid.uuid4()),
        username=req.username,
        hashed_password=_hash_password(req.password),
        created_at=datetime.now(timezone.utc).isoformat(),
        is_admin=req.is_admin,
    )
    await add_user(user)
    log.info(
        "[admin:%s] created account: %s (admin=%s)",
        current_admin.username,
        user.username,
        user.is_admin,
    )
    return JSONResponse(_user_row(user), status_code=201)


@router.patch("/admin/api/users/{user_id}")
async def admin_update_user(
    user_id: str,
    req: AdminUserUpdate,
    current_admin: UserInDB = Depends(require_admin),
) -> JSONResponse:
    """Rename an account, set a new password, or grant/revoke the admin role."""
    user = _users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    changes = req.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update")

    if "username" in changes and changes["username"] != user.username:
        if changes["username"] in _username_index:
            raise HTTPException(status_code=409, detail="Username already taken")
        if is_env_admin(user):
            raise HTTPException(
                status_code=403,
                detail="This admin is defined by the environment and cannot be renamed here",
            )
        _username_index.pop(user.username, None)
        user.username = changes["username"]
        _username_index[user.username] = user.id

    if changes.get("password"):
        if user.auth_provider != "local":
            raise HTTPException(status_code=400, detail="This account signs in through SSO")
        user.hashed_password = _hash_password(changes["password"])
        if user.username == settings.admin_user:
            try:
                initial_password_file().unlink(missing_ok=True)
            except OSError:
                pass

    if "is_admin" in changes and changes["is_admin"] is not None:
        if not changes["is_admin"] and user.id == current_admin.id:
            raise HTTPException(status_code=403, detail="You cannot remove your own admin role")
        if not changes["is_admin"] and is_env_admin(user):
            raise HTTPException(
                status_code=403,
                detail="This admin is defined by the environment (HUNTER_ADMIN_USERNAMES)",
            )
        user.is_admin = bool(changes["is_admin"])

    _save_users()
    await _db_module.get_db().save_user(user.model_dump())
    log.info(
        "[admin:%s] updated account %s: %s",
        current_admin.username,
        user.username,
        ", ".join(k for k in changes if changes[k] is not None),
    )
    return JSONResponse(_user_row(user))


@router.delete("/admin/api/users/{user_id}")
async def admin_delete_user(
    user_id: str,
    current_admin: UserInDB = Depends(require_admin),
) -> dict:
    user = _users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if is_env_admin(user):
        raise HTTPException(
            status_code=403, detail="This admin is defined by the environment and cannot be deleted"
        )
    if user_id == current_admin.id:
        raise HTTPException(status_code=403, detail="Cannot delete your own account")
    del _users[user_id]
    _username_index.pop(user.username, None)
    _stores.pop(user_id, None)
    _target_indexes.pop(user_id, None)
    _user_alerts.pop(user_id, None)
    _user_cases.pop(user_id, None)
    _save_users()
    await apikeys.revoke_all(user_id)
    asyncio.create_task(_db_module.get_db().soft_delete_user(user_id))
    log.info("[admin:%s] deleted account: %s", current_admin.username, user.username)
    return {"status": "ok"}


@router.get("/admin/api/users/{user_id}/api-keys")
async def admin_list_user_keys(user_id: str, _: UserInDB = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(
        [
            {
                "id": k.id,
                "name": k.name,
                "prefix": k.prefix,
                "created_at": k.created_at,
                "last_used_at": k.last_used_at,
            }
            for k in apikeys.keys_for_user(user_id)
        ]
    )


@router.delete("/admin/api/users/{user_id}/api-keys")
async def admin_revoke_user_keys(
    user_id: str, current_admin: UserInDB = Depends(require_admin)
) -> dict:
    """Revoke every API key of an account."""
    count = await apikeys.revoke_all(user_id)
    log.info("[admin:%s] revoked %d API key(s) of %s", current_admin.username, count, user_id)
    return {"status": "ok", "revoked": count}


@router.get("/admin/api/users/export")
async def admin_export_users(current_admin: UserInDB = Depends(require_admin)):
    from fastapi.responses import Response as _Resp

    data = json.dumps(
        {
            "users": {uid: u.model_dump() for uid, u in _users.items()},
            "username_index": dict(_username_index),
        },
        indent=2,
    )
    log.info("[admin:%s] exported users.json (%d accounts)", current_admin.username, len(_users))
    return _Resp(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=users.json"},
    )


@router.post("/admin/api/users/import")
async def admin_import_users(
    file: UploadFile,
    current_admin: UserInDB = Depends(require_admin),
) -> dict:
    # A08 — cap upload at 1 MiB to prevent memory exhaustion
    raw = await file.read(1024 * 1024)
    if len(raw) == 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 1 MiB)")
    try:
        data = json.loads(raw)
        if not isinstance(data.get("users"), dict):
            raise ValueError("missing users")
        if not isinstance(data.get("username_index"), dict):
            raise ValueError("missing username_index")
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid users.json format")
    imported = 0
    for uid, u_data in data["users"].items():
        try:
            user = UserInDB(**u_data)
        except Exception:
            continue
        if user.id != uid or not _USERNAME_RE.match(user.username):
            continue
        _users[uid] = user
        imported += 1
    # Never trust the index from the file: rebuild it from the accounts.
    rebuild_username_index()
    _save_users()
    for user in list(_users.values()):
        await _db_module.get_db().save_user(user.model_dump())
    log.info(
        "[admin:%s] imported users.json — %d accounts loaded", current_admin.username, imported
    )
    return {"status": "ok", "imported": imported}
