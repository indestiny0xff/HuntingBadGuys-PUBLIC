"""Authentication: bcrypt passwords, signed session cookies, FastAPI dependencies.

Accounts live in memory (hydrated from PostgreSQL and `users.json` at startup)
and every change is written through to both stores. Single sign-on accounts are
created by `app.sso` and have no password.
"""

from __future__ import annotations

import html
import json
import logging
import pathlib
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse

from . import apikeys
from .config import settings
from .models import (
    AccessRequest,
    ApiKeyCreate,
    ApiKeyPublic,
    LoginRequest,
    PasswordChange,
    UserCreate,
    UserInDB,
    UserPublic,
    UserRegister,
)
from .security import sanitize_for_log as _sl

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_NAME = "_s"
_ALGORITHM = "HS256"
_VERIFY_HOURS = 1
_BCRYPT_ROUNDS = 12
_MAX_PENDING_REQUESTS = 500
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[a-zA-Z]{2,24}$")

# ── Stores ────────────────────────────────────────────────────────────────────

_users: dict[str, UserInDB] = {}
_username_index: dict[str, str] = {}
_pending_requests: dict[str, dict] = {}  # token -> {name, email, reason, expires}


def _users_file() -> pathlib.Path:
    return pathlib.Path(settings.data_dir) / "users.json"


def _save_users() -> None:
    try:
        path = _users_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "users": {uid: u.model_dump() for uid, u in _users.items()},
            "username_index": dict(_username_index),
        }
        path.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.error("Failed to save users to disk: %s", exc)


def load_users() -> None:
    try:
        path = _users_file()
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for uid, u_data in data.get("users", {}).items():
            _users[uid] = UserInDB(**u_data)
        _username_index.update(data.get("username_index", {}))
        log.info("Loaded %d user(s) from %s", len(_users), path)
    except Exception as exc:
        log.error("Failed to load users from disk: %s", exc)


def rebuild_username_index() -> None:
    _username_index.clear()
    for uid, user in _users.items():
        _username_index[user.username] = uid


def find_user_by_username(username: str) -> UserInDB | None:
    uid = _username_index.get(username)
    return _users.get(uid) if uid else None


def find_user_by_sso_subject(subject: str) -> UserInDB | None:
    for user in _users.values():
        if user.sso_subject == subject:
            return user
    return None


async def add_user(user: UserInDB) -> None:
    """Register a user in memory, on disk and in the database."""
    from . import db as _db

    _users[user.id] = user
    _username_index[user.username] = user.id
    _save_users()
    # Awaited so the users row exists before anything references it (foreign keys).
    try:
        await _db.get_db().save_user(user.model_dump())
    except Exception as exc:
        log.warning("DB save_user failed (uid=%s): %s", user.id, exc)


# ── Passwords ─────────────────────────────────────────────────────────────────

_DUMMY_HASH = bcrypt.hashpw(b"__dummy__", bcrypt.gensalt(_BCRYPT_ROUNDS))


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(_BCRYPT_ROUNDS)).decode()


def _verify_password(plain: str, hashed: str | bytes) -> bool:
    if isinstance(hashed, str):
        hashed = hashed.encode()
    return bcrypt.checkpw(plain.encode(), hashed)


# ── Brute-force protection ────────────────────────────────────────────────────
# Keyed by username AND client IP so an attacker cannot lock out a victim by
# spamming their username. Lockouts double on every further batch of failures.

_MAX_ATTEMPTS = 5
_BASE_LOCKOUT_SECONDS = 30
_MAX_LOCKOUT_SECONDS = 15 * 60

_attempt_counts: dict[str, int] = {}
_lockout_until: dict[str, float] = {}
_lockout_level: dict[str, int] = {}


def _key(username: str, ip: str) -> str:
    return f"{username}|{ip}"


def _check_lockout(username: str, ip: str) -> None:
    remaining = _lockout_until.get(_key(username, ip), 0.0) - time.monotonic()
    if remaining > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {int(remaining) + 1}s.",
        )


def _record_failure(username: str, ip: str) -> None:
    key = _key(username, ip)
    count = _attempt_counts.get(key, 0) + 1
    _attempt_counts[key] = count
    if count >= _MAX_ATTEMPTS:
        level = _lockout_level.get(key, 0)
        lock = min(_BASE_LOCKOUT_SECONDS * (2**level), _MAX_LOCKOUT_SECONDS)
        _lockout_until[key] = time.monotonic() + lock
        _lockout_level[key] = level + 1
        _attempt_counts[key] = 0
        log.warning("LOGIN_LOCKOUT user=%s ip=%s seconds=%d", _sl(username), ip, lock)


def _clear_failures(username: str, ip: str) -> None:
    key = _key(username, ip)
    _attempt_counts.pop(key, None)
    _lockout_until.pop(key, None)
    _lockout_level.pop(key, None)


# ── Sessions ──────────────────────────────────────────────────────────────────


def _create_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(hours=settings.session_hours),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGORITHM)


def _decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return str(user_id)


def set_session_cookie(response: Response, user: UserInDB) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=_create_token(user.id),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_hours * 3600,
        path="/",
    )


def client_ip(request: Request) -> str:
    return getattr(request.client, "host", None) or "unknown"


# ── FastAPI dependencies ──────────────────────────────────────────────────────


def _api_key_from_request(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return request.headers.get("x-api-key") or None


async def get_current_user(request: Request, _s: str | None = Cookie(default=None)) -> UserInDB:
    """Resolve the caller from an API key header or the session cookie."""
    token = _api_key_from_request(request)
    if token:
        key = apikeys.resolve(token)
        user = _users.get(key.user_id) if key else None
        if not user:
            log.warning(
                "API_KEY_REJECTED ip=%s %s %s", client_ip(request), request.method, request.url.path
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        request.state.api_key_id = key.id
        # Audit trail: one line per key-authenticated request (visible in /admin logs).
        log.info(
            "API_KEY user=%s key=%s ip=%s %s %s",
            _sl(user.username),
            key.prefix,
            client_ip(request),
            request.method,
            request.url.path,
        )
        return user
    if not _s:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user = _users.get(_decode_token(_s))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_admin_usernames() -> list[str]:
    names = list(settings.admin_username_list)
    if settings.admin_user and settings.admin_user not in names:
        names.append(settings.admin_user)
    return names


def is_admin(user: UserInDB) -> bool:
    return user.is_admin or user.username in get_admin_usernames()


def is_env_admin(user: UserInDB) -> bool:
    """Admin granted by HUNTER_ADMIN_USERNAMES / HUNTER_ADMIN_USER (not editable in the UI)."""
    return user.username in get_admin_usernames()


async def require_admin(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    if not is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


# ── Bootstrap ─────────────────────────────────────────────────────────────────


def is_weak_admin_password() -> bool:
    """True when the operator chose a weak HUNTER_ADMIN_PASSWORD."""
    pw = settings.admin_password
    return bool(pw) and (
        len(pw) < 12 or pw.lower() in {"admin", "password", "changeme", "admin123"}
    )


def initial_password_file() -> pathlib.Path:
    return pathlib.Path(settings.data_dir) / "initial-admin-password.txt"


def initial_password_pending() -> bool:
    """True while the generated bootstrap password has not been changed."""
    return initial_password_file().exists()


async def bootstrap_admin() -> None:
    """Create the admin account from HUNTER_ADMIN_USER / HUNTER_ADMIN_PASSWORD
    when it does not exist yet. Idempotent.

    With an empty HUNTER_ADMIN_PASSWORD a random password is generated, printed
    once in the log and written to the data volume (owner-only file) so the
    operator can retrieve it. The file is deleted when the password is changed.
    """
    if not settings.admin_user:
        return
    if find_user_by_username(settings.admin_user):
        return
    try:
        UserCreate.validate_username(settings.admin_user)
    except ValueError as exc:
        log.error("Bootstrap admin rejected: %s", exc)
        return

    generated = not settings.admin_password
    password = settings.admin_password or secrets.token_urlsafe(18)
    if is_weak_admin_password():
        log.warning(
            "SECURITY: the bootstrap admin password is weak. Set a strong "
            "HUNTER_ADMIN_PASSWORD or change it in the app before exposing this instance."
        )
    user = UserInDB(
        id=str(uuid.uuid4()),
        username=settings.admin_user,
        hashed_password=_hash_password(password),
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    await add_user(user)
    log.info("Bootstrap admin account created: %s", _sl(user.username))
    if generated:
        path = initial_password_file()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(password + "\n", encoding="utf-8")
            path.chmod(0o600)
        except Exception as exc:
            log.warning("Could not write %s: %s", path, exc)
        log.warning(
            "\n%s\nInitial admin password for user '%s': %s\n"
            "Also saved to %s (deleted once you change the password).\n%s",
            "=" * 72,
            user.username,
            password,
            path,
            "=" * 72,
        )


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/config")
async def auth_config() -> dict:
    """Public, non-sensitive settings the login pages need to render."""
    return {
        "app_name": settings.app_name,
        "theme": settings.theme,
        "registration_enabled": settings.registration_enabled,
        "access_requests_enabled": bool(settings.access_request_email and settings.smtp_host),
        "password_login_enabled": not settings.oidc_only,
        "sso_enabled": settings.sso_enabled,
        "sso_label": settings.oidc_button_label,
        "sso_login_url": "/auth/sso/login" if settings.sso_enabled else None,
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: UserRegister, request: Request) -> UserPublic:
    """Create a local account. Requires the invite code."""
    if not settings.registration_enabled or req.invite_code != settings.invite_code:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid invite code")
    if req.username in _username_index:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    now = datetime.now(timezone.utc).isoformat()
    user = UserInDB(
        id=str(uuid.uuid4()),
        username=req.username,
        hashed_password=_hash_password(req.password),
        created_at=now,
    )
    await add_user(user)
    log.info("Registered new user: %s (ip=%s)", _sl(req.username), client_ip(request))
    return UserPublic(id=user.id, username=user.username, created_at=now)


@router.post("/login")
async def login(response: Response, req: LoginRequest, request: Request) -> dict:
    """Verify credentials and set the HttpOnly session cookie."""
    if settings.oidc_only:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Password login is disabled"
        )
    ip = client_ip(request)
    _check_lockout(req.username, ip)
    stored = find_user_by_username(req.username)
    # Always run bcrypt so response time does not reveal whether the user exists.
    candidate = stored.hashed_password if stored and stored.hashed_password else _DUMMY_HASH
    valid = _verify_password(req.password, candidate)
    if not stored or not stored.hashed_password or not valid:
        _record_failure(req.username, ip)
        log.warning("LOGIN_FAILED user=%s ip=%s", _sl(req.username), ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    _clear_failures(req.username, ip)
    log.info("Login: %s (ip=%s)", _sl(stored.username), ip)
    set_session_cookie(response, stored)
    return {"status": "ok", "username": stored.username}


@router.post("/password")
async def change_password(
    req: PasswordChange,
    request: Request,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """Change the caller's password (local accounts only)."""
    from . import db as _db

    if not current_user.hashed_password:
        raise HTTPException(status_code=400, detail="This account signs in through SSO")
    if not _verify_password(req.current_password, current_user.hashed_password):
        _record_failure(current_user.username, client_ip(request))
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    if req.new_password == req.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")
    current_user.hashed_password = _hash_password(req.new_password)
    _save_users()
    try:
        await _db.get_db().save_user(current_user.model_dump())
    except Exception as exc:
        log.warning("DB save_user failed during password change (uid=%s): %s", current_user.id, exc)
    if current_user.username == settings.admin_user:
        try:
            initial_password_file().unlink(missing_ok=True)
        except OSError:
            pass
    log.info("Password changed: %s", _sl(current_user.username))
    return {"status": "ok"}


# ── API keys ──────────────────────────────────────────────────────────────────


def _key_public(key) -> ApiKeyPublic:
    return ApiKeyPublic(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
    )


@router.get("/api-keys")
async def list_api_keys(current_user: UserInDB = Depends(get_current_user)) -> list[ApiKeyPublic]:
    """The caller's API keys (never the secret itself)."""
    return [_key_public(k) for k in apikeys.keys_for_user(current_user.id)]


@router.post("/api-keys", status_code=201)
async def create_api_key(
    req: ApiKeyCreate, current_user: UserInDB = Depends(get_current_user)
) -> dict:
    """Create an API key. The `key` field is returned once and never again."""
    try:
        key, token = await apikeys.create(current_user.id, req.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log.info("API key created: %s (%s)", _sl(current_user.username), key.prefix)
    return {**_key_public(key).model_dump(), "key": token}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user: UserInDB = Depends(get_current_user)) -> dict:
    key = apikeys.get(key_id)
    if not key or key.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="API key not found")
    await apikeys.revoke(key_id)
    log.info("API key revoked: %s (%s)", _sl(current_user.username), key.prefix)
    return {"status": "ok"}


@router.post("/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(key=COOKIE_NAME, httponly=True, samesite="lax", path="/")
    return {"status": "ok"}


@router.get("/me")
async def me(current_user: UserInDB = Depends(get_current_user)) -> UserPublic:
    return UserPublic(
        id=current_user.id,
        username=current_user.username,
        created_at=current_user.created_at,
        is_admin=is_admin(current_user),
        auth_provider=current_user.auth_provider,
    )


# ── Access requests (email verification, then forwarded to the operator) ──────


def _purge_pending() -> None:
    now = time.time()
    for token in [t for t, p in _pending_requests.items() if p["expires"] < now]:
        _pending_requests.pop(token, None)


@router.post("/request-access", status_code=202)
async def request_access(req: AccessRequest, request: Request) -> dict:
    """Store the request and email the requester a verification link."""
    from .services.alert_svc import send_email

    if not settings.access_request_email:
        raise HTTPException(status_code=404, detail="Access requests are disabled")
    if not _EMAIL_RE.match(req.email):
        raise HTTPException(status_code=422, detail="Invalid email address")
    _purge_pending()
    if len(_pending_requests) >= _MAX_PENDING_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many pending requests, try again later")

    token = uuid.uuid4().hex
    _pending_requests[token] = {
        "name": req.name,
        "email": req.email,
        "reason": req.reason,
        "expires": time.time() + _VERIFY_HOURS * 3600,
    }
    verify_url = f"{settings.public_url}/auth/verify-request?token={token}"
    name = html.escape(req.name)
    app_name = html.escape(settings.app_name)
    body_html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:20px;background:#080c16;color:#e2e8f0;font-family:system-ui,sans-serif">
  <div style="max-width:600px;margin:auto">
    <h2 style="color:#6366f1">Confirm your access request</h2>
    <p>Hi {name},</p>
    <p style="margin-top:12px">Click the button below to verify your email and submit your access request to {app_name}.</p>
    <p style="margin-top:24px"><a href="{verify_url}" style="display:inline-block;padding:10px 22px;background:#6366f1;color:#fff;border-radius:6px;text-decoration:none;font-weight:600">Verify my email</a></p>
    <p style="margin-top:16px;color:#64748b;font-size:12px">This link expires in {_VERIFY_HOURS} hour. If you did not request access, ignore this email.</p>
  </div>
</body></html>"""
    body_text = (
        f"Hi {req.name},\n\nConfirm your email and submit your access request to "
        f"{settings.app_name} by opening this link:\n{verify_url}\n\n"
        f"This link expires in {_VERIFY_HOURS} hour. If you did not request access, ignore this email."
    )
    log.info("Access request from %s <%s>", _sl(req.name), _sl(req.email))
    sent = False
    try:
        sent = await send_email(
            req.email,
            f"Verify your access request - {settings.app_name}",
            body_html,
            text=body_text,
            reply_to=settings.access_request_email,
        )
    except Exception as exc:
        log.error("Verification email failed for %s: %s", _sl(req.email), exc)
    return {
        "status": "pending",
        "email_sent": bool(sent),
        "admin_email": settings.access_request_email,
    }


_VERIFY_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>{title}</title>
<style>
  body{{margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;
       background:#080c16;color:#e2e8f0;font-family:system-ui,sans-serif}}
  .box{{max-width:460px;text-align:center;padding:2rem}}
  h2{{color:{color};margin-bottom:.75rem}} p{{color:#94a3b8;line-height:1.6}} a{{color:#6366f1;text-decoration:none}}
</style></head>
<body><div class="box"><h2>{heading}</h2><p>{body}</p></div></body></html>"""


@router.get("/verify-request")
async def verify_request(token: str) -> HTMLResponse:
    """Confirm the requester's email and forward the request to the operator."""
    from .services.alert_svc import send_email

    pending = _pending_requests.pop(token, None)
    if not pending or time.time() > pending["expires"]:
        page = _VERIFY_PAGE.format(
            title="Link expired",
            color="#ef4444",
            heading="Link expired or invalid",
            body="This verification link has expired or was already used. "
            'Please <a href="/">go back</a> and submit a new request.',
        )
        return HTMLResponse(page, status_code=400)

    name, email, reason = (html.escape(pending[k]) for k in ("name", "email", "reason"))
    admin_html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:20px;background:#080c16;color:#e2e8f0;font-family:system-ui,sans-serif">
  <div style="max-width:600px;margin:auto">
    <h2 style="color:#6366f1">{html.escape(settings.app_name)}: access request</h2>
    <p><strong>Name:</strong> {name}</p>
    <p><strong>Email:</strong> {email}</p>
    <p><strong>Reason:</strong><br>{reason or "-"}</p>
  </div>
</body></html>"""
    admin_text = (
        f"Access request from {pending['name']} <{pending['email']}>\n\n"
        f"Reason:\n{pending['reason'] or '-'}"
    )
    log.info("Email verified; forwarding access request from %s", _sl(pending["email"]))
    await send_email(
        settings.access_request_email,
        f"[{settings.app_name}] Access request from {pending['name']}",
        admin_html,
        text=admin_text,
        reply_to=pending["email"],
    )
    page = _VERIFY_PAGE.format(
        title="Email verified",
        color="#22c55e",
        heading="Email verified",
        body=f"Your access request has been sent. We will get back to you at <strong>{email}</strong>.",
    )
    return HTMLResponse(page)
