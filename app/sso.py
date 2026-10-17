"""Single sign-on through OpenID Connect (authorization code flow with PKCE).

Any standards-compliant provider works: Google, Microsoft Entra ID, Okta,
Keycloak, Authentik, Zitadel. Configure ``HUNTER_OIDC_ISSUER``,
``HUNTER_OIDC_CLIENT_ID`` and ``HUNTER_OIDC_CLIENT_SECRET``; the redirect URI to
register at the provider is ``<HUNTER_PUBLIC_URL>/auth/sso/callback``.

Flow:
1. ``/auth/sso/login`` stores state, nonce and the PKCE verifier in a short-lived
   signed cookie and redirects to the provider.
2. ``/auth/sso/callback`` exchanges the code, validates the ID token against the
   provider's JWKS (issuer, audience, nonce, expiry), then finds or creates the
   local account by its stable ``sub`` claim and sets the session cookie.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from . import auth
from .config import settings
from .models import UserInDB
from .security import sanitize_for_log as _sl

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/sso", tags=["sso"])

_FLOW_COOKIE = "_sso"
_FLOW_TTL_SECONDS = 600
_DISCOVERY_TTL_SECONDS = 3600
_USERNAME_RE = re.compile(r"[^a-zA-Z0-9_-]")

_discovery_cache: dict = {"fetched": 0.0, "doc": None}
_jwks_clients: dict[str, jwt.PyJWKClient] = {}


# ── Provider metadata ─────────────────────────────────────────────────────────


async def _discovery() -> dict:
    now = time.time()
    if _discovery_cache["doc"] and now - _discovery_cache["fetched"] < _DISCOVERY_TTL_SECONDS:
        return _discovery_cache["doc"]
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url)
    resp.raise_for_status()
    doc = resp.json()
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if key not in doc:
            raise RuntimeError(f"OIDC discovery document is missing {key}")
    _discovery_cache.update(fetched=now, doc=doc)
    return doc


def _jwks_client(jwks_uri: str) -> jwt.PyJWKClient:
    client = _jwks_clients.get(jwks_uri)
    if client is None:
        client = jwt.PyJWKClient(jwks_uri, cache_keys=True, lifespan=_DISCOVERY_TTL_SECONDS)
        _jwks_clients[jwks_uri] = client
    return client


# ── Flow state cookie (signed, short-lived) ───────────────────────────────────


def _sign_flow(data: dict) -> str:
    payload = {**data, "exp": datetime.now(timezone.utc) + timedelta(seconds=_FLOW_TTL_SECONDS)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def _read_flow(token: str | None) -> dict:
    if not token:
        raise HTTPException(status_code=400, detail="SSO flow expired, start again")
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="SSO flow expired, start again")


def _safe_next(value: str | None) -> str:
    """Only allow same-site relative paths as post-login destinations."""
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/app"


def _redirect_uri() -> str:
    return f"{settings.public_url}/auth/sso/callback"


# ── Account mapping ───────────────────────────────────────────────────────────


def _derive_username(claims: dict) -> str:
    base = claims.get("preferred_username") or claims.get("email") or claims.get("sub") or "user"
    base = base.split("@", 1)[0]
    base = _USERNAME_RE.sub("-", base).strip("-")[:28] or "user"
    if len(base) < 3:
        base = f"{base}-sso"
    candidate = base
    suffix = 1
    while auth.find_user_by_username(candidate):
        suffix += 1
        candidate = f"{base[:26]}-{suffix}"
    return candidate


def _email_allowed(email: str | None) -> bool:
    allowed = [d.strip().lower() for d in settings.oidc_allowed_domains.split(",") if d.strip()]
    if not allowed:
        return True
    if not email or "@" not in email:
        return False
    return email.rsplit("@", 1)[1].lower() in allowed


async def _find_or_create_user(claims: dict) -> UserInDB:
    subject = str(claims["sub"])
    email = claims.get("email")
    user = auth.find_user_by_sso_subject(subject)
    if user:
        return user
    if not settings.oidc_auto_create:
        raise HTTPException(status_code=403, detail="No local account is linked to this identity")
    if not _email_allowed(email):
        raise HTTPException(status_code=403, detail="This email domain is not allowed to sign in")
    user = UserInDB(
        id=str(uuid.uuid4()),
        username=_derive_username(claims),
        hashed_password=None,
        created_at=datetime.now(timezone.utc).isoformat(),
        email=email,
        auth_provider="oidc",
        sso_subject=subject,
    )
    await auth.add_user(user)
    log.info("SSO account created: %s <%s>", _sl(user.username), _sl(email or ""))
    return user


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/login")
async def sso_login(request: Request, next: str | None = None) -> Response:
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO is not configured")
    try:
        doc = await _discovery()
    except Exception as exc:
        log.error("OIDC discovery failed: %s", exc)
        raise HTTPException(status_code=502, detail="Identity provider unreachable")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": _redirect_uri(),
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge.decode(),
        "code_challenge_method": "S256",
    }
    response = RedirectResponse(
        f"{doc['authorization_endpoint']}?{urlencode(params)}", status_code=302
    )
    response.set_cookie(
        _FLOW_COOKIE,
        _sign_flow(
            {"state": state, "nonce": nonce, "verifier": verifier, "next": _safe_next(next)}
        ),
        max_age=_FLOW_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/auth/sso",
    )
    return response


@router.get("/callback")
async def sso_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> Response:
    if not settings.sso_enabled:
        raise HTTPException(status_code=404, detail="SSO is not configured")
    if error:
        log.warning("OIDC provider returned error=%s: %s", _sl(error), _sl(error_description or ""))
        raise HTTPException(
            status_code=400, detail="Sign-in was cancelled or refused by the provider"
        )
    flow = _read_flow(request.cookies.get(_FLOW_COOKIE))
    if not code or not state or not secrets.compare_digest(state, flow.get("state", "")):
        raise HTTPException(status_code=400, detail="Invalid SSO state")

    doc = await _discovery()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(),
        "client_id": settings.oidc_client_id,
        "code_verifier": flow["verifier"],
    }
    if settings.oidc_client_secret:
        data["client_secret"] = settings.oidc_client_secret
    async with httpx.AsyncClient(timeout=20) as client:
        token_resp = await client.post(doc["token_endpoint"], data=data)
    if token_resp.status_code != 200:
        log.error("OIDC token exchange failed: HTTP %s", token_resp.status_code)
        raise HTTPException(
            status_code=502, detail="Token exchange with the identity provider failed"
        )
    id_token = token_resp.json().get("id_token")
    if not id_token:
        raise HTTPException(status_code=502, detail="Identity provider did not return an ID token")

    try:
        signing_key = _jwks_client(doc["jwks_uri"]).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256", "PS256"],
            audience=settings.oidc_client_id,
            issuer=doc["issuer"],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        log.warning("OIDC ID token rejected: %s", exc)
        raise HTTPException(status_code=401, detail="ID token validation failed")
    if not secrets.compare_digest(str(claims.get("nonce", "")), flow.get("nonce", "")):
        raise HTTPException(status_code=401, detail="ID token nonce mismatch")

    user = await _find_or_create_user(claims)
    log.info("SSO login: %s", _sl(user.username))
    response = RedirectResponse(flow.get("next") or "/app", status_code=302)
    response.delete_cookie(_FLOW_COOKIE, path="/auth/sso")
    auth.set_session_cookie(response, user)
    return response
