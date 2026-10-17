"""Security middleware: rate limiting, cross-site request checks, response headers.

The client IP comes from `request.client`, which Uvicorn fills from
X-Forwarded-For only for proxies listed in ``--forwarded-allow-ips``. The
middleware never parses forwarded headers itself, so they cannot be spoofed.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from collections.abc import Callable
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import settings

log = logging.getLogger("app.security")


# ── Sliding-window rate limiter ───────────────────────────────────────────────


class _Window:
    __slots__ = ("_hits", "limit", "window")

    def __init__(self, limit: int, window: int) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        hits = [t for t in self._hits[key] if t > cutoff]
        if len(hits) >= self.limit:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True

    def prune(self) -> None:
        cutoff = time.monotonic() - self.window
        for key in [k for k, v in self._hits.items() if not v or v[-1] < cutoff]:
            self._hits.pop(key, None)


# Auth routes: 20 req / 60 s per IP (brute force, registration spam).
# Everything else: 120 req / 60 s per IP (scraping, resource exhaustion).
_rl_auth = _Window(limit=20, window=60)
_rl_api = _Window(limit=120, window=60)
_last_prune = 0.0


def _client_ip(request: Request) -> str:
    return getattr(request.client, "host", None) or "unknown"


# ── Content Security Policy ───────────────────────────────────────────────────


def _csp(production: bool) -> str:
    # 'unsafe-inline' for scripts is required by the single-file SPA (inline
    # event handlers and a large inline script block).
    directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net",
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net",
        "img-src 'self' data: blob:",
        "connect-src 'self' https://cdn.jsdelivr.net",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "worker-src 'none'",
    ]
    if production:
        directives.append("upgrade-insecure-requests")
    return "; ".join(directives)


_NOCACHE = ("/auth/", "/analyse/", "/query", "/store", "/alerts", "/cases", "/admin", "/feed/")
# Cheap, authenticated status polls: the UI polls one per scanned IP every few
# seconds, which would otherwise trip the per-IP limit on large batches.
_RATE_LIMIT_EXEMPT = frozenset({("GET", "/analyse/ip/hig"), ("GET", "/health")})
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _same_site(request: Request) -> bool:
    """Reject state-changing requests whose Origin (or Referer) is another site.

    SameSite=Lax cookies already block most cross-site writes; this is the
    second layer for browsers that do not enforce it."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return True  # non-browser clients (curl, scripts)
    source = urlparse(origin)
    if not source.netloc:
        return True
    expected = {request.headers.get("host", ""), urlparse(settings.public_url).netloc}
    return source.netloc in expected


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        global _last_prune
        ip = _client_ip(request)
        path = request.url.path

        # Rate limiting (loopback exempt: the in-container ingest job runs locally).
        if ip not in ("127.0.0.1", "::1") and (request.method, path) not in _RATE_LIMIT_EXEMPT:
            limiter = _rl_auth if path.startswith("/auth/") else _rl_api
            if not limiter.allowed(ip):
                log.warning("RATE_LIMIT ip=%s path=%s", ip, path)
                return JSONResponse(
                    {"detail": "Too many requests, please slow down."},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
        now = time.monotonic()
        if now - _last_prune > 300:
            _rl_auth.prune()
            _rl_api.prune()
            _last_prune = now

        if request.method in _UNSAFE_METHODS and not _same_site(request):
            log.warning("CROSS_SITE_BLOCKED ip=%s path=%s", ip, path)
            return JSONResponse({"detail": "Cross-site request blocked"}, status_code=403)

        response: Response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["X-XSS-Protection"] = "0"  # legacy filter is harmful; CSP is the control
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
            "magnetometer=(), accelerometer=(), gyroscope=()"
        )
        h["Content-Security-Policy"] = _csp(settings.production)
        if settings.production:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        for hdr in ("server", "x-powered-by"):
            if hdr in h:
                del h[hdr]
        if any(path.startswith(p) for p in _NOCACHE):
            h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            h["Pragma"] = "no-cache"
        return response
