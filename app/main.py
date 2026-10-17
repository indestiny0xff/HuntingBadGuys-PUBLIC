"""FastAPI application factory and lifespan.

Routes live in `app.routes.*`; per-user in-memory state in `app.state`; the
shared Playwright browser in `app.browser`.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from . import __version__, apikeys, auth, browser, db, sso, state
from .config import settings
from .logbuffer import configure_logging
from .middleware import SecurityMiddleware
from .models import AlertNotification, AlertRule, ApiKey, Case, Folder, UserInDB
from .routes import (
    admin,
    alerts,
    analysis,
    api_docs,
    blog,
    export,
    extraction,
    graph,
    pages,
    public,
    store,
)
from .routes.analysis import _VOLATILE_HEADERS, _stable_headers_hash  # noqa: F401 (test imports)
from .services import alert_svc, geoip_svc, screenshot_svc
from .state import _stores, _target_indexes, _user_alerts  # noqa: F401 (test imports)

configure_logging()
log = logging.getLogger(__name__)


async def _alert_scheduler() -> None:
    """Wake every 60 s and fire due alert rules for every user."""
    while True:
        await asyncio.sleep(60)
        for uid, rules in list(state._user_alerts.items()):
            if rules:
                await alert_svc.check_alerts(
                    state._stores.get(uid, {}), rules, state._notifications_for(uid)
                )


async def _hydrate_from_db() -> None:
    """Load users, results, cases, folders, alerts and notifications into memory."""
    data = await db.get_db().load_all()
    for uid, results in data.get("results", {}).items():
        state._stores[uid] = results
    for uid, index in data.get("result_index", {}).items():
        state._target_indexes[uid] = index
    for uid, cases in data.get("cases", {}).items():
        state._user_cases[uid] = {cid: Case(**c) for cid, c in cases.items()}
    for uid, folders in data.get("folders", {}).items():
        state._user_folders[uid] = {fid: Folder(**f) for fid, f in folders.items()}
    for uid, rules in data.get("alerts", {}).items():
        try:
            state._user_alerts[uid] = {aid: AlertRule(**a) for aid, a in rules.items()}
        except Exception as exc:
            log.warning("Could not restore alerts for %s: %s", uid, exc)
    for uid, notifs in data.get("notifications", {}).items():
        try:
            state._user_notifications[uid] = [AlertNotification(**n) for n in notifs]
        except Exception as exc:
            log.warning("Could not restore notifications for %s: %s", uid, exc)

    # Users: the database wins over a stale users.json; then push any
    # JSON-only users (fresh database bootstrap) back into the database.
    for u_data in data.get("users", []):
        try:
            user = UserInDB(**u_data)
            auth._users[user.id] = user
            auth._username_index[user.username] = user.id
        except Exception as exc:
            log.warning("Could not restore user from DB: %s", exc)
    for user in list(auth._users.values()):
        try:
            await db.get_db().save_user(user.model_dump())
        except Exception as exc:
            log.warning("Could not sync user to DB: %s", exc)
    if auth._users:
        log.info("Loaded %d user(s)", len(auth._users))
    for k_data in data.get("api_keys", []):
        try:
            apikeys.register(ApiKey(**k_data))
        except Exception as exc:
            log.warning("Could not restore API key: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.load_users()
    apikeys.load_keys()
    await db.init_db(settings.db_dsn)
    await _hydrate_from_db()
    await auth.bootstrap_admin()
    geoip_refresh = await geoip_svc.init(settings.geoip_db)
    await browser.start()
    screenshot_svc.init_semaphore(max_concurrent=4)
    scheduler = asyncio.create_task(_alert_scheduler())
    log.info(
        "%s v%s ready (registration=%s, sso=%s, db=%s)",
        settings.app_name,
        __version__,
        settings.registration_enabled,
        settings.sso_enabled,
        "postgres" if settings.db_dsn else "memory",
    )
    try:
        yield
    finally:
        scheduler.cancel()
        geoip_refresh.cancel()
        await browser.stop()
        await db.close_db()


app = FastAPI(
    title=settings.app_name,
    version=__version__,
    lifespan=lifespan,
    # The API is not public: no automatic docs to avoid leaking the surface.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(SecurityMiddleware)

app.include_router(auth.router)
app.include_router(sso.router)
app.include_router(pages.router)
app.include_router(public.router)
app.include_router(blog.router)
app.include_router(analysis.router)
app.include_router(store.router)
app.include_router(alerts.router)
app.include_router(admin.router)
app.include_router(extraction.router)
app.include_router(graph.router)
app.include_router(export.router)

# Versioned API: the same handlers mounted under /api/v1 for integrations
# (API-key authenticated). The unprefixed paths stay for the web app.
API_PREFIX = "/api/v1"
for _r in (
    auth.router,
    public.router,
    blog.router,
    analysis.router,
    store.router,
    alerts.router,
    extraction.router,
    graph.router,
    export.router,
    admin.router,
):
    app.include_router(_r, prefix=API_PREFIX, include_in_schema=True)
app.include_router(api_docs.router)


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Never leak stack traces to clients."""
    if isinstance(exc, HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    log.error("Unhandled exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)
