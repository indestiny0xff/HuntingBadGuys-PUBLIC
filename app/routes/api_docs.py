"""API reference for signed-in users: OpenAPI schema and Swagger UI.

Only the versioned ``/api/v1`` paths are documented; the public schema at
``/openapi.json`` stays disabled.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

from .. import __version__
from ..auth import get_current_user
from ..config import settings
from ..models import UserInDB

router = APIRouter()

_DESCRIPTION = """Authenticate with an API key created in the app (user menu, API keys):

    Authorization: Bearer hbg_...    or    X-API-Key: hbg_...

Every endpoint below is also reachable without the `/api/v1` prefix by the web app
with a session cookie."""


def build_schema(app) -> dict:
    schema = get_openapi(
        title=f"{settings.app_name} API",
        version=__version__,
        description=_DESCRIPTION,
        routes=app.routes,
    )
    schema["paths"] = {p: v for p, v in schema.get("paths", {}).items() if p.startswith("/api/v1/")}
    schema["components"] = schema.get("components", {})
    schema["components"]["securitySchemes"] = {
        "ApiKeyBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "API key"},
        "ApiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
    }
    schema["security"] = [{"ApiKeyBearer": []}, {"ApiKeyHeader": []}]
    schema["servers"] = [{"url": settings.public_url}]
    return schema


@router.get("/api/openapi.json", include_in_schema=False)
async def api_openapi(request: Request, _: UserInDB = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse(build_schema(request.app))


@router.get("/api/docs", include_in_schema=False)
async def api_docs(_: UserInDB = Depends(get_current_user)) -> HTMLResponse:
    return get_swagger_ui_html(
        openapi_url="/api/openapi.json",
        title=f"{settings.app_name} API reference",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_favicon_url="/favicon.svg",
    )
