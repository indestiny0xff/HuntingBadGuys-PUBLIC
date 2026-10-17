"""Tests for features added in the infra/secure-vps-deployment-2026 branch.

Covers:
- /health endpoint
- _NullDB (in-memory fallback when DB_DSN is not set)
- PostgreSQL DB layer interface contract
- Config: db_dsn replaces supabase_url/supabase_key
- Public results limit changed to 50000
- AlertRuleCreate now accepts a label field
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app import auth as auth_module
from app import db as db_module
from app.config import settings
from app.main import app

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_users():
    auth_module._users.clear()
    auth_module._username_index.clear()
    yield
    auth_module._users.clear()
    auth_module._username_index.clear()


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def auth_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        await c.post(
            "/auth/register",
            json={
                "username": "testuser",
                "password": "testpassword",
                "invite_code": settings.invite_code,
            },
        )
        await c.post(
            "/auth/login",
            json={
                "username": "testuser",
                "password": "testpassword",
            },
        )
        yield c


# ── Health endpoint ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_returns_200(client):
    r = await client.get("/health")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_health_returns_ok_json(client):
    r = await client.get("/health")
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"]


@pytest.mark.asyncio
async def test_health_no_auth_required(client):
    """Health endpoint must be reachable without authentication."""
    r = await client.get("/health")
    assert r.status_code == 200


# ── Static pages are served by FastAPI ───────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/login", "/app", "/features", "/intel", "/blog"])
async def test_pages_are_served(client, path):
    r = await client.get(path)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "/branding.css" in r.text


@pytest.mark.asyncio
async def test_branding_placeholders_are_filled(client):
    r = await client.get("/app")
    assert "{{APP_NAME}}" not in r.text and "{{BRAND_A}}" not in r.text


@pytest.mark.asyncio
async def test_branding_css_uses_configured_theme(client):
    r = await client.get("/branding.css")
    assert r.status_code == 200
    assert "--accent:" in r.text


# ── _NullDB interface ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_null_db_load_all_returns_empty():
    db = db_module._NullDB()
    result = await db.load_all()
    assert result == {}


@pytest.mark.asyncio
async def test_null_db_save_result_is_noop():
    db = db_module._NullDB()
    await db.save_result("uid", {"_id": "x", "target": "example.com"})


@pytest.mark.asyncio
async def test_null_db_get_result_returns_none():
    db = db_module._NullDB()
    result = await db.get_result("nonexistent")
    assert result is None


# ── init_db with empty DSN uses NullDB ───────────────────────────────────────


@pytest.mark.asyncio
async def test_init_db_empty_dsn_uses_nulldb():
    await db_module.init_db("")
    assert isinstance(db_module.get_db(), db_module._NullDB)


@pytest.mark.asyncio
async def test_init_db_invalid_dsn_falls_back_to_nulldb():
    await db_module.init_db("postgresql://invalid:invalid@localhost:9999/nonexistent")
    assert isinstance(db_module.get_db(), db_module._NullDB)


# ── Config: db_dsn exists, supabase gone ─────────────────────────────────────


def test_config_has_db_dsn():
    assert hasattr(settings, "db_dsn")


def test_config_no_supabase_url():
    assert not hasattr(settings, "supabase_url")


def test_config_no_supabase_key():
    assert not hasattr(settings, "supabase_key")


def test_config_db_dsn_empty_by_default():
    assert settings.db_dsn == "" or settings.db_dsn.startswith("postgresql://")


# ── Public results limit ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_public_results_limits(client):
    """Full documents are capped to 500 per page; the compact card
    projection (fields=list) may be requested in bulk."""
    r = await client.get("/public/results")
    assert r.status_code == 200
    assert r.json()["limit"] == 500
    r = await client.get("/public/results?fields=list")
    assert r.status_code == 200
    assert r.json()["limit"] == 50000


# ── AlertRuleCreate label field ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_label_stored_and_returned(auth_client):
    r = await auth_client.post(
        "/alerts",
        json={
            "email": "test@example.com",
            "query": "final_status == 200",
            "label": "Campaign 2026",
            "frequency_minutes": 60,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["label"] == "Campaign 2026"


@pytest.mark.asyncio
async def test_alert_label_defaults_to_empty(auth_client):
    r = await auth_client.post(
        "/alerts",
        json={
            "email": "test@example.com",
            "query": "final_status == 200",
            "frequency_minutes": 60,
        },
    )
    assert r.status_code == 201
    assert r.json()["label"] == ""


@pytest.mark.asyncio
async def test_alert_case_name_used_as_label_when_no_label(auth_client):
    """If no label is given but a case exists, case name fills the label."""
    # Create a case first
    cr = await auth_client.post("/cases", json={"name": "Phishing 2026"})
    assert cr.status_code == 201
    case_id = cr.json()["id"]

    r = await auth_client.post(
        "/alerts",
        json={
            "email": "test@example.com",
            "query": "final_status == 200",
            "frequency_minutes": 60,
            "case_id": case_id,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["label"] == "Phishing 2026"


@pytest.mark.asyncio
async def test_alert_explicit_label_wins_over_case_name(auth_client):
    """An explicit label takes priority over the case name."""
    cr = await auth_client.post("/cases", json={"name": "Case A"})
    case_id = cr.json()["id"]

    r = await auth_client.post(
        "/alerts",
        json={
            "email": "test@example.com",
            "query": "final_status == 200",
            "frequency_minutes": 60,
            "case_id": case_id,
            "label": "My Custom Label",
        },
    )
    assert r.status_code == 201
    assert r.json()["label"] == "My Custom Label"


# ── _PostgresDB interface (mocked asyncpg pool) ───────────────────────────────


@pytest.mark.asyncio
async def test_postgres_db_save_result_calls_pool():
    """_PostgresDB.save_result acquires a connection and executes INSERT."""
    mock_conn = AsyncMock()
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    db = db_module._PostgresDB(mock_pool)
    await db.save_result(
        "uid1",
        {
            "_id": "result-id-1",
            "target": "evil.com",
            "kind": "domain",
            "is_private": False,
            "scanned_at": "2026-01-01T00:00:00Z",
        },
    )
    mock_conn.execute.assert_called()


@pytest.mark.asyncio
async def test_postgres_db_delete_result_calls_pool():
    mock_conn = AsyncMock()
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    db = db_module._PostgresDB(mock_pool)
    await db.delete_result("uid1", "result-id-1")
    mock_conn.execute.assert_called_once()


@pytest.mark.asyncio
async def test_postgres_db_get_result_returns_none_when_not_found():
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = None
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    db = db_module._PostgresDB(mock_pool)
    result = await db.get_result("nonexistent-id")
    assert result is None


@pytest.mark.asyncio
async def test_postgres_db_load_all_returns_structured_dict():
    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = []
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    db = db_module._PostgresDB(mock_pool)
    result = await db.load_all()

    assert "results" in result
    assert "result_index" in result
    assert "cases" in result
    assert "folders" in result
    assert "alerts" in result
    assert "notifications" in result
    assert "users" in result


@pytest.mark.asyncio
async def test_postgres_db_save_user_calls_pool():
    mock_conn = AsyncMock()
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    db = db_module._PostgresDB(mock_pool)
    await db.save_user(
        {
            "id": "user-1",
            "username": "alice",
            "hashed_password": "$2b$12$...",
            "created_at": "2026-01-01T00:00:00Z",
        }
    )
    mock_conn.execute.assert_called_once()


@pytest.mark.asyncio
async def test_postgres_db_errors_are_swallowed():
    """DB errors must not propagate — they're logged and swallowed."""
    mock_conn = AsyncMock()
    mock_conn.execute.side_effect = Exception("DB connection lost")
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    db = db_module._PostgresDB(mock_pool)
    # Must NOT raise even when the DB call fails
    await db.save_result("uid", {"_id": "x", "target": "t"})
    await db.delete_result("uid", "x")
    await db.save_user({"id": "u", "username": "u", "hashed_password": "h"})
