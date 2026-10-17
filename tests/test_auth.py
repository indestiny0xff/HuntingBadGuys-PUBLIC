"""Tests for auth: register, login, logout, /me, edge cases."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app import auth as auth_module
from app.config import settings
from app.main import app

_INVITE = settings.invite_code


@pytest.fixture(autouse=True)
def clear_users():
    """Reset in-memory user store between tests."""
    auth_module._users.clear()
    auth_module._username_index.clear()
    auth_module._attempt_counts.clear()
    auth_module._lockout_until.clear()
    yield
    auth_module._users.clear()
    auth_module._username_index.clear()
    auth_module._attempt_counts.clear()
    auth_module._lockout_until.clear()


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Register ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_register_success(client):
    r = await client.post(
        "/auth/register",
        json={"username": "alice", "password": "secret123", "invite_code": _INVITE},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice"
    assert "id" in body
    assert "hashed_password" not in body


@pytest.mark.asyncio
async def test_register_duplicate_username(client):
    payload = {"username": "bob", "password": "password1", "invite_code": _INVITE}
    await client.post("/auth/register", json=payload)
    r = await client.post("/auth/register", json=payload)
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_register_short_password(client):
    r = await client.post(
        "/auth/register", json={"username": "carol", "password": "short", "invite_code": _INVITE}
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_username(client):
    r = await client.post(
        "/auth/register", json={"username": "a!", "password": "validpass", "invite_code": _INVITE}
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_register_password_too_long(client):
    r = await client.post(
        "/auth/register", json={"username": "dave", "password": "x" * 129, "invite_code": _INVITE}
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_register_wrong_invite_code(client):
    r = await client.post(
        "/auth/register",
        json={"username": "eve2", "password": "validpass1", "invite_code": "wrong"},
    )
    assert r.status_code == 403


# ── Login ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_login_success(client):
    await client.post(
        "/auth/register", json={"username": "eve", "password": "mypassword", "invite_code": _INVITE}
    )
    r = await client.post("/auth/login", json={"username": "eve", "password": "mypassword"})
    assert r.status_code == 200
    assert r.json()["username"] == "eve"
    assert "_s" in r.cookies


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post(
        "/auth/register", json={"username": "frank", "password": "correct", "invite_code": _INVITE}
    )
    r = await client.post("/auth/login", json={"username": "frank", "password": "wrongpassword"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client):
    r = await client.post("/auth/login", json={"username": "nobody", "password": "anything"})
    assert r.status_code == 401


# ── /me ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_me_authenticated(client):
    await client.post(
        "/auth/register",
        json={"username": "grace", "password": "password1", "invite_code": _INVITE},
    )
    await client.post("/auth/login", json={"username": "grace", "password": "password1"})
    r = await client.get("/auth/me")
    assert r.status_code == 200
    assert r.json()["username"] == "grace"


@pytest.mark.asyncio
async def test_me_unauthenticated(client):
    r = await client.get("/auth/me")
    assert r.status_code == 401


# ── Logout ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_logout_clears_cookie(client):
    await client.post(
        "/auth/register",
        json={"username": "henry", "password": "password1", "invite_code": _INVITE},
    )
    await client.post("/auth/login", json={"username": "henry", "password": "password1"})
    r = await client.post("/auth/logout")
    assert r.status_code == 200
    # Cookie should be cleared — subsequent /me should be 401
    r2 = await client.get("/auth/me")
    assert r2.status_code == 401


# ── Protected routes require auth ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_requires_auth(client):
    r = await client.get("/store")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_alerts_requires_auth(client):
    r = await client.get("/alerts")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_query_requires_auth(client):
    r = await client.post("/query", json={"query": "final_status == 200"})
    assert r.status_code == 401
