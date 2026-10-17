"""Tests for alert CRUD and per-user isolation."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app import auth as auth_module
from app.config import settings
from app.main import _stores, _target_indexes, _user_alerts, app

_INVITE = settings.invite_code


@pytest.fixture(autouse=True)
def clear_state():
    auth_module._users.clear()
    auth_module._username_index.clear()
    _stores.clear()
    _user_alerts.clear()
    _target_indexes.clear()
    yield
    auth_module._users.clear()
    auth_module._username_index.clear()
    _stores.clear()
    _user_alerts.clear()
    _target_indexes.clear()


@pytest.fixture
async def auth_client():
    """Client pre-logged-in as testuser."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        await c.post(
            "/auth/register",
            json={"username": "testuser", "password": "password123", "invite_code": _INVITE},
        )
        await c.post("/auth/login", json={"username": "testuser", "password": "password123"})
        yield c


# ── Alert CRUD ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_alert(auth_client):
    r = await auth_client.post(
        "/alerts",
        json={
            "email": "test@example.com",
            "query": "final_status == 200",
            "frequency_minutes": 60,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "test@example.com"
    assert body["query"] == "final_status == 200"
    assert "id" in body


@pytest.mark.asyncio
async def test_list_alerts_empty(auth_client):
    r = await auth_client.get("/alerts")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_alerts_after_create(auth_client):
    await auth_client.post(
        "/alerts",
        json={
            "email": "a@b.com",
            "query": "final_status == 200",
            "frequency_minutes": 30,
        },
    )
    r = await auth_client.get("/alerts")
    assert len(r.json()) == 1


@pytest.mark.asyncio
async def test_delete_alert(auth_client):
    cr = await auth_client.post(
        "/alerts",
        json={
            "email": "a@b.com",
            "query": "final_status == 200",
            "frequency_minutes": 60,
        },
    )
    alert_id = cr.json()["id"]
    dr = await auth_client.delete(f"/alerts/{alert_id}")
    assert dr.status_code == 200
    r = await auth_client.get("/alerts")
    assert r.json() == []


@pytest.mark.asyncio
async def test_create_alert_invalid_query(auth_client):
    r = await auth_client.post(
        "/alerts",
        json={
            "email": "a@b.com",
            "query": "INVALID ??? query",
            "frequency_minutes": 60,
        },
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_alert_with_label_and_targets(auth_client):
    r = await auth_client.post(
        "/alerts",
        json={
            "email": "a@b.com",
            "query": "final_status == 200",
            "targets": ["evil.com", "phish.net"],
            "label": "My alert",
            "frequency_minutes": 15,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["label"] == "My alert"
    # `targets` on AlertRule is deprecated (kept for migration only);
    # the endpoint ignores it in favour of query-based matching.


# ── Per-user isolation ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_isolated_between_users():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c1:
        await c1.post(
            "/auth/register",
            json={"username": "user1", "password": "password1", "invite_code": _INVITE},
        )
        await c1.post("/auth/login", json={"username": "user1", "password": "password1"})
        await c1.post(
            "/alerts",
            json={
                "email": "u1@x.com",
                "query": "final_status == 200",
                "frequency_minutes": 60,
            },
        )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c2:
        await c2.post(
            "/auth/register",
            json={"username": "user2", "password": "password2", "invite_code": _INVITE},
        )
        await c2.post("/auth/login", json={"username": "user2", "password": "password2"})
        r = await c2.get("/alerts")
        assert r.json() == []


# ── Alert test endpoint ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_test_no_matches(auth_client):
    cr = await auth_client.post(
        "/alerts",
        json={
            "email": "a@b.com",
            "query": "final_status == 999",
            "frequency_minutes": 60,
        },
    )
    alert_id = cr.json()["id"]
    r = await auth_client.post(f"/alerts/{alert_id}/test")
    assert r.status_code == 200
    assert r.json()["sent"] is False
    assert r.json()["matches"] == 0


@pytest.mark.asyncio
async def test_alert_test_not_found(auth_client):
    r = await auth_client.post("/alerts/nonexistent-id/test")
    assert r.status_code == 404
