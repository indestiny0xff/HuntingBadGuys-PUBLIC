"""Tests for the Intel team feed, CTI report notes, and the public blog
(infra/secure-vps-deployment-2026 branch)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app import auth as auth_module
from app import main as main_module
from app.config import settings
from app.main import app
from app.services import blog_svc


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
                "username": "analyst1",
                "password": "testpassword",
                "invite_code": settings.invite_code,
            },
        )
        await c.post("/auth/login", json={"username": "analyst1", "password": "testpassword"})
        yield c


# ── Blog markdown sanitisation ─────────────────────────────────────────────────


def test_render_md_strips_scripts_keeps_tables_and_data_images():
    md = (
        "# Title\n\n<script>alert(1)</script>\n\n"
        "| a | b |\n|---|---|\n| 1 | 2 |\n\n"
        "![g](data:image/png;base64,iVBOR)\n\n[x](javascript:alert(1))"
    )
    html = blog_svc.render_md(md)
    assert "<script" not in html.lower()
    assert "javascript:" not in html.lower()
    assert "<table" in html  # GFM tables rendered
    assert "data:image/png" in html  # embedded graph PNG survives


# ── Intel team feed ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_feed_requires_auth(client):
    r = await client.get("/feed/results")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_feed_visibility_in_memory_fallback(auth_client):
    """With NullDB the feed builds from in-memory stores: viewer sees all
    non-private results + their own private ones, but not others' private."""
    uid = auth_module._username_index["analyst1"]
    other = "other-user-id"
    main_module._stores[other] = {
        "p1": {
            "_id": "p1",
            "target": "public-other.com",
            "kind": "domain",
            "is_private": False,
            "scanned_at": "2026-01-02T00:00:00+00:00",
        },
        "s1": {
            "_id": "s1",
            "target": "secret-other.com",
            "kind": "domain",
            "is_private": True,
            "scanned_at": "2026-01-03T00:00:00+00:00",
        },
    }
    main_module._stores[uid] = {
        "m1": {
            "_id": "m1",
            "target": "my-private.com",
            "kind": "domain",
            "is_private": True,
            "scanned_at": "2026-01-04T00:00:00+00:00",
        },
    }
    try:
        r = await auth_client.get("/feed/results?slim=true&limit=100&page=1")
        assert r.status_code == 200
        targets = {x["target"] for x in r.json()["results"]}
        assert "public-other.com" in targets  # other user's public → visible
        assert "my-private.com" in targets  # my own private → visible
        assert "secret-other.com" not in targets  # other user's private → hidden
    finally:
        main_module._stores.pop(other, None)
        main_module._stores.pop(uid, None)


# ── Blog API ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blog_list_public_ok(client):
    r = await client.get("/api/blog/posts")
    assert r.status_code == 200
    assert "posts" in r.json()


@pytest.mark.asyncio
async def test_blog_post_missing_404(client):
    r = await client.get("/api/blog/posts/does-not-exist")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_blog_publish_any_authenticated_user(auth_client):
    """Any authenticated user (not just admins) can publish."""
    r = await auth_client.post(
        "/api/blog/posts", json={"title": "My Report", "slug": "my-report", "body_md": "# hi"}
    )
    assert r.status_code in (200, 201)
    assert r.json()["slug"] == "my-report"


@pytest.mark.asyncio
async def test_blog_publish_requires_login(client):
    r = await client.post("/api/blog/posts", json={"title": "T", "slug": "t"})
    assert r.status_code in (401, 403)


# ── Case CTI notes ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_case_report_shared_read_write(auth_client):
    """Report read/save via the team-shared cross-user endpoints."""
    cid = (await auth_client.post("/cases", json={"name": "Shared Op"})).json()["id"]
    pr = await auth_client.put(
        f"/cases/{cid}/report",
        json={"notes_md": "# Shared\n\nteam notes", "report_title": "Shared Op Report"},
    )
    assert pr.status_code == 200
    gr = await auth_client.get(f"/cases/{cid}/report")
    assert gr.status_code == 200
    body = gr.json()
    assert body["notes_md"].startswith("# Shared")
    assert body["report_title"] == "Shared Op Report"


@pytest.mark.asyncio
async def test_all_reports_lists_started_reports(auth_client):
    """GET /reports lists only cases that have a report started, team-wide."""
    # case with no notes — should NOT appear
    await auth_client.post("/cases", json={"name": "Empty Case"})
    # case with a report — should appear
    cid = (await auth_client.post("/cases", json={"name": "Active Op"})).json()["id"]
    await auth_client.put(
        f"/cases/{cid}/report", json={"notes_md": "# notes", "report_title": "Active Op"}
    )
    r = await auth_client.get("/reports")
    assert r.status_code == 200
    reports = r.json()["reports"]
    titles = {x["title"] for x in reports}
    assert "Active Op" in titles
    assert "Empty Case" not in titles
    row = next(x for x in reports if x["title"] == "Active Op")
    assert row["case_id"] == cid and row["mine"] is True


@pytest.mark.asyncio
async def test_all_reports_requires_auth(client):
    r = await client.get("/reports")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_report_results_endpoint(auth_client):
    cid = (await auth_client.post("/cases", json={"name": "R"})).json()["id"]
    r = await auth_client.get(f"/cases/{cid}/report-results")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_blog_unpublish_missing_404(auth_client):
    r = await auth_client.post("/api/blog/posts/nope-nope/unpublish")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_blog_by_case_empty(auth_client):
    r = await auth_client.get("/api/blog/by-case/no-such-case")
    assert r.status_code == 200
    assert r.json() == {}


@pytest.mark.asyncio
async def test_case_notes_md_persists(auth_client):
    cr = await auth_client.post("/cases", json={"name": "Op Test"})
    assert cr.status_code == 201
    cid = cr.json()["id"]
    pr = await auth_client.patch(
        f"/cases/{cid}",
        json={"notes_md": "# Report\n\nSome **markdown** notes.", "report_title": "Op Test Report"},
    )
    assert pr.status_code == 200
    body = pr.json()
    assert body["notes_md"].startswith("# Report")
    assert body["report_title"] == "Op Test Report"
    assert body["report_updated_at"]
