"""Tests for the 1.0 hardening: SSRF guard, auth config, SSO wiring, lockouts,
input validation, origin checks, branding and the admin changelog."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app import auth as auth_module
from app import security
from app.config import settings
from app.main import app
from app.query.engine import QueryParseError, validate
from app.services import hig_svc

_INVITE = settings.invite_code


@pytest.fixture(autouse=True)
def clear_users():
    auth_module._users.clear()
    auth_module._username_index.clear()
    auth_module._attempt_counts.clear()
    auth_module._lockout_until.clear()
    auth_module._lockout_level.clear()
    yield
    auth_module._users.clear()
    auth_module._username_index.clear()
    auth_module._attempt_counts.clear()
    auth_module._lockout_until.clear()
    auth_module._lockout_level.clear()


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _register_and_login(client, username="analyst", password="password123"):
    await client.post(
        "/auth/register", json={"username": username, "password": password, "invite_code": _INVITE}
    )
    r = await client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200


# ── SSRF guard ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.5", "169.254.169.254", "::1"]
)
def test_private_ips_are_rejected(ip):
    assert security.is_safe_ip(ip) is False


def test_public_ip_is_allowed():
    assert security.is_safe_ip("93.184.216.34") is True


async def test_is_safe_url_rejects_metadata_endpoint():
    assert await security.is_safe_url("http://169.254.169.254/latest/meta-data") is False


async def test_is_safe_url_rejects_non_http_schemes():
    assert await security.is_safe_url("file:///etc/passwd") is False
    assert await security.is_safe_url("gopher://example.com") is False


async def test_is_safe_host_resolves_names(monkeypatch):
    monkeypatch.setattr(security, "_resolve_sync", lambda host: ["10.0.0.9"])
    assert await security.is_safe_host("internal.example") is False
    monkeypatch.setattr(security, "_resolve_sync", lambda host: ["93.184.216.34"])
    assert await security.is_safe_host("example.com") is True


async def test_onion_hosts_skip_resolution():
    assert await security.is_safe_host("abcdefghijklmnop.onion") is True


async def test_allow_private_targets_disables_guard(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_targets", True)
    assert security.is_safe_ip("127.0.0.1") is True
    assert await security.is_safe_url("http://127.0.0.1:8000/") is True


# ── Regex guard / query validation ────────────────────────────────────────────


def test_regex_guard_rejects_nested_quantifiers():
    with pytest.raises(ValueError):
        security.validate_user_regex("(a+)+$")


def test_regex_guard_rejects_long_patterns():
    with pytest.raises(ValueError):
        security.validate_user_regex("a" * 300)


def test_query_validate_checks_regex_operands():
    validate('certs.san ~= "^login\\\\."')
    with pytest.raises(QueryParseError):
        validate('certs.san ~= "(a+)+$"')


async def test_public_query_rejects_pathological_regex(client):
    r = await client.post("/public/query", json={"query": 'target ~= "(a+)+$"'})
    assert r.status_code == 400


# ── Log sanitiser ─────────────────────────────────────────────────────────────


def test_sanitize_for_log_strips_control_characters():
    out = security.sanitize_for_log("evil\nINFO forged line\r\x00")
    assert "\n" not in out and "\r" not in out and "\x00" not in out


# ── Auth configuration and SSO wiring ─────────────────────────────────────────


async def test_auth_config_is_public(client):
    r = await client.get("/auth/config")
    assert r.status_code == 200
    body = r.json()
    assert body["app_name"] == settings.app_name
    assert body["registration_enabled"] is True
    assert body["sso_enabled"] is False
    assert body["password_login_enabled"] is True


async def test_sso_login_404_when_not_configured(client):
    r = await client.get("/auth/sso/login", follow_redirects=False)
    assert r.status_code == 404


async def test_sso_config_advertises_button(client, monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "https://issuer.example")
    monkeypatch.setattr(settings, "oidc_client_id", "client-id")
    r = await client.get("/auth/config")
    assert r.json()["sso_enabled"] is True
    assert r.json()["sso_login_url"] == "/auth/sso/login"


async def test_sso_login_redirects_to_provider(client, monkeypatch):
    from app import sso

    monkeypatch.setattr(settings, "oidc_issuer", "https://issuer.example")
    monkeypatch.setattr(settings, "oidc_client_id", "client-id")

    async def fake_discovery():
        return {
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
            "issuer": "https://issuer.example",
        }

    monkeypatch.setattr(sso, "_discovery", fake_discovery)
    r = await client.get("/auth/sso/login?next=/intel", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://issuer.example/authorize?")
    assert "code_challenge_method=S256" in location
    assert "client_id=client-id" in location
    assert "_sso" in r.cookies


async def test_sso_callback_rejects_bad_state(client, monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "https://issuer.example")
    monkeypatch.setattr(settings, "oidc_client_id", "client-id")
    r = await client.get("/auth/sso/callback?code=x&state=y", follow_redirects=False)
    assert r.status_code == 400


def test_sso_username_derivation_avoids_collisions():
    from app import sso

    auth_module._username_index["alice"] = "uid-1"
    auth_module._users["uid-1"] = auth_module.UserInDB(
        id="uid-1", username="alice", hashed_password="x", created_at="now"
    )
    assert sso._derive_username({"email": "alice@example.com"}) == "alice-2"
    assert sso._derive_username({"preferred_username": "Bob Smith"}) == "Bob-Smith"


def test_sso_domain_allow_list(monkeypatch):
    from app import sso

    monkeypatch.setattr(settings, "oidc_allowed_domains", "example.com, corp.example")
    assert sso._email_allowed("a@example.com") is True
    assert sso._email_allowed("a@CORP.example") is True
    assert sso._email_allowed("a@evil.example") is False
    assert sso._email_allowed(None) is False


async def test_sso_only_user_cannot_use_password_login(client):
    user = auth_module.UserInDB(
        id="uid-sso",
        username="ssouser",
        hashed_password=None,
        created_at="now",
        auth_provider="oidc",
        sso_subject="sub-1",
    )
    auth_module._users[user.id] = user
    auth_module._username_index[user.username] = user.id
    r = await client.post("/auth/login", json={"username": "ssouser", "password": "whatever1"})
    assert r.status_code == 401


# ── Login lockout keyed by username + IP ──────────────────────────────────────


async def test_lockout_after_repeated_failures(client):
    await client.post(
        "/auth/register",
        json={"username": "victim", "password": "password123", "invite_code": _INVITE},
    )
    for _ in range(auth_module._MAX_ATTEMPTS):
        r = await client.post("/auth/login", json={"username": "victim", "password": "wrongpass1"})
        assert r.status_code == 401
    r = await client.post("/auth/login", json={"username": "victim", "password": "password123"})
    assert r.status_code == 429


def test_lockout_is_per_ip():
    for _ in range(auth_module._MAX_ATTEMPTS):
        auth_module._record_failure("victim", "1.1.1.1")
    with pytest.raises(Exception):
        auth_module._check_lockout("victim", "1.1.1.1")
    auth_module._check_lockout("victim", "2.2.2.2")  # another client is unaffected


# ── Input validation ──────────────────────────────────────────────────────────


async def test_hig_target_must_be_an_ip(client):
    await _register_and_login(client)
    r = await client.post("/analyse/ip/hig", json={"target": "-iL /etc/passwd"})
    assert r.status_code == 422
    r = await client.post("/analyse/ip/hig", json={"target": "example.com"})
    assert r.status_code == 422


async def test_hig_private_ip_is_blocked(client):
    await _register_and_login(client)
    r = await client.post("/analyse/ip/hig", json={"target": "10.0.0.1"})
    assert r.status_code == 400


async def test_result_patch_ignores_unknown_fields(client):
    await _register_and_login(client)
    from app.main import _stores

    uid = auth_module._username_index["analyst"]
    _stores[uid] = {"rid": {"_id": "rid", "target": "t", "is_private": False}}
    r = await client.patch("/store/rid", json={"is_private": True, "target": "hacked"})
    assert r.status_code == 200
    assert _stores[uid]["rid"]["target"] == "t"
    assert _stores[uid]["rid"]["is_private"] is True
    _stores.pop(uid, None)


async def test_access_request_validates_email(client, monkeypatch):
    monkeypatch.setattr(settings, "access_request_email", "ops@example.com")
    r = await client.post("/auth/request-access", json={"name": "A", "email": "not-an-email"})
    assert r.status_code == 422


async def test_access_request_disabled_without_inbox(client):
    r = await client.post("/auth/request-access", json={"name": "A", "email": "a@example.com"})
    assert r.status_code == 404


# ── Cross-site write protection ───────────────────────────────────────────────


async def test_cross_site_post_is_rejected(client):
    r = await client.post(
        "/auth/login",
        json={"username": "nobody", "password": "yyyyyyyy"},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403


async def test_same_site_post_is_allowed(client):
    r = await client.post(
        "/auth/login",
        json={"username": "nobody", "password": "yyyyyyyy"},
        headers={"Origin": "http://test"},
    )
    assert r.status_code == 401  # reached the handler


# ── Headers ───────────────────────────────────────────────────────────────────


async def test_security_headers_present(client):
    r = await client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-xss-protection"] == "0"


# ── Branding ──────────────────────────────────────────────────────────────────


async def test_app_name_is_rendered_everywhere(client, monkeypatch):
    monkeypatch.setattr(settings, "app_name", "Acme Threat Lab")
    for path in ("/", "/app", "/login", "/features"):
        r = await client.get(path)
        assert "Acme Threat Lab" in r.text, path
        assert "{{" not in r.text, path
    r = await client.get("/login")
    assert "ACME<span>THREATLAB</span>" in r.text


async def test_theme_css_switches_palette(client, monkeypatch):
    monkeypatch.setattr(settings, "theme", "red")
    r = await client.get("/branding.css")
    assert "--accent:#ef4444" in r.text
    monkeypatch.setattr(settings, "theme", "black")
    r = await client.get("/branding.css")
    assert "--bg:#000000" in r.text


# ── Admin: changelog and info ─────────────────────────────────────────────────


async def test_admin_changelog_requires_admin(client):
    await _register_and_login(client, "plain", "password123")
    r = await client.get("/admin/api/changelog")
    assert r.status_code == 403


async def test_admin_changelog_renders_markdown(client, monkeypatch):
    monkeypatch.setattr(settings, "admin_usernames", "boss")
    await _register_and_login(client, "boss", "password123")
    r = await client.get("/admin/api/changelog")
    assert r.status_code == 200
    body = r.json()
    assert body["version"]
    assert "<h1>" in body["html"] or "<h2>" in body["html"]
    assert "<script" not in body["html"]
    r = await client.get("/admin/api/info")
    assert r.status_code == 200 and r.json()["version"] == body["version"]


async def test_bootstrap_admin_is_created(monkeypatch):
    monkeypatch.setattr(settings, "admin_user", "bootstrap")
    monkeypatch.setattr(settings, "admin_password", "bootstrap-pass-1")
    await auth_module.bootstrap_admin()
    user = auth_module.find_user_by_username("bootstrap")
    assert user is not None and user.hashed_password
    assert "bootstrap" in auth_module.get_admin_usernames()
    await auth_module.bootstrap_admin()  # idempotent
    assert sum(1 for u in auth_module._users.values() if u.username == "bootstrap") == 1


# ── nmap --reason ─────────────────────────────────────────────────────────────


def test_hig_argv_has_reason_flag():
    assert "--reason" in hig_svc._build_argv("1.2.3.4", via_tor=True, all_ports=False)


async def test_bootstrap_admin_accepts_default_password_with_warning(monkeypatch, caplog):
    monkeypatch.setattr(settings, "admin_user", "admin")
    monkeypatch.setattr(settings, "admin_password", "admin")
    await auth_module.bootstrap_admin()
    assert auth_module.find_user_by_username("admin") is not None
    assert auth_module.is_weak_admin_password() is True
    assert any("weak" in rec.message.lower() for rec in caplog.records)


# ── Random bootstrap password and password change ────────────────────────────


async def test_bootstrap_generates_random_password_when_empty(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    monkeypatch.setattr(settings, "admin_user", "admin")
    monkeypatch.setattr(settings, "admin_password", "")
    await auth_module.bootstrap_admin()
    user = auth_module.find_user_by_username("admin")
    assert user is not None and user.hashed_password
    saved = (tmp_path / "initial-admin-password.txt").read_text().strip()
    assert len(saved) >= 20
    assert auth_module._verify_password(saved, user.hashed_password)
    assert auth_module.initial_password_pending() is True
    assert any("Initial admin password" in rec.message for rec in caplog.records)


async def test_login_does_not_enforce_registration_policy(client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    monkeypatch.setattr(settings, "admin_user", "admin")
    monkeypatch.setattr(settings, "admin_password", "admin")
    await auth_module.bootstrap_admin()
    r = await client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200


async def test_password_change_flow(client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    monkeypatch.setattr(settings, "admin_user", "admin")
    monkeypatch.setattr(settings, "admin_password", "")
    await auth_module.bootstrap_admin()
    initial = (tmp_path / "initial-admin-password.txt").read_text().strip()
    r = await client.post("/auth/login", json={"username": "admin", "password": initial})
    assert r.status_code == 200
    # wrong current password
    r = await client.post(
        "/auth/password", json={"current_password": "nope", "new_password": "new-secret-pass-1"}
    )
    assert r.status_code == 403
    # too short new password
    r = await client.post(
        "/auth/password", json={"current_password": initial, "new_password": "short"}
    )
    assert r.status_code == 422
    r = await client.post(
        "/auth/password", json={"current_password": initial, "new_password": "new-secret-pass-1"}
    )
    assert r.status_code == 200
    assert auth_module.initial_password_pending() is False
    await client.post("/auth/logout")
    r = await client.post("/auth/login", json={"username": "admin", "password": initial})
    assert r.status_code == 401
    r = await client.post(
        "/auth/login", json={"username": "admin", "password": "new-secret-pass-1"}
    )
    assert r.status_code == 200


async def test_sso_account_cannot_change_password(client):
    user = auth_module.UserInDB(
        id="uid-sso2",
        username="ssouser2",
        hashed_password=None,
        created_at="now",
        auth_provider="oidc",
        sso_subject="sub-2",
    )
    auth_module._users[user.id] = user
    auth_module._username_index[user.username] = user.id
    client.cookies.set("_s", auth_module._create_token(user.id))
    r = await client.post(
        "/auth/password", json={"current_password": "x", "new_password": "new-secret-pass-1"}
    )
    assert r.status_code == 400


async def test_branding_css_theme_override(client, monkeypatch):
    monkeypatch.setattr(settings, "theme", "purple")
    r = await client.get("/branding.css?theme=green")
    assert "--accent:#22c55e" in r.text
    r = await client.get("/branding.css?theme=not-a-theme")
    assert "--accent:#7c3aed" in r.text  # falls back to the server default


async def test_pages_ship_theme_selector(client):
    for path in ("/", "/app", "/intel", "/blog", "/features"):
        r = await client.get(path)
        assert 'class="theme-menu"' in r.text, path
        assert "hbgApplyTheme" in r.text, path
        assert "hbgToggleMode" in r.text, path


async def test_ip_mode_resolves_hostnames(client, monkeypatch):
    from app.models import DNSRecords
    from app.routes import analysis
    from app.services import dns_svc

    async def fake_resolve(domain):
        return DNSRecords(A=["93.184.216.34", "93.184.216.35"])

    async def fake_analyse(ip, browser, resolved_from=None):
        from app.models import IPResult

        return IPResult(target=ip, resolved_from=resolved_from)

    monkeypatch.setattr(dns_svc, "resolve", fake_resolve)
    monkeypatch.setattr(analysis, "_analyse_ip", fake_analyse)

    async def no_browser():
        return None

    monkeypatch.setattr(analysis, "ensure_browser", no_browser)
    await _register_and_login(client, "resolver", "password123")
    r = await client.post("/analyse/ip", json={"targets": ["https://example.com/login", "1.1.1.1"]})
    assert r.status_code == 200
    body = r.json()
    assert [x["target"] for x in body] == ["93.184.216.34", "93.184.216.35", "1.1.1.1"]
    assert body[0]["resolved_from"] == "example.com" and body[2]["resolved_from"] is None


async def test_ip_mode_unresolvable_name_reports_error(client, monkeypatch):
    from app.models import DNSRecords
    from app.routes import analysis
    from app.services import dns_svc

    async def fake_resolve(domain):
        return DNSRecords()

    async def no_browser():
        return None

    monkeypatch.setattr(dns_svc, "resolve", fake_resolve)
    monkeypatch.setattr(analysis, "ensure_browser", no_browser)
    await _register_and_login(client, "resolver2", "password123")
    r = await client.post("/analyse/ip", json={"targets": ["does-not-exist.invalid"]})
    assert r.status_code == 200
    assert "dns" in r.json()[0]["errors"]


async def test_hig_status_poll_is_not_rate_limited(client, monkeypatch):
    from app import middleware

    monkeypatch.setattr(middleware, "_client_ip", lambda request: "203.0.113.9")
    await _register_and_login(client, "poller", "password123")
    codes = set()
    for _ in range(130):
        r = await client.get("/analyse/ip/hig?target=1.1.1.1")
        codes.add(r.status_code)
    assert codes == {200}


# ── Admin account management ──────────────────────────────────────────────────


async def _login_as_admin(client, monkeypatch, name="boss"):
    monkeypatch.setattr(settings, "admin_usernames", name)
    await _register_and_login(client, name, "password123")


async def test_admin_creates_edits_and_deletes_accounts(client, monkeypatch):
    await _login_as_admin(client, monkeypatch)
    r = await client.post(
        "/admin/api/users", json={"username": "alice", "password": "alice-pass-1"}
    )
    assert r.status_code == 201
    uid = r.json()["id"]
    assert r.json()["is_admin"] is False
    # duplicate username
    r = await client.post(
        "/admin/api/users", json={"username": "alice", "password": "alice-pass-1"}
    )
    assert r.status_code == 409
    # rename + new password + promote
    r = await client.patch(
        f"/admin/api/users/{uid}",
        json={"username": "alicia", "password": "alicia-pass-2", "is_admin": True},
    )
    assert (
        r.status_code == 200 and r.json()["username"] == "alicia" and r.json()["is_admin"] is True
    )
    # the account can sign in with the new credentials and is an admin
    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    r = await other.post("/auth/login", json={"username": "alicia", "password": "alicia-pass-2"})
    assert r.status_code == 200
    r = await other.get("/auth/me")
    assert r.json()["is_admin"] is True
    await other.aclose()
    # demote and delete
    r = await client.patch(f"/admin/api/users/{uid}", json={"is_admin": False})
    assert r.status_code == 200 and r.json()["is_admin"] is False
    r = await client.delete(f"/admin/api/users/{uid}")
    assert r.status_code == 200
    assert auth_module.find_user_by_username("alicia") is None


async def test_admin_cannot_demote_self_or_env_admin(client, monkeypatch):
    await _login_as_admin(client, monkeypatch)
    me = (await client.get("/auth/me")).json()
    r = await client.patch(f"/admin/api/users/{me['id']}", json={"is_admin": False})
    assert r.status_code == 403
    r = await client.patch(f"/admin/api/users/{me['id']}", json={"username": "renamed"})
    assert r.status_code == 403  # env-defined admin


async def test_admin_user_endpoints_require_admin(client):
    await _register_and_login(client, "plainuser", "password123")
    r = await client.post("/admin/api/users", json={"username": "x1234", "password": "password123"})
    assert r.status_code == 403


async def test_result_viewer_pages_are_branded(client, monkeypatch):
    monkeypatch.setattr(settings, "app_name", "Acme Threat Lab")
    for path in ("/public/r/some-id", "/feed/r/some-id"):
        r = await client.get(path)
        assert r.status_code == 200
        assert "{{" not in r.text and "ACME<em>THREATLAB</em>" in r.text, path
        assert r.headers["x-robots-tag"].startswith("noindex")


async def test_case_graph_route_is_registered(client):
    await _register_and_login(client, "grapher", "password123")
    r = await client.get("/cases/no-such-case/graph")
    assert r.status_code == 404
    assert (
        r.json()["detail"] == "No results found for this case"
    )  # handler reached, not a missing route


async def test_case_graph_returns_nodes(client):
    from app.main import _stores

    await _register_and_login(client, "grapher2", "password123")
    uid = auth_module._username_index["grapher2"]
    _stores[uid] = {
        "r1": {
            "_id": "r1",
            "kind": "domain",
            "target": "example.com",
            "case_id": "c1",
            "dns": {"A": ["93.184.216.34"], "NS": ["ns1.example.com"]},
            "final_status": 200,
        }
    }
    r = await client.get("/cases/c1/graph")
    assert r.status_code == 200
    ids = {n["id"] for n in r.json()["nodes"]}
    assert "r1" in ids and "ip_93.184.216.34" in ids
    _stores.pop(uid, None)


# ── API keys and /api/v1 ──────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_api_keys(tmp_path, monkeypatch):
    from app import apikeys

    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    apikeys._keys.clear()
    apikeys._hash_index.clear()
    yield
    apikeys._keys.clear()
    apikeys._hash_index.clear()


async def test_api_key_lifecycle(client):
    await _register_and_login(client, "keyuser", "password123")
    r = await client.post("/auth/api-keys", json={"name": "SOAR"})
    assert r.status_code == 201
    body = r.json()
    assert body["key"].startswith("hbg_") and body["prefix"] == body["key"][:12]
    key = body["key"]
    # listing never returns the secret
    r = await client.get("/auth/api-keys")
    assert r.status_code == 200 and "key" not in r.json()[0] and r.json()[0]["name"] == "SOAR"
    # the key authenticates without a cookie, on both header styles and on /api/v1
    anon = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    r = await anon.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200 and r.json()["username"] == "keyuser"
    r = await anon.get("/api/v1/store", headers={"X-API-Key": key})
    assert r.status_code == 200
    r = await anon.get("/store", headers={"X-API-Key": key})
    assert r.status_code == 200
    r = await anon.get("/api/v1/auth/me", headers={"Authorization": "Bearer hbg_wrong"})
    assert r.status_code == 401
    # revoke
    r = await client.delete(f"/auth/api-keys/{body['id']}")
    assert r.status_code == 200
    r = await anon.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 401
    await anon.aclose()


async def test_api_key_cannot_be_revoked_by_another_user(client):
    await _register_and_login(client, "owner", "password123")
    kid = (await client.post("/auth/api-keys", json={"name": "k"})).json()["id"]
    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await other.post(
        "/auth/register",
        json={"username": "intruder", "password": "password123", "invite_code": _INVITE},
    )
    await other.post("/auth/login", json={"username": "intruder", "password": "password123"})
    r = await other.delete(f"/auth/api-keys/{kid}")
    assert r.status_code == 404
    await other.aclose()


async def test_admin_can_revoke_all_keys_and_delete_cleans_up(client, monkeypatch):
    from app import apikeys

    await _login_as_admin(client, monkeypatch, "keyadmin")
    uid = (
        await client.post(
            "/admin/api/users", json={"username": "victim2", "password": "victim2-pass"}
        )
    ).json()["id"]
    await apikeys.create(uid, "a")
    await apikeys.create(uid, "b")
    r = await client.get(f"/admin/api/users/{uid}/api-keys")
    assert len(r.json()) == 2
    r = await client.delete(f"/admin/api/users/{uid}/api-keys")
    assert r.json()["revoked"] == 2
    await apikeys.create(uid, "c")
    await client.delete(f"/admin/api/users/{uid}")
    assert apikeys.keys_for_user(uid) == []


async def test_api_docs_for_signed_in_users_only(client):
    r = await client.get("/api/docs")
    assert r.status_code == 401
    await _register_and_login(client, "docuser", "password123")
    r = await client.get("/api/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert all(p.startswith("/api/v1/") for p in paths)
    assert "/api/v1/analyse/domain" in paths and "/api/v1/auth/api-keys" in paths
    assert "ApiKeyBearer" in r.json()["components"]["securitySchemes"]
    r = await client.get("/api/docs")
    assert r.status_code == 200 and "swagger-ui" in r.text


async def test_api_key_requests_are_audited(client, caplog):
    import logging

    await _register_and_login(client, "audited", "password123")
    key = (await client.post("/auth/api-keys", json={"name": "audit"})).json()["key"]
    anon = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    with caplog.at_level(logging.INFO, logger="app.auth"):
        await anon.get("/api/v1/store", headers={"Authorization": f"Bearer {key}"})
        await anon.get("/api/v1/store", headers={"Authorization": "Bearer hbg_bad"})
    await anon.aclose()
    msgs = [r.getMessage() for r in caplog.records]
    assert any(
        m.startswith("API_KEY user=audited key=hbg_") and "GET /api/v1/store" in m for m in msgs
    )
    assert any(m.startswith("API_KEY_REJECTED") for m in msgs)


def test_refetch_proxy_follows_scan_mode():
    from app.routes.extraction import _proxy_for

    assert _proxy_for({"target": "example.com"}) is None
    assert _proxy_for({"target": "abc.onion"}) == settings.tor_proxy
    assert _proxy_for({"target": "example.com", "via_tor": True}) == settings.tor_proxy


# ── Case export (JSON / CSV / STIX / MISP) ────────────────────────────────────


async def _seed_case(client, name="exporter"):
    from app.main import _stores

    await _register_and_login(client, name, "password123")
    uid = auth_module._username_index[name]
    cid = (await client.post("/cases", json={"name": "Phish wave"})).json()["id"]
    _stores[uid] = {
        "d1": {
            "_id": "d1",
            "kind": "domain",
            "target": "login-example.com",
            "case_id": cid,
            "scan_url": "https://login-example.com/",
            "final_url": "https://cdn.login-example.com/x?a=1",
            "dns": {"A": ["93.184.216.34"], "NS": ["ns1.example.net"]},
            "root_files": [
                {
                    "path": "/gate.php",
                    "url": "https://login-example.com/gate.php",
                    "status_code": 200,
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                }
            ],
            "whois": {"emails": ["abuse@registrar.example"]},
            "efi": {"emails": ["drop@evil.example"]},
            "certs": [
                {"common_name": "login-example.com", "issuer": "R3", "san": ["login-example.com"]}
            ],
        },
        "i1": {
            "_id": "i1",
            "kind": "ip",
            "target": "203.0.113.9",
            "case_id": cid,
            "resolved_from": "c2.example",
        },
    }
    return cid, uid


async def test_case_export_json_csv(client):
    from app.main import _stores

    cid, uid = await _seed_case(client)
    r = await client.get(f"/cases/{cid}/export")
    assert r.status_code == 200
    body = r.json()
    domains = {d["value"] for d in body["domains"]}
    assert {"login-example.com", "cdn.login-example.com"} <= domains
    assert {i["value"] for i in body["ips"]} == {"93.184.216.34", "203.0.113.9"}
    assert body["hashes"][0]["value"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert {e["value"] for e in body["emails"]} == {"abuse@registrar.example", "drop@evil.example"}
    assert body["dns"]["login-example.com"]["A"] == ["93.184.216.34"]
    assert len(body["results"]) == 2 and body["case"]["name"] == "Phish wave"
    r = await client.get(f"/cases/{cid}/export?format=csv")
    assert r.status_code == 200 and r.text.startswith("type,value,sources")
    assert "ip,203.0.113.9,c2.example" in r.text
    _stores.pop(uid, None)


async def test_case_export_stix_and_misp(client):
    from app.main import _stores

    cid, uid = await _seed_case(client, "exporter2")
    r = await client.get(f"/cases/{cid}/export?format=stix")
    bundle = r.json()
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types and "report" in types
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    patterns = {o["pattern"] for o in indicators}
    assert "[domain-name:value = 'login-example.com']" in patterns
    assert "[ipv4-addr:value = '203.0.113.9']" in patterns
    assert "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']" in patterns
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert set(report["object_refs"]) == {o["id"] for o in indicators}
    again = await client.get(f"/cases/{cid}/export?format=stix")
    assert {o["id"] for o in again.json()["objects"] if o["type"] == "indicator"} == {
        o["id"] for o in indicators
    }
    r = await client.get(f"/cases/{cid}/export?format=misp")
    ev = r.json()["Event"]
    attr = {(a["type"], a["value"]) for a in ev["Attribute"]}
    assert ("domain", "login-example.com") in attr and ("ip-dst", "203.0.113.9") in attr
    assert ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709") in attr
    assert ev["info"].endswith("Phish wave")
    r = await client.get(f"/cases/{cid}/export?format=xml")
    assert r.status_code == 422
    r = await client.get("/cases/nope/export")
    assert r.status_code == 404
    _stores.pop(uid, None)
