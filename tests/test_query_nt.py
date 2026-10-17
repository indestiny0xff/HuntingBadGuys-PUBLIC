"""Tests for query engine filtering on NT (Network Traffic) fields."""

from __future__ import annotations

import pytest

from app.query.engine import evaluate, flatten

# ── Fixture ───────────────────────────────────────────────────────────────────


@pytest.fixture
def nt_result():
    """Domain result with a rich NT block covering all sub-structures."""
    return {
        "_id": "nt-test-id",
        "target": "evil.com",
        "kind": "domain",
        "final_status": 200,
        "final_url": "https://evil.com/",
        "final_headers": {"server": "nginx"},
        "dns": None,
        "whois": None,
        "chain": [],
        "root_files": [],
        "crawled_files": [],
        "screenshot": None,
        "screenshot_phash": None,
        "certs": [],
        "geo_ips": [],
        "errors": {},
        "nt": {
            "dynamic": True,
            "fetch_calls": [
                {"url": "https://api.tracker.com/collect", "method": "POST"},
                {"url": "https://cdn.evil.com/script.js", "method": "GET"},
            ],
            "xhr_calls": [
                {"url": "https://track.evil.com/pixel", "method": "GET"},
            ],
            "other_calls": [
                {
                    "url": "https://cdn.example.com/lib.js",
                    "method": "GET",
                    "resource_type": "script",
                },
            ],
            "websockets": [
                "wss://ws.evil.com/socket",
                "ws://chat.example.com/",
            ],
            "axios_calls": [
                {"url": "https://api.evil.com/data", "method": "POST"},
            ],
            "jquery_calls": [
                {"url": "https://ajax.evil.com/endpoint", "method": "GET"},
            ],
            "php_http": [
                {"url": "https://c2.evil.com/gate.php", "fn": "file_get_contents"},
            ],
            "form_actions": [
                {"action": "/submit_form.php", "method": "POST"},
                {"action": "https://exfil.evil.com/collect", "method": "GET"},
            ],
        },
    }


@pytest.fixture
def nt_result_empty_nt(nt_result):
    r = dict(nt_result)
    r["nt"] = {}
    return r


@pytest.fixture
def nt_result_no_nt(nt_result):
    r = dict(nt_result)
    r["nt"] = None
    return r


# ── flatten sanity ────────────────────────────────────────────────────────────


def test_flatten_nt_fetch_calls_url(nt_result):
    flat = flatten(nt_result)
    assert "nt.fetch_calls.url" in flat
    urls = flat["nt.fetch_calls.url"]
    urls = [urls] if isinstance(urls, str) else urls
    assert "https://api.tracker.com/collect" in urls
    assert "https://cdn.evil.com/script.js" in urls


def test_flatten_nt_fetch_calls_method(nt_result):
    flat = flatten(nt_result)
    methods = flat["nt.fetch_calls.method"]
    methods = [methods] if isinstance(methods, str) else methods
    assert "POST" in methods
    assert "GET" in methods


def test_flatten_nt_websockets(nt_result):
    flat = flatten(nt_result)
    ws = flat["nt.websockets"]
    assert isinstance(ws, list)
    assert "wss://ws.evil.com/socket" in ws


def test_flatten_nt_form_actions_action(nt_result):
    flat = flatten(nt_result)
    actions = flat["nt.form_actions.action"]
    actions = [actions] if isinstance(actions, str) else actions
    assert "/submit_form.php" in actions
    assert "https://exfil.evil.com/collect" in actions


def test_flatten_nt_php_http_url(nt_result):
    flat = flatten(nt_result)
    assert "nt.php_http.url" in flat
    urls = flat["nt.php_http.url"]
    urls = [urls] if isinstance(urls, str) else urls
    assert "https://c2.evil.com/gate.php" in urls


# ── exists / not exists ───────────────────────────────────────────────────────


def test_nt_exists(nt_result):
    assert evaluate("nt exists", nt_result)


def test_nt_not_exists_when_none(nt_result_no_nt):
    assert evaluate("nt not exists", nt_result_no_nt)


def test_nt_not_exists_when_empty(nt_result_empty_nt):
    assert evaluate("nt not exists", nt_result_empty_nt)


def test_nt_fetch_calls_exists(nt_result):
    assert evaluate("nt.fetch_calls exists", nt_result)


def test_nt_websockets_exists(nt_result):
    assert evaluate("nt.websockets exists", nt_result)


def test_nt_axios_calls_exists(nt_result):
    assert evaluate("nt.axios_calls exists", nt_result)


def test_nt_form_actions_exists(nt_result):
    assert evaluate("nt.form_actions exists", nt_result)


def test_nt_php_http_exists(nt_result):
    assert evaluate("nt.php_http exists", nt_result)


# ── fetch_calls ───────────────────────────────────────────────────────────────


def test_nt_fetch_url_contains(nt_result):
    assert evaluate('nt.fetch_calls.url contains "tracker"', nt_result)


def test_nt_fetch_url_contains_cdn(nt_result):
    assert evaluate('nt.fetch_calls.url contains "cdn"', nt_result)


def test_nt_fetch_url_no_match(nt_result):
    assert not evaluate('nt.fetch_calls.url contains "notpresent.xyz"', nt_result)


def test_nt_fetch_url_exact(nt_result):
    assert evaluate('nt.fetch_calls.url == "https://api.tracker.com/collect"', nt_result)


def test_nt_fetch_method_post(nt_result):
    assert evaluate('nt.fetch_calls.method == "POST"', nt_result)


def test_nt_fetch_method_get(nt_result):
    assert evaluate('nt.fetch_calls.method == "GET"', nt_result)


def test_nt_fetch_method_no_match(nt_result):
    assert not evaluate('nt.fetch_calls.method == "DELETE"', nt_result)


def test_nt_fetch_url_startswith(nt_result):
    assert evaluate('nt.fetch_calls.url startswith "https://api"', nt_result)


def test_nt_fetch_url_endswith(nt_result):
    assert evaluate('nt.fetch_calls.url endswith "collect"', nt_result)


def test_nt_fetch_url_regex(nt_result):
    assert evaluate(r'nt.fetch_calls.url ~= "tracker\\.com"', nt_result)


# ── xhr_calls ─────────────────────────────────────────────────────────────────


def test_nt_xhr_url_contains(nt_result):
    assert evaluate('nt.xhr_calls.url contains "pixel"', nt_result)


def test_nt_xhr_url_no_match(nt_result):
    assert not evaluate('nt.xhr_calls.url contains "notpresent.xyz"', nt_result)


def test_nt_xhr_method_get(nt_result):
    assert evaluate('nt.xhr_calls.method == "GET"', nt_result)


def test_nt_xhr_url_exact(nt_result):
    assert evaluate('nt.xhr_calls.url == "https://track.evil.com/pixel"', nt_result)


# ── other_calls ───────────────────────────────────────────────────────────────


def test_nt_other_url_contains(nt_result):
    assert evaluate('nt.other_calls.url contains "cdn.example"', nt_result)


def test_nt_other_url_no_match(nt_result):
    assert not evaluate('nt.other_calls.url contains "nope.xyz"', nt_result)


# ── websockets ────────────────────────────────────────────────────────────────


def test_nt_websockets_contains_wss(nt_result):
    assert evaluate('nt.websockets contains "wss://"', nt_result)


def test_nt_websockets_contains_ws(nt_result):
    assert evaluate('nt.websockets contains "ws://"', nt_result)


def test_nt_websockets_contains_domain(nt_result):
    assert evaluate('nt.websockets contains "ws.evil.com"', nt_result)


def test_nt_websockets_no_match(nt_result):
    assert not evaluate('nt.websockets contains "nope.xyz"', nt_result)


def test_nt_websockets_exact(nt_result):
    assert evaluate('nt.websockets == "wss://ws.evil.com/socket"', nt_result)


# ── axios_calls ───────────────────────────────────────────────────────────────


def test_nt_axios_url_contains(nt_result):
    assert evaluate('nt.axios_calls.url contains "api.evil"', nt_result)


def test_nt_axios_method_post(nt_result):
    assert evaluate('nt.axios_calls.method == "POST"', nt_result)


def test_nt_axios_url_no_match(nt_result):
    assert not evaluate('nt.axios_calls.url contains "nope.xyz"', nt_result)


# ── jquery_calls ──────────────────────────────────────────────────────────────


def test_nt_jquery_url_contains(nt_result):
    assert evaluate('nt.jquery_calls.url contains "ajax.evil"', nt_result)


def test_nt_jquery_method_get(nt_result):
    assert evaluate('nt.jquery_calls.method == "GET"', nt_result)


def test_nt_jquery_url_no_match(nt_result):
    assert not evaluate('nt.jquery_calls.url contains "nope.xyz"', nt_result)


# ── php_http ──────────────────────────────────────────────────────────────────


def test_nt_php_http_url_contains(nt_result):
    assert evaluate('nt.php_http.url contains "c2.evil"', nt_result)


def test_nt_php_http_url_contains_gate(nt_result):
    assert evaluate('nt.php_http.url contains "gate.php"', nt_result)


def test_nt_php_http_url_no_match(nt_result):
    assert not evaluate('nt.php_http.url contains "nope.xyz"', nt_result)


def test_nt_php_http_url_exact(nt_result):
    assert evaluate('nt.php_http.url == "https://c2.evil.com/gate.php"', nt_result)


# ── form_actions ──────────────────────────────────────────────────────────────


def test_nt_form_action_contains_submit(nt_result):
    assert evaluate('nt.form_actions.action contains "submit"', nt_result)


def test_nt_form_action_contains_exfil(nt_result):
    assert evaluate('nt.form_actions.action contains "exfil"', nt_result)


def test_nt_form_action_no_match(nt_result):
    assert not evaluate('nt.form_actions.action contains "nope.xyz"', nt_result)


def test_nt_form_method_post(nt_result):
    assert evaluate('nt.form_actions.method == "POST"', nt_result)


def test_nt_form_action_exact(nt_result):
    assert evaluate('nt.form_actions.action == "/submit_form.php"', nt_result)


# ── compound queries ──────────────────────────────────────────────────────────


def test_nt_fetch_post_and_tracker(nt_result):
    assert evaluate(
        'nt.fetch_calls.method == "POST" AND nt.fetch_calls.url contains "tracker"', nt_result
    )


def test_nt_websockets_or_fetch(nt_result):
    assert evaluate(
        'nt.websockets contains "wss://" OR nt.fetch_calls.url contains "nope"', nt_result
    )


def test_nt_combined_with_status(nt_result):
    assert evaluate('final_status == 200 AND nt.fetch_calls.url contains "tracker"', nt_result)


def test_nt_not_fetch(nt_result):
    assert evaluate('NOT nt.fetch_calls.url contains "nope.xyz"', nt_result)


def test_nt_fetch_post_no_match_when_no_nt(nt_result_no_nt):
    assert not evaluate('nt.fetch_calls.method == "POST"', nt_result_no_nt)


def test_nt_websockets_no_match_when_no_nt(nt_result_no_nt):
    assert not evaluate('nt.websockets contains "wss://"', nt_result_no_nt)
