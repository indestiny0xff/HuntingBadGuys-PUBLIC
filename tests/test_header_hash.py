"""Tests for stable header hashing — volatile headers must not affect the fingerprint."""

from __future__ import annotations

from app.main import _VOLATILE_HEADERS, _stable_headers_hash


def test_hash_is_none_when_only_volatile_headers():
    volatile_only = {
        "date": "Mon, 01 Jan 2024 00:00:00 GMT",
        "set-cookie": "session=abc123; HttpOnly",
        "cf-ray": "7a1b2c3d4e5f-LHR",
    }
    assert _stable_headers_hash(volatile_only) is None


def test_hash_stable_across_volatile_changes():
    stable_headers = {"server": "nginx/1.24", "content-type": "text/html; charset=utf-8"}

    headers_a = {**stable_headers, "date": "Mon, 01 Jan 2024 00:00:00 GMT", "cf-ray": "aaa-LHR"}
    headers_b = {**stable_headers, "date": "Tue, 02 Jan 2024 12:00:00 GMT", "cf-ray": "bbb-AMS"}

    assert _stable_headers_hash(headers_a) == _stable_headers_hash(headers_b)


def test_hash_changes_when_stable_header_changes():
    base = {"date": "Mon, 01 Jan 2024 00:00:00 GMT"}

    h1 = {**base, "server": "nginx/1.24"}
    h2 = {**base, "server": "apache/2.4"}

    assert _stable_headers_hash(h1) != _stable_headers_hash(h2)


def test_hash_is_hex_string():
    headers = {"server": "nginx", "x-frame-options": "DENY"}
    result = _stable_headers_hash(headers)
    assert result is not None
    assert len(result) == 64  # sha256 hex digest
    assert all(c in "0123456789abcdef" for c in result)


def test_all_volatile_headers_excluded():
    """Every known volatile header must appear in _VOLATILE_HEADERS."""
    expected_volatile = {
        "date",
        "set-cookie",
        "cf-ray",
        "x-request-id",
        "x-amz-request-id",
        "x-cache",
        "age",
        "via",
    }
    for h in expected_volatile:
        assert h in _VOLATILE_HEADERS, f"Expected {h!r} in _VOLATILE_HEADERS"


def test_empty_headers_returns_none():
    assert _stable_headers_hash({}) is None


def test_hash_is_deterministic():
    headers = {"server": "cloudflare", "content-security-policy": "default-src 'self'"}
    assert _stable_headers_hash(headers) == _stable_headers_hash(headers)


def test_hash_order_independent():
    """Header dict ordering must not affect the fingerprint."""
    h1 = {"server": "nginx", "x-powered-by": "PHP/8"}
    h2 = {"x-powered-by": "PHP/8", "server": "nginx"}
    assert _stable_headers_hash(h1) == _stable_headers_hash(h2)
