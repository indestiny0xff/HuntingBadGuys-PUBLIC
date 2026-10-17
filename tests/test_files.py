"""Tests for the root-files fetching and hashing service."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.files_svc import _minhash, _minhash_bands, _sha1, fetch_all


def _mock_response(status: int, body: bytes, content_type: str = "text/plain") -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.content = body
    r.headers = httpx.Headers({"content-type": content_type})
    return r


# ── SHA-1 ─────────────────────────────────────────────────────────────────────


def test_sha1_known_value():
    assert _sha1(b"") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_sha1_content():
    data = b"Hello, phish hunter!"
    assert _sha1(data) == hashlib.sha1(data).hexdigest()


# ── MinHash ───────────────────────────────────────────────────────────────────


def test_minhash_returns_32_char_hex():
    mh = _minhash(b"Hello, world! This is a test of MinHash.")
    assert mh is not None
    assert len(mh) == 32
    assert all(c in "0123456789abcdef" for c in mh)


def test_minhash_same_content_same_hash():
    data = b"identical content for minhash test " * 10
    assert _minhash(data) == _minhash(data)


def test_minhash_different_content_different_hash():
    a = _minhash(b"robots.txt disallow admin path " * 20)
    b = _minhash(b"sitemap xml version url loc " * 20)
    assert a != b


def test_minhash_none_on_short_input():
    assert _minhash(b"") is None
    assert _minhash(b"ab") is None
    assert _minhash(b"abc") is None


def test_minhash_handles_exactly_4_bytes():
    result = _minhash(b"abcd")
    assert result is not None
    assert len(result) == 32


def test_minhash_caps_at_64kb():
    large = b"x" * (128 * 1024)
    small = b"x" * (64 * 1024)
    assert _minhash(large) == _minhash(small)


def test_minhash_similar_content_shares_band():
    """Two nearly-identical files must share at least one LSH band fingerprint.

    We use 1000 bytes of diverse content (all 256 byte values cycling) so the
    shingle set is large and unique. Adding one byte gives Jaccard ≈ 0.999,
    making band collision probability essentially 1.
    """
    base = bytes(i % 256 for i in range(1000))
    variant = base + b"\x00"  # single extra byte → only 1 new shingle
    bands_a = _minhash_bands(_minhash(base))
    bands_b = _minhash_bands(_minhash(variant))
    assert any(a == b for a, b in zip(bands_a, bands_b)), (
        "Nearly-identical content must share at least one LSH band"
    )


def test_minhash_unrelated_content_different_hash():
    """Completely different content must produce a different hash."""
    a = _minhash(b"robots.txt content allow all " * 30)
    b = _minhash(b"sitemap index urlset url loc " * 30)
    assert a != b


# ── MinHash bands ─────────────────────────────────────────────────────────────


def test_minhash_bands_length():
    mh = _minhash(b"test data for bands " * 10)
    assert mh is not None
    bands = _minhash_bands(mh)
    assert len(bands) == 8


def test_minhash_bands_cover_full_hash():
    mh = _minhash(b"test content " * 20)
    assert mh is not None
    bands = _minhash_bands(mh)
    assert "".join(bands) == mh


def test_minhash_bands_empty_on_wrong_length():
    assert _minhash_bands("short") == []
    assert _minhash_bands("") == []


def test_minhash_bands_same_content_same_bands():
    data = b"consistent content " * 15
    mh = _minhash(data)
    assert mh is not None
    assert _minhash_bands(mh) == _minhash_bands(mh)


# ── Fetch integration ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_all_200_hashes():
    body = b"User-agent: *\nDisallow: /admin"
    resp = _mock_response(200, body)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("app.services.files_svc.httpx.AsyncClient", return_value=mock_client):
        files = await fetch_all("https://example.com")

    found = [f for f in files if f.status_code == 200]
    assert len(found) > 0
    assert found[0].sha1 == hashlib.sha1(body).hexdigest()


@pytest.mark.asyncio
async def test_fetch_all_200_has_minhash():
    body = b"User-agent: *\nDisallow: /admin\n" * 5
    resp = _mock_response(200, body)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("app.services.files_svc.httpx.AsyncClient", return_value=mock_client):
        files = await fetch_all("https://example.com")

    found = [f for f in files if f.status_code == 200]
    assert len(found) > 0
    assert found[0].minhash is not None
    assert len(found[0].minhash_bands) == 8


@pytest.mark.asyncio
async def test_fetch_all_404_no_hash():
    resp = _mock_response(404, b"Not Found")
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("app.services.files_svc.httpx.AsyncClient", return_value=mock_client):
        files = await fetch_all("https://example.com")

    for f in files:
        assert f.sha1 is None
        assert f.minhash is None
        assert f.minhash_bands == []


@pytest.mark.asyncio
async def test_fetch_all_returns_all_configured_paths():
    resp = _mock_response(200, b"data " * 10)
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("app.services.files_svc.httpx.AsyncClient", return_value=mock_client):
        files = await fetch_all("https://example.com")

    from app.config import settings

    assert len(files) == len(settings.root_paths)


@pytest.mark.asyncio
async def test_fetch_network_error_returns_status_zero():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=Exception("connection refused"))

    with patch("app.services.files_svc.httpx.AsyncClient", return_value=mock_client):
        files = await fetch_all("https://unreachable.invalid")

    for f in files:
        assert f.status_code == 0
