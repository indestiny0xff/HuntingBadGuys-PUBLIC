"""Tests for the HTTP headers / redirect chain service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.headers_svc import fetch


def _mock_response(status: int, headers: dict, url: str) -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.headers = httpx.Headers(headers)
    r.url = httpx.URL(url)
    return r


@pytest.mark.asyncio
async def test_fetch_single_200():
    responses = [_mock_response(200, {"server": "nginx"}, "https://example.com")]

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=responses)

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("https://example.com")

    assert len(hops) == 1
    assert hops[0].status_code == 200
    assert hops[0].response_headers["server"] == "nginx"


@pytest.mark.asyncio
async def test_fetch_redirect_chain():
    r1 = _mock_response(301, {"location": "https://example.com/"}, "http://example.com")
    r2 = _mock_response(200, {"server": "cloudflare"}, "https://example.com/")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=[r1, r2])

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("http://example.com")

    assert len(hops) == 2
    assert hops[0].status_code == 301
    assert hops[1].status_code == 200
    assert hops[1].response_headers["server"] == "cloudflare"


@pytest.mark.asyncio
async def test_fetch_auto_prepends_https():
    r = _mock_response(200, {"server": "apache"}, "https://example.com")
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=r)

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("example.com")

    # Plain domain must start with http:// so the redirect chain (http→https) is captured
    called_url = mock_client.get.call_args[0][0]
    assert called_url.startswith("http://")


@pytest.mark.asyncio
async def test_fetch_plain_domain_captures_http_to_https_redirect():
    """Plain domain → http:// first, then follows 301 to https:// — full chain captured."""
    r1 = _mock_response(301, {"location": "https://example.com/"}, "http://example.com")
    r2 = _mock_response(200, {"server": "nginx"}, "https://example.com/")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=[r1, r2])

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("example.com")

    assert len(hops) == 2
    assert hops[0].url == "http://example.com"
    assert hops[0].status_code == 301
    assert hops[1].url == "https://example.com/"
    assert hops[1].status_code == 200


@pytest.mark.asyncio
async def test_fetch_network_error_returns_empty():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("https://unreachable.invalid")

    assert hops == []


@pytest.mark.asyncio
async def test_fetch_headers_lowercased():
    r = _mock_response(
        200, {"Content-Type": "text/html", "X-Frame-Options": "DENY"}, "https://x.com"
    )
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=r)

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("https://x.com")

    # httpx.Headers normalises to lowercase
    assert "content-type" in hops[0].response_headers


@pytest.mark.asyncio
async def test_fetch_308_redirect_no_loop():
    """308 Permanent Redirect must not loop; it should follow to the final URL."""
    r1 = _mock_response(308, {"location": "https://www.example.com/"}, "https://example.com")
    r2 = _mock_response(200, {"server": "nginx"}, "https://www.example.com/")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=[r1, r2])

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("https://example.com")

    assert len(hops) == 2
    assert hops[0].status_code == 308
    assert hops[1].status_code == 200
    assert hops[1].url == "https://www.example.com/"


@pytest.mark.asyncio
async def test_fetch_relative_location_uses_urljoin():
    """Relative redirect location must be resolved relative to the current URL."""
    r1 = _mock_response(301, {"location": "/new-path"}, "https://example.com/old")
    r2 = _mock_response(200, {"server": "apache"}, "https://example.com/new-path")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=[r1, r2])

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("https://example.com/old")

    assert len(hops) == 2
    assert hops[1].url == "https://example.com/new-path"


@pytest.mark.asyncio
async def test_fetch_redirect_loop_stops():
    """Visiting the same URL twice must stop the loop (deduplication via seen set)."""
    r_loop = _mock_response(308, {"location": "https://example.com/"}, "https://example.com/")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=r_loop)

    with (
        patch("app.services.headers_svc.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.headers_svc._tls_info", AsyncMock(return_value=None)),
    ):
        hops = await fetch("https://example.com/")

    # First request records the hop, second is the same URL → break
    assert len(hops) == 1
