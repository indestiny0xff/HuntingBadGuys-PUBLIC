"""Tests for the BGP / HE.net service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import ASNInfo, BGPInfo, PrefixInfo
from app.services.bgp_svc import (
    _asn_from_rdap,
    _fetch_he_tabs,
    _is_public,
    _prefix_from_bgpview,
    lookup,
)

# ── _is_public ────────────────────────────────────────────────────────────────


def test_is_public_global_ip():
    assert _is_public("8.8.8.8") is True
    assert _is_public("1.1.1.1") is True


def test_is_public_private_rfc1918():
    assert _is_public("192.168.1.1") is False
    assert _is_public("10.0.0.1") is False
    assert _is_public("172.16.0.1") is False


def test_is_public_loopback():
    assert _is_public("127.0.0.1") is False


def test_is_public_link_local():
    assert _is_public("169.254.0.1") is False


def test_is_public_invalid_string():
    assert _is_public("not-an-ip") is False
    assert _is_public("") is False


def test_is_public_ipv6_global():
    assert _is_public("2001:4860:4860::8888") is True


def test_is_public_ipv6_loopback():
    assert _is_public("::1") is False


# ── _asn_from_rdap ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_asn_from_rdap_success():
    rdap_data = {
        "asn": "15133",
        "asn_cidr": "93.184.216.0/24",
        "asn_country_code": "US",
        "asn_date": "2007-03-19",
        "asn_description": "EDGECAST, US",
        "asn_registry": "arin",
    }
    with patch("app.services.bgp_svc._ipwhois_sync", return_value=rdap_data):
        result = await _asn_from_rdap("93.184.216.34")

    assert result.asn == "AS15133"
    assert result.asn_cidr == "93.184.216.0/24"
    assert result.asn_country_code == "US"
    assert result.asn_description == "EDGECAST, US"


@pytest.mark.asyncio
async def test_asn_from_rdap_empty_on_failure():
    with patch("app.services.bgp_svc._ipwhois_sync", return_value={}):
        result = await _asn_from_rdap("8.8.8.8")

    assert result.asn is None
    assert result.asn_cidr is None


@pytest.mark.asyncio
async def test_asn_from_rdap_timeout_returns_empty():
    # If the underlying sync call raises (e.g. on timeout), we should get empty ASNInfo
    with patch("app.services.bgp_svc._ipwhois_sync", side_effect=Exception("simulated timeout")):
        result = await _asn_from_rdap("8.8.8.8")

    assert result.asn is None


# ── _prefix_from_bgpview ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prefix_from_bgpview_success():
    payload = {
        "data": {
            "prefixes": [
                {
                    "prefix": "8.8.8.0/24",
                    "name": "LVLT-GOGL-8-8-8",
                    "description": "Google LLC",
                    "country_code": "US",
                    "asns": [{"asn": 15169, "name": "GOOGLE", "description": "Google LLC"}],
                }
            ]
        }
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = payload

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.services.bgp_svc.httpx.AsyncClient", return_value=mock_client):
        result = await _prefix_from_bgpview("8.8.8.8")

    assert result.prefix == "8.8.8.0/24"
    assert result.name == "LVLT-GOGL-8-8-8"
    assert result.country_code == "US"
    assert len(result.asns) == 1
    assert result.asns[0]["asn"] == 15169


@pytest.mark.asyncio
async def test_prefix_from_bgpview_non_200_returns_empty():
    mock_resp = MagicMock()
    mock_resp.status_code = 503

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.services.bgp_svc.httpx.AsyncClient", return_value=mock_client):
        result = await _prefix_from_bgpview("8.8.8.8")

    assert result.prefix is None


@pytest.mark.asyncio
async def test_prefix_from_bgpview_empty_prefixes():
    payload = {"data": {"prefixes": []}}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = payload

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.services.bgp_svc.httpx.AsyncClient", return_value=mock_client):
        result = await _prefix_from_bgpview("8.8.8.8")

    assert result.prefix is None


@pytest.mark.asyncio
async def test_prefix_from_bgpview_network_error_returns_empty():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=Exception("connect failed"))

    with patch("app.services.bgp_svc.httpx.AsyncClient", return_value=mock_client):
        result = await _prefix_from_bgpview("8.8.8.8")

    assert result.prefix is None


# ── _fetch_he_tabs ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_he_tabs_success():
    # Simple test mocking the httpx client
    dns = [{"Hostname": "x.example.com", "IP": "1.2.3.4"}]
    search = [{"Prefix": "1.2.3.0/24", "Description": "Test", "Country": "US"}]

    html = """<div id="_dnsrecords"><table><tr><th>Hostname</th><th>IP</th></tr><tr><td>x.example.com</td><td>1.2.3.4</td></tr></table></div>
              <div id="_SearchTab"><table><tr><th>Prefix</th><th>Description</th><th>Country</th></tr><tr><td>1.2.3.0/24</td><td>Test</td><td>US</td></tr></table></div>"""

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("app.services.bgp_svc.httpx.AsyncClient", return_value=mock_client):
        dns_records, search_results = await _fetch_he_tabs("1.2.3.0/24")

    assert dns_records == dns
    assert search_results == search


# ── lookup ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_private_ip_returns_empty_bgpinfo():
    result = await lookup("192.168.1.1")
    assert isinstance(result, BGPInfo)
    assert result.asn is None
    assert result.prefix is None
    assert result.he_url is None
    assert result.he_dns_records == []
    assert result.he_search_results == []


@pytest.mark.asyncio
async def test_lookup_builds_he_url_from_prefix():
    asn = ASNInfo(asn="AS15169", asn_cidr=None)
    prefix = PrefixInfo(prefix="8.8.8.0/24")

    with (
        patch("app.services.bgp_svc._asn_from_rdap", return_value=asn),
        patch("app.services.bgp_svc._prefix_from_bgpview", return_value=prefix),
        patch("app.services.bgp_svc._fetch_he_tabs", return_value=([], [])),
    ):
        result = await lookup("8.8.8.8")

    assert result.he_url == "https://bgp.he.net/net/8.8.8.0/24#_dnsrecords"


@pytest.mark.asyncio
async def test_lookup_falls_back_to_asn_cidr_for_he_url():
    asn = ASNInfo(asn="AS15169", asn_cidr="8.8.8.0/24")
    prefix = PrefixInfo(prefix=None)  # no prefix from BGPView

    with (
        patch("app.services.bgp_svc._asn_from_rdap", return_value=asn),
        patch("app.services.bgp_svc._prefix_from_bgpview", return_value=prefix),
        patch("app.services.bgp_svc._fetch_he_tabs", return_value=([], [])),
    ):
        result = await lookup("8.8.8.8")

    assert result.he_url == "https://bgp.he.net/net/8.8.8.0/24#_dnsrecords"


@pytest.mark.asyncio
async def test_lookup_no_cidr_he_url_is_none():
    asn = ASNInfo(asn=None, asn_cidr=None)
    prefix = PrefixInfo(prefix=None)

    with (
        patch("app.services.bgp_svc._asn_from_rdap", return_value=asn),
        patch("app.services.bgp_svc._prefix_from_bgpview", return_value=prefix),
    ):
        result = await lookup("8.8.8.8")

    assert result.he_url is None


@pytest.mark.asyncio
async def test_lookup_calls_fetch_and_populates_he_data():
    asn = ASNInfo(asn="AS15169", asn_cidr=None)
    prefix = PrefixInfo(prefix="8.8.8.0/24")
    dns_rows = [{"Hostname": "dns.google", "IP": "8.8.8.8"}]
    search_rows = [{"Prefix": "8.8.8.0/24", "Description": "Google Public DNS"}]

    with (
        patch("app.services.bgp_svc._asn_from_rdap", return_value=asn),
        patch("app.services.bgp_svc._prefix_from_bgpview", return_value=prefix),
        patch(
            "app.services.bgp_svc._fetch_he_tabs", return_value=(dns_rows, search_rows)
        ) as mock_fetch,
    ):
        result = await lookup("8.8.8.8")

    mock_fetch.assert_called_once_with("8.8.8.0/24")
    assert result.he_dns_records == dns_rows
    assert result.he_search_results == search_rows


@pytest.mark.asyncio
async def test_lookup_without_cidr_skips_fetch():
    asn = ASNInfo(asn="AS15169", asn_cidr=None)
    prefix = PrefixInfo(prefix=None)

    with (
        patch("app.services.bgp_svc._asn_from_rdap", return_value=asn),
        patch("app.services.bgp_svc._prefix_from_bgpview", return_value=prefix),
        patch("app.services.bgp_svc._fetch_he_tabs") as mock_fetch,
    ):
        result = await lookup("8.8.8.8")

    mock_fetch.assert_not_called()
    assert result.he_dns_records == []
    assert result.he_search_results == []


@pytest.mark.asyncio
async def test_lookup_fetch_timeout_still_returns_result():
    asn = ASNInfo(asn="AS15169", asn_cidr=None)
    prefix = PrefixInfo(prefix="8.8.8.0/24")

    # Simulate _fetch_he_tabs itself raising TimeoutError (as asyncio.wait_for would)
    async def times_out(*_):
        raise TimeoutError()

    with (
        patch("app.services.bgp_svc._asn_from_rdap", return_value=asn),
        patch("app.services.bgp_svc._prefix_from_bgpview", return_value=prefix),
        patch("app.services.bgp_svc._fetch_he_tabs", side_effect=times_out),
    ):
        result = await lookup("8.8.8.8")

    # Should still return valid BGP info with empty HE data
    assert result.asn is not None
    assert result.prefix is not None
    assert result.he_dns_records == []
    assert result.he_search_results == []


# ── Query engine integration: BGP + HE fields ────────────────────────────────


def test_query_he_dns_records(ip_result):
    from app.query.engine import evaluate

    assert evaluate('bgp.he_dns_records.Hostname contains "in-addr.arpa"', ip_result)


def test_query_he_search_results(ip_result):
    from app.query.engine import evaluate

    assert evaluate('bgp.he_search_results.Description contains "Edgecast"', ip_result)


def test_query_he_fields_no_match(ip_result):
    from app.query.engine import evaluate

    assert not evaluate('bgp.he_dns_records.Hostname contains "nonexistent"', ip_result)
