"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from app.config import settings

# Tests exercise self-registration, so give the suite a known invite code and
# make sure no operator-specific settings leak in from a local .env file.
settings.invite_code = "test-invite-code"
settings.oidc_only = False
settings.oidc_issuer = ""
settings.oidc_client_id = ""
settings.oidc_allowed_domains = ""
settings.production = False
settings.db_dsn = ""
settings.smtp_host = ""
settings.access_request_email = ""
settings.admin_user = ""
settings.admin_password = ""
settings.admin_usernames = ""
settings.app_name = "Hunting Bad Guys"
settings.theme = "purple"
settings.public_url = "http://test"
settings.allow_private_targets = False


@pytest.fixture(autouse=True)
def reset_module_singletons():
    """Reset all module-level singletons between tests.

    Several services keep module-level state that accumulates across tests:
    - SecurityMiddleware: per-IP rate-limit hit counts
    - bgp_svc: HE.net CIDR scrape cache (avoids re-scraping same prefix)

    Without this reset the rate limiter returns 429 for unrelated tests after
    ~20 auth requests, and the CIDR cache causes mocked _fetch_he_tabs calls
    to be skipped (cache hit → mock never called → assert_called_once fails).
    """
    from app.middleware import _rl_api, _rl_auth
    from app.services import bgp_svc

    _rl_auth._hits.clear()
    _rl_api._hits.clear()
    bgp_svc._he_cache.clear()
    yield
    _rl_auth._hits.clear()
    _rl_api._hits.clear()
    bgp_svc._he_cache.clear()


# ── Sample domain result (mirrors DomainResult.model_dump()) ─────────────────


@pytest.fixture
def domain_result() -> dict:
    return {
        "_id": "test-id-123",
        "target": "example.com",
        "kind": "domain",
        "final_status": 200,
        "final_url": "https://example.com/",
        "final_headers": {
            "server": "nginx/1.24",
            "content-type": "text/html; charset=utf-8",
            "x-powered-by": "PHP/8.2",
            "cf-ray": "abc123-CDG",
        },
        "dns": {
            "A": ["93.184.216.34", "93.184.216.35"],
            "AAAA": [],
            "MX": [
                {"priority": 10, "exchange": "mail.example.com"},
                {"priority": 20, "exchange": "mail2.example.com"},
            ],
            "TXT": ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "CNAME": [],
            "SOA": {
                "mname": "ns1.example.com",
                "rname": "hostmaster.example.com",
                "serial": 2024010101,
                "refresh": 3600,
                "retry": 900,
                "expire": 604800,
                "minimum": 300,
            },
        },
        "whois": {
            "domain_name": "example.com",
            "registrar": "ICANN",
            "creation_date": "1995-08-13T00:00:00",
            "expiration_date": "2025-08-13T00:00:00",
            "updated_date": "2023-08-13T00:00:00",
            "status": ["clienttransferprohibited"],
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "emails": ["abuse@example.com"],
            "raw": None,
        },
        "chain": [
            {
                "url": "http://example.com",
                "status_code": 301,
                "response_headers": {"location": "https://example.com/", "server": "nginx"},
                "tls": None,
            },
            {
                "url": "https://example.com/",
                "status_code": 200,
                "response_headers": {"server": "nginx/1.24", "content-type": "text/html"},
                "tls": {
                    "version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "subject": {"commonName": "example.com"},
                    "issuer": {"organizationName": "DigiCert"},
                    "not_before": "Jan  1 00:00:00 2024 GMT",
                    "not_after": "Jan  1 00:00:00 2025 GMT",
                    "san": ["example.com", "www.example.com"],
                },
            },
        ],
        "root_files": [
            {
                "path": "/robots.txt",
                "url": "https://example.com/robots.txt",
                "status_code": 200,
                "content_type": "text/plain",
                "size": 25,
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "minhash": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "minhash_bands": ["a1b2", "c3d4", "e5f6", "0718", "293a", "4b5c", "6d7e", "8f90"],
            },
            {
                "path": "/favicon.ico",
                "url": "https://example.com/favicon.ico",
                "status_code": 404,
                "content_type": None,
                "size": 0,
                "sha1": None,
                "minhash": None,
                "minhash_bands": [],
            },
        ],
        "geo_ips": [
            {
                "ip": "93.184.216.34",
                "country_iso": "US",
                "country_name": "United States",
                "city": "Norristown",
                "continent": "North America",
                "latitude": 40.1209,
                "longitude": -75.3397,
                "timezone": "America/New_York",
                "postal_code": "19401",
            },
            {
                "ip": "93.184.216.35",
                "country_iso": "DE",
                "country_name": "Germany",
                "city": "Frankfurt am Main",
                "continent": "Europe",
                "latitude": 50.1188,
                "longitude": 8.6843,
                "timezone": "Europe/Berlin",
                "postal_code": "60308",
            },
        ],
        "screenshot": None,
        "screenshot_phash": None,
        "certs": [
            {
                "id": 1001,
                "common_name": "example.com",
                "issuer": "DigiCert",
                "not_before": "2024-01-01",
                "not_after": "2025-01-01",
                "san": ["example.com", "www.example.com"],
            }
        ],
        "errors": {},
    }


@pytest.fixture
def ip_result() -> dict:
    return {
        "_id": "test-ip-id",
        "target": "93.184.216.34",
        "kind": "ip",
        "geo": {
            "country_iso": "US",
            "country_name": "United States",
            "city": "Norristown",
            "continent": "North America",
            "latitude": 40.1209,
            "longitude": -75.3397,
            "timezone": "America/New_York",
            "postal_code": "19401",
        },
        "bgp": {
            "asn": {
                "asn": "AS15133",
                "asn_cidr": "93.184.216.0/24",
                "asn_country_code": "US",
                "asn_date": "2007-03-19",
                "asn_description": "EDGECAST, US",
                "asn_registry": "arin",
            },
            "prefix": {
                "prefix": "93.184.216.0/24",
                "name": "EDGECAST-NETBLK-03",
                "description": "Edgecast Networks",
                "country_code": "US",
                "asns": [{"asn": 15133, "name": "EDGECAST"}],
            },
            "he_url": "https://bgp.he.net/net/93.184.216.0/24#_dnsrecords",
            "he_dns_records": [
                {"Hostname": "93.184.216.34.in-addr.arpa", "IP": "93.184.216.34"},
            ],
            "he_search_results": [
                {"Prefix": "93.184.216.0/24", "Description": "Edgecast Networks", "Country": "US"},
            ],
        },
        "errors": {},
    }
