from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

log = logging.getLogger(__name__)

_CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
_CRTSH = "https://crt.sh"

# Strip www/www2/m prefixes so www.example.com and example.com always hit the same CT data
_WWW_PREFIX = re.compile(r"^(?:www\d*|m)\.", re.IGNORECASE)


def _apex(domain: str) -> str:
    """Return the apex domain, stripping common www/m prefixes."""
    return _WWW_PREFIX.sub("", domain.lower().strip())


# ── Per-source parsers ────────────────────────────────────────────────────────


def _parse_certspotter(raw: list[dict]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in raw:
        dns_names: list[str] = c.get("dns_names") or []
        issuer = c.get("issuer", {})
        out.append(
            {
                "id": c.get("id"),
                "common_name": dns_names[0] if dns_names else None,
                "issuer": issuer.get("name") if isinstance(issuer, dict) else str(issuer),
                "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "san": dns_names,
            }
        )
    return out


def _parse_crtsh(raw: list[dict]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in raw:
        out.append(
            {
                "id": c.get("id"),
                "common_name": c.get("common_name"),
                "issuer": c.get("issuer_name"),
                "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "san": [s for s in c.get("name_value", "").split("\n") if s],
            }
        )
    return out


# ── Per-source fetchers ───────────────────────────────────────────────────────


async def _fetch_certspotter(domain: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Paginate certspotter until exhausted or 500 certs collected."""
    results: list[dict[str, Any]] = []
    after: str | None = None
    root = _apex(domain)
    while len(results) < 500:
        params: dict[str, str] = {
            "domain": root,
            "include_subdomains": "true",
            "expand": "dns_names",
            "limit": "100",
        }
        if after:
            params["after"] = after
        try:
            resp = await client.get(
                _CERTSPOTTER, params=params, headers={"Accept": "application/json"}, timeout=15
            )
            if resp.status_code == 429:
                log.warning("certspotter: rate-limited for %s — stopping pagination", domain)
                break
            if resp.status_code != 200:
                log.warning("certspotter: HTTP %s for %s", resp.status_code, domain)
                break
            page = _parse_certspotter(resp.json())
            if not page:
                break
            results.extend(page)
            if len(page) < 100:
                break  # last page
            after = str(page[-1]["id"])
        except Exception as exc:
            log.warning("certspotter failed for %s: %s", domain, exc)
            break
    log.debug("certspotter: %d certs for %s", len(results), root)
    return results


async def _fetch_crtsh(domain: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Query crt.sh for both subdomain certs (%.apex) and root-domain certs (apex)."""
    root = _apex(domain)
    results: list[dict[str, Any]] = []
    # Two passes: wildcard/subdomains then exact root — catches all cert types
    for q in (f"%.{root}", root):
        try:
            resp = await client.get(
                _CRTSH,
                params={"q": q, "output": "json"},
                headers={"Accept": "application/json"},
                timeout=20,
            )
            if resp.status_code != 200:
                log.warning("crt.sh: HTTP %s for %s", resp.status_code, q)
                continue
            results.extend(_parse_crtsh(resp.json()))
        except Exception as exc:
            log.warning("crt.sh failed for %s: %s", q, exc)
    log.debug("crt.sh: %d certs for %s", len(results), root)
    return results


# ── Public entry point ────────────────────────────────────────────────────────


async def search(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh and certspotter in parallel, merge and deduplicate.

    crt.sh has no rate limit and covers the bulk of results.
    certspotter queries CT logs directly and is more reliable when crt.sh is down.
    Running both in parallel maximises completeness with no extra latency cost.
    """
    async with httpx.AsyncClient(follow_redirects=True) as client:
        crtsh_task = asyncio.create_task(_fetch_crtsh(domain, client))
        certspotter_task = asyncio.create_task(_fetch_certspotter(domain, client))
        crtsh_res, certspotter_res = await asyncio.gather(
            crtsh_task, certspotter_task, return_exceptions=True
        )

    crtsh_certs = crtsh_res if isinstance(crtsh_res, list) else []
    certspotter_certs = certspotter_res if isinstance(certspotter_res, list) else []

    # Merge: crt.sh first (usually more results), then certspotter extras
    seen: set[tuple] = set()
    merged: list[dict[str, Any]] = []
    for cert in crtsh_certs + certspotter_certs:
        key = (cert.get("common_name"), cert.get("not_after"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(cert)

    log.info(
        "cert search %s (apex: %s): %d crt.sh + %d certspotter → %d unique",
        domain,
        _apex(domain),
        len(crtsh_certs),
        len(certspotter_certs),
        len(merged),
    )
    return merged
