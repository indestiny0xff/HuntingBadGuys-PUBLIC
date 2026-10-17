from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Any

import httpx
from ipwhois import IPWhois

from ..models import ASNInfo, BGPInfo, PrefixInfo

log = logging.getLogger(__name__)
_BGPVIEW = "https://api.bgpview.io"
_HE = "https://bgp.he.net"

_HE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _ipwhois_sync(ip: str) -> dict[str, Any]:
    try:
        return IPWhois(ip).lookup_rdap(depth=1)
    except Exception:
        return {}


async def _asn_from_rdap(ip: str) -> ASNInfo:
    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, _ipwhois_sync, ip),
            timeout=15.0,
        )
    except Exception:
        data = {}
    return ASNInfo(
        asn=f"AS{data['asn']}" if data.get("asn") else None,
        asn_cidr=data.get("asn_cidr"),
        asn_country_code=data.get("asn_country_code"),
        asn_date=data.get("asn_date"),
        asn_description=data.get("asn_description"),
        asn_registry=data.get("asn_registry"),
    )


async def _prefix_from_bgpview(ip: str) -> PrefixInfo:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{_BGPVIEW}/ip/{ip}")
        if resp.status_code != 200:
            return PrefixInfo()
        prefixes: list[dict] = resp.json().get("data", {}).get("prefixes", [])
        if not prefixes:
            return PrefixInfo()
        p = prefixes[0]  # most specific prefix first
        return PrefixInfo(
            prefix=p.get("prefix"),
            name=p.get("name"),
            description=p.get("description"),
            country_code=p.get("country_code"),
            asns=[
                {"asn": a.get("asn"), "name": a.get("name"), "description": a.get("description")}
                for a in p.get("asns", [])
            ],
        )
    except Exception as exc:
        log.warning("bgpview failed %s: %s", ip, exc)
        return PrefixInfo()


# ── Hurricane Electric scraping ───────────────────────────────────────────────


async def _fetch_he_tabs(cidr: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch bgp.he.net/net/<cidr> and extract tab tables using httpx."""
    url = f"{_HE}/net/{cidr}"
    dns_records: list[dict[str, Any]] = []
    search_results: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(headers=_HE_HEADERS, timeout=15) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                log.warning("HE.net responded %s for %s", resp.status_code, cidr)
                return [], []
            html = resp.text

            def parse_table(html_chunk: str) -> list[dict[str, Any]]:
                rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html_chunk, re.IGNORECASE | re.DOTALL)
                if not rows:
                    return []
                header_match = re.findall(
                    r"<t(?:h|d)[^>]*>(.*?)</t(?:h|d)>", rows[0], re.IGNORECASE | re.DOTALL
                )
                headers = [re.sub(r"<[^>]+>", "", h).strip() for h in header_match]
                if not headers:
                    return []
                out = []
                for row_html in rows[1:]:
                    cells_match = re.findall(
                        r"<td[^>]*>(.*?)</td>", row_html, re.IGNORECASE | re.DOTALL
                    )
                    if cells_match and len(cells_match) == len(headers):
                        cells = [re.sub(r"<[^>]+>", "", c).strip() for c in cells_match]
                        out.append(dict(zip(headers, cells)))
                return out

            dns_match = re.search(
                r"id=[\'\"]_?dnsrecords[\'\"][^>]*>(.*?)</table>", html, re.IGNORECASE | re.DOTALL
            )
            if dns_match:
                dns_records = parse_table(dns_match.group(1))

            search_match = re.search(
                r"id=[\'\"]_?[Ss]earch[^\"]*[\'\"][^>]*>(.*?)</table>",
                html,
                re.IGNORECASE | re.DOTALL,
            )
            if search_match:
                search_results = parse_table(search_match.group(1))

            if not search_results:
                # Fallback to the newer certs API if the table isn't statically present
                api_url = f"{_HE}/certs/api/ip-search?ip={cidr}"
                resp_cert = await client.get(api_url)
                if resp_cert.status_code == 200:
                    try:
                        data = resp_cert.json()
                        entries = data.get("entries", [])
                        for e in entries:
                            hostnames = e.get("hostnames", [])
                            search_results.append(
                                {"Domain": ", ".join(hostnames), "IP": e.get("ip", "")}
                            )
                    except Exception as e:
                        log.debug("Failed to parse cert API json: %s", e)

    except Exception as exc:
        log.warning("HE.net fetch failed for %s: %s", cidr, exc)

    return dns_records, search_results


# ── HE.net CIDR-level cache (avoids re-scraping the same prefix) ──────────────

_he_cache: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
_he_locks: dict[str, asyncio.Lock] = {}


async def _fetch_he_tabs_cached(
    cidr: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if cidr not in _he_locks:
        _he_locks[cidr] = asyncio.Lock()
    async with _he_locks[cidr]:
        if cidr in _he_cache:
            log.debug("HE.net cache hit for %s", cidr)
            return _he_cache[cidr]
        result = await asyncio.wait_for(_fetch_he_tabs(cidr), timeout=25.0)
        _he_cache[cidr] = result
        return result


# ── Public entry point ────────────────────────────────────────────────────────


async def lookup(ip: str, browser: Any = None) -> BGPInfo:
    if not _is_public(ip):
        return BGPInfo()

    asn_info, prefix_info = await asyncio.gather(_asn_from_rdap(ip), _prefix_from_bgpview(ip))

    # Build Hurricane Electric deep-link if we have a CIDR
    cidr = prefix_info.prefix or asn_info.asn_cidr
    he_url = f"{_HE}/net/{cidr}#_dnsrecords" if cidr else None

    # Optionally scrape HE.net tab data (cached per CIDR)
    he_dns_records: list[dict[str, Any]] = []
    he_search_results: list[dict[str, Any]] = []
    if cidr:
        try:
            he_dns_records, he_search_results = await _fetch_he_tabs_cached(cidr)
        except Exception as exc:
            log.warning("HE.net fetch timed out or failed for %s: %s", cidr, exc)

    return BGPInfo(
        asn=asn_info,
        prefix=prefix_info,
        he_url=he_url,
        he_dns_records=he_dns_records,
        he_search_results=he_search_results,
    )
