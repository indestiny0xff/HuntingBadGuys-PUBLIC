"""Domain / IP analysis pipeline and the host intelligence (HIG) jobs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from .. import db as _db_module
from ..auth import get_current_user
from ..browser import ensure_browser
from ..config import settings
from ..models import (
    DomainRequest,
    DomainResult,
    GeoIPEntry,
    GeoIPInfo,
    HIGInfo,
    HIGRequest,
    IPRequest,
    IPResult,
    UserInDB,
)
from ..security import is_safe_ip, is_safe_url, is_valid_ip, sanitize_for_log
from ..services import (
    bgp_svc,
    cert_svc,
    dns_svc,
    files_svc,
    geoip_svc,
    headers_svc,
    hig_svc,
    screenshot_svc,
    whois_svc,
)
from ..state import (
    _index_for,
    _store_for,
)

log = logging.getLogger(__name__)
router = APIRouter()

# ── Stable header fingerprinting ──────────────────────────────────────────────
# These headers change on every request and must be excluded from the hash so
# the fingerprint stays stable across re-scans of the same server.
_VOLATILE_HEADERS = frozenset(
    {
        "date",
        "set-cookie",
        "x-request-id",
        "x-correlation-id",
        "x-amz-request-id",
        "x-amz-cf-id",
        "cf-ray",
        "age",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-limit",
        "x-cache",
        "x-cache-hits",
        "x-timer",
        "x-served-by",
        "via",
        "x-edge-ip",
        "x-pull",
        "x-datacenter",
    }
)


def _stable_headers_hash(headers: dict[str, str]) -> str | None:
    """SHA-256 fingerprint of response headers, excluding volatile per-request values."""
    stable = {k: v for k, v in headers.items() if k not in _VOLATILE_HEADERS}
    if not stable:
        return None
    canonical = json.dumps(sorted(stable.items()), separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _random_ua() -> str | None:
    pool = [ua.strip() for ua in settings.user_agents.split("|") if ua.strip()]
    return random.choice(pool) if pool else None


def _parse_target(raw: str) -> tuple[str, str]:
    """Return (domain, scan_url). scan_url keeps the full path/query for chain + screenshot."""
    t = raw.strip()
    rest = t
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            rest = t[len(prefix) :]
            break
    domain = rest.split("/")[0].split("?")[0].split("#")[0]
    has_scheme = t.startswith("http://") or t.startswith("https://")
    scan_url = t if has_scheme else f"http://{t}"
    return domain, scan_url


async def _analyse_domain(raw: str, req: DomainRequest, browser: Any) -> DomainResult:
    domain, scan_url = _parse_target(raw)
    result = DomainResult(target=raw.strip(), scan_url=scan_url)

    # SSRF guard: resolve first and refuse private / internal destinations
    # before any request is made (the redirect chain re-checks every hop).
    if not await is_safe_url(scan_url):
        result.errors["ssrf"] = "Target resolves to a private/internal address, blocked"
        log.warning("SSRF_BLOCKED domain=%s", sanitize_for_log(domain))
        return result

    is_onion = domain.lower().endswith(".onion")
    # Route through Tor for .onion targets, or when the user opts into Random IP.
    tor_proxy = settings.tor_proxy if (is_onion or req.random_ip) else None
    result.via_tor = tor_proxy is not None
    ua = _random_ua() if req.random_ua else None
    # .onion services use HTTP (Tor provides end-to-end encryption at the circuit level)
    if is_onion and scan_url.startswith("https://"):
        scan_url = "http://" + scan_url[8:]
    domain_root_url = f"http://{domain}" if is_onion else f"https://{domain}"

    svc_tasks: dict[str, Any] = {
        "dns": dns_svc.resolve(domain),  # returns empty DNSRecords for .onion
        "chain": headers_svc.fetch(scan_url, proxy=tor_proxy, ua=ua),
    }
    # WHOIS and cert transparency don't apply to .onion hidden services
    if req.whois and not is_onion:
        svc_tasks["whois"] = whois_svc.lookup(domain)
    if req.root_files:
        svc_tasks["files"] = files_svc.fetch_all(domain_root_url, proxy=tor_proxy, ua=ua)
    if getattr(req, "crawled_files", False):
        # When the user submitted a deep URL (e.g. a download link) rather than
        # a bare domain, crawl from that specific URL so that the file is
        # captured directly.  For bare-domain targets, crawl from the root
        # (which ensures HTTPS and picks up standard files/links).
        _scan_parts = scan_url.split("/", 3)
        _has_deep_path = len(_scan_parts) > 3 and bool(_scan_parts[3].strip("/"))
        _crawl_base = scan_url if _has_deep_path else domain_root_url
        svc_tasks["crawled"] = files_svc.crawl_website(
            _crawl_base, proxy=tor_proxy, ua=ua, browser=browser
        )
    if req.certs and not is_onion:
        svc_tasks["certs"] = cert_svc.search(domain)

    gathered = await asyncio.gather(*svc_tasks.values(), return_exceptions=True)
    svc_results = dict(zip(svc_tasks.keys(), gathered))

    for key, val in svc_results.items():
        if isinstance(val, Exception):
            result.errors[key] = str(val)
            continue
        match key:
            case "dns":
                result.dns = val
            case "chain":
                result.chain = val
                if val:
                    last = val[-1]
                    result.final_status = last.status_code
                    result.final_url = last.url
                    result.final_headers = last.response_headers
                    if last.response_headers:
                        result.headers_hash = _stable_headers_hash(last.response_headers)
            case "whois":
                result.whois = val
            case "files":
                result.root_files = val
            case "crawled":
                result.crawled_files = val
            case "certs":
                result.certs = val

    if req.screenshot and result.final_status == 200:
        try:
            screenshot_url = result.final_url or scan_url
            if not await is_safe_url(screenshot_url):
                raise ValueError("final URL points to a private/internal address")
            b64, phash = await screenshot_svc.capture(browser, screenshot_url, proxy=tor_proxy)
            result.screenshot = b64
            result.screenshot_phash = phash
            if b64 is None:
                # capture() swallows its own exceptions — surface the miss so
                # it shows up in errors instead of failing silently
                result.errors["screenshot"] = "capture failed (see server logs)"
        except Exception as exc:
            result.errors["screenshot"] = str(exc)

    # A10 SSRF — abort if DNS resolved to a private/internal IP
    a_records: list[str] = result.dns.A if result.dns else []
    if a_records and not all(is_safe_ip(ip) for ip in a_records):
        result.errors["ssrf"] = "Target resolves to a private/internal IP address — blocked"
        log.warning("SSRF_BLOCKED domain=%s resolved_ips=%s", domain, a_records)
        return result

    # GeoIP — look up every A record (.onion has none)
    if a_records:
        try:
            geo_map = await geoip_svc.lookup_many(a_records)
            result.geo_ips = [GeoIPEntry(ip=ip, **geo) for ip, geo in geo_map.items()]
        except Exception as exc:
            result.errors["geoip"] = str(exc)

    return result


_MAX_IPS_PER_NAME = 8


async def _expand_ip_target(raw: str) -> list[tuple[str, str | None]]:
    """Turn one IP-mode target into (ip, resolved_from) pairs.

    A literal address maps to itself. A hostname is resolved (A then AAAA) and
    each address is scanned separately, tagged with the name it came from so
    the UI can show it. Unresolvable names yield a single error result.
    """
    target = raw.strip()
    for prefix in ("https://", "http://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix) :]
    target = target.split("/")[0].split("?")[0].strip().strip("[]")
    if is_valid_ip(target):
        return [(target, None)]
    try:
        records = await dns_svc.resolve(target)
        ips = list(dict.fromkeys(records.A + records.AAAA))
    except Exception as exc:
        log.warning("ip-mode resolution failed for %s: %s", sanitize_for_log(target), exc)
        ips = []
    if not ips:
        return [(target, target)]
    return [(ip, target) for ip in ips[:_MAX_IPS_PER_NAME]]


async def _analyse_ip(raw: str, browser: Any, resolved_from: str | None = None) -> IPResult:
    ip = raw.strip()
    result = IPResult(target=ip, resolved_from=resolved_from)
    if not is_valid_ip(ip):
        result.errors["dns"] = "Could not resolve this name to an IP address"
        return result
    # A10 SSRF — block private/internal IPs
    if not is_safe_ip(ip):
        result.errors["ssrf"] = "Private/internal IP address — blocked"
        log.warning("SSRF_BLOCKED ip=%s", ip)
        return result
    try:
        result.bgp = await bgp_svc.lookup(ip, browser)
    except Exception as exc:
        result.errors["bgp"] = str(exc)
    try:
        geo = await geoip_svc.lookup(ip)
        if geo:
            result.geo = GeoIPInfo(**geo)
    except Exception as exc:
        result.errors["geoip"] = str(exc)
    # Host Intelligence Gathering is intentionally NOT run here — it is slow (a
    # service/port scan over Tor) and would block the BGP/Geo result. The
    # frontend triggers it in the background via POST /analyse/ip/hig.
    return result


@router.post("/analyse/domain")
async def analyse_domain(
    req: DomainRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    if len(req.targets) > settings.max_targets_per_request:
        raise HTTPException(
            status_code=400,
            detail=f"Too many targets: {len(req.targets)} exceeds the limit of {settings.max_targets_per_request}.",
        )
    store = _store_for(current_user.id)
    index = _index_for(current_user.id)
    log.info(
        "[%s] analyse domain: %s",
        current_user.username,
        sanitize_for_log(", ".join(req.targets[:5]) + (" ..." if len(req.targets) > 5 else "")),
    )
    browser = await ensure_browser()
    tasks = [_analyse_domain(t, req, browser) for t in req.targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for r in results:
        if isinstance(r, Exception):
            log.warning("domain analysis failed: %s", r)
            continue
        d = r.model_dump()
        existing_id = index.get(d["target"])
        d["_id"] = existing_id or str(uuid.uuid4())
        d["scanned_at"] = now_iso
        d["is_private"] = req.is_private
        if req.case_id:
            d["case_id"] = req.case_id
        store[d["_id"]] = d
        index[d["target"]] = d["_id"]
        out.append(d)
        asyncio.create_task(_db_module.get_db().save_result(current_user.id, d))
    return JSONResponse(out)


# ── IP analysis ───────────────────────────────────────────────────────────────


@router.post("/analyse/ip")
async def analyse_ip(
    req: IPRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    if len(req.targets) > settings.max_targets_per_request:
        raise HTTPException(
            status_code=400,
            detail=f"Too many targets: {len(req.targets)} exceeds the limit of {settings.max_targets_per_request}.",
        )
    store = _store_for(current_user.id)
    index = _index_for(current_user.id)
    log.info(
        "[%s] analyse ip: %s",
        current_user.username,
        sanitize_for_log(", ".join(req.targets[:5]) + (" ..." if len(req.targets) > 5 else "")),
    )
    browser = await ensure_browser()
    # Hostnames are accepted too: they are resolved and every address is scanned.
    expanded = await asyncio.gather(*[_expand_ip_target(t) for t in req.targets])
    pairs: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for group in expanded:
        for ip, origin in group:
            if ip not in seen:
                seen.add(ip)
                pairs.append((ip, origin))
    if len(pairs) > settings.max_targets_per_request:
        raise HTTPException(
            status_code=400,
            detail=f"Too many addresses after resolution: {len(pairs)} exceeds the limit of "
            f"{settings.max_targets_per_request}.",
        )
    tasks = [_analyse_ip(ip, browser, resolved_from=origin) for ip, origin in pairs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for r in results:
        if isinstance(r, Exception):
            log.warning("ip analysis failed: %s", r)
            continue
        d = r.model_dump()
        existing_id = index.get(d["target"])
        d["_id"] = existing_id or str(uuid.uuid4())
        d["scanned_at"] = now_iso
        d["is_private"] = req.is_private
        if req.case_id:
            d["case_id"] = req.case_id
        store[d["_id"]] = d
        index[d["target"]] = d["_id"]
        out.append(d)
        asyncio.create_task(_db_module.get_db().save_result(current_user.id, d))
    return JSONResponse(out)


# Host intelligence scans run for minutes (port/service scan, often over Tor),
# far longer than the nginx/proxy read timeout. So the scan runs as a background
# task keyed by user+target, and the frontend polls GET /analyse/ip/hig for the
# result instead of holding one long HTTP request (which would 504).
_hig_jobs: dict[str, dict[str, Any]] = {}
_MAX_HIG_JOBS = 2000


def _hig_key(user_id: str, ip: str) -> str:
    return f"{user_id}:{ip}"


async def _run_hig_job(
    user_id: str, key: str, ip: str, via_tor: bool, all_ports: bool, rid: str | None
) -> None:
    try:
        hig = await hig_svc.scan(ip, via_tor=via_tor, all_ports=all_ports)
        d = hig.model_dump()
        _hig_jobs[key] = {"status": "done", "hig": d}
        store = _store_for(user_id)
        if rid and rid in store and store[rid].get("target") == ip:
            store[rid]["hig"] = d
            await _db_module.get_db().save_result(user_id, store[rid])
    except Exception as exc:
        log.warning("HIG job failed for %s: %s", ip, exc)
        _hig_jobs[key] = {
            "status": "error",
            "hig": HIGInfo(
                ip=ip, via_tor=via_tor, all_ports=all_ports, error=str(exc)
            ).model_dump(),
        }


@router.post("/analyse/ip/hig")
async def analyse_ip_hig(
    req: HIGRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Start a background host intelligence scan for one IP.

    Returns immediately with ``{"status": "running"}``; poll GET /analyse/ip/hig
    for the result. Used after an IP scan and by the "Extend" (all-ports) button.
    """
    if not settings.hig_enabled:
        return JSONResponse(
            {
                "status": "done",
                "hig": HIGInfo(
                    ip=req.target.strip(),
                    via_tor=req.via_tor,
                    all_ports=req.all_ports,
                    error="Host intelligence gathering is disabled",
                ).model_dump(),
            }
        )
    ip = req.target.strip()
    if not is_safe_ip(ip):
        log.warning("SSRF_BLOCKED hig ip=%s", ip)
        raise HTTPException(status_code=400, detail="Private/internal IP address — blocked")
    log.info(
        "[%s] HIG scan: %s (all_ports=%s, via_tor=%s)",
        current_user.username,
        ip,
        req.all_ports,
        req.via_tor,
    )
    key = _hig_key(current_user.id, ip)
    if len(_hig_jobs) >= _MAX_HIG_JOBS:
        # Drop old finished jobs so the table cannot grow without bound.
        finished = [k for k, v in list(_hig_jobs.items()) if v.get("status") != "running"]
        for old_key in finished[:500]:
            _hig_jobs.pop(old_key, None)
    _hig_jobs[key] = {"status": "running"}
    asyncio.create_task(_run_hig_job(current_user.id, key, ip, req.via_tor, req.all_ports, req.id))
    return JSONResponse({"status": "running"})


@router.get("/analyse/ip/hig")
async def analyse_ip_hig_status(
    target: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Poll the status/result of a background host intelligence scan."""
    job = _hig_jobs.get(_hig_key(current_user.id, target.strip()))
    return JSONResponse(job or {"status": "idle"})
