"""Indicator export for integrations (OpenCTI, MISP, SIEM, scripts).

``GET /cases/{case_id}/export?format=json|csv|stix|misp`` collects every
observable from the results of a case (domains, IPs, URLs, file hashes,
emails, DNS records, certificates) and returns it in the requested format.
Cases are team-shared, so results from every account are included.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Query as QParam
from fastapi.responses import JSONResponse, PlainTextResponse

from .. import __version__
from ..auth import get_current_user
from ..config import settings
from ..models import UserInDB
from ..security import is_valid_ip
from ..state import _stores, _user_cases

router = APIRouter()

# Stable namespace so the same indicator gets the same STIX id on every export
# (OpenCTI and MISP deduplicate on it).
_NS = uuid.UUID("7d1f4c53-1b8e-4e63-9c2a-3c9b6b8f1a2e")


def _case_results(case_id: str) -> tuple[dict | None, list[dict]]:
    case = None
    for cases in _user_cases.values():
        if case_id in cases:
            case = cases[case_id].model_dump()
            break
    results = [
        {k: v for k, v in item.items() if k != "screenshot"}
        for store in _stores.values()
        for item in store.values()
        if item.get("case_id") == case_id
    ]
    return case, results


def _host(url: str | None) -> str | None:
    try:
        return urlparse(url).hostname if url else None
    except ValueError:
        return None


def collect_indicators(results: list[dict]) -> dict[str, Any]:
    """Normalise a case's results into flat indicator lists plus per-domain DNS."""
    domains: dict[str, set[str]] = {}
    ips: dict[str, set[str]] = {}
    urls: dict[str, set[str]] = {}
    hashes: dict[str, set[str]] = {}
    emails: dict[str, set[str]] = {}
    dns: dict[str, dict] = {}
    certs: list[dict] = []

    def add(bucket: dict[str, set[str]], value: str | None, source: str) -> None:
        if value:
            bucket.setdefault(
                value.strip().lower() if bucket is not urls else value.strip(), set()
            ).add(source)

    for r in results:
        target = str(r.get("target", "")).strip()
        kind = r.get("kind")
        if kind == "domain":
            host = _host(r.get("scan_url")) or target.split("/")[0]
            if host and not is_valid_ip(host):
                add(domains, host, target)
            elif host:
                add(ips, host, target)
            if r.get("final_url"):
                add(urls, r["final_url"], target)
                fh = _host(r["final_url"])
                if fh and not is_valid_ip(fh):
                    add(domains, fh, target)
            d = r.get("dns") or {}
            for ip in (d.get("A") or []) + (d.get("AAAA") or []):
                add(ips, ip, target)
            if d:
                dns[host or target] = {
                    k: d.get(k)
                    for k in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
                    if d.get(k)
                }
            for f in (r.get("root_files") or []) + (r.get("crawled_files") or []):
                if f.get("status_code") == 200 and f.get("sha1"):
                    add(hashes, f["sha1"], f.get("url") or target)
            for e in (r.get("whois") or {}).get("emails") or []:
                add(emails, e, target)
            for e in (r.get("efi") or {}).get("emails") or []:
                add(emails, e, target)
            for c in r.get("certs") or []:
                certs.append(
                    {
                        "target": target,
                        "common_name": c.get("common_name"),
                        "issuer": c.get("issuer"),
                        "not_before": c.get("not_before"),
                        "not_after": c.get("not_after"),
                        "san": c.get("san") or [],
                    }
                )
        elif kind == "ip":
            # Open ports and services stay in the JSON results; only the address is an indicator.
            add(ips, target, r.get("resolved_from") or target)

    def flat(bucket: dict[str, set[str]]) -> list[dict]:
        return [{"value": v, "sources": sorted(s)} for v, s in sorted(bucket.items())]

    return {
        "domains": flat(domains),
        "ips": flat(ips),
        "urls": flat(urls),
        "hashes": flat(hashes),
        "emails": flat(emails),
        "dns": dns,
        "certificates": certs,
    }


# ── STIX 2.1 ──────────────────────────────────────────────────────────────────

_STIX_PATTERNS = {
    "domains": lambda v: f"[domain-name:value = '{v}']",
    "ips": lambda v: f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']",
    "urls": lambda v: "[url:value = '" + v.replace("\\", "\\\\").replace("'", "\\'") + "']",
    "hashes": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "emails": lambda v: f"[email-addr:value = '{v}']",
}


def stix_bundle(case: dict | None, case_id: str, ind: dict[str, Any]) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = f"identity--{uuid.uuid5(_NS, settings.app_name)}"
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": settings.app_name,
            "identity_class": "system",
        }
    ]
    refs: list[str] = []
    for bucket, pattern in _STIX_PATTERNS.items():
        for item in ind[bucket]:
            value = item["value"]
            sid = f"indicator--{uuid.uuid5(_NS, bucket + ':' + value)}"
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": sid,
                    "created": now,
                    "modified": now,
                    "created_by_ref": identity_id,
                    "name": value,
                    "description": "Observed on: " + ", ".join(item["sources"][:10]),
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern(value),
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                    "valid_from": now,
                    "labels": [bucket.rstrip("s") if bucket != "hashes" else "file-hash"],
                }
            )
            refs.append(sid)
    name = (case or {}).get("name") or case_id
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid5(_NS, 'case:' + case_id)}",
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": name,
            "description": (case or {}).get("description")
            or f"Indicators exported from case {name}",
            "report_types": ["threat-report"],
            "published": now,
            "object_refs": refs or [identity_id],
            "external_references": [
                {
                    "source_name": settings.app_name,
                    "url": f"{settings.public_url}/app",
                    "external_id": case_id,
                }
            ],
        }
    )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ── MISP event ────────────────────────────────────────────────────────────────

_MISP_TYPES = {
    "domains": "domain",
    "ips": "ip-dst",
    "urls": "url",
    "hashes": "sha1",
    "emails": "email-src",
}
_MISP_CATEGORY = {
    "domains": "Network activity",
    "ips": "Network activity",
    "urls": "Network activity",
    "hashes": "Payload delivery",
    "emails": "Payload delivery",
}


def misp_event(case: dict | None, case_id: str, ind: dict[str, Any]) -> dict:
    name = (case or {}).get("name") or case_id
    attributes = []
    for bucket, mtype in _MISP_TYPES.items():
        for item in ind[bucket]:
            attributes.append(
                {
                    "type": mtype,
                    "category": _MISP_CATEGORY[bucket],
                    "value": item["value"],
                    "to_ids": bucket != "emails",
                    "comment": "Observed on: " + ", ".join(item["sources"][:10]),
                }
            )
    return {
        "Event": {
            "info": f"{settings.app_name}: {name}",
            "distribution": 0,
            "threat_level_id": 2,
            "analysis": 1,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "Tag": [{"name": f"source:{settings.app_name.lower().replace(' ', '-')}"}],
            "Attribute": attributes,
        }
    }


# ── Route ─────────────────────────────────────────────────────────────────────


@router.get("/cases/{case_id}/export")
async def export_case(
    case_id: str,
    format: str = QParam(default="json", pattern="^(json|csv|stix|misp)$"),
    _: UserInDB = Depends(get_current_user),
):
    """Indicators of a case as JSON, CSV, a STIX 2.1 bundle or a MISP event.

    - json: {"case", "domains", "ips", "urls", "hashes", "emails", "dns", "certificates", "results"}
    - csv:  type,value,sources
    - stix: STIX 2.1 bundle (indicators + report) for OpenCTI and others
    - misp: MISP event JSON ready for PyMISP add_event / the REST API
    """
    case, results = _case_results(case_id)
    if case is None and not results:
        raise HTTPException(status_code=404, detail="Case not found")
    ind = collect_indicators(results)

    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "sources"])
        for bucket, label in (
            ("domains", "domain"),
            ("ips", "ip"),
            ("urls", "url"),
            ("hashes", "sha1"),
            ("emails", "email"),
        ):
            for item in ind[bucket]:
                w.writerow([label, item["value"], " ".join(item["sources"])])
        return PlainTextResponse(
            buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="case-{case_id}.csv"'},
        )
    if format == "stix":
        return JSONResponse(stix_bundle(case, case_id, ind))
    if format == "misp":
        return JSONResponse(misp_event(case, case_id, ind))
    return JSONResponse(
        {
            "case": case or {"id": case_id},
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "generator": f"{settings.app_name} {__version__}",
            **ind,
            "results": results,
        }
    )
