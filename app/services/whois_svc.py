from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

import whois

from ..models import WhoisInfo

log = logging.getLogger(__name__)


def _norm_date(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, list):
        val = next((v for v in val if v is not None), None)
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)[:64]


def _norm_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val.strip().lower()] if val.strip() else []
    return [str(v).strip().lower() for v in val if v]


async def lookup(domain: str) -> WhoisInfo:
    loop = asyncio.get_event_loop()
    try:
        w = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: whois.whois(domain)),
            timeout=20.0,
        )
    except Exception as exc:
        log.warning("whois failed %s: %s", domain, exc)
        return WhoisInfo()

    return WhoisInfo(
        domain_name=(str(w.domain_name).lower() if w.domain_name else None),
        registrar=(str(w.registrar) if w.registrar else None),
        creation_date=_norm_date(w.creation_date),
        expiration_date=_norm_date(w.expiration_date),
        updated_date=_norm_date(w.updated_date),
        status=_norm_list(w.status),
        nameservers=_norm_list(w.name_servers),
        emails=_norm_list(w.emails),
        raw=(w.text if hasattr(w, "text") else None),
    )
