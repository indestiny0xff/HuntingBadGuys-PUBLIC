from __future__ import annotations

import asyncio
import logging
from typing import Any

import dns.asyncresolver
import dns.exception

from ..models import DNSRecords, MXRecord, SOARecord

log = logging.getLogger(__name__)
_RTYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


async def _query(resolver: dns.asyncresolver.Resolver, domain: str, rtype: str) -> list[Any]:
    try:
        ans = await resolver.resolve(domain, rtype, lifetime=8.0)
        return list(ans)
    except Exception:
        return []


async def resolve(domain: str) -> DNSRecords:
    if domain.lower().endswith(".onion"):
        return DNSRecords()

    r = dns.asyncresolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.use_edns(
        edns=0, ednsflags=0, payload=65535
    )  # large EDNS payload avoids truncation on huge TXT records

    raw = await asyncio.gather(*[_query(r, domain, t) for t in _RTYPES], return_exceptions=True)
    ans = {t: ([] if isinstance(v, Exception) else v) for t, v in zip(_RTYPES, raw)}

    rec = DNSRecords(
        A=[str(x) for x in ans.get("A", [])],
        AAAA=[str(x) for x in ans.get("AAAA", [])],
        MX=[
            MXRecord(priority=x.preference, exchange=str(x.exchange).rstrip("."))
            for x in ans.get("MX", [])
        ],
        TXT=[b"".join(x.strings).decode(errors="replace") for x in ans.get("TXT", [])],
        NS=[str(x).rstrip(".") for x in ans.get("NS", [])],
        CNAME=[str(x).rstrip(".") for x in ans.get("CNAME", [])],
    )

    soa_list = ans.get("SOA", [])
    if soa_list:
        s = soa_list[0]
        rec.SOA = SOARecord(
            mname=str(s.mname).rstrip("."),
            rname=str(s.rname).rstrip("."),
            serial=s.serial,
            refresh=s.refresh,
            retry=s.retry,
            expire=s.expire,
            minimum=s.minimum,
        )

    return rec
