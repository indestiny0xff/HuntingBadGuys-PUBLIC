"""Tests for DNS service."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.services.dns_svc import resolve


def _make_rdata(rtype: str, **kwargs):
    """Build a minimal mock rdata object for a given record type."""
    m = MagicMock()
    if rtype == "A" or rtype == "AAAA":
        m.__str__ = lambda _: kwargs["address"]
    elif rtype == "MX":
        m.preference = kwargs["priority"]
        m.exchange = MagicMock()
        m.exchange.__str__ = lambda _: kwargs["exchange"] + "."
    elif rtype == "TXT":
        m.strings = [s.encode() for s in kwargs["strings"]]
    elif rtype == "NS":
        m.__str__ = lambda _: kwargs["name"] + "."
    elif rtype == "CNAME":
        m.__str__ = lambda _: kwargs["target"] + "."
    elif rtype == "SOA":
        m.mname = MagicMock()
        m.mname.__str__ = lambda _: kwargs["mname"] + "."
        m.rname = MagicMock()
        m.rname.__str__ = lambda _: kwargs["rname"] + "."
        m.serial = kwargs.get("serial", 1)
        m.refresh = kwargs.get("refresh", 3600)
        m.retry = kwargs.get("retry", 900)
        m.expire = kwargs.get("expire", 604800)
        m.minimum = kwargs.get("minimum", 300)
    return m


@pytest.mark.asyncio
async def test_resolve_a_record():
    a_rdata = _make_rdata("A", address="1.2.3.4")

    async def fake_query(resolver, domain, rtype):
        if rtype == "A":
            return [a_rdata]
        return []

    with patch("app.services.dns_svc._query", side_effect=fake_query):
        rec = await resolve("example.com")

    assert "1.2.3.4" in rec.A


@pytest.mark.asyncio
async def test_resolve_mx_record():
    mx_rdata = _make_rdata("MX", priority=10, exchange="mail.example.com")

    async def fake_query(resolver, domain, rtype):
        if rtype == "MX":
            return [mx_rdata]
        return []

    with patch("app.services.dns_svc._query", side_effect=fake_query):
        rec = await resolve("example.com")

    assert len(rec.MX) == 1
    assert rec.MX[0].priority == 10
    assert rec.MX[0].exchange == "mail.example.com"


@pytest.mark.asyncio
async def test_resolve_soa():
    soa_rdata = _make_rdata(
        "SOA", mname="ns1.example.com", rname="admin.example.com", serial=2024010101
    )

    async def fake_query(resolver, domain, rtype):
        if rtype == "SOA":
            return [soa_rdata]
        return []

    with patch("app.services.dns_svc._query", side_effect=fake_query):
        rec = await resolve("example.com")

    assert rec.SOA is not None
    assert rec.SOA.mname == "ns1.example.com"
    assert rec.SOA.serial == 2024010101


@pytest.mark.asyncio
async def test_resolve_handles_all_empty():
    async def fake_query(resolver, domain, rtype):
        return []

    with patch("app.services.dns_svc._query", side_effect=fake_query):
        rec = await resolve("nonexistent.invalid")

    assert rec.A == []
    assert rec.MX == []
    assert rec.SOA is None


@pytest.mark.asyncio
async def test_resolve_partial_failure():
    """One record type failing should not break the rest."""
    a_rdata = _make_rdata("A", address="1.2.3.4")

    async def fake_query(resolver, domain, rtype):
        if rtype == "A":
            return [a_rdata]
        if rtype == "MX":
            raise Exception("simulated timeout")
        return []

    with patch("app.services.dns_svc._query", side_effect=fake_query):
        rec = await resolve("example.com")

    # A record should still be resolved despite MX failing
    assert "1.2.3.4" in rec.A
