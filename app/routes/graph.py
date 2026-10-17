"""Case relationship graph (nodes/edges for the vis.js view)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from ..auth import get_current_user
from ..models import UserInDB
from ..state import (
    _store_for,
)

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/cases/{case_id}/graph")
async def case_graph(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Return vis.js-ready nodes + edges + node metadata for all results in a case.

    Cross-result connections are implicit: shared IP / NS / registrar / cert nodes
    are the same object in the graph, so two domains that resolve to the same IP
    are automatically linked through it.
    """
    store = _store_for(current_user.id)
    results = [r for r in store.values() if r.get("case_id") == case_id]
    if not results:
        raise HTTPException(status_code=404, detail="No results found for this case")

    nodes: dict[str, dict] = {}  # nid → node dict
    edges: list[dict] = []
    edge_set: set[tuple] = set()
    node_meta: dict[str, dict] = {}  # nid → detail metadata for frontend card

    def _node(nid: str, label: str, group: str, meta: dict) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "group": group}
            node_meta[nid] = {"type": group, "label": label, **meta}

    def _edge(src: str, dst: str, rel: str, dashes: bool = False) -> None:
        key = (src, dst, rel)
        if key not in edge_set:
            edge_set.add(key)
            edges.append({"from": src, "to": dst, "label": rel, "dashes": dashes, "arrows": "to"})

    for r in results:
        target = r.get("target", "")
        rid = r.get("_id", target)
        kind = r.get("kind", "domain")

        # ── GeoIP helper (shared between domain A-records and standalone IPs) ──
        def _add_geo_for_ip(ip_nid: str, geo: dict) -> None:
            cc = geo.get("country_iso") or ""
            cn = geo.get("country_name") or cc
            city = geo.get("city") or ""
            tz = geo.get("timezone") or ""
            lat = geo.get("latitude")
            lon = geo.get("longitude")
            if cc:
                cnid = f"country_{cc}"
                _node(
                    cnid,
                    f"{cc}",
                    "country",
                    {"Country": cn, "ISO": cc, "Continent": geo.get("continent", "")},
                )
                _edge(ip_nid, cnid, "country")
            if city:
                city_nid = f"city_{cc}_{city}"
                _node(
                    city_nid,
                    city,
                    "city",
                    {"City": city, "Country": cn, "Timezone": tz, "Lat": lat, "Lon": lon},
                )
                _edge(ip_nid, city_nid, "city")

        # ── IP helper (shared between A-record IPs and standalone IP results) ──
        def _add_ip(ip: str, geo_list: list, asn_src: dict | None = None) -> str:
            nid = f"ip_{ip}"
            _node(nid, ip, "ip", {"IP": ip})
            # Geo
            for geo in geo_list:
                if geo.get("ip") == ip or "ip" not in geo:
                    _add_geo_for_ip(nid, geo)
                    node_meta[nid].update(
                        {
                            k: v
                            for k, v in {
                                "Country": geo.get("country_name") or geo.get("country_iso"),
                                "City": geo.get("city"),
                                "ASN": (asn_src or {}).get("asn_description"),
                            }.items()
                            if v
                        }
                    )
                    break
            # ASN from BGP (if provided)
            if asn_src and asn_src.get("asn"):
                asn_nid = f"asn_{asn_src['asn']}"
                _node(
                    asn_nid,
                    asn_src["asn"],
                    "asn",
                    {
                        "ASN": asn_src["asn"],
                        "Description": asn_src.get("asn_description", ""),
                        "Country": asn_src.get("asn_country_code", ""),
                        "Registry": asn_src.get("asn_registry", ""),
                        "CIDR": asn_src.get("asn_cidr", ""),
                    },
                )
                _edge(nid, asn_nid, "ASN")
            return nid

        if kind == "domain":
            status = r.get("final_status")
            _node(
                rid,
                target,
                "domain",
                {
                    "Domain": target,
                    "Status": status,
                    "Final URL": r.get("final_url", ""),
                    "Screenshot": "yes" if r.get("has_screenshot") else "no",
                    "Scanned": r.get("scanned_at", ""),
                },
            )

            dns = r.get("dns") or {}
            geo_ips = r.get("geo_ips") or []

            # A / AAAA records
            for ip in dns.get("A") or []:
                ip_nid = _add_ip(ip, geo_ips)
                _edge(rid, ip_nid, "A")
            for ip in (dns.get("AAAA") or [])[:4]:
                ip_nid = _add_ip(ip, [])
                _edge(rid, ip_nid, "AAAA")

            # CNAME
            for cname in (dns.get("CNAME") or [])[:3]:
                cnid = f"cname_{cname}"
                _node(cnid, cname[:30], "cname", {"CNAME": cname})
                _edge(rid, cnid, "CNAME")

            # NS records
            for ns in (dns.get("NS") or [])[:6]:
                nid = f"ns_{ns}"
                _node(nid, ns[:30], "ns", {"Nameserver": ns})
                _edge(rid, nid, "NS")

            # MX records
            for mx in (dns.get("MX") or [])[:4]:
                exch = mx.get("exchange", "") if isinstance(mx, dict) else str(mx)
                prio = mx.get("priority", "") if isinstance(mx, dict) else ""
                if not exch:
                    continue
                nid = f"mx_{exch}"
                _node(nid, exch[:30], "mx", {"Exchange": exch, "Priority": prio})
                _edge(rid, nid, "MX")

            # TXT (interesting ones only)
            for txt in (dns.get("TXT") or [])[:8]:
                if any(
                    k in txt.lower()
                    for k in (
                        "spf",
                        "dkim",
                        "dmarc",
                        "v=spf",
                        "v=dkim",
                        "google",
                        "microsoft",
                        "verification",
                    )
                ):
                    nid = f"txt_{hash(txt) & 0xFFFFFF:06x}"
                    _node(nid, txt[:25], "txt", {"TXT": txt})
                    _edge(rid, nid, "TXT", dashes=True)

            # WHOIS
            w = r.get("whois") or {}
            if w.get("registrar"):
                reg_key = w["registrar"][:50].lower().replace(" ", "_")
                nid = f"reg_{reg_key}"
                _node(
                    nid,
                    w["registrar"][:22],
                    "registrar",
                    {
                        "Registrar": w["registrar"],
                        "Created": w.get("creation_date", ""),
                        "Expires": w.get("expiration_date", ""),
                    },
                )
                _edge(rid, nid, "registrar")
            for email in (w.get("emails") or [])[:4]:
                nid = f"email_{email}"
                _node(nid, email[:30], "email", {"Email": email, "Source": "WHOIS"})
                _edge(rid, nid, "WHOIS email")
            for ns in (w.get("nameservers") or [])[:4]:
                ns_nid = f"ns_{ns.lower()}"
                _node(ns_nid, ns[:30], "ns", {"Nameserver": ns, "Source": "WHOIS"})
                _edge(rid, ns_nid, "NS (WHOIS)")

            # Certificates
            for cert in (r.get("certs") or [])[:5]:
                cn = cert.get("common_name") or ""
                if not cn:
                    continue
                cert_nid = f"cert_{cn[:50]}"
                _node(
                    cert_nid,
                    cn[:22],
                    "cert",
                    {
                        "CN": cn,
                        "Not Before": cert.get("not_before", ""),
                        "Not After": cert.get("not_after", ""),
                        "SANs": ", ".join((cert.get("san") or [])[:10]),
                    },
                )
                _edge(rid, cert_nid, "cert")
                # Cert issuer
                issuer = cert.get("issuer") or ""
                if issuer:
                    iss_key = issuer[:40].lower().replace(" ", "_")
                    iss_nid = f"issuer_{iss_key}"
                    _node(iss_nid, issuer[:22], "cert_issuer", {"Issuer": issuer})
                    _edge(cert_nid, iss_nid, "issued by")
                # SAN domains (as domain nodes if they differ from target)
                for san in (cert.get("san") or [])[:8]:
                    san_clean = san.lstrip("*.")
                    if san_clean and san_clean != target and not san_clean.startswith("*"):
                        san_nid = f"san_{san_clean[:50]}"
                        _node(san_nid, san[:22], "san", {"SAN": san, "Cert": cn})
                        _edge(cert_nid, san_nid, "SAN", dashes=True)

            # Crawled files (200 OK only, max 15)
            for f in r.get("crawled_files") or []:
                if f.get("status_code") == 200:
                    fpath = f.get("path", "")
                    sha1 = f.get("sha1", "")
                    # Share file nodes by sha1 if available (same file across domains)
                    fnid = f"file_sha1_{sha1}" if sha1 else f"file_{rid}_{fpath}"
                    _node(
                        fnid,
                        fpath[-25:] if len(fpath) > 25 else fpath,
                        "file",
                        {
                            "Path": fpath,
                            "URL": f.get("url", ""),
                            "Type": f.get("content_type", ""),
                            "Size": f.get("size", ""),
                            "SHA1": sha1,
                            "MinHash": f.get("minhash", ""),
                        },
                    )
                    _edge(rid, fnid, "file")

            # Root files (200 only, max 6)
            for f in r.get("root_files") or []:
                if f.get("status_code") == 200 and f.get("sha1"):
                    fpath = f.get("path", "")
                    fnid = f"rootfile_sha1_{f['sha1']}"
                    _node(
                        fnid,
                        fpath,
                        "file",
                        {
                            "Path": fpath,
                            "URL": f.get("url", ""),
                            "Type": f.get("content_type", ""),
                            "Size": f.get("size", ""),
                            "SHA1": f["sha1"],
                            "Source": "root file",
                        },
                    )
                    _edge(rid, fnid, "root file", dashes=True)

            # HTTP redirect chain
            chain = r.get("chain") or []
            if len(chain) > 1:
                final = chain[-1]
                fu = final.get("url", "")
                fu_host = fu.split("/")[2] if "//" in fu else ""
                if fu_host and fu_host != target:
                    fnid = f"redirect_{fu_host[:50]}"
                    _node(
                        fnid,
                        fu_host[:28],
                        "redirect",
                        {
                            "URL": fu,
                            "Status": final.get("status_code", ""),
                            "Chain length": len(chain),
                        },
                    )
                    _edge(rid, fnid, "→ redirect")

            # EFI extracted emails
            efi = r.get("efi") or {}
            for em in (efi.get("emails") or [])[:3]:
                nid = f"email_{em}"
                _node(nid, em[:30], "email", {"Email": em, "Source": "EFI"})
                _edge(rid, nid, "EFI email", dashes=True)
            for tg in (efi.get("telegram") or [])[:2]:
                nid = f"tg_{tg}"
                _node(nid, tg[:28], "social", {"Telegram": tg})
                _edge(rid, nid, "Telegram", dashes=True)

        elif kind == "ip":
            bgp = r.get("bgp") or {}
            asn_info = bgp.get("asn") or {}
            geo = r.get("geo") or {}
            ip_nid = _add_ip(target, [geo] if geo else [], asn_info)

            # BGP prefix
            prefix_info = bgp.get("prefix") or {}
            if prefix_info.get("prefix"):
                pfx = prefix_info["prefix"]
                pfx_nid = f"cidr_{pfx}"
                _node(
                    pfx_nid,
                    pfx,
                    "cidr",
                    {
                        "CIDR": pfx,
                        "Name": prefix_info.get("name", ""),
                        "Description": prefix_info.get("description", ""),
                        "Country": prefix_info.get("country_code", ""),
                    },
                )
                _edge(ip_nid, pfx_nid, "prefix")

            # HE.net PTR/DNS records
            for rec in (bgp.get("he_dns_records") or [])[:5]:
                hostname = rec.get("Hostname") or rec.get("hostname") or ""
                if hostname:
                    ptr_nid = f"ptr_{hostname[:50]}"
                    _node(ptr_nid, hostname[:28], "ptr", {"PTR": hostname, "IP": target})
                    _edge(ip_nid, ptr_nid, "PTR", dashes=True)

    return JSONResponse(
        {
            "nodes": list(nodes.values()),
            "edges": edges,
            "node_meta": node_meta,
            "result_count": len(results),
        }
    )
