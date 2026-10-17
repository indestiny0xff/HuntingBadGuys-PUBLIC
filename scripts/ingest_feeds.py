#!/usr/bin/env python3
"""
ingest_feeds.py — Pull phishing / ransomware URLs from public threat feeds,
auto-create folders + cases by source/group, and submit them as *public*
(non-private) scans so results appear on the /public page.

Usage examples:
    # Phishing feeds only (free, no key needed)
    python scripts/ingest_feeds.py --username admin --password SECRET

    # Add ransomware victims from ransomware.live + ransomlook
    python scripts/ingest_feeds.py -u admin -p SECRET --feeds openphish urlhaus phishstats ransomware_live ransomlook

    # Add phishunt.io (requires free API key)
    python scripts/ingest_feeds.py -u admin -p SECRET --phishunt-key YOUR_KEY

    # Test feed connectivity without submitting anything
    python scripts/ingest_feeds.py -u admin -p SECRET --test-feeds

    # Dry-run: fetch feeds, print what would be submitted, don't scan
    python scripts/ingest_feeds.py -u admin -p SECRET --dry-run

Folder/case structure created automatically:
    Phishing/
        OpenPhish
        URLhaus
        PhishStats
        PhishHunt
        ThreatFox
    Ransomware/
        LockBit            ← one case per group
        RansomHub
        ALPHV
        …
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import ipaddress
import logging
import sys
from collections import defaultdict
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    sys.exit("httpx is required:  pip install httpx")

log = logging.getLogger("ingest")
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# ── Feed fetchers ──────────────────────────────────────────────────────────────


async def fetch_openphish(client: httpx.AsyncClient) -> list[dict]:
    log.info("[openphish] fetching…")
    # Try primary URL first, then community fallback
    urls_to_try = [
        "https://openphish.com/feed.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    ]
    for url in urls_to_try:
        try:
            r = await client.get(url, timeout=30)
            if r.status_code == 200:
                lines = [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")]
                if lines:
                    log.info("[openphish] %d URLs from %s", len(lines), url)
                    return [{"url": u, "group": "OpenPhish"} for u in lines]
                log.warning("[openphish] empty response from %s", url)
            else:
                log.warning("[openphish] HTTP %s from %s", r.status_code, url)
        except Exception as e:
            log.warning("[openphish] %s from %s: %s", type(e).__name__, url, e)
    return []


_URLHAUS_TAGS = {"phishing", "clickfix", "clearfake"}


async def fetch_urlhaus(client: httpx.AsyncClient) -> list[dict]:
    """URLhaus CSV export — keep only phishing and ClickFix/ClearFake entries.
    Columns: id, date_added, url, url_status, last_online, threat, tags, link, reporter"""
    log.info("[urlhaus] fetching…")
    try:
        r = await client.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=30,
        )
        r.raise_for_status()
        items = []
        reader = csv.reader(l for l in r.text.splitlines() if not l.startswith("#") and l.strip())
        for row in reader:
            if len(row) < 7 or row[3].strip().lower() != "online":
                continue
            url = row[2].strip()
            threat = row[5].strip().lower()
            tags = {t.strip().lower() for t in row[6].split(",")}
            if threat == "phishing" or _URLHAUS_TAGS & tags:
                items.append({"url": url, "group": "URLhaus"})
        log.info("[urlhaus] %d phishing/clickfix URLs", len(items))
        return items
    except Exception as e:
        log.warning("[urlhaus] %s", e)
        return []


async def fetch_phishstats(client: httpx.AsyncClient) -> list[dict]:
    """PhishStats API (port 2096). Frequently returns 522 (Cloudflare origin timeout).
    Falls back gracefully with a warning when unreachable."""
    log.info("[phishstats] fetching…")
    try:
        r = await client.get(
            "https://phishstats.info:2096/api/phishing",
            params={"_where": "(score,gt,3)", "_sort": "-id", "_size": "200"},
            timeout=45,
        )
        r.raise_for_status()
        items = [{"url": row["url"], "group": "PhishStats"} for row in r.json() if row.get("url")]
        log.info("[phishstats] %d URLs", len(items))
        return items
    except httpx.ConnectError as e:
        log.warning("[phishstats] connection refused (port 2096 blocked): %s", e)
        return []
    except httpx.TimeoutException as e:
        log.warning("[phishstats] timed out (port 2096 unreachable or Cloudflare 522): %s", e)
        return []
    except httpx.HTTPStatusError as e:
        log.warning("[phishstats] HTTP %s — feed may be down: %s", e.response.status_code, e)
        return []
    except Exception as e:
        log.warning("[phishstats] %s", e)
        return []


async def fetch_phishunt(client: httpx.AsyncClient) -> list[dict]:
    """PhishHunt public feed — no API key required."""
    log.info("[phishunt] fetching…")
    try:
        r = await client.get("https://phishunt.io/feed.txt", timeout=30)
        r.raise_for_status()
        items = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = line if line.startswith("http") else f"http://{line}"
            items.append({"url": url, "group": "PhishHunt"})
        log.info("[phishunt] %d URLs", len(items))
        return items
    except Exception as e:
        log.warning("[phishunt] %s", e)
        return []


async def fetch_threatfox(client: httpx.AsyncClient) -> list[dict]:
    """ThreatFox switched to requiring API keys on their JSON endpoint.
    The daily CSV export is still public. We parse it for url/domain IOC types."""
    log.info("[threatfox] fetching…")
    try:
        r = await client.get(
            "https://threatfox.abuse.ch/export/csv/recent/",
            timeout=30,
        )
        r.raise_for_status()
        _TF_TAGS = {"clickfix", "clearfake"}
        out = []
        # CSV: timestamp, id, ioc_value, ioc_type, threat_type, malware_alias, ...
        reader = csv.reader(io.StringIO(r.text), skipinitialspace=True)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 6:
                continue
            ioc_value = row[2].strip()
            ioc_type = row[3].strip().lower()
            threat_type = row[4].strip().lower()
            malware = row[5].strip().lower()
            if ioc_type in ("url", "domain") and ioc_value:
                if threat_type == "phishing" or any(t in malware for t in _TF_TAGS):
                    url = ioc_value if ioc_value.startswith("http") else f"http://{ioc_value}"
                    out.append({"url": url, "group": "ThreatFox"})
        log.info("[threatfox] %d IOCs", len(out))
        return out
    except Exception as e:
        log.warning("[threatfox] %s", e)
        return []


async def fetch_ransomware_live(client: httpx.AsyncClient) -> list[dict]:
    """Fetch ransomware operator DLS (Data Leak Site) URLs from ransomware.live.
    Each item → folder=Ransomware, case=group_name.
    .onion URLs are included — they will be submitted with use_tor=True."""
    log.info("[ransomware.live] fetching groups…")
    try:
        r = await client.get("https://api.ransomware.live/v1/groups", timeout=30)
        r.raise_for_status()
        out = []
        onion_count = 0
        for g in r.json():
            group_name = (g.get("name") or "unknown").strip().title()
            for loc in g.get("locations", []):
                url = loc.get("fqdn") or loc.get("slug") or ""
                if not url:
                    continue
                if not url.startswith("http"):
                    url = f"http://{url}"
                if ".onion" in url.lower():
                    onion_count += 1
                out.append({"url": url, "group": group_name, "folder": "Ransomware"})
        log.info("[ransomware.live] %d operator URLs (%d .onion)", len(out), onion_count)
        return out
    except Exception as e:
        log.warning("[ransomware.live] %s", e)
        return []


async def fetch_ransomlook(client: httpx.AsyncClient) -> list[dict]:
    """Fetch ransomware DLS URLs from ransomlook.io (top groups by recency)."""
    log.info("[ransomlook] fetching groups…")
    try:
        r = await client.get("https://www.ransomlook.io/api/groups", timeout=20)
        r.raise_for_status()
        data = r.json()
        # API returns either a list of group names or a list of objects
        if not data:
            log.info("[ransomlook] empty group list")
            return []

        group_names: list[str] = []
        if isinstance(data, list):
            for item in data[:60]:  # cap at 60 groups to avoid API spam
                if isinstance(item, str):
                    group_names.append(item)
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("group") or ""
                    if name:
                        group_names.append(str(name))

        if not group_names:
            log.info("[ransomlook] no group names parsed — skipping")
            return []

        out: list[dict] = []
        # Fetch up to 30 groups concurrently
        sem = asyncio.Semaphore(10)

        async def _fetch_group(name: str) -> None:
            async with sem:
                try:
                    gr = await client.get(
                        f"https://www.ransomlook.io/api/group/{name}",
                        timeout=15,
                    )
                    if gr.status_code != 200:
                        return
                    gdata = gr.json()
                    group_title = name.strip().title()
                    # ransomlook /api/group/{name} returns a list of group-info
                    # objects, each with a "locations" list of site dicts.
                    # Each location has "slug" (full http URL) and "fqdn".
                    if not isinstance(gdata, list):
                        gdata = [gdata] if isinstance(gdata, dict) else []
                    for group_obj in gdata:
                        if not isinstance(group_obj, dict):
                            continue
                        for loc in group_obj.get("locations", []):
                            url = ""
                            if isinstance(loc, str):
                                url = loc
                            elif isinstance(loc, dict):
                                url = loc.get("slug") or loc.get("fqdn") or loc.get("url") or ""
                            if not url:
                                continue
                            if not url.startswith("http"):
                                url = f"http://{url}"
                            out.append({"url": url, "group": group_title, "folder": "Ransomware"})
                except Exception:
                    pass

        await asyncio.gather(*[_fetch_group(n) for n in group_names[:30]])
        onion_count = sum(1 for x in out if ".onion" in x["url"].lower())
        log.info("[ransomlook] %d operator URLs (%d .onion)", len(out), onion_count)
        return out
    except Exception as e:
        log.warning("[ransomlook] %s", e)
        return []


async def fetch_ransomwatch(client: httpx.AsyncClient) -> list[dict]:
    """Ransomwatch — community-maintained ransomware DLS monitor.
    Complements ransomware.live with additional group coverage."""
    log.info("[ransomwatch] fetching groups…")
    try:
        r = await client.get("https://ransomwatch.telemetry.ltd/INDEX.json", timeout=30)
        r.raise_for_status()
        out = []
        onion_count = 0
        for group in r.json():
            name = (group.get("name") or "unknown").strip().title()
            for loc in group.get("locations", []):
                fqdn = loc.get("fqdn") or ""
                if not fqdn:
                    continue
                url = fqdn if fqdn.startswith("http") else f"http://{fqdn}"
                if ".onion" in url.lower():
                    onion_count += 1
                out.append({"url": url, "group": name, "folder": "Ransomware"})
        log.info("[ransomwatch] %d operator URLs (%d .onion)", len(out), onion_count)
        return out
    except Exception as e:
        log.warning("[ransomwatch] %s", e)
        return []


# ── Target classification (IP vs domain) ──────────────────────────────────────


def _classify_target(url: str) -> tuple[str, str]:
    """Return (kind, target) for smart routing:
    - ('ip', '1.2.3.4')       → bare IP, submit to /analyse/ip for BGP/geo
    - ('domain', 'http://...') → URL with path or domain, submit to /analyse/domain
    Rule: if the host is an IP AND there is no meaningful path → IP scan.
          If the host is an IP but has a real path → domain scan (visit the URL).
          All .onion and named domains → domain scan.
    """
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        host = parsed.netloc.split(":")[0].strip("[]")
        path = parsed.path.strip("/")
        try:
            ipaddress.ip_address(host)
            # It's an IP host — only do IP scan if there's no meaningful path
            if not path or path in ("index.html", "index.php", "index.htm"):
                return ("ip", host)
            # Has a real path (e.g. /panel/login.php) → visit the URL
            return ("domain", url)
        except ValueError:
            pass  # not an IP, fall through
    except Exception:
        pass
    return ("domain", url if url.startswith("http") else f"http://{url}")


# ── Deduplication ──────────────────────────────────────────────────────────────


def _norm(url: str) -> str:
    try:
        p = urlparse(url if url.startswith("http") else "http://" + url)
        return f"{p.netloc.lower()}{p.path.rstrip('/')}".rstrip("/")
    except Exception:
        return url.lower().strip()


def deduplicate(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for it in items:
        k = _norm(it["url"])
        if k and k not in seen:
            seen.add(k)
            out.append(it)
    return out


# ── Folder / case management ──────────────────────────────────────────────────


async def _api(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
    """Call the API with automatic retry on 429 (rate-limit) using exponential backoff."""
    for attempt in range(6):
        r = await getattr(client, method)(url, **kwargs)
        if r.status_code != 429:
            return r
        wait = 2**attempt  # 1s, 2s, 4s, 8s, 16s, 32s
        log.warning("  429 rate-limit — waiting %ds before retry %d", wait, attempt + 1)
        await asyncio.sleep(wait)
    return r  # return last response after all retries


async def get_or_create_folder(client: httpx.AsyncClient, base: str, name: str) -> str:
    r = await _api(client, "get", f"{base}/folders", timeout=10)
    if r.status_code == 200:
        for f in r.json():
            if f["name"].lower() == name.lower():
                log.info("  folder exists: '%s' (%s)", name, f["id"])
                return f["id"]
    r = await _api(client, "post", f"{base}/folders", json={"name": name}, timeout=10)
    r.raise_for_status()
    fid = r.json()["id"]
    log.info("  created folder: '%s' (%s)", name, fid)
    return fid


async def fetch_cases_for_folder(
    client: httpx.AsyncClient, base: str, folder_id: str
) -> dict[str, str]:
    """Fetch all existing cases for a folder in one request → {name_lower: id}."""
    r = await _api(client, "get", f"{base}/cases", params={"folder_id": folder_id}, timeout=10)
    if r.status_code == 200:
        return {c["name"].lower(): c["id"] for c in r.json()}
    return {}


async def get_or_create_case(
    client: httpx.AsyncClient,
    base: str,
    name: str,
    folder_id: str,
    cache: dict[str, str],
) -> str:
    """Look up case in the pre-fetched cache; only POST if it doesn't exist."""
    existing = cache.get(name.lower())
    if existing:
        log.info("    case exists: '%s' (%s)", name, existing)
        return existing
    r = await _api(
        client, "post", f"{base}/cases", json={"name": name, "folder_id": folder_id}, timeout=10
    )
    r.raise_for_status()
    cid = r.json()["id"]
    cache[name.lower()] = cid  # update cache so duplicates aren't re-created
    log.info("    created case: '%s' (%s)", name, cid)
    return cid


# ── Scanner client ─────────────────────────────────────────────────────────────


async def login(client: httpx.AsyncClient, base: str, username: str, password: str) -> bool:
    try:
        r = await client.post(
            f"{base}/auth/login", json={"username": username, "password": password}, timeout=15
        )
        if r.status_code == 200:
            cookie_hdr = r.headers.get("set-cookie")
            if cookie_hdr:
                k, v = cookie_hdr.split(";")[0].split("=", 1)
                client.cookies.set(k.strip(), v.strip())
            log.info("Logged in as %s", username)
            return True
        log.error("Login failed: %s %s", r.status_code, r.text[:200])
        return False
    except Exception as e:
        log.error("Login error: %s", e)
        return False


async def _submit_domain_chunk(
    client: httpx.AsyncClient,
    base: str,
    urls: list[str],
    case_id: str | None,
    use_tor: bool,
) -> tuple[int, list[str]]:
    """Submit one chunk of domain/URL targets to /analyse/domain.

    Returns (count, result_ids_with_status_200) so NT can be run on live results.
    """
    try:
        r = await client.post(
            f"{base}/analyse/domain",
            json={
                "targets": urls,
                "is_private": False,
                "case_id": case_id,
                "screenshot": True,
                "root_files": True,
                "crawled_files": True,
                "whois": True,
                "certs": True,
                "random_ua": True,
                "use_tor": use_tor,
            },
            # Well above worst-case server time for a batch (10 targets with
            # screenshots + Tor). A client timeout makes uvicorn cancel the
            # in-flight analysis, silently losing the whole batch.
            timeout=900,
        )
        if r.status_code == 200:
            results = r.json()
            tor_tag = " [Tor]" if use_tor else ""
            log.info(
                "  submitted %d domain%s → got %d results back", len(urls), tor_tag, len(results)
            )
            # Only return IDs for results that actually loaded (status 200) — NT needs a live page
            live_ids = [d["_id"] for d in results if d.get("_id") and d.get("final_status") == 200]
            return len(results), live_ids
        log.warning("  domain submit failed: %s %s", r.status_code, r.text[:300])
        return 0, []
    except Exception as e:
        log.warning("  domain submit error: %r", e)
        return 0, []


async def _run_nt_for_results(
    client: httpx.AsyncClient,
    base: str,
    result_ids: list[str],
) -> None:
    """Call POST /results/{id}/nt sequentially for each live domain result."""
    for rid in result_ids:
        try:
            r = await client.post(f"{base}/results/{rid}/nt", timeout=60)
            if r.status_code == 200:
                data = r.json()
                n = (
                    len(data.get("fetch_calls", []))
                    + len(data.get("xhr_calls", []))
                    + len(data.get("other_calls", []))
                    + len(data.get("websockets", []))
                )
                log.info("    NT %s: %d call%s captured", rid[:8], n, "s" if n != 1 else "")
            else:
                log.debug("    NT %s: HTTP %s (no data)", rid[:8], r.status_code)
        except Exception as e:
            log.debug("    NT %s: %s", rid[:8], e)


async def _submit_ip_chunk(
    client: httpx.AsyncClient,
    base: str,
    ips: list[str],
    case_id: str | None,
) -> int:
    """Submit one chunk of bare IP addresses to /analyse/ip."""
    try:
        r = await client.post(
            f"{base}/analyse/ip",
            json={"targets": ips, "is_private": False, "case_id": case_id},
            timeout=900,
        )
        if r.status_code == 200:
            n = len(r.json())
            log.info("  submitted %d IPs → got %d results back", len(ips), n)
            return n
        log.warning("  IP submit failed: %s %s", r.status_code, r.text[:300])
        return 0
    except Exception as e:
        log.warning("  IP submit error: %r", e)
        return 0


async def submit_batch(
    client: httpx.AsyncClient,
    base: str,
    urls: list[str],
    case_id: str | None,
    args: argparse.Namespace,
) -> int:
    """Submit URLs in a batch.

    Automatically:
    - Routes bare IP addresses (no meaningful path) to /analyse/ip
    - Routes domain/URL targets to /analyse/domain
    - Splits .onion URLs into a separate sub-batch with use_tor=True
    """
    classified = [_classify_target(u) for u in urls]
    ip_targets = [t for kind, t in classified if kind == "ip"]
    domain_targets = [t for kind, t in classified if kind == "domain"]

    if args.dry_run:
        onion = [u for u in domain_targets if ".onion" in u.lower()]
        log.info(
            "  [DRY-RUN] case=%s  %d domains (%d .onion) + %d bare IPs: %s…",
            case_id or "—",
            len(domain_targets),
            len(onion),
            len(ip_targets),
            urls[0] if urls else "",
        )
        return len(urls)

    total = 0

    # Domain targets: split clearnet vs .onion
    normal_urls = [u for u in domain_targets if ".onion" not in u.lower()]
    onion_urls = [u for u in domain_targets if ".onion" in u.lower()]
    for chunk_urls, use_tor in [(normal_urls, False), (onion_urls, True)]:
        for i in range(0, len(chunk_urls), args.batch):
            chunk = chunk_urls[i : i + args.batch]
            if not chunk:
                continue
            n, live_ids = await _submit_domain_chunk(client, base, chunk, case_id, use_tor)
            total += n
            if getattr(args, "nt", False) and live_ids:
                log.info(
                    "  Running NT capture for %d live result%s…",
                    len(live_ids),
                    "s" if len(live_ids) != 1 else "",
                )
                await _run_nt_for_results(client, base, live_ids)
            if i + args.batch < len(chunk_urls):
                await asyncio.sleep(args.delay)

    # Bare IP targets
    for i in range(0, len(ip_targets), args.batch):
        chunk = ip_targets[i : i + args.batch]
        if not chunk:
            continue
        total += await _submit_ip_chunk(client, base, chunk, case_id)
        if i + args.batch < len(ip_targets):
            await asyncio.sleep(args.delay)

    return total


# ── Feed connectivity test ─────────────────────────────────────────────────────


async def test_feeds(feeds: list[str]) -> None:
    """Fetch each feed and print a connectivity/data report. No scan is submitted."""
    print("\n--- Feed Connectivity Test -------------------------------------------")
    async with httpx.AsyncClient(follow_redirects=True, headers=_HEADERS) as http:
        tasks: list[tuple[str, object]] = []
        for feed in feeds:
            if feed in FEED_MAP:
                fn, _ = FEED_MAP[feed]
                tasks.append((feed, fn(http)))

        results = await asyncio.gather(*[t for _, t in tasks], return_exceptions=True)
        all_ok = True
        for (feed, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                print(f"  ERR {feed:<20}  ERROR: {result}")
                all_ok = False
            elif isinstance(result, list) and result:
                onion = sum(1 for x in result if ".onion" in x.get("url", "").lower())
                print(f"  OK  {feed:<20}  {len(result):>5} URLs  ({onion} .onion)")
            else:
                print(f"  ERR {feed:<20}  0 URLs (empty or blocked)")
                all_ok = False

    print("-" * 60)
    print("All feeds OK" if all_ok else "Some feeds failed -- check logs above")
    print()


# ── Main ───────────────────────────────────────────────────────────────────────

FEED_MAP = {
    "openphish": (fetch_openphish, "Phishing"),
    "urlhaus": (fetch_urlhaus, "Phishing"),
    "phishstats": (fetch_phishstats, "Phishing"),
    "threatfox": (fetch_threatfox, "Phishing"),
    "phishunt": (fetch_phishunt, "Phishing"),
    "ransomware_live": (fetch_ransomware_live, "Ransomware"),
    "ransomlook": (fetch_ransomlook, "Ransomware"),
    "ransomwatch": (fetch_ransomwatch, "Ransomware"),
}


async def main(args: argparse.Namespace) -> None:
    # ── 0. Test-feeds mode: just verify connectivity ────────────────────────
    if getattr(args, "test_feeds", False):
        await test_feeds(list(args.feeds))
        return

    async with httpx.AsyncClient(follow_redirects=True, headers=_HEADERS) as http:
        # ── 1. Fetch all feeds ──────────────────────────────────────────────
        tasks = []
        for feed in args.feeds:
            if feed in FEED_MAP:
                fn, _ = FEED_MAP[feed]
                tasks.append(fn(http))
            else:
                log.warning("Unknown feed: %s", feed)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw: list[dict] = []
        for batch in results:
            if isinstance(batch, list):
                raw.extend(batch)
            elif isinstance(batch, Exception):
                log.warning("Feed task error: %s", batch)

        # Default folder for feeds without an explicit folder key
        for it in raw:
            if "folder" not in it:
                it["folder"] = "Phishing"

        items = deduplicate(raw)
        onion_total = sum(1 for x in items if ".onion" in x["url"].lower())
        log.info("Unique targets after dedup: %d (%d .onion)", len(items), onion_total)

        if not items:
            log.info("Nothing to submit — exiting.")
            return
        if args.dry_run:
            log.info("[DRY-RUN] first 10: %s", [x["url"] for x in items[:10]])
            return

        # ── 2. Login ────────────────────────────────────────────────────────
        async with httpx.AsyncClient(follow_redirects=True, headers=_HEADERS) as scan:
            if not await login(scan, args.base_url, args.username, args.password):
                sys.exit(1)

            # ── 3. Build folder/case map ─────────────────────────────────
            groups: dict[tuple[str, str], list[str]] = defaultdict(list)
            for it in items:
                groups[(it["folder"], it["group"])].append(it["url"])

            folder_ids: dict[str, str] = {}
            case_ids: dict[tuple[str, str], str] = {}
            # One GET /cases per folder (not one per group)
            case_caches: dict[str, dict[str, str]] = {}

            # ── Ensure folders exist ─────────────────────────────────────
            for folder_name in {fn for fn, _ in groups}:
                log.info("Ensuring folder: '%s'", folder_name)
                folder_ids[folder_name] = await get_or_create_folder(
                    scan, args.base_url, folder_name
                )

            # ── Pre-fetch all existing cases per folder (one request each) ──
            for folder_name, fid in folder_ids.items():
                log.info("Loading cases for folder '%s'…", folder_name)
                case_caches[folder_name] = await fetch_cases_for_folder(scan, args.base_url, fid)
                log.info("  %d existing cases loaded", len(case_caches[folder_name]))

            # ── Create missing cases (POST only when absent from cache) ──
            for folder_name, group_name in groups:
                fid = folder_ids[folder_name]
                cache = case_caches[folder_name]
                case_ids[(folder_name, group_name)] = await get_or_create_case(
                    scan, args.base_url, group_name, fid, cache
                )
                await asyncio.sleep(0.05)  # light pace only for new POSTs

            # ── 4. Submit in batches per case ────────────────────────────
            # submit_batch internally splits .onion from clearnet URLs
            total_submitted = 0
            for (folder_name, group_name), urls in groups.items():
                cid = case_ids[(folder_name, group_name)]
                onion_n = sum(1 for u in urls if ".onion" in u.lower())
                log.info(
                    "── %s / %s  (%d targets, %d .onion)",
                    folder_name,
                    group_name,
                    len(urls),
                    onion_n,
                )
                total_submitted += await submit_batch(scan, args.base_url, urls, cid, args)
                await asyncio.sleep(args.delay)

            log.info("Done — %d URLs submitted across %d cases.", total_submitted, len(groups))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ingest threat feeds as public scans")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument(
        "--feeds",
        nargs="+",
        default=[
            "openphish",
            "urlhaus",
            "phishstats",
            "threatfox",
            "phishunt",
            "ransomware_live",
            "ransomlook",
            "ransomwatch",
        ],
        choices=list(FEED_MAP),
    )
    p.add_argument("--batch", type=int, default=10, help="Targets per API request")
    p.add_argument("--delay", type=int, default=5, help="Seconds between batches")
    p.add_argument("--dry-run", action="store_true", help="Fetch feeds but don't submit")
    p.add_argument("--test-feeds", action="store_true", help="Test feed connectivity and exit")
    p.add_argument(
        "--no-nt",
        dest="nt",
        action="store_false",
        help="Skip dynamic NT capture on live domain results",
    )
    p.set_defaults(nt=True)
    return p.parse_args()


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
