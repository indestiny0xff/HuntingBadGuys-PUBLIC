from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import struct
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..config import settings
from ..models import RootFile
from ..security import ssrf_request_hook

log = logging.getLogger(__name__)

# ── MinHash (LSH) ─────────────────────────────────────────────────────────────
# 128 permutations, 4-byte shingles, capped at 64 KiB input.
# Each permutation: h(x) = (a*x + b) mod (2^32), then min over all shingles.
# LSH: 8 bands of 16 hash values each → 8 band-level fingerprints.

_MH_PERMS = 128
_MH_BANDS = 8
_MH_ROWS = _MH_PERMS // _MH_BANDS  # 16
_MH_CAP = 64 * 1024  # 64 KiB
_MOD = 2**32

# Deterministic coefficients from a fixed seed so results are reproducible.
_rng_seed = 0xDEADBEEF
_a_vals: list[int] = []
_b_vals: list[int] = []
for _i in range(_MH_PERMS):
    _rng_seed = (_rng_seed * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
    _a_vals.append((_rng_seed >> 33) | 1)  # odd so gcd with 2^32 == 1
    _rng_seed = (_rng_seed * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
    _b_vals.append(_rng_seed >> 33)


def _minhash(data: bytes) -> str | None:
    """Return MinHash-LSH fingerprint as a 32-char hex string, or None if data too short.

    Algorithm:
      1. Compute 128 minimum hash values over the set of 4-byte shingles.
      2. Split into 8 bands of 16 values each.
      3. Hash each band's 16 uint32s with MD5, keep the first 2 bytes → 16-bit band id.
      4. Concatenate 8 × 16-bit band ids → 128 bits → 32-char hex.

    LSH property: documents with similar content share the same band id in at least
    one band, making them detectable via `minhash_bands contains "<band>"`.
    """
    data = data[:_MH_CAP]
    if len(data) < 4:
        return None
    shingles = {struct.unpack_from(">I", data, i)[0] for i in range(len(data) - 3)}
    if not shingles:
        return None
    # 128 minimum values — one per permutation
    mins: list[int] = [
        min(((a * x + b) & 0xFFFFFFFF) for x in shingles) for a, b in zip(_a_vals, _b_vals)
    ]
    # Compress to 32-char hex: 8 bands × 16-bit hash = 128 bits
    parts: list[str] = []
    for band in range(_MH_BANDS):
        band_vals = mins[band * _MH_ROWS : (band + 1) * _MH_ROWS]
        band_bytes = struct.pack(f">{_MH_ROWS}I", *band_vals)
        band_id = int.from_bytes(hashlib.md5(band_bytes).digest()[:2], "big")
        parts.append(f"{band_id:04x}")
    return "".join(parts)


def _minhash_bands(mh_hex: str) -> list[str]:
    """Split a 32-char MinHash hex into 8 band-level fingerprints for LSH."""
    if len(mh_hex) != 32:
        return []
    # Each band covers 16 bits (4 hex chars) of the 128-bit value
    return [mh_hex[i * 4 : (i + 1) * 4] for i in range(_MH_BANDS)]


# ── SHA-1 ────────────────────────────────────────────────────────────────────


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


# ── Content-Disposition filename extractor ────────────────────────────────────

_CD_FNAME_RE = re.compile(
    r'filename\*?\s*=\s*(?:UTF-8\'\')?["\']?([^"\';\r\n]+)',
    re.IGNORECASE,
)


def _cd_filename(header: str) -> str | None:
    """Extract suggested filename from a Content-Disposition header value."""
    m = _CD_FNAME_RE.search(header)
    if not m:
        return None
    fname = m.group(1).strip().strip("\"'")
    # Basic sanitisation — no path traversal
    fname = fname.replace("/", "_").replace("\\", "_").strip()
    return fname or None


def _resolve_display_path(url_path: str, content_disp: str) -> str:
    """Return display path, substituting Content-Disposition filename if present and different."""
    fname = _cd_filename(content_disp) if content_disp else None
    if not fname:
        return url_path
    existing_name = url_path.rstrip("/").rsplit("/", 1)[-1]
    if fname == existing_name:
        return url_path
    dir_part = url_path.rstrip("/").rsplit("/", 1)[0] or ""
    new_path = f"{dir_part}/{fname}"
    return new_path if new_path.startswith("/") else f"/{new_path}"


# ── Fetcher ───────────────────────────────────────────────────────────────────


async def _fetch_one(client: httpx.AsyncClient, base: str, path: str) -> RootFile:
    url = base.rstrip("/") + path
    try:
        resp = await client.get(url)
        body = resp.content[: settings.max_file_bytes]

        # Use Content-Disposition filename for display path when server signals a download
        cd = resp.headers.get("content-disposition", "")
        display_path = _resolve_display_path(path, cd)

        if resp.status_code == 200 and body:
            sha1 = _sha1(body)
            mh = _minhash(body)
            bands = _minhash_bands(mh) if mh else []
        else:
            sha1 = mh = None
            bands = []
        return RootFile(
            path=display_path,
            url=url,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type"),
            size=len(body),
            sha1=sha1,
            minhash=mh,
            minhash_bands=bands,
        )
    except Exception as exc:
        log.debug("file fetch failed %s: %s", url, exc)
        return RootFile(path=path, url=url, status_code=0)


def _client_kwargs(proxy: str | None, ua: str | None) -> dict:
    """httpx client options shared by the root-file and crawl fetchers.

    Certificate verification is intentionally off: the targets are suspicious
    hosts with broken or self-signed TLS. The SSRF hook refuses private
    destinations, including redirects, unless Tor is in use (.onion)."""
    kwargs: dict = dict(follow_redirects=True, timeout=settings.timeout, verify=False)
    if proxy:
        kwargs["proxy"] = proxy
    else:
        kwargs["event_hooks"] = {"request": [ssrf_request_hook]}
    if ua:
        kwargs["headers"] = {"User-Agent": ua}
    return kwargs


async def fetch_all(
    base_url: str, proxy: str | None = None, ua: str | None = None
) -> list[RootFile]:
    kwargs = _client_kwargs(proxy, ua)
    async with httpx.AsyncClient(**kwargs) as client:
        return list(
            await asyncio.gather(*[_fetch_one(client, base_url, p) for p in settings.root_paths])
        )


async def _playwright_fetch_download(browser: Any, url: str) -> list[RootFile]:
    """Fetch a Cloudflare-protected or download URL via Playwright.

    Used when httpx receives a ``cf-mitigated`` challenge response.  A fresh
    browser context is created (so no session state leaks), the page is loaded
    (allowing real Chrome to solve the JS challenge), and any triggered file
    download is captured and returned as a ``RootFile``.  Returns an empty list
    if no download fires within the timeout or if any error occurs.

    Anti-bot hardening applied to the context:
    * ``navigator.webdriver`` patched to ``undefined`` (primary CF detection signal)
    * ``wait_until='load'`` used instead of ``'networkidle'`` — CF challenge pages
      fire continuous XHR beacons that prevent ``networkidle`` from ever resolving.
      After the ``load`` event the challenge JS keeps running; we wait separately.
    """
    try:
        context = await browser.new_context(
            accept_downloads=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            # Extra viewport/locale signals that headless contexts often omit
            viewport={"width": 1280, "height": 900},
            locale="en-US",
        )
        # Patch the primary headless-detection signal before any page scripts run
        await context.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
        )
        try:
            page = await context.new_page()
            loop = asyncio.get_running_loop()
            dl_future: asyncio.Future = loop.create_future()
            # Track last non-HTML content-type from any response (the real file response)
            last_ct: list[str] = [""]

            async def _on_response(resp: Any) -> None:
                ct = resp.headers.get("content-type", "")
                if ct and "text/html" not in ct and "javascript" not in ct:
                    last_ct[0] = ct

            async def _on_dl(dl: Any) -> None:
                if not dl_future.done():
                    dl_future.set_result(dl)

            page.on("response", _on_response)
            page.on("download", _on_dl)

            # Use 'load' (not 'networkidle') — CF challenge JS fires continuous XHR
            # beacons that prevent networkidle from ever resolving.  After the load
            # event the challenge continues in the background; we wait separately.
            try:
                await asyncio.wait_for(
                    page.goto(url, wait_until="load"),
                    timeout=10.0,
                )
            except Exception:
                pass  # expected: timeout or nav error — challenge may still complete

            # Wait up to 15 s for the CF challenge to resolve + download to trigger.
            try:
                dl = await asyncio.wait_for(asyncio.shield(dl_future), timeout=15.0)
                dl_path = await dl.path()
                if dl_path:

                    def _read(p: str) -> bytes:
                        with open(p, "rb") as fh:
                            return fh.read()

                    body = await asyncio.to_thread(_read, dl_path)
                    body = body[: settings.max_file_bytes]
                    fname = (
                        dl.suggested_filename
                        or urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
                        or "download"
                    )
                    ct = last_ct[0]
                    sha1_val = _sha1(body)
                    mh = _minhash(body)
                    bands = _minhash_bands(mh) if mh else []
                    parsed_url = urlparse(url)
                    dir_part = parsed_url.path.rstrip("/").rsplit("/", 1)[0] or ""
                    display_path = f"{dir_part}/{fname}"
                    if not display_path.startswith("/"):
                        display_path = "/" + display_path
                    log.info(
                        "playwright captured download: %s → %s (%d bytes)",
                        url,
                        fname,
                        len(body),
                    )
                    return [
                        RootFile(
                            path=display_path,
                            url=url,
                            status_code=200,
                            content_type=ct,
                            size=len(body),
                            sha1=sha1_val,
                            minhash=mh,
                            minhash_bands=bands,
                        )
                    ]
            except TimeoutError:
                log.debug(
                    "playwright: no download from %s within timeout — CF may be blocking this IP",
                    url,
                )

        finally:
            await context.close()
    except Exception as exc:
        log.debug("playwright CF fetch failed %s: %s", url, exc)

    return []


async def crawl_website(
    base_url: str, proxy: str | None = None, ua: str | None = None, browser: Any = None
) -> list[RootFile]:
    kwargs = _client_kwargs(proxy, ua)

    async with httpx.AsyncClient(**kwargs) as client:
        try:
            resp = await client.get(base_url)
        except Exception as exc:
            log.debug("crawl fetch failed %s: %s", base_url, exc)
            return []

        # ── Cloudflare JS challenge detection ─────────────────────────────────
        # httpx cannot solve CF's JavaScript challenges.  When ``cf-mitigated``
        # is present, fall back to the Playwright browser (real Chrome) which
        # executes the JS challenge, then captures any file download that follows.
        if resp.headers.get("cf-mitigated") and browser is not None:
            log.debug("CF mitigation on %s — trying Playwright fallback", base_url)
            pw_results = await _playwright_fetch_download(browser, base_url)
            return pw_results  # empty list if Playwright also failed

        results: list[RootFile] = []
        content_type = resp.headers.get("content-type", "")
        content_disp = resp.headers.get("content-disposition", "")
        is_html = "text/html" in content_type or "application/xhtml" in content_type

        # ── If the URL itself serves a downloadable file, capture it ──────────
        # Triggers when: Content-Disposition: attachment is present, OR the
        # response is clearly not an HTML page (binary/application type).
        is_download = "attachment" in content_disp or (
            not is_html
            and not content_type.startswith("text/")
            and resp.status_code == 200
            and resp.content
        )
        if is_download and resp.status_code == 200 and resp.content:
            parsed_base = urlparse(base_url)
            path = parsed_base.path or "/"
            display_path = _resolve_display_path(path, content_disp)
            body = resp.content[: settings.max_file_bytes]
            sha1_val = _sha1(body)
            mh = _minhash(body)
            bands = _minhash_bands(mh) if mh else []
            results.append(
                RootFile(
                    path=display_path,
                    url=str(resp.url),
                    status_code=resp.status_code,
                    content_type=content_type,
                    size=len(body),
                    sha1=sha1_val,
                    minhash=mh,
                    minhash_bands=bands,
                )
            )
            # Binary file — no HTML to parse for further links
            return results

        # ── Parse HTML for links ───────────────────────────────────────────────
        try:
            body_text = resp.text
        except Exception as exc:
            log.debug("crawl decode failed %s: %s", base_url, exc)
            return results

        links: set[str] = set()
        base_parsed = urlparse(base_url)

        for match in re.finditer(
            r'(?:href|src|action|data-src)\s*=\s*["\']([^"\']+)["\']',
            body_text,
            re.IGNORECASE,
        ):
            link = match.group(1).strip()
            if link.startswith(("data:", "mailto:", "javascript:", "#")):
                continue

            abs_url = urljoin(base_url, link)
            parsed = urlparse(abs_url)

            if parsed.netloc != base_parsed.netloc or parsed.scheme not in ("http", "https"):
                continue

            path = parsed.path
            if not path.startswith("/"):
                path = "/" + path
            if parsed.query:
                path += "?" + parsed.query
            if path and path != "/":
                links.add(path)

        links_list = list(links)[:30]
        if not links_list:
            return results

        crawled = list(await asyncio.gather(*[_fetch_one(client, base_url, p) for p in links_list]))
        results.extend(crawled)
        return results
