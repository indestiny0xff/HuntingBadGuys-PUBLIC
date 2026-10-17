"""NT — Dynamic Network Traffic capture via Playwright sandbox.

Loads the target URL in an isolated browser context with stealth patches.
Same-origin requests are passed through so the page executes normally
(including self-deobfuscating JS). All cross-origin (outbound) requests
are intercepted, captured, and ABORTED — nothing actually leaves.

WebSocket connections are captured via page events; they cannot be aborted
via route() in Playwright, so container-level firewall rules provide the
hard guarantee for those.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_NAV_TIMEOUT_S = 20  # page.goto timeout (seconds)
_SETTLE_S = 5  # extra wait after load for deferred / beacon JS
_MAX_CAPTURE = 150  # hard cap on captured requests


async def capture(browser: Any, url: str, proxy: str | None = None) -> dict[str, Any]:
    """Load *url* in an isolated context, block all cross-origin traffic, return captured calls.

    Returns an empty dict when the browser is unavailable or nothing was captured.
    """
    if not browser:
        return {}

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    http_captured: list[dict] = []
    ws_caught: list[str] = []
    ctx = None

    try:
        ctx_kwargs: dict = dict(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            locale="en-US",
            timezone_id="America/New_York",
        )
        if proxy:
            ctx_kwargs["proxy"] = {"server": proxy}

        ctx = await browser.new_context(**ctx_kwargs)
        # Hide automation signals before any page scripts run
        await ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
        )
        page = await ctx.new_page()

        async def _intercept(route: Any) -> None:
            req = route.request
            req_url = req.url

            # Allow same-origin and data/blob URIs — page must load normally
            if (
                req_url.startswith(origin)
                or req_url.startswith("data:")
                or req_url.startswith("blob:")
            ):
                await route.continue_()
                return

            # Cross-origin: capture + abort (nothing leaves)
            if len(http_captured) < _MAX_CAPTURE:
                h = {
                    k: v
                    for k, v in (req.headers or {}).items()
                    if k.lower() not in ("cookie", "authorization", "x-api-key")
                }
                http_captured.append(
                    {
                        "url": req_url,
                        "method": req.method,
                        "resource_type": req.resource_type,
                        "post_data": (req.post_data or "")[:500],
                        "headers": h,
                    }
                )
            await route.abort("blockedbyclient")

        def _on_ws(ws: Any) -> None:
            # WebSocket connections can't be aborted via route(); capture the URL
            if ws.url not in ws_caught and not ws.url.startswith(origin):
                ws_caught.append(ws.url)

        await page.route("**/*", _intercept)
        page.on("websocket", _on_ws)

        try:
            await asyncio.wait_for(
                page.goto(url, wait_until="domcontentloaded"),
                timeout=_NAV_TIMEOUT_S,
            )
        except Exception:
            pass  # navigation errors are expected when cross-origin resources are blocked

        # Wait for deferred JS — setTimeout beacons, lazy fetch chains, etc.
        await asyncio.sleep(_SETTLE_S)

    except Exception as exc:
        log.warning("NT dynamic capture failed for %s: %s", url, exc)
    finally:
        if ctx:
            try:
                await ctx.close()
            except Exception:
                pass

    if not http_captured and not ws_caught:
        return {}

    return _format(http_captured, ws_caught)


def _format(captured: list[dict], ws_urls: list[str]) -> dict[str, Any]:
    """Map Playwright resource types to the NT schema the frontend expects."""
    seen: set[str] = set()
    result: dict[str, Any] = {"dynamic": True}

    for req in captured:
        key = f"{req['method']}:{req['url']}"
        if key in seen:
            continue
        seen.add(key)

        entry: dict[str, Any] = {"url": req["url"], "method": req["method"]}
        if req.get("post_data"):
            entry["post_data"] = req["post_data"]

        rtype = req["resource_type"]
        if rtype == "fetch":
            result.setdefault("fetch_calls", []).append(entry)
        elif rtype == "xhr":
            result.setdefault("xhr_calls", []).append(entry)
        else:
            # script, document, image, beacon, ping, etc.
            entry["resource_type"] = rtype
            result.setdefault("other_calls", []).append(entry)

    if ws_urls:
        result["websockets"] = ws_urls

    return result
