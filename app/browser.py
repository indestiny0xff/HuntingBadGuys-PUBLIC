"""Shared Playwright browser: launch, responsiveness probe and relaunch.

One Chromium instance is shared by screenshots, network-traffic capture and
Cloudflare download fallbacks. A wedged browser (connected but every
new_context() hangs) would otherwise starve every scan, so callers go through
`ensure_browser()` which probes and relaunches as needed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from playwright.async_api import async_playwright

log = logging.getLogger(__name__)

BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-zygote",
]

_playwright: Any = None
_browser: Any = None
_lock = asyncio.Lock()


async def start() -> Any:
    """Launch the Playwright driver and the shared browser. Returns the browser."""
    global _playwright, _browser
    _playwright = await async_playwright().start()
    _browser = await _playwright.chromium.launch(args=BROWSER_ARGS)
    log.info("Browser launched")
    return _browser


async def stop() -> None:
    global _playwright, _browser
    if _browser is not None:
        try:
            await asyncio.wait_for(_browser.close(), 10)
        except Exception:
            pass
        _browser = None
    if _playwright is not None:
        try:
            await asyncio.wait_for(_playwright.stop(), 10)
        except Exception:
            pass
        _playwright = None
    log.info("Browser closed")


def current() -> Any:
    return _browser


async def _is_responsive(browser: Any) -> bool:
    if browser is None or not browser.is_connected():
        return False
    try:
        ctx = await asyncio.wait_for(browser.new_context(), 15)
        await asyncio.wait_for(ctx.close(), 10)
        return True
    except Exception:
        return False


async def ensure_browser() -> Any:
    """Return a live, responsive browser, relaunching Chromium (and the driver
    if necessary). Returns None when a relaunch fails; callers skip browser
    work gracefully in that case."""
    global _playwright, _browser
    if await _is_responsive(_browser):
        return _browser
    async with _lock:
        if await _is_responsive(_browser):
            return _browser
        log.warning("Shared browser is dead or unresponsive, relaunching Chromium")
        if _browser is not None:
            try:
                await asyncio.wait_for(_browser.close(), 10)
            except Exception:
                pass
        try:
            _browser = await asyncio.wait_for(_playwright.chromium.launch(args=BROWSER_ARGS), 60)
        except Exception as exc:
            # launch() goes through the driver process; if that died every
            # launch fails forever, so restart the whole driver.
            log.error("Chromium relaunch failed: %r, restarting the Playwright driver", exc)
            try:
                try:
                    await asyncio.wait_for(_playwright.stop(), 15)
                except Exception:
                    pass
                _playwright = await asyncio.wait_for(async_playwright().start(), 60)
                _browser = await asyncio.wait_for(
                    _playwright.chromium.launch(args=BROWSER_ARGS), 60
                )
                log.info("Playwright driver restarted, Chromium relaunched")
            except Exception as exc2:
                log.error(
                    "Playwright driver restart failed: %r, browser work will be skipped", exc2
                )
                _browser = None
                return None
        log.info("Chromium relaunched")
        return _browser
