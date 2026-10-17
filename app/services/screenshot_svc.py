from __future__ import annotations

import asyncio
import base64
import logging
from typing import TYPE_CHECKING

from ..config import settings

if TYPE_CHECKING:
    from playwright.async_api import Browser

log = logging.getLogger(__name__)

# ── Stealth JS patches ────────────────────────────────────────────────────────
# Injected before page navigation to hide Playwright/Chrome automation signals.
# These cover the most common bot-detection fingerprints without requiring the
# playwright-stealth package. If playwright-stealth is installed it will be
# applied on top of these patches for deeper evasion.
_STEALTH_JS = """
(function () {
  // 1. Hide webdriver flag
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

  // 2. Add realistic chrome.runtime stub
  if (!window.chrome) window.chrome = {};
  if (!window.chrome.runtime) window.chrome.runtime = {};

  // 3. Override permission query to look like a real browser
  const _origPerms = navigator.permissions.query.bind(navigator.permissions);
  navigator.permissions.query = (params) => {
    if (params.name === 'notifications') {
      return Promise.resolve({ state: Notification.permission, onchange: null });
    }
    return _origPerms(params);
  };

  // 4. Realistic plugin list
  Object.defineProperty(navigator, 'plugins', {
    get: () => {
      const arr = [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chrome PDF Viewer',  filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
        { name: 'Native Client',      filename: 'internal-nacl-plugin',  description: '' },
      ];
      arr.item = i => arr[i];
      arr.namedItem = n => arr.find(p => p.name === n);
      arr.refresh = () => {};
      Object.setPrototypeOf(arr, PluginArray.prototype);
      return arr;
    },
  });

  // 5. Realistic language list
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

  // 6. Proper hardware concurrency
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });

  // 7. Remove automation-specific properties
  delete navigator.__proto__.webdriver;
})();
"""

# Semaphore limiting concurrent pages (set during lifespan init)
_sem: asyncio.Semaphore | None = None


def init_semaphore(max_concurrent: int = 5) -> None:
    global _sem
    _sem = asyncio.Semaphore(max_concurrent)


def _phash_png(png_bytes: bytes) -> str | None:
    """
    Compute a 64-bit DCT-based perceptual hash from raw PNG bytes.
    Returns a 16-char lowercase hex string, or None on failure.

    Algorithm: resize to 32×32 greyscale → 2-pass 2D DCT → extract 8×8
    low-frequency block → compare each coefficient to the median → 63 bits
    packed into a 64-bit int.  More tolerant than dHash of brightness shifts,
    minor colour differences, and font/text changes while still matching
    visually similar pages (e.g. two Netflix phishing variants).
    """
    try:
        import io
        import math

        from PIL import Image

        img = Image.open(io.BytesIO(png_bytes)).convert("L").resize((32, 32), Image.LANCZOS)
        pixels = [float(p) for p in img.tobytes()]  # 1024 greyscale floats

        N = 32

        def _dct1d(vals: list) -> list:
            n = len(vals)
            out = []
            for k in range(n):
                s = 0.0
                for i in range(n):
                    s += vals[i] * math.cos(math.pi * k * (2 * i + 1) / (2 * n))
                out.append(s)
            return out

        # Row-wise DCT
        row_dct = [_dct1d(pixels[r * N : (r + 1) * N]) for r in range(N)]
        # Column-wise DCT on the row-DCT output
        dct2 = [[0.0] * N for _ in range(N)]
        for c in range(N):
            col = _dct1d([row_dct[r][c] for r in range(N)])
            for r in range(N):
                dct2[r][c] = col[r]

        # Extract 8×8 low-frequency block, skip DC coefficient at [0][0]
        low_freq = [dct2[r][c] for r in range(8) for c in range(8) if not (r == 0 and c == 0)]

        median = sorted(low_freq)[len(low_freq) // 2]
        bits = 0
        for v in low_freq:
            bits = (bits << 1) | (1 if v > median else 0)

        return f"{bits:016x}"
    except Exception as exc:
        log.debug("phash failed: %s", exc)
        return None


async def _apply_stealth(page) -> None:
    """Apply JS stealth patches and optionally use playwright-stealth package."""
    await page.add_init_script(_STEALTH_JS)
    if settings.stealth_mode:
        try:
            from playwright_stealth import Stealth  # type: ignore[import]

            await Stealth().apply_stealth_async(page)
        except Exception as exc:  # optional dependency, built-in patches still apply
            log.debug("playwright-stealth unavailable: %s", exc)


# Cookie/consent dialog selectors — covers Google, GDPR banners, OneTrust, etc.
_CONSENT_SELECTORS = [
    # Google consent
    'button[aria-label="Accept all"]',
    'button[aria-label="Agree to the use of cookies and other data for the purposes described"]',
    "#L2AGLb",  # Google "I agree" button
    'form[action*="consent"] button[type="submit"]',
    # OneTrust / common GDPR banners
    "#onetrust-accept-btn-handler",
    ".onetrust-accept-btn-handler",
    '[id*="accept"][id*="cookie"]',
    '[class*="accept"][class*="cookie"]',
    'button[id*="acceptAll"]',
    'button[id*="accept-all"]',
    # Generic patterns
    'button:has-text("Accept all")',
    'button:has-text("Accept All")',
    'button:has-text("Accept all cookies")',
    'button:has-text("Allow all")',
    'button:has-text("I agree")',
    'button:has-text("Agree")',
    'button:has-text("Got it")',
    'button:has-text("OK")',
]


async def _dismiss_consent(page) -> None:
    """Try to click away cookie consent / GDPR banners."""
    for sel in _CONSENT_SELECTORS:
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                await el.click(timeout=1500)
                await asyncio.sleep(0.5)
                log.debug("dismissed consent dialog: %s", sel)
                return
        except Exception:
            continue


async def capture(
    browser: Browser, url: str, proxy: str | None = None
) -> tuple[str | None, str | None]:
    """Return (base64_png, phash) or (None, None) on failure. Only call when status==200."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    sem = _sem or asyncio.Semaphore(1)
    async with sem:
        ctx = None
        try:
            # Hard cap on the whole capture. Individual playwright calls have
            # their own timeouts, but a wedged browser makes new_context()/
            # screenshot() hang forever — which would leak this semaphore
            # permit and eventually block every analyse request that has a
            # live target.
            async with asyncio.timeout(90):
                ctx_kwargs: dict = dict(
                    viewport={
                        "width": settings.screenshot_width,
                        "height": settings.screenshot_height,
                    },
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
                page = await ctx.new_page()
                await _apply_stealth(page)

                try:
                    await page.goto(
                        url, timeout=settings.timeout * 1_000, wait_until="domcontentloaded"
                    )
                except Exception:
                    # Try networkidle fallback
                    try:
                        await page.goto(url, timeout=settings.timeout * 1_000, wait_until="load")
                    except Exception:
                        pass

                # Wait for page to settle, then dismiss any consent dialogs
                await asyncio.sleep(1.5)
                await _dismiss_consent(page)
                await asyncio.sleep(0.5)

                data = await page.screenshot(full_page=False)
                b64 = base64.b64encode(data).decode()
                phash = _phash_png(data)
                return b64, phash
        except TimeoutError:
            log.warning(
                "screenshot hard-timeout (90s) %s — browser may be wedged, closing it for relaunch",
                url,
            )
            try:
                await asyncio.wait_for(browser.close(), 10)
            except Exception:
                pass
            return None, None
        except Exception as exc:
            log.warning("screenshot failed %s: %s", url, exc)
            return None, None
        finally:
            if ctx:
                try:
                    await asyncio.wait_for(ctx.close(), 10)
                except Exception:
                    pass
