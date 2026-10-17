from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import Any

import httpx

from ..config import settings
from ..models import RedirectHop
from ..security import is_safe_url

log = logging.getLogger(__name__)
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"


def _tls_info_sync(hostname: str, port: int = 443) -> dict[str, Any] | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                return {
                    "version": sock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "subject": {k: v for pair in cert.get("subject", []) for k, v in pair},
                    "issuer": {k: v for pair in cert.get("issuer", []) for k, v in pair},
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [v for _, v in cert.get("subjectAltName", [])],
                }
    except Exception:
        return None


async def _tls_info(url: str) -> dict[str, Any] | None:
    if not url.startswith("https://"):
        return None
    hostname = url.split("//", 1)[1].split("/")[0].split(":")[0]
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _tls_info_sync, hostname)


async def fetch(url: str, proxy: str | None = None, ua: str | None = None) -> list[RedirectHop]:
    """Follow redirects manually, capturing each hop's headers and TLS info."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    hops: list[RedirectHop] = []
    current_url = url
    seen: set[str] = set()

    client_kwargs: dict = dict(
        follow_redirects=False,
        timeout=settings.timeout,
        verify=False,
        headers={"User-Agent": ua or _UA},
    )
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        for _ in range(15):  # redirect limit
            if current_url in seen:
                break
            seen.add(current_url)

            if not proxy and not await is_safe_url(current_url):
                log.warning("SSRF_BLOCKED redirect hop %s", current_url)
                break
            try:
                resp = await client.get(current_url)
            except Exception as exc:
                log.warning("http error on %s: %s", current_url, exc)
                break

            tls = None if proxy else await _tls_info(current_url)
            hops.append(
                RedirectHop(
                    url=current_url,
                    status_code=resp.status_code,
                    response_headers={k.lower(): v for k, v in resp.headers.items()},
                    tls=tls,
                )
            )

            if resp.status_code not in (301, 302, 303, 307, 308):
                break

            location = resp.headers.get("location")
            if not location:
                break

            from urllib.parse import urljoin

            current_url = urljoin(current_url, location)

    return hops
