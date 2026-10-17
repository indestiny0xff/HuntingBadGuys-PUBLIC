"""Security helpers shared by routes and services.

- SSRF guard: refuse to touch private, loopback, link-local or reserved
  addresses unless the operator explicitly allows it.
- Log sanitiser: strip control characters from user-controlled strings before
  they reach a log line.
- Regex guard: reject oversized or obviously pathological user patterns.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse

from .config import settings

_MAX_REGEX_LEN = 256
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")


def sanitize_for_log(value: object, limit: int = 160) -> str:
    """Return a single-line, length-capped representation safe for logs."""
    text = str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text[:limit]


def is_safe_ip(ip: str) -> bool:
    """True when `ip` may be contacted.

    Non-IP strings return True so hostnames fall through to `is_safe_host`,
    which resolves them first.
    """
    if settings.allow_private_targets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_global and not addr.is_loopback and not addr.is_link_local


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_sync(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


async def is_safe_host(host: str) -> bool:
    """Resolve `host` and check every address against the SSRF policy.

    Hosts that do not resolve are considered safe: the request will simply
    fail at connection time. `.onion` hosts are only reachable through Tor and
    are always allowed.
    """
    if settings.allow_private_targets:
        return True
    host = host.strip("[]").lower()
    if host.endswith(".onion"):
        return True
    if is_valid_ip(host):
        return is_safe_ip(host)
    loop = asyncio.get_running_loop()
    addresses = await loop.run_in_executor(None, _resolve_sync, host)
    return all(is_safe_ip(addr) for addr in addresses)


async def is_safe_url(url: str) -> bool:
    """SSRF check for a full URL (scheme must be http/https)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    return await is_safe_host(parsed.hostname)


async def ssrf_request_hook(request) -> None:
    """httpx event hook: abort any request (including followed redirects) whose
    host resolves to a private address. Attach with
    ``httpx.AsyncClient(event_hooks={"request": [ssrf_request_hook]})``."""
    host = request.url.host
    if host and not await is_safe_host(host):
        raise RuntimeError(f"blocked request to private/internal host {host}")


def validate_user_regex(pattern: str) -> str:
    """Raise ValueError for user-supplied regexes that are too long or
    contain nested quantifiers (classic ReDoS shape)."""
    if len(pattern) > _MAX_REGEX_LEN:
        raise ValueError(f"regex longer than {_MAX_REGEX_LEN} characters")
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError("nested quantifiers are not allowed")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    return pattern
