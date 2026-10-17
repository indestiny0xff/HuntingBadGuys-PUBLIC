from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import httpx

from ..config import settings

log = logging.getLogger(__name__)

_DEFAULT_DB = Path("data/GeoLite2-City.mmdb")
_REFRESH_SECS = 86_400  # 24 h

_reader = None
_db_path: Path = _DEFAULT_DB


# ── Download ──────────────────────────────────────────────────────────────────


async def _download(path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".mmdb.tmp")
    log.info("GeoIP: downloading %s → %s", settings.geoip_download_url, path)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=180) as client:
            async with client.stream("GET", settings.geoip_download_url) as resp:
                if resp.status_code != 200:
                    log.warning("GeoIP download failed: HTTP %s", resp.status_code)
                    return False
                with open(tmp, "wb") as fh:
                    async for chunk in resp.aiter_bytes(65_536):
                        fh.write(chunk)
        tmp.replace(path)
        log.info("GeoIP: download complete (%s)", path)
        return True
    except Exception as exc:
        log.warning("GeoIP download error: %s", exc)
        tmp.unlink(missing_ok=True)
        return False


# ── Reader ────────────────────────────────────────────────────────────────────


def _load(path: Path) -> bool:
    global _reader
    if not path.exists():
        return False
    try:
        import geoip2.database

        new = geoip2.database.Reader(str(path))
        old = _reader
        _reader = new
        if old:
            try:
                old.close()
            except Exception:
                pass
        log.info("GeoIP: loaded %s", path)
        return True
    except Exception as exc:
        log.warning("GeoIP: could not load %s — %s", path, exc)
        return False


# ── Background refresh ────────────────────────────────────────────────────────


async def _refresh_loop(path: Path) -> None:
    while True:
        await asyncio.sleep(_REFRESH_SECS)
        log.info("GeoIP: 24 h refresh triggered")
        if await _download(path):
            _load(path)


# ── Public init ───────────────────────────────────────────────────────────────


async def init(db_path_override: str = "") -> asyncio.Task:
    """
    Initialise GeoIP:
    1. Resolve path (override → default `data/GeoLite2-City.mmdb`).
    2. Download if the file is absent.
    3. Load the mmdb reader.
    4. Start a background task that re-downloads every 24 h.
    Returns the background Task (cancel it on shutdown).
    """
    global _db_path
    _db_path = Path(db_path_override) if db_path_override else _DEFAULT_DB

    if not _db_path.exists():
        await _download(_db_path)

    _load(_db_path)
    return asyncio.create_task(_refresh_loop(_db_path))


# ── Lookup ────────────────────────────────────────────────────────────────────


def _lookup_sync(ip: str) -> dict[str, Any] | None:
    if _reader is None:
        return None
    try:
        r = _reader.city(ip)
        city_name = r.city.name
        if not city_name and r.subdivisions:
            city_name = r.subdivisions.most_specific.name

        return {
            "country_iso": r.country.iso_code,
            "country_name": r.country.name,
            "city": city_name,
            "continent": r.continent.name,
            "latitude": r.location.latitude,
            "longitude": r.location.longitude,
            "timezone": r.location.time_zone,
            "postal_code": r.postal.code,
        }
    except Exception:
        return None


async def lookup(ip: str) -> dict[str, Any] | None:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _lookup_sync, ip)


async def lookup_many(ips: list[str]) -> dict[str, dict[str, Any]]:
    results = await asyncio.gather(*[lookup(ip) for ip in ips])
    return {ip: geo for ip, geo in zip(ips, results) if geo}
