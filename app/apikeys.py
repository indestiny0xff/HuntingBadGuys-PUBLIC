"""Per-user API keys.

Keys are random, shown once at creation and stored only as a SHA-256 hash.
They live in memory (hydrated from PostgreSQL, mirrored to ``api_keys.json``
in the data directory when no database is configured) and authenticate
requests through ``Authorization: Bearer <key>`` or ``X-API-Key: <key>``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import secrets
import time
import uuid
from datetime import datetime, timezone

from .config import settings
from .models import ApiKey

log = logging.getLogger(__name__)

KEY_PREFIX = "hbg_"
_MAX_KEYS_PER_USER = 20
_TOUCH_INTERVAL = 60  # seconds between last_used_at updates per key

_keys: dict[str, ApiKey] = {}  # key id -> ApiKey
_hash_index: dict[str, str] = {}  # sha256(key) -> key id
_last_touch: dict[str, float] = {}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _keys_file() -> pathlib.Path:
    return pathlib.Path(settings.data_dir) / "api_keys.json"


def _save_keys() -> None:
    try:
        path = _keys_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({k: v.model_dump() for k, v in _keys.items()}, indent=2))
        path.chmod(0o600)
    except Exception as exc:
        log.error("Failed to save API keys to disk: %s", exc)


def load_keys() -> None:
    """Load keys from ``api_keys.json`` (fallback when PostgreSQL is not used)."""
    try:
        path = _keys_file()
        if not path.exists():
            return
        for data in json.loads(path.read_text()).values():
            register(ApiKey(**data))
        log.info("Loaded %d API key(s) from %s", len(_keys), path)
    except Exception as exc:
        log.error("Failed to load API keys from disk: %s", exc)


def register(key: ApiKey) -> None:
    _keys[key.id] = key
    _hash_index[key.key_hash] = key.id


def keys_for_user(user_id: str) -> list[ApiKey]:
    return sorted((k for k in _keys.values() if k.user_id == user_id), key=lambda k: k.created_at)


def get(key_id: str) -> ApiKey | None:
    return _keys.get(key_id)


async def create(user_id: str, name: str) -> tuple[ApiKey, str]:
    """Create a key for `user_id`. Returns the record and the plaintext key
    (the only time it is available)."""
    from . import db as _db

    if len(keys_for_user(user_id)) >= _MAX_KEYS_PER_USER:
        raise ValueError(f"At most {_MAX_KEYS_PER_USER} API keys per account")
    token = KEY_PREFIX + secrets.token_urlsafe(32)
    key = ApiKey(
        id=str(uuid.uuid4()),
        user_id=user_id,
        name=name.strip()[:80] or "API key",
        key_hash=_hash(token),
        prefix=token[:12],
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    register(key)
    _save_keys()
    try:
        await _db.get_db().save_api_key(key.model_dump())
    except Exception as exc:
        log.warning("DB save_api_key failed: %s", exc)
    return key, token


async def revoke(key_id: str) -> bool:
    from . import db as _db

    key = _keys.pop(key_id, None)
    if not key:
        return False
    _hash_index.pop(key.key_hash, None)
    _last_touch.pop(key_id, None)
    _save_keys()
    try:
        await _db.get_db().delete_api_key(key_id)
    except Exception as exc:
        log.warning("DB delete_api_key failed: %s", exc)
    return True


async def revoke_all(user_id: str) -> int:
    count = 0
    for key in keys_for_user(user_id):
        if await revoke(key.id):
            count += 1
    return count


def resolve(token: str) -> ApiKey | None:
    """Return the key record for a plaintext token, updating last_used_at."""
    if not token or not token.startswith(KEY_PREFIX):
        return None
    key_id = _hash_index.get(_hash(token))
    key = _keys.get(key_id) if key_id else None
    if key is None:
        return None
    now = time.monotonic()
    if now - _last_touch.get(key.id, 0) > _TOUCH_INTERVAL:
        _last_touch[key.id] = now
        key.last_used_at = datetime.now(timezone.utc).isoformat()
        _save_keys()
        try:
            import asyncio

            from . import db as _db

            asyncio.get_running_loop().create_task(
                _db.get_db().touch_api_key(key.id, key.last_used_at)
            )
        except Exception:
            pass
    return key
