"""PostgreSQL persistence layer (asyncpg).

Write-through cache pattern: in-memory dicts are the primary read store,
every write is also mirrored to PostgreSQL. On startup all rows are loaded
back into memory so the process resumes where it left off.

Falls back to a silent no-op when HUNTER_DB_DSN is not set, preserving
the original in-memory-only behaviour.
"""

from __future__ import annotations

import json
import logging
import pathlib
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)


def _strip_nul(o: Any) -> Any:
    """Recursively drop NUL (\\u0000) chars — PostgreSQL jsonb cannot store them
    (asyncpg raises UntranslatableCharacterError). Report HTML / extracted file
    content (hex dumps, dex, strings) routinely contain NUL bytes."""
    if isinstance(o, str):
        return o.replace("\x00", "") if "\x00" in o else o
    if isinstance(o, list):
        return [_strip_nul(x) for x in o]
    if isinstance(o, dict):
        return {k: _strip_nul(v) for k, v in o.items()}
    return o


def _json_pg(obj: Any) -> str:
    """JSON-serialise for a jsonb column, with NUL chars stripped."""
    return json.dumps(_strip_nul(obj))


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    if isinstance(s, datetime):
        return s
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


# ── No-op fallback ────────────────────────────────────────────────────────────


class _NullDB:
    async def load_all(self) -> dict:
        return {}

    async def save_result(self, uid: str, result: dict) -> None: ...
    async def delete_result(self, uid: str, result_id: str) -> None: ...
    async def clear_results(self, uid: str) -> None: ...
    async def patch_result(self, uid: str, result_id: str, updates: dict) -> None: ...

    async def save_case(self, uid: str, case: dict) -> None: ...
    async def delete_case(self, uid: str, case_id: str) -> None: ...

    async def save_folder(self, uid: str, folder: dict) -> None: ...
    async def delete_folder(self, uid: str, folder_id: str) -> None: ...

    async def save_alert(self, uid: str, alert: dict) -> None: ...
    async def delete_alert(self, uid: str, alert_id: str) -> None: ...
    async def patch_alert_hashes(self, uid: str, alert_id: str, hashes: dict) -> None: ...

    async def save_notification(self, uid: str, notif: dict) -> None: ...
    async def delete_notification(self, uid: str, notif_id: str) -> None: ...
    async def clear_notifications(self, uid: str) -> None: ...

    async def save_user(self, user: dict) -> None: ...
    async def soft_delete_user(self, user_id: str) -> None: ...
    async def save_api_key(self, key: dict) -> None: ...
    async def delete_api_key(self, key_id: str) -> None: ...
    async def touch_api_key(self, key_id: str, when: str) -> None: ...

    async def get_result(self, result_id: str) -> dict | None:
        return None

    async def get_result_for_viewer(self, result_id: str, viewer_id: str) -> dict | None:
        return None

    async def get_public_results_page(
        self,
        limit: int = 1000,
        offset: int = 0,
        kind: str | None = None,
        compact: bool = False,
    ) -> tuple[int, list[dict]]:
        return 0, []

    async def get_feed_results_page(
        self,
        viewer_id: str,
        limit: int = 1000,
        offset: int = 0,
        kind: str | None = None,
        exclude_uids: list[str] | None = None,
        compact: bool = False,
    ) -> tuple[int, list[dict]]:
        return 0, []

    async def list_published_posts(self, limit: int = 50, offset: int = 0) -> list[dict]:
        return []

    async def list_all_posts(self) -> list[dict]:
        return []

    async def get_post_by_slug(self, slug: str) -> dict | None:
        return None

    async def upsert_post(self, post: dict) -> None: ...
    async def delete_post(self, post_id: str) -> None: ...
    async def get_post_by_case(self, case_id: str) -> dict | None:
        return None

    async def set_post_published(self, slug: str, published: bool) -> bool:
        return False


# ── PostgreSQL implementation ─────────────────────────────────────────────────


class _PostgresDB:
    """asyncpg connection pool wrapper."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    # -- helpers ------------------------------------------------------------------

    @staticmethod
    def _json(obj: Any) -> str:
        return json.dumps(_strip_nul(obj), default=str)

    # -- Bulk load on startup -----------------------------------------------------

    async def load_all(self) -> dict:
        out: dict = {
            "results": {},
            "result_index": {},
            "cases": {},
            "folders": {},
            "alerts": {},
            "notifications": {},
            "users": [],
            "api_keys": [],
        }
        async with self._pool.acquire() as conn:
            # Users
            try:
                rows = await conn.fetch(
                    "SELECT id, username, hashed_password, created_at, email, "
                    "auth_provider, sso_subject, is_admin FROM users WHERE is_deleted = FALSE"
                )
                for r in rows:
                    out["users"].append(
                        {
                            "id": r["id"],
                            "username": r["username"],
                            "hashed_password": r["hashed_password"] or None,
                            "created_at": str(r["created_at"]),
                            "email": r["email"],
                            "auth_provider": r["auth_provider"] or "local",
                            "sso_subject": r["sso_subject"],
                            "is_admin": bool(r["is_admin"]),
                        }
                    )
            except Exception as exc:
                log.warning("DB load users: %s", exc)

            # Results (strip screenshot bytes at load time to keep memory lean)
            try:
                rows = await conn.fetch("SELECT id, user_id, data, has_screenshot FROM results")
                for r in rows:
                    uid = r["user_id"]
                    data: dict = r["data"] if isinstance(r["data"], dict) else json.loads(r["data"])
                    lean = {k: v for k, v in data.items() if k != "screenshot"}
                    lean["has_screenshot"] = bool(r["has_screenshot"] or data.get("screenshot"))
                    rid = r["id"]
                    out["results"].setdefault(uid, {})[rid] = lean
                    target = lean.get("target", "")
                    if target:
                        out["result_index"].setdefault(uid, {})[target] = rid
            except Exception as exc:
                log.warning("DB load results: %s", exc)

            # Cases
            try:
                rows = await conn.fetch("SELECT id, user_id, data FROM cases")
                for r in rows:
                    data = r["data"] if isinstance(r["data"], dict) else json.loads(r["data"])
                    out["cases"].setdefault(r["user_id"], {})[r["id"]] = data
            except Exception as exc:
                log.warning("DB load cases: %s", exc)

            # Folders
            try:
                rows = await conn.fetch("SELECT id, user_id, data FROM folders")
                for r in rows:
                    data = r["data"] if isinstance(r["data"], dict) else json.loads(r["data"])
                    out["folders"].setdefault(r["user_id"], {})[r["id"]] = data
            except Exception as exc:
                log.warning("DB load folders: %s", exc)

            # Alert rules
            try:
                rows = await conn.fetch("SELECT id, user_id, data FROM alert_rules")
                for r in rows:
                    data = r["data"] if isinstance(r["data"], dict) else json.loads(r["data"])
                    out["alerts"].setdefault(r["user_id"], {})[r["id"]] = data
            except Exception as exc:
                log.warning("DB load alert_rules: %s", exc)

            # Notifications
            try:
                rows = await conn.fetch("SELECT id, user_id, data FROM notifications")
                for r in rows:
                    data = r["data"] if isinstance(r["data"], dict) else json.loads(r["data"])
                    out["notifications"].setdefault(r["user_id"], []).append(data)
            except Exception as exc:
                log.warning("DB load notifications: %s", exc)

            # API keys
            try:
                rows = await conn.fetch(
                    "SELECT id, user_id, name, key_hash, prefix, created_at, last_used_at FROM api_keys"
                )
                for r in rows:
                    out["api_keys"].append(
                        {
                            "id": r["id"],
                            "user_id": r["user_id"],
                            "name": r["name"],
                            "key_hash": r["key_hash"],
                            "prefix": r["prefix"],
                            "created_at": str(r["created_at"]),
                            "last_used_at": str(r["last_used_at"]) if r["last_used_at"] else None,
                        }
                    )
            except Exception as exc:
                log.warning("DB load api_keys: %s", exc)

        return out

    # -- API keys -----------------------------------------------------------------

    async def save_api_key(self, key: dict) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO api_keys (id, user_id, name, key_hash, prefix, created_at, last_used_at)
                    VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz)
                    ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, last_used_at = EXCLUDED.last_used_at
                    """,
                    key["id"],
                    key["user_id"],
                    key["name"],
                    key["key_hash"],
                    key["prefix"],
                    _parse_ts(key.get("created_at")),
                    _parse_ts(key.get("last_used_at")),
                )
        except Exception as exc:
            log.warning("DB save_api_key: %s", exc)

    async def delete_api_key(self, key_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("DELETE FROM api_keys WHERE id = $1", key_id)
        except Exception as exc:
            log.warning("DB delete_api_key: %s", exc)

    async def touch_api_key(self, key_id: str, when: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE api_keys SET last_used_at = $2::timestamptz WHERE id = $1",
                    key_id,
                    _parse_ts(when),
                )
        except Exception as exc:
            log.warning("DB touch_api_key: %s", exc)

    # -- Results ------------------------------------------------------------------

    async def save_result(self, uid: str, result: dict) -> None:
        screenshot = result.get("screenshot")
        lean = {k: v for k, v in result.items() if k != "screenshot"}
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                async with self._pool.acquire() as conn:
                    has_ss = bool(screenshot)
                    if not screenshot:
                        # A prior successful capture for this id may already be
                        # stored (detail endpoints re-attach it from the
                        # screenshots table). Don't let a later re-scan whose
                        # capture happened to fail (e.g. a browser outage)
                        # stamp a bogus "capture failed" error onto a result
                        # that still visibly has a screenshot. Keep the flag
                        # true and drop the stale error.
                        existing_ss = await conn.fetchval(
                            "SELECT 1 FROM screenshots WHERE result_id = $1", result["_id"]
                        )
                        if existing_ss:
                            has_ss = True
                            errs = lean.get("errors")
                            if isinstance(errs, dict):
                                errs.pop("screenshot", None)
                    await conn.execute(
                        """
                        INSERT INTO results (id, user_id, target, is_private, has_screenshot, scanned_at, kind, data)
                        VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7, $8::jsonb)
                        ON CONFLICT (id) DO UPDATE SET
                            is_private = EXCLUDED.is_private,
                            has_screenshot = EXCLUDED.has_screenshot,
                            scanned_at = EXCLUDED.scanned_at,
                            kind = EXCLUDED.kind,
                            data = EXCLUDED.data
                        """,
                        result["_id"],
                        uid,
                        result.get("target", ""),
                        result.get("is_private", False),
                        has_ss,
                        _parse_ts(result.get("scanned_at")),
                        result.get("kind"),
                        self._json(lean),
                    )
                    if screenshot:
                        await conn.execute(
                            """
                            INSERT INTO screenshots (result_id, b64, phash)
                            VALUES ($1, $2, $3)
                            ON CONFLICT (result_id) DO UPDATE SET b64 = EXCLUDED.b64, phash = EXCLUDED.phash
                            """,
                            result["_id"],
                            screenshot,
                            result.get("screenshot_phash") or "",
                        )
                return
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    import asyncio as _aio

                    await _aio.sleep(0.5 * (2**attempt))
        log.error(
            "DB save_result failed after 3 attempts (uid=%s target=%s): %s",
            uid,
            result.get("target", "?"),
            last_exc,
        )

    async def delete_result(self, uid: str, result_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM results WHERE id = $1 AND user_id = $2", result_id, uid
                )
        except Exception as exc:
            log.warning("DB delete_result: %s", exc)

    async def clear_results(self, uid: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("DELETE FROM results WHERE user_id = $1", uid)
        except Exception as exc:
            log.warning("DB clear_results: %s", exc)

    async def patch_result(self, uid: str, result_id: str, updates: dict) -> None:
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT data FROM results WHERE id = $1 AND user_id = $2", result_id, uid
                )
                if not row:
                    return
                data: dict = (
                    row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
                )
                data.update(updates)
                extra = {}
                if "is_private" in updates:
                    extra["is_private"] = updates["is_private"]
                if extra:
                    await conn.execute(
                        "UPDATE results SET data = $1::jsonb, is_private = $2 WHERE id = $3 AND user_id = $4",
                        self._json(data),
                        extra["is_private"],
                        result_id,
                        uid,
                    )
                else:
                    await conn.execute(
                        "UPDATE results SET data = $1::jsonb WHERE id = $2 AND user_id = $3",
                        self._json(data),
                        result_id,
                        uid,
                    )
        except Exception as exc:
            log.warning("DB patch_result: %s", exc)

    # -- Cases --------------------------------------------------------------------

    async def save_case(self, uid: str, case: dict) -> None:
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO cases (id, user_id, data) VALUES ($1, $2, $3::jsonb)
                        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data
                        """,
                        case["id"],
                        uid,
                        self._json(case),
                    )
                return
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    import asyncio as _aio

                    await _aio.sleep(0.5 * (2**attempt))
        log.error(
            "DB save_case failed after 3 attempts (uid=%s case=%s): %s",
            uid,
            case.get("name", "?"),
            last_exc,
        )

    async def delete_case(self, uid: str, case_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("DELETE FROM cases WHERE id = $1 AND user_id = $2", case_id, uid)
        except Exception as exc:
            log.warning("DB delete_case: %s", exc)

    # -- Folders ------------------------------------------------------------------

    async def save_folder(self, uid: str, folder: dict) -> None:
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO folders (id, user_id, data) VALUES ($1, $2, $3::jsonb)
                        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data
                        """,
                        folder["id"],
                        uid,
                        self._json(folder),
                    )
                return
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    import asyncio as _aio

                    await _aio.sleep(0.5 * (2**attempt))
        log.error(
            "DB save_folder failed after 3 attempts (uid=%s folder=%s): %s",
            uid,
            folder.get("name", "?"),
            last_exc,
        )

    async def delete_folder(self, uid: str, folder_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM folders WHERE id = $1 AND user_id = $2", folder_id, uid
                )
        except Exception as exc:
            log.warning("DB delete_folder: %s", exc)

    # -- Alert rules --------------------------------------------------------------

    async def save_alert(self, uid: str, alert: dict) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO alert_rules (id, user_id, data) VALUES ($1, $2, $3::jsonb)
                    ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data
                    """,
                    alert["id"],
                    uid,
                    self._json(alert),
                )
        except Exception as exc:
            log.warning("DB save_alert: %s", exc)

    async def delete_alert(self, uid: str, alert_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM alert_rules WHERE id = $1 AND user_id = $2", alert_id, uid
                )
        except Exception as exc:
            log.warning("DB delete_alert: %s", exc)

    async def patch_alert_hashes(self, uid: str, alert_id: str, hashes: dict) -> None:
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow("SELECT data FROM alert_rules WHERE id = $1", alert_id)
                if not row:
                    return
                data: dict = (
                    row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
                )
                data["seen_hashes"] = hashes
                await conn.execute(
                    "UPDATE alert_rules SET data = $1::jsonb WHERE id = $2",
                    self._json(data),
                    alert_id,
                )
        except Exception as exc:
            log.warning("DB patch_alert_hashes: %s", exc)

    # -- Notifications ------------------------------------------------------------

    async def save_notification(self, uid: str, notif: dict) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO notifications (id, user_id, data) VALUES ($1, $2, $3::jsonb)
                    ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data
                    """,
                    notif["id"],
                    uid,
                    self._json(notif),
                )
        except Exception as exc:
            log.warning("DB save_notification: %s", exc)

    async def delete_notification(self, uid: str, notif_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM notifications WHERE id = $1 AND user_id = $2", notif_id, uid
                )
        except Exception as exc:
            log.warning("DB delete_notification: %s", exc)

    async def clear_notifications(self, uid: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("DELETE FROM notifications WHERE user_id = $1", uid)
        except Exception as exc:
            log.warning("DB clear_notifications: %s", exc)

    # -- Users --------------------------------------------------------------------

    async def save_user(self, user: dict) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO users (id, username, hashed_password, created_at, is_deleted,
                                       email, auth_provider, sso_subject, is_admin)
                    VALUES ($1, $2, $3, $4::timestamptz, FALSE, $5, $6, $7, $8)
                    ON CONFLICT (id) DO UPDATE SET
                        username = EXCLUDED.username,
                        hashed_password = EXCLUDED.hashed_password,
                        email = EXCLUDED.email,
                        auth_provider = EXCLUDED.auth_provider,
                        sso_subject = EXCLUDED.sso_subject,
                        is_admin = EXCLUDED.is_admin,
                        is_deleted = FALSE
                    """,
                    user["id"],
                    user["username"],
                    user.get("hashed_password") or "",
                    _parse_ts(user.get("created_at")),
                    user.get("email"),
                    user.get("auth_provider") or "local",
                    user.get("sso_subject"),
                    bool(user.get("is_admin", False)),
                )
        except Exception as exc:
            log.warning("DB save_user: %s", exc)

    async def soft_delete_user(self, user_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("UPDATE users SET is_deleted = TRUE WHERE id = $1", user_id)
        except Exception as exc:
            log.warning("DB soft_delete_user: %s", exc)

    async def get_result(self, result_id: str) -> dict | None:
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT data FROM results WHERE id = $1 LIMIT 1", result_id
                )
                if not row:
                    return None
                data: dict = (
                    row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
                )
                ss = await conn.fetchrow(
                    "SELECT b64, phash FROM screenshots WHERE result_id = $1 LIMIT 1", result_id
                )
                if ss:
                    data["screenshot"] = ss["b64"]
                    data["screenshot_phash"] = ss["phash"]
                return data
        except Exception as exc:
            log.warning("DB get_result: %s", exc)
            return None

    async def get_result_for_viewer(self, result_id: str, viewer_id: str) -> dict | None:
        """Like get_result, but applies Intel-feed visibility: a private result
        is only returned to its owner. Non-private results are returned to anyone."""
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT data, user_id, is_private FROM results WHERE id = $1 LIMIT 1",
                    result_id,
                )
                if not row:
                    return None
                if row["is_private"] and row["user_id"] != viewer_id:
                    return None
                data: dict = (
                    row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
                )
                ss = await conn.fetchrow(
                    "SELECT b64, phash FROM screenshots WHERE result_id = $1 LIMIT 1", result_id
                )
                if ss:
                    data["screenshot"] = ss["b64"]
                    data["screenshot_phash"] = ss["phash"]
                return data
        except Exception as exc:
            log.warning("DB get_result_for_viewer: %s", exc)
            return None

    # Compact card-view projection. The canonical copy lives pre-computed in
    # results.list_data (maintained by a BEFORE INSERT OR UPDATE trigger, see
    # init_db) so list pages never detoast the full result jsonb — some rows
    # reach 24 MB and every '->' access decompresses the whole document. The
    # template is instantiated with row="NEW" for the trigger function and
    # row="r" as a COALESCE fallback for rows the backfill hasn't reached.
    _COMPACT_PROJ_TPL = """jsonb_strip_nulls(jsonb_build_object(
        '_id',              {row}.data->'_id',
        'target',           {row}.data->'target',
        'kind',             {row}.data->'kind',
        'final_status',     {row}.data->'final_status',
        'final_url',        {row}.data->'final_url',
        'scanned_at',       {row}.data->'scanned_at',
        'is_private',       {row}.is_private,
        'screenshot_phash', {row}.data->'screenshot_phash',
        'cf', (COALESCE({row}.data->'final_headers' ? 'cf-ray', FALSE)
               OR COALESCE((SELECT bool_or(h->'response_headers' ? 'cf-ray')
                            FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof({row}.data->'chain')='array'
                                   THEN {row}.data->'chain' ELSE '[]'::jsonb END) h), FALSE)),
        'certs_count', CASE WHEN jsonb_typeof({row}.data->'certs')='array'
                            THEN jsonb_array_length({row}.data->'certs') ELSE 0 END,
        'whois', CASE WHEN jsonb_typeof({row}.data->'whois')='object'
                      THEN jsonb_build_object('registrar', {row}.data->'whois'->'registrar') END,
        'dns',   CASE WHEN jsonb_typeof({row}.data->'dns'->'A')='array'
                      THEN jsonb_build_object('A', {row}.data->'dns'->'A') END,
        'bgp',   CASE WHEN jsonb_typeof({row}.data->'bgp'->'asn')='object'
                      THEN jsonb_build_object('asn', jsonb_build_object(
                           'asn',             {row}.data->'bgp'->'asn'->'asn',
                           'asn_description', {row}.data->'bgp'->'asn'->'asn_description')) END,
        'geo',   CASE WHEN jsonb_typeof({row}.data->'geo')='object'
                      THEN jsonb_build_object(
                           'country_iso',  {row}.data->'geo'->'country_iso',
                           'country_name', {row}.data->'geo'->'country_name') END,
        'geo_ips', (SELECT jsonb_agg(DISTINCT jsonb_build_object(
                        'country_iso',  e->'country_iso',
                        'country_name', e->'country_name'))
                    FROM jsonb_array_elements(
                      CASE WHEN jsonb_typeof({row}.data->'geo_ips')='array'
                           THEN {row}.data->'geo_ips' ELSE '[]'::jsonb END) e
                    WHERE e->>'country_iso' IS NOT NULL)
    ))"""
    _COMPACT_DATA_SQL = "COALESCE(r.list_data, " + _COMPACT_PROJ_TPL.format(row="r") + ")"

    def _lean_page_row(self, row: Any, compact: bool) -> dict:
        d: dict = row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
        if compact:
            lean = d
            lean["has_screenshot"] = bool(row["has_screenshot"])
        else:
            lean = {k: v for k, v in d.items() if k != "screenshot"}
            lean["has_screenshot"] = bool(row["has_screenshot"] or d.get("screenshot"))
        if row["case_name"]:
            lean["_case_name"] = row["case_name"]
        if row["folder_name"]:
            lean["_folder_name"] = row["folder_name"]
        return lean

    async def get_public_results_page(
        self,
        limit: int = 1000,
        offset: int = 0,
        kind: str | None = None,
        compact: bool = False,
    ) -> tuple[int, list[dict]]:
        """Return (total_public, page_rows) straight from the DB, newest first.

        The DB is the source of truth for the public listing — the in-memory
        store can be empty or only partially hydrated after a restart, so the
        public page must not depend on it."""
        try:
            async with self._pool.acquire() as conn:
                where = "WHERE r.is_private = FALSE"
                params: list = []
                if kind:
                    params.append(kind)
                    where += f" AND r.data->>'kind' = ${len(params)}"
                total = await conn.fetchval(f"SELECT COUNT(*) FROM results r {where}", *params)
                params.extend([limit, offset])
                data_sel = self._COMPACT_DATA_SQL if compact else "r.data"
                # Paginate first, then join/project: the projection and the
                # cases/folders joins must only ever run over one page of rows,
                # never over the OFFSET rows being skipped.
                rows = await conn.fetch(
                    f"""SELECT {data_sel} AS data, r.has_screenshot,
                               c.data->>'name' AS case_name,
                               f.data->>'name' AS folder_name
                        FROM (SELECT r.* FROM results r
                              {where}
                              ORDER BY r.scanned_at DESC
                              LIMIT ${len(params) - 1} OFFSET ${len(params)}) r
                        LEFT JOIN cases c ON r.data->>'case_id' = c.id
                        LEFT JOIN folders f ON c.data->>'folder_id' = f.id
                        ORDER BY r.scanned_at DESC""",
                    *params,
                )
                out = [self._lean_page_row(row, compact) for row in rows]
                return int(total or 0), out
        except Exception as exc:
            log.warning("DB get_public_results_page: %s", exc)
            return 0, []

    async def get_feed_results_page(
        self,
        viewer_id: str,
        limit: int = 1000,
        offset: int = 0,
        kind: str | None = None,
        exclude_uids: list[str] | None = None,
        compact: bool = False,
    ) -> tuple[int, list[dict]]:
        """Authenticated team feed: every user's non-private results PLUS the
        viewer's own (including private), newest first. Mirrors
        get_public_results_page but with a viewer-aware visibility filter.

        Other users' private results are intentionally excluded. *exclude_uids*
        drops entire accounts (e.g. the bulk feed-ingest account)."""
        try:
            async with self._pool.acquire() as conn:
                params: list = [viewer_id]
                where = "WHERE (r.is_private = FALSE OR r.user_id = $1)"
                if exclude_uids:
                    params.append(list(exclude_uids))
                    where += f" AND r.user_id <> ALL(${len(params)})"
                if kind:
                    params.append(kind)
                    where += f" AND r.data->>'kind' = ${len(params)}"
                total = await conn.fetchval(f"SELECT COUNT(*) FROM results r {where}", *params)
                params.extend([limit, offset])
                data_sel = self._COMPACT_DATA_SQL if compact else "r.data"
                rows = await conn.fetch(
                    f"""SELECT {data_sel} AS data, r.has_screenshot,
                               c.data->>'name' AS case_name,
                               f.data->>'name' AS folder_name
                        FROM (SELECT r.* FROM results r
                              {where}
                              ORDER BY r.scanned_at DESC
                              LIMIT ${len(params) - 1} OFFSET ${len(params)}) r
                        LEFT JOIN cases c ON r.data->>'case_id' = c.id
                        LEFT JOIN folders f ON c.data->>'folder_id' = f.id
                        ORDER BY r.scanned_at DESC""",
                    *params,
                )
                out = [self._lean_page_row(row, compact) for row in rows]
                return int(total or 0), out
        except Exception as exc:
            log.warning("DB get_feed_results_page: %s", exc)
            return 0, []

    # -- Blog ---------------------------------------------------------------------

    async def list_published_posts(self, limit: int = 50, offset: int = 0) -> list[dict]:
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """SELECT id, slug, published_at, data FROM blog_posts
                       WHERE is_published = TRUE
                       ORDER BY published_at DESC LIMIT $1 OFFSET $2""",
                    limit,
                    offset,
                )
                return [self._post_row(r, body=False) for r in rows]
        except Exception as exc:
            log.warning("DB list_published_posts: %s", exc)
            return []

    async def list_all_posts(self) -> list[dict]:
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT id, slug, published_at, is_published, data FROM blog_posts ORDER BY published_at DESC"
                )
                return [self._post_row(r, body=False) for r in rows]
        except Exception as exc:
            log.warning("DB list_all_posts: %s", exc)
            return []

    async def get_post_by_slug(self, slug: str) -> dict | None:
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id, slug, published_at, is_published, data FROM blog_posts WHERE slug = $1",
                    slug,
                )
                return self._post_row(row, body=True) if row else None
        except Exception as exc:
            log.warning("DB get_post_by_slug: %s", exc)
            return None

    async def upsert_post(self, post: dict) -> None:
        """post: {id, slug, is_published, published_at, data{...}}"""
        data = {
            k: v for k, v in post.items() if k not in ("id", "slug", "is_published", "published_at")
        }
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO blog_posts (id, slug, is_published, published_at, data)
                       VALUES ($1,$2,$3, COALESCE($4, NOW()), $5)
                       ON CONFLICT (id) DO UPDATE SET
                         slug = EXCLUDED.slug, is_published = EXCLUDED.is_published, data = EXCLUDED.data""",
                    post["id"],
                    post["slug"],
                    post.get("is_published", True),
                    post.get("published_at"),
                    _json_pg(data),
                )
        except Exception as exc:
            log.warning("DB upsert_post: %s", exc)
            raise

    async def delete_post(self, post_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("DELETE FROM blog_posts WHERE id = $1", post_id)
        except Exception as exc:
            log.warning("DB delete_post: %s", exc)

    async def get_post_by_case(self, case_id: str) -> dict | None:
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id, slug, published_at, is_published, data FROM blog_posts "
                    "WHERE data->>'case_id' = $1 ORDER BY published_at DESC LIMIT 1",
                    case_id,
                )
                return self._post_row(row, body=False) if row else None
        except Exception as exc:
            log.warning("DB get_post_by_case: %s", exc)
            return None

    async def set_post_published(self, slug: str, published: bool) -> bool:
        try:
            async with self._pool.acquire() as conn:
                res = await conn.execute(
                    "UPDATE blog_posts SET is_published = $2 WHERE slug = $1", slug, published
                )
                return res.endswith("1")
        except Exception as exc:
            log.warning("DB set_post_published: %s", exc)
            return False

    @staticmethod
    def _post_row(r, body: bool) -> dict:
        d: dict = r["data"] if isinstance(r["data"], dict) else json.loads(r["data"] or "{}")
        out = {
            "id": r["id"],
            "slug": r["slug"],
            "published_at": str(r["published_at"]) if r["published_at"] else None,
            "is_published": r.get("is_published", True),
            "title": d.get("title", ""),
            "summary": d.get("summary", ""),
            "author": d.get("author", ""),
            "tags": d.get("tags", []),
            "case_id": d.get("case_id"),
        }
        if body:
            out["body_html"] = d.get("body_html", "")
            out["body_md"] = d.get("body_md", "")
            out["stix"] = d.get("stix")
            out["report_html"] = d.get("report_html", "")
            out["graph_svg"] = d.get("graph_svg", "")
            out["graph_png"] = d.get("graph_png", "")
        return out


# ── Module singleton ──────────────────────────────────────────────────────────

_db: _NullDB | _PostgresDB = _NullDB()


def get_db() -> _NullDB | _PostgresDB:
    return _db


async def init_db(dsn: str) -> None:
    """Initialise asyncpg pool at startup. Safe to call with an empty string."""
    global _db
    if not dsn:
        log.info("DB_DSN not configured — results are in-memory only")
        _db = _NullDB()
        return
    log.info("Connecting to PostgreSQL")
    try:
        import asyncpg  # type: ignore[import]

        pool = await asyncpg.create_pool(dsn, min_size=2, max_size=20, command_timeout=30)
        _db = _PostgresDB(pool)
        log.info("PostgreSQL connected")
        # Apply the base schema (idempotent) so a fresh database needs no manual step.
        try:
            schema_path = pathlib.Path(__file__).resolve().parent.parent / "data" / "schema.sql"
            if schema_path.exists():
                async with pool.acquire() as conn:
                    await conn.execute(schema_path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("schema.sql apply: %s", exc)
        # Ensure the blog table exists (idempotent).
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """CREATE TABLE IF NOT EXISTS blog_posts (
                           id            TEXT        PRIMARY KEY,
                           slug          TEXT        NOT NULL UNIQUE,
                           is_published  BOOLEAN     NOT NULL DEFAULT TRUE,
                           published_at  TIMESTAMPTZ DEFAULT NOW(),
                           data          JSONB       NOT NULL DEFAULT '{}'
                       );
                       CREATE INDEX IF NOT EXISTS blog_posts_pub
                           ON blog_posts (is_published, published_at DESC);"""
                )
        except Exception as exc:
            log.warning("blog_posts DDL: %s", exc)
        # results.list_data: pre-computed compact card projection, maintained by
        # trigger so list pages never detoast multi-MB result documents.
        # Existing rows are backfilled separately (batched
        # "UPDATE results SET list_data = NULL WHERE list_data IS NULL" — the
        # trigger recomputes); until then queries COALESCE to a live projection.
        try:
            async with pool.acquire() as conn:
                proj_new = _PostgresDB._COMPACT_PROJ_TPL.format(row="NEW")
                await conn.execute(
                    f"""ALTER TABLE results ADD COLUMN IF NOT EXISTS list_data JSONB;
                        CREATE INDEX IF NOT EXISTS results_scanned_at
                            ON results (scanned_at DESC);
                        CREATE INDEX IF NOT EXISTS results_public_scanned_at
                            ON results (scanned_at DESC) WHERE is_private = FALSE;
                        CREATE OR REPLACE FUNCTION results_compute_list_data()
                        RETURNS trigger AS $fn$
                        BEGIN
                            NEW.list_data := {proj_new};
                            RETURN NEW;
                        END $fn$ LANGUAGE plpgsql;
                        DROP TRIGGER IF EXISTS trg_results_list_data ON results;
                        CREATE TRIGGER trg_results_list_data
                            BEFORE INSERT OR UPDATE ON results
                            FOR EACH ROW EXECUTE FUNCTION results_compute_list_data();"""
                )
        except Exception as exc:
            log.warning("results.list_data DDL: %s", exc)
    except ImportError:
        log.warning("asyncpg not installed — in-memory only (pip install asyncpg)")
        _db = _NullDB()
    except Exception as exc:
        log.error("PostgreSQL init failed (%s) — falling back to in-memory", exc)
        _db = _NullDB()


async def close_db() -> None:
    global _db
    if isinstance(_db, _PostgresDB):
        try:
            await _db._pool.close()
            log.info("PostgreSQL pool closed")
        except Exception as exc:
            log.warning("DB close: %s", exc)
