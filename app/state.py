"""Per-user in-memory stores.

The in-memory dicts are the primary read store; every write is mirrored to
PostgreSQL by the route handlers (write-through). On startup the lifespan
hydrates them from the database.
"""

from __future__ import annotations

from typing import Any

from .models import AlertNotification, AlertRule, Case, Folder

_stores: dict[str, dict[str, Any]] = {}
_target_indexes: dict[str, dict[str, str]] = {}
_user_alerts: dict[str, dict[str, AlertRule]] = {}
_user_cases: dict[str, dict[str, Case]] = {}
_user_folders: dict[str, dict[str, Folder]] = {}
_user_notifications: dict[str, list[AlertNotification]] = {}


def _store_for(uid: str) -> dict[str, Any]:
    return _stores.setdefault(uid, {})


def _index_for(uid: str) -> dict[str, str]:
    return _target_indexes.setdefault(uid, {})


def _alerts_for(uid: str) -> dict[str, AlertRule]:
    return _user_alerts.setdefault(uid, {})


def _cases_for(uid: str) -> dict[str, Case]:
    return _user_cases.setdefault(uid, {})


def _folders_for(uid: str) -> dict[str, Folder]:
    return _user_folders.setdefault(uid, {})


def _notifications_for(uid: str) -> list[AlertNotification]:
    return _user_notifications.setdefault(uid, [])
