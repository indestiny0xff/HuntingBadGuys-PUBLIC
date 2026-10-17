"""Alert rules, cached notifications and the manual alert test endpoint."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from .. import db as _db_module
from ..auth import get_current_user
from ..config import settings
from ..models import AlertNotification, AlertRule, AlertRuleCreate, UserInDB
from ..query.engine import filter_results
from ..query.engine import validate as query_validate
from ..services import alert_svc
from ..services.alert_svc import result_hash as _alert_result_hash
from ..services.alert_svc import store_hashes as _alert_store_hashes
from ..state import (
    _alerts_for,
    _cases_for,
    _notifications_for,
    _store_for,
    _user_notifications,
)

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/alerts")
async def list_alerts(
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    return JSONResponse([a.model_dump() for a in _alerts_for(current_user.id).values()])


@router.post("/alerts", status_code=201)
async def create_alert(
    req: AlertRuleCreate,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    store = _store_for(current_user.id)
    alerts = _alerts_for(current_user.id)
    now = datetime.now(timezone.utc)

    case_name: str | None = None
    if req.case_id:
        case = _cases_for(current_user.id).get(req.case_id)
        case_name = case.name if case else None

    # Pre-populate seen_hashes with all results currently in the case so
    # the first run only notifies about genuinely new or changed results.
    pool = [v for v in store.values() if not req.case_id or v.get("case_id") == req.case_id]
    initial_hashes = {v["_id"]: _alert_store_hashes(v) for v in pool if v.get("_id")}

    effective_query = req.query.strip() or 'kind == "domain" OR kind == "ip"'
    try:
        query_validate(effective_query)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Query syntax error: {exc}")

    # Validate and compute next_run for scheduled_time
    scheduled_time = req.scheduled_time
    if scheduled_time:
        try:
            h, m = map(int, scheduled_time.split(":"))
            assert 0 <= h <= 23 and 0 <= m <= 59
        except Exception:
            raise HTTPException(status_code=400, detail="scheduled_time must be HH:MM (UTC)")
        trigger_today = now.replace(hour=h, minute=m, second=0, microsecond=0)
        next_run = trigger_today if trigger_today > now else trigger_today + timedelta(days=1)
    else:
        next_run = now + timedelta(minutes=req.frequency_minutes)

    alert = AlertRule(
        id=str(uuid.uuid4()),
        email=req.email,
        query=effective_query,
        targets=[],
        case_id=req.case_id,
        case_name=case_name,
        label=req.label or case_name or "",
        frequency_minutes=req.frequency_minutes,
        scheduled_time=scheduled_time,
        created_at=now.isoformat(),
        next_run=next_run.isoformat(),
        seen_ids=[],
        seen_hashes=initial_hashes,
    )
    alerts[alert.id] = alert
    asyncio.create_task(_db_module.get_db().save_alert(current_user.id, alert.model_dump()))
    log.info(
        "Alert created by %s: case=%s → %s schedule=%s",
        current_user.username,
        case_name,
        req.email,
        scheduled_time or f"every {req.frequency_minutes}min",
    )
    return JSONResponse(alert.model_dump(), status_code=201)


@router.delete("/alerts/{alert_id}")
async def delete_alert(
    alert_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    _alerts_for(current_user.id).pop(alert_id, None)
    asyncio.create_task(_db_module.get_db().delete_alert(current_user.id, alert_id))
    return {"status": "ok"}


# ── Notifications (cached alert results) ─────────────────────────────────────


@router.get("/notifications")
async def list_notifications(
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    return JSONResponse([n.model_dump() for n in _notifications_for(current_user.id)])


@router.delete("/notifications/{notif_id}")
async def delete_notification(
    notif_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    notifs = _notifications_for(current_user.id)
    _user_notifications[current_user.id] = [n for n in notifs if n.id != notif_id]
    asyncio.create_task(_db_module.get_db().delete_notification(current_user.id, notif_id))
    return {"status": "ok"}


@router.delete("/notifications")
async def clear_notifications(
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    _user_notifications[current_user.id] = []
    asyncio.create_task(_db_module.get_db().clear_notifications(current_user.id))
    return {"status": "ok"}


@router.post("/alerts/{alert_id}/test")
async def test_alert(
    alert_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    alerts = _alerts_for(current_user.id)
    alert = alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    store = _store_for(current_user.id)
    pool = [v for v in store.values() if (not alert.case_id or v.get("case_id") == alert.case_id)]
    matching = filter_results(alert.query, pool)
    if not matching:
        return JSONResponse(
            {"sent": False, "cached": False, "matches": 0, "detail": "No results in this case yet"}
        )

    # Detect new vs changed using section-level hashes
    from .services.alert_svc import diff_sections as _diff_sections

    triggered = []
    for r in matching:
        rid = r.get("_id")
        if not rid:
            continue
        stored = alert.seen_hashes.get(rid)
        cur_overall = _alert_result_hash(r)
        if stored is None:
            triggered.append({**r, "_change_type": "new", "_changed_sections": []})
        else:
            prev_overall = stored if isinstance(stored, str) else stored.get("_overall")
            if prev_overall != cur_overall:
                sections = _diff_sections(stored, r)
                triggered.append({**r, "_change_type": "changed", "_changed_sections": sections})
            else:
                triggered.append({**r, "_change_type": "unchanged", "_changed_sections": []})

    notif_results = [r for r in triggered if r["_change_type"] != "unchanged"]
    if not notif_results:
        notif_results = triggered  # test always shows something

    # Replace previous notification for this alert, then append new one
    notifs = _notifications_for(current_user.id)
    for i in range(len(notifs) - 1, -1, -1):
        if notifs[i].alert_id == alert.id:
            notifs.pop(i)
            break
    notifs.append(
        AlertNotification(
            id=str(uuid.uuid4()),
            alert_id=alert.id,
            case_id=alert.case_id,
            case_name=alert.case_name,
            triggered_at=datetime.now(timezone.utc).isoformat(),
            result_count=len(notif_results),
            results=[
                {
                    "target": r.get("target"),
                    "kind": r.get("kind"),
                    "final_status": r.get("final_status"),
                    "_id": r.get("_id"),
                    "change_type": r.get("_change_type", "new"),
                    "changed_sections": r.get("_changed_sections", []),
                }
                for r in notif_results
            ],
        )
    )

    # Only send email if an address is configured
    if not alert.email:
        return JSONResponse(
            {
                "sent": False,
                "cached": True,
                "matches": len(matching),
                "detail": "Cached — no email address set",
            }
        )

    label = f" — {alert.case_name}" if alert.case_name else ""
    subject = (
        f"[{settings.app_name} TEST]{label} {len(matching)} "
        f"match{'es' if len(matching) != 1 else ''}"
    )
    html = alert_svc._build_html(alert, matching)
    try:
        await alert_svc.send_email(alert.email, subject, html)
    except Exception as exc:
        log.error("Test alert email failed for %s: %s", alert.email, exc)
        return JSONResponse(
            {
                "sent": False,
                "cached": True,
                "matches": len(matching),
                "detail": f"Cached — SMTP error: {exc}",
            }
        )
    return JSONResponse({"sent": True, "cached": True, "matches": len(matching)})
