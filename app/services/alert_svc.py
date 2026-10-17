from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import smtplib
import textwrap
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from html import escape as html_escape
from typing import Any

from ..config import settings
from ..models import AlertNotification, AlertRule
from ..query.engine import filter_results

log = logging.getLogger(__name__)

# ── Hashing ───────────────────────────────────────────────────────────────────

_HASH_EXCLUDE = frozenset(
    {
        "_id",
        "scanned_at",
        "target",
        "kind",
        "case_id",
        "scan_url",
        "screenshot",  # base64 — huge; screenshot_phash covers visual changes
    }
)

# Section extractors — what to hash per section
_SECTIONS: dict[str, Any] = {
    "status": lambda r: r.get("final_status"),
    "dns": lambda r: r.get("dns"),
    "whois": lambda r: r.get("whois"),
    "chain": lambda r: [
        (h.get("url"), h.get("status_code"), h.get("response_headers"))
        for h in (r.get("chain") or [])
    ],
    "headers": lambda r: r.get("final_headers"),
    "root_files": lambda r: [
        (f.get("path"), f.get("status_code"), f.get("sha1")) for f in (r.get("root_files") or [])
    ],
    "crawled_files": lambda r: [
        (f.get("path"), f.get("status_code"), f.get("sha1")) for f in (r.get("crawled_files") or [])
    ],
    "screenshot": lambda r: r.get("screenshot_phash"),
    "geo": lambda r: r.get("geo") or r.get("geo_ips"),
    "bgp": lambda r: r.get("bgp"),
    "certs": lambda r: [(c.get("common_name"), c.get("not_after")) for c in (r.get("certs") or [])],
    "errors": lambda r: r.get("errors"),
}

_SECTION_LABELS = {
    "status": "HTTP Status",
    "dns": "DNS",
    "whois": "WHOIS",
    "chain": "HTTP Chain",
    "headers": "Headers",
    "root_files": "Root Files",
    "crawled_files": "Crawled Files",
    "screenshot": "Screenshot",
    "geo": "Geo IP",
    "bgp": "BGP / ASN",
    "certs": "Certificates",
    "errors": "Errors",
}


def _h(value: Any, length: int = 8) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[
        :length
    ]


def result_hash(r: dict) -> str:
    """Overall content hash (excludes identity/timestamp fields)."""
    data = {k: v for k, v in r.items() if k not in _HASH_EXCLUDE}
    return _h(data, 16)


def store_hashes(r: dict) -> dict[str, str]:
    """Compute section-level hashes for storing in seen_hashes."""
    out: dict[str, str] = {"_overall": result_hash(r)}
    for key, extractor in _SECTIONS.items():
        try:
            val = extractor(r)
            if val is not None:
                out[key] = _h(val)
        except Exception:
            pass
    return out


def diff_sections(old: dict | str, new_r: dict) -> list[str]:
    """Return human-readable list of sections that changed."""
    if isinstance(old, str):
        # old format — can't tell which sections
        return []
    new_secs = store_hashes(new_r)
    changed = []
    for key in _SECTIONS:
        old_h = old.get(key)
        new_h = new_secs.get(key)
        if old_h and new_h and old_h != new_h:
            changed.append(_SECTION_LABELS.get(key, key))
        elif not old_h and new_h:
            changed.append(_SECTION_LABELS.get(key, key))  # section appeared
    return changed


# ── Email ─────────────────────────────────────────────────────────────────────


def _build_html(alert: AlertRule, triggered: list[dict[str, Any]]) -> str:
    rows = ""
    for r in triggered:
        target = html_escape(str(r.get("target", "-")))
        kind = html_escape(str(r.get("kind", "-")).upper())
        status = html_escape(str(r.get("final_status", "") or ""))
        url = html_escape(str(r.get("final_url") or ""))
        ct = r.get("_change_type", "new")
        secs = r.get("_changed_sections", [])
        badge_color = "#22c55e" if ct == "new" else "#f59e0b"
        badge_label = "NEW" if ct == "new" else "CHANGED"
        secs_html = (
            f'<br><span style="color:#94a3b8;font-size:10px">{", ".join(secs)}</span>'
            if secs
            else ""
        )
        rows += f"""
        <tr>
          <td style="padding:6px 10px;border-bottom:1px solid #1e2d45;white-space:nowrap">
            <span style="background:{badge_color};color:#000;font-size:10px;font-weight:700;padding:1px 5px;border-radius:3px">{badge_label}</span>
            {secs_html}
          </td>
          <td style="padding:6px 10px;border-bottom:1px solid #1e2d45">{kind}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #1e2d45;font-family:monospace">{target}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #1e2d45;color:#6366f1">{status}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #1e2d45;font-family:monospace;font-size:11px">{url}</td>
        </tr>"""

    label = f" — {alert.case_name}" if alert.case_name else ""
    n_new = sum(1 for r in triggered if r.get("_change_type") == "new")
    n_chg = len(triggered) - n_new
    parts = ([f"{n_new} new"] if n_new else []) + ([f"{n_chg} changed"] if n_chg else [])
    case_html = (
        (
            f'<p style="color:#94a3b8;margin:0 0 8px">Case: '
            f'<code style="background:#0f1423;padding:1px 5px;border-radius:3px">{html_escape(alert.case_name)}</code></p>'
        )
        if alert.case_name
        else ""
    )
    app_name = html_escape(settings.app_name)
    schedule = (
        f"daily at {alert.scheduled_time} UTC"
        if alert.scheduled_time
        else f"every {alert.frequency_minutes} min"
    )

    return textwrap.dedent(f"""\
        <!DOCTYPE html><html>
        <body style="margin:0;padding:20px;background:#080c16;color:#e2e8f0;font-family:system-ui,sans-serif">
          <div style="max-width:740px;margin:auto">
            <h2 style="color:#6366f1;margin-bottom:4px">{app_name} Alert{label}</h2>
            <p style="color:#94a3b8;margin:0 0 8px"><strong style="color:#e2e8f0">{", ".join(parts)}</strong></p>
            {case_html}
            <table style="width:100%;border-collapse:collapse;background:#0f1423;border-radius:8px;overflow:hidden">
              <thead><tr style="background:#161d30">
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px">CHANGE</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px">KIND</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px">TARGET</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px">STATUS</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px">FINAL URL</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
            <p style="color:#64748b;font-size:11px;margin-top:16px">{app_name} &middot; {schedule}</p>
          </div>
        </body></html>
    """)


def _html_to_text(html: str) -> str:
    """Best-effort plain-text rendering of an HTML email body.

    A text/plain alternative part materially improves deliverability — HTML-only
    bodies are a common spam signal. Links are preserved as `text (url)`.
    """
    text = re.sub(r"(?is)<(script|style).*?</\1>", "", html)
    text = re.sub(
        r"(?i)<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
        lambda m: f"{re.sub(r'<[^>]+>', '', m.group(2)).strip()} ({m.group(1)})",
        text,
    )
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|h[1-6]|tr|li)>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


def _send_sync(
    to: str, subject: str, html: str, text: str | None = None, reply_to: str | None = None
) -> bool:
    """Send one email. Returns True if actually sent, False if SMTP is unconfigured."""
    if not settings.smtp_host:
        log.warning("SMTP not configured — skipping email to %s", to)
        return False
    from_addr = parseaddr(settings.smtp_from or settings.smtp_user)[1]
    domain = (from_addr.split("@", 1)[1] if "@" in from_addr else None) or "localhost"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = formataddr((settings.app_name, from_addr))
    msg["To"] = to
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    if reply_to:
        msg["Reply-To"] = reply_to
    # text/plain first, then text/html (clients pick the richest they support).
    msg.attach(MIMEText(text or _html_to_text(html), "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
        if settings.smtp_starttls:
            s.starttls()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password)
        s.sendmail(from_addr, [to], msg.as_string())
    log.info("Email sent to %s (subject: %s)", to, subject)
    return True


async def send_email(
    to: str, subject: str, html: str, text: str | None = None, reply_to: str | None = None
) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _send_sync, to, subject, html, text, reply_to)


# ── Scheduler tick ────────────────────────────────────────────────────────────


async def check_alerts(
    store: dict[str, dict[str, Any]],
    alerts: dict[str, AlertRule],
    notifications: list[AlertNotification],
) -> None:
    now = datetime.now(timezone.utc)
    for alert in list(alerts.values()):
        try:
            next_run = datetime.fromisoformat(alert.next_run)
            if next_run.tzinfo is None:
                next_run = next_run.replace(tzinfo=timezone.utc)
            if now < next_run:
                continue

            pool = [
                v
                for v in store.values()
                if (not alert.case_id or v.get("case_id") == alert.case_id)
            ]
            matching = filter_results(alert.query, pool)

            # Migration: seen_ids → seen_hashes silently
            if not alert.seen_hashes and alert.seen_ids:
                for r in matching:
                    rid = r.get("_id")
                    if rid and rid in alert.seen_ids:
                        alert.seen_hashes[rid] = store_hashes(r)
                alert.seen_ids = []
                _advance(alert, now)
                continue

            # Detect new / changed
            triggered: list[dict] = []
            for r in matching:
                rid = r.get("_id")
                if not rid:
                    continue
                stored = alert.seen_hashes.get(rid)
                cur_overall = result_hash(r)
                if stored is None:
                    triggered.append({**r, "_change_type": "new", "_changed_sections": []})
                else:
                    prev_overall = stored if isinstance(stored, str) else stored.get("_overall")
                    if prev_overall != cur_overall:
                        sections = diff_sections(stored, r)
                        triggered.append(
                            {**r, "_change_type": "changed", "_changed_sections": sections}
                        )

            # Update hashes for all seen results
            for r in matching:
                rid = r.get("_id")
                if rid:
                    alert.seen_hashes[rid] = store_hashes(r)

            if triggered:
                label = f" — {alert.case_name}" if alert.case_name else ""
                n_new = sum(1 for r in triggered if r["_change_type"] == "new")
                n_chg = len(triggered) - n_new
                parts = ([f"{n_new} new"] if n_new else []) + (
                    [f"{n_chg} changed"] if n_chg else []
                )
                subject = f"[{settings.app_name}]{label} {', '.join(parts)}"

                if alert.email:
                    await send_email(alert.email, subject, _build_html(alert, triggered))

                # Replace previous notification for this alert (keep only latest)
                for i in range(len(notifications) - 1, -1, -1):
                    if notifications[i].alert_id == alert.id:
                        notifications.pop(i)
                        break

                notifications.append(
                    AlertNotification(
                        id=str(uuid.uuid4()),
                        alert_id=alert.id,
                        case_id=alert.case_id,
                        case_name=alert.case_name,
                        triggered_at=now.isoformat(),
                        result_count=len(triggered),
                        results=[
                            {
                                "target": r.get("target"),
                                "kind": r.get("kind"),
                                "final_status": r.get("final_status"),
                                "_id": r.get("_id"),
                                "change_type": r.get("_change_type", "new"),
                                "changed_sections": r.get("_changed_sections", []),
                            }
                            for r in triggered
                        ],
                    )
                )

            _advance(alert, now)

        except Exception as exc:
            log.warning("Alert %s check failed: %s", alert.id, exc)


def _advance(alert: AlertRule, now: datetime) -> None:
    if alert.scheduled_time:
        h, m = map(int, alert.scheduled_time.split(":"))
        trigger = now.replace(hour=h, minute=m, second=0, microsecond=0)
        alert.next_run = (trigger + timedelta(days=1)).isoformat()
    else:
        alert.next_run = (now + timedelta(minutes=alert.frequency_minutes)).isoformat()
