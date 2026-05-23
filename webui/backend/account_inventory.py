"""Read local pipeline account records and summarize reuse readiness.

This module is read-only: it never returns token values, only booleans/status
labels derived from the local SQLite runtime database.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .db import describe_database, get_db


_OAUTH_TRANSIENT_COOLDOWN_S = 6 * 3600


def _norm_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _live_plan_state(last_check_status: str, last_check_message: str) -> str:
    if str(last_check_status or "") != "plan":
        return ""
    msg = str(last_check_message or "")
    if msg.startswith("plan_check:"):
        parts = msg.split(":", 3)
        return parts[1] if len(parts) > 1 else ""
    return ""


def _live_plan_type(last_check_message: str) -> str:
    msg = str(last_check_message or "")
    marker = ":plan="
    if marker not in msg:
        return ""
    val = msg.split(marker, 1)[1].split(":", 1)[0].strip()
    return "" if val == "-" else val


def _latest_registered_accounts() -> tuple[list[dict], dict[str, int]]:
    """Return newest row per email, newest first, plus per-email row counts."""
    rows = get_db().iter_registered_accounts()
    attempts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        email = _norm_email(row.get("email"))
        if email:
            attempts[email] = attempts.get(email, 0) + 1

    out: list[dict] = []
    seen: set[str] = set()
    for row in reversed(rows):
        if not isinstance(row, dict):
            continue
        email = _norm_email(row.get("email"))
        if not email or email in seen:
            continue
        item = dict(row)
        item["email"] = email
        out.append(item)
        seen.add(email)
    return out, attempts


def _payment_events() -> list[dict]:
    events: list[dict] = []

    for row in get_db().iter_pipeline_results():
        pay = row.get("payment") if isinstance(row.get("payment"), dict) else {}
        reg = row.get("registration") if isinstance(row.get("registration"), dict) else {}
        email = _norm_email(
            pay.get("email")
            or reg.get("email")
            or row.get("chatgpt_email")
            or row.get("email")
        )
        if not email:
            continue
        events.append({
            "source": "pipeline_batch",
            "ts": row.get("ts") or "",
            "email": email,
            "status": str(pay.get("status") or row.get("status") or ""),
            "error": str(pay.get("error") or row.get("error") or ""),
            "cpa_import": str(row.get("cpa_import") or ""),
        })

    for row in get_db().iter_card_results():
        email = _norm_email(row.get("chatgpt_email") or row.get("email"))
        if not email:
            continue
        events.append({
            "source": "card_results",
            "ts": row.get("ts") or "",
            "email": email,
            "status": str(row.get("status") or ""),
            "error": str(row.get("error") or ""),
            "session_id": row.get("session_id") or "",
            "channel": row.get("channel") or "",
            "has_refresh_token": bool(row.get("refresh_token")),
            "team_account_id": str(row.get("team_account_id") or ""),
        })

    # PayOnly/PayPal guest success is recorded first on the account row.  Treat
    # that marker as a payment event too, so inventory doesn't show "plus" with
    # blank/unpaid payment status when the final card_results row was not written
    # by older scripts.
    for row in get_db().iter_registered_accounts():
        email = _norm_email(row.get("email"))
        if not email:
            continue
        msg = str(row.get("last_check_message") or "")
        st = str(row.get("last_check_status") or "")
        if st == "plan" and "paypal_success" in msg.lower():
            ts = ""
            try:
                raw_ts = float(row.get("last_check_at") or 0)
                if raw_ts > 0:
                    ts = datetime.fromtimestamp(raw_ts, timezone.utc).isoformat()
            except Exception:
                ts = ""
            events.append({
                "source": "registered_accounts",
                "ts": ts,
                "email": email,
                "status": "succeeded",
                "error": msg,
                "session_id": "",
                "channel": "paypal_guest_payonly",
                "has_refresh_token": bool(row.get("refresh_token")),
                "team_account_id": "",
            })
    return events


def _team_emails(events: list[dict]) -> set[str]:
    return {ev["email"] for ev in events if ev.get("team_account_id")}


def _cpa_push_status_by_email(events: list[dict]) -> dict[str, str]:
    """Latest cpa_import status per email from pipeline_results.
    Values: '' (never tried) | 'ok' | 'no_rt' | 'fail_upload' | ..."""
    out: dict[str, str] = {}
    for ev in events:
        st = ev.get("cpa_import")
        if not st:
            continue
        out[ev["email"]] = st
    return out


def _plan_override_map() -> dict[str, str]:
    raw = get_db().get_runtime_json("inventory_plan_overrides", {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        email = _norm_email(k)
        plan = str(v or "").strip().lower()
        if email and plan in {"free", "plus", "team"}:
            out[email] = plan
    return out


def _derive_plan_tag(email: str, *, paid: bool, is_team: bool, overrides: dict[str, str] | None = None) -> str:
    override = (overrides or {}).get(_norm_email(email))
    if override:
        return override
    if is_team:
        return "team"
    if paid:
        return "plus"
    return "free"


def _latest_payment_by_email(events: list[dict]) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for ev in events:
        latest[ev["email"]] = ev
    return latest


def _payment_time_for_email(events: list[dict], email: str) -> str:
    target = _norm_email(email)
    fallback = ""
    for ev in events:
        if ev.get("email") != target:
            continue
        ts = str(ev.get("ts") or "")
        status = str(ev.get("status") or "").lower()
        err = str(ev.get("error") or "").lower()
        if status == "succeeded" or "user is already paid" in err:
            fallback = ts or fallback
    return fallback


def _refresh_token_emails() -> set[str]:
    emails: set[str] = set()
    for row in get_db().iter_registered_accounts():
        if not isinstance(row, dict) or not row.get("refresh_token"):
            continue
        email = _norm_email(row.get("email"))
        if email:
            emails.add(email)
    for row in get_db().iter_card_results():
        if not row.get("refresh_token"):
            continue
        email = _norm_email(row.get("chatgpt_email") or row.get("email"))
        if email:
            emails.add(email)
    return emails


def _oauth_cooldown_remaining_s(oauth: dict) -> int:
    if str(oauth.get("status") or "") != "transient_failed":
        return 0
    try:
        ts = datetime.fromisoformat(str(oauth.get("ts") or ""))
    except Exception:
        return 0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
    return max(0, int(_OAUTH_TRANSIENT_COOLDOWN_S - elapsed))


def _rt_state(has_rt: bool, oauth: dict) -> str:
    if has_rt:
        return "has_rt"
    status = str(oauth.get("status") or "")
    if status == "succeeded":
        return "oauth_succeeded"
    if status == "dead":
        return "dead"
    if status == "transient_failed":
        return "cooldown" if _oauth_cooldown_remaining_s(oauth) > 0 else "retryable"
    return "missing"


def build_accounts_inventory() -> dict:
    accounts, attempts = _latest_registered_accounts()
    payment_events = _payment_events()
    latest_payment = _latest_payment_by_email(payment_events)
    consumed_emails: set[str] = set()
    for ev in payment_events:
        status = str(ev.get("status") or "").lower()
        err = str(ev.get("error") or "")
        if status == "succeeded" or "user is already paid" in err.lower():
            consumed_emails.add(ev["email"])
    team_emails = _team_emails(payment_events)
    cpa_status_by_email = _cpa_push_status_by_email(payment_events)
    oauth_map = get_db().load_oauth_status_map()
    rt_emails = _refresh_token_emails()
    plan_overrides = _plan_override_map()

    items: list[dict] = []
    counts = {
        "registered_total": len(accounts),
        "raw_registered_rows": sum(attempts.values()),
        "with_auth": 0,
        "pay_only_eligible": 0,
        "pay_only_consumed": 0,
        "pay_only_no_auth": 0,
        "with_refresh_token": 0,
        "rt_missing": 0,
        "rt_processed": 0,
        "rt_retryable": 0,
        "rt_cooldown": 0,
        "rt_dead": 0,
    }

    for acc in accounts:
        email = acc["email"]
        has_session = bool(acc.get("session_token"))
        has_access = bool(acc.get("access_token"))
        has_auth = has_session or has_access
        has_rt = email in rt_emails
        consumed = email in consumed_emails
        oauth = oauth_map.get(email.lower()) or oauth_map.get(email) or {}
        latest = latest_payment.get(email) or {}
        error = str(latest.get("error") or "")
        pay_state = "reusable"
        if consumed:
            pay_state = "consumed"
        elif not has_auth:
            pay_state = "no_auth"
        rt_state = _rt_state(has_rt, oauth)
        can_backfill_rt = rt_state in ("missing", "retryable")

        if has_auth:
            counts["with_auth"] += 1
        if pay_state == "reusable":
            counts["pay_only_eligible"] += 1
        elif pay_state == "consumed":
            counts["pay_only_consumed"] += 1
        else:
            counts["pay_only_no_auth"] += 1
        if has_rt:
            counts["with_refresh_token"] += 1
        if rt_state in ("has_rt", "oauth_succeeded"):
            counts["rt_processed"] += 1
        elif rt_state == "retryable":
            counts["rt_retryable"] += 1
        elif rt_state == "cooldown":
            counts["rt_cooldown"] += 1
        elif rt_state == "dead":
            counts["rt_dead"] += 1
        if rt_state == "missing":
            counts["rt_missing"] += 1

        plan_override = plan_overrides.get(_norm_email(email), "")
        live_plan_state = _live_plan_state(acc.get("last_check_status") or "", acc.get("last_check_message") or "")
        live_plan_type = _live_plan_type(acc.get("last_check_message") or "")
        live_paid = live_plan_state == "paid"
        live_free = live_plan_state == "free"
        if live_paid:
            consumed = True
            pay_state = "consumed"
        elif live_free and pay_state == "consumed":
            consumed = False
            pay_state = "reusable" if has_auth else "no_auth"
        plan_tag = _derive_plan_tag(
            email,
            paid=consumed,
            is_team=email in team_emails,
            overrides=plan_overrides,
        )
        if live_paid:
            plan_tag = "team" if live_plan_type == "team" else "plus"
        elif live_free:
            plan_tag = "free"
        cpa_status = cpa_status_by_email.get(email, "")
        cpa_pushed = cpa_status == "ok"
        items.append({
            "id": acc.get("id"),
            "email": email,
            "plan_tag": plan_tag,
            "plan_override": plan_override,
            "cpa_status": cpa_status,
            "cpa_pushed": cpa_pushed,
            "registered_at": acc.get("ts") or "",
            "attempts": attempts.get(email, 1),
            "has_session_token": has_session,
            "has_access_token": has_access,
            "has_device_id": bool(acc.get("device_id")),
            "has_refresh_token": has_rt,
            "pay_state": pay_state,
            "pay_only_eligible": pay_state == "reusable",
            "rt_state": rt_state,
            "can_backfill_rt": can_backfill_rt,
            "oauth_status": oauth.get("status") or "",
            "oauth_fail_reason": oauth.get("fail_reason") or "",
            "oauth_updated_at": oauth.get("ts") or "",
            "oauth_cooldown_remaining_s": _oauth_cooldown_remaining_s(oauth),
            "latest_payment_status": latest.get("status") or "",
            "latest_payment_source": latest.get("source") or "",
            "latest_payment_time": _payment_time_for_email(payment_events, email),
            "latest_payment_error": error[:200],
            "latest_payment_is_already_paid": "user is already paid" in error.lower(),
            "last_check_status": acc.get("last_check_status") or "",
            "last_check_message": acc.get("last_check_message") or "",
            "last_check_at": acc.get("last_check_at") or 0,
            "live_plan_state": live_plan_state,
            "live_plan_type": live_plan_type,
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": {
            "database": describe_database(get_db().path),
        },
        "counts": counts,
        "accounts": items,
    }
