"""Detect a stored ChatGPT account's current paid/free plan.

Signals, strongest first:
  1. id_token JWT claim: https://api.openai.com/auth.chatgpt_plan_type
  2. refresh_token -> fresh access/id token, then the same id_token claim
  3. ChatGPT accounts/check: account.plan_type or entitlement.subscription_plan

The result is stored in registered_accounts.last_check_* using status='plan' so the
inventory page can show the live paid-state probe without adding another table.
"""
from __future__ import annotations

import base64
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional

import httpx
import requests

from .db import get_db


_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
_ACCOUNTS_CHECK_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
_SUBSCRIPTION_CHECK_URL = "https://chong.sxzfd.com/check.php"
_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
_PAID_PLANS = {"plus", "team", "pro", "enterprise", "business"}
_FREE_PLANS = {"", "free", "free_user", "freeuser"}


def _gost_alive(port: int = 18898) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _client(timeout: float, proxy: Optional[str]) -> httpx.Client:
    return httpx.Client(timeout=timeout, follow_redirects=False, proxy=proxy)


def _jwt_payload(token: str) -> dict:
    token = (token or "").strip()
    if token.count(".") < 2:
        return {}
    try:
        part = token.split(".")[1]
        part += "=" * ((4 - len(part) % 4) % 4)
        obj = json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _plan_from_id_token(id_token: str) -> str:
    payload = _jwt_payload(id_token)
    auth = payload.get("https://api.openai.com/auth") or {}
    if isinstance(auth, dict):
        return str(auth.get("chatgpt_plan_type") or "").strip().lower()
    return ""


def _normalize_plan(plan: object) -> str:
    s = str(plan or "").strip().lower()
    if s in {"chatgptplusplan", "plus_user"}:
        return "plus"
    if s in {"chatgptteamplan", "team_user"}:
        return "team"
    if s in {"freeuser"}:
        return "free"
    return s


def _classify(plan: str) -> str:
    plan = _normalize_plan(plan)
    if plan in _PAID_PLANS:
        return "paid"
    if plan in _FREE_PLANS:
        return "free"
    return "unknown"


def _build_cookie(account: dict) -> str:
    cookie_header = (account.get("cookie_header") or "").strip()
    if cookie_header:
        return cookie_header
    session_token = (account.get("session_token") or "").strip()
    if session_token:
        return f"__Secure-next-auth.session-token={session_token}"
    return ""


def _extract_accounts_check_plan(data: object) -> str:
    if not isinstance(data, dict):
        return ""
    account = data.get("account")
    if isinstance(account, dict):
        plan = _normalize_plan(account.get("plan_type") or account.get("planType"))
        if plan:
            return plan
    entitlement = data.get("entitlement")
    if isinstance(entitlement, dict):
        plan = _normalize_plan(entitlement.get("subscription_plan") or entitlement.get("subscriptionPlan"))
        if plan:
            return plan
    return ""


def _refresh_tokens(refresh_token: str, timeout: float, proxy: Optional[str]) -> tuple[str, str, str]:
    """Return (access_token, id_token, error)."""
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": _CODEX_CLIENT_ID,
        "scope": "openid profile email offline_access",
    }
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    try:
        with _client(timeout, proxy) as c:
            r = c.post(_OAUTH_TOKEN_URL, data=body, headers=headers)
    except httpx.TimeoutException:
        return "", "", "rt timeout"
    except (httpx.NetworkError, httpx.ProxyError) as e:
        return "", "", f"rt {type(e).__name__}"
    except Exception as e:
        return "", "", f"rt {type(e).__name__}: {str(e)[:80]}"
    if r.status_code != 200:
        try:
            err = r.json().get("error") or ""
        except Exception:
            err = ""
        return "", "", f"rt http {r.status_code} {err}".strip()
    try:
        data = r.json()
    except Exception:
        return "", "", "rt 200 non-json"
    return str(data.get("access_token") or ""), str(data.get("id_token") or ""), ""


def _accounts_check(account: dict, access_token: str, timeout: float, proxy: Optional[str]) -> tuple[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
        "Referer": "https://chatgpt.com/",
    }
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    cookie = _build_cookie(account)
    if cookie:
        headers["Cookie"] = cookie
    if not (access_token or cookie):
        return "", "accounts/check no bearer/cookie"
    params = {"timezone_offset_min": "-480"}
    try:
        with _client(timeout, proxy) as c:
            r = c.get(_ACCOUNTS_CHECK_URL, params=params, headers=headers)
    except httpx.TimeoutException:
        return "", "accounts/check timeout"
    except (httpx.NetworkError, httpx.ProxyError) as e:
        return "", f"accounts/check {type(e).__name__}"
    except Exception as e:
        return "", f"accounts/check {type(e).__name__}: {str(e)[:80]}"
    if r.status_code != 200:
        return "", f"accounts/check http {r.status_code}"
    try:
        return _extract_accounts_check_plan(r.json()), ""
    except Exception:
        return "", "accounts/check 200 non-json"


def _subscription_source_check(access_token: str, timeout: float) -> tuple[str, str]:
    """Return (plan, error) from the subscription-source token checker.

    This is a fallback for cases where ChatGPT accounts/check is blocked by
    Cloudflare/403 from this server. Never log or persist the token itself.
    """
    access_token = (access_token or "").strip()
    if not access_token:
        return "", "subscription/check no bearer"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
    }
    try:
        r = requests.post(
            _SUBSCRIPTION_CHECK_URL,
            json={"token": access_token},
            headers=headers,
            timeout=timeout,
        )
    except requests.Timeout:
        return "", "subscription/check timeout"
    except requests.RequestException as e:
        return "", f"subscription/check {type(e).__name__}"
    except Exception as e:
        return "", f"subscription/check {type(e).__name__}: {str(e)[:80]}"
    if r.status_code != 200:
        return "", f"subscription/check http {r.status_code}"
    try:
        data = r.json()
    except Exception:
        return "", "subscription/check 200 non-json"
    plan = _normalize_plan(data.get("planRaw") or data.get("planDisplay"))
    has_active = bool(data.get("hasActive"))
    subscription_id = str(data.get("subscriptionId") or "").strip()
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    product_code = str(source.get("productCode") or "").strip().lower()
    source_label = str(source.get("label") or "").strip().lower()
    if plan in _PAID_PLANS and has_active and subscription_id:
        return plan, ""
    if plan in _FREE_PLANS or (not has_active and not subscription_id and source_label == "chatgpt_not_purchased"):
        return "free", ""
    if product_code == "oai.chatgpt.plus" and has_active and subscription_id:
        return plan or "plus", ""
    return plan, "subscription/check no decisive plan"


def check_account_plan(account: dict, *, timeout_s: float = 10.0, use_proxy: bool = True) -> tuple[str, str, str]:
    """Return (state, plan_type, message); state ∈ paid|free|unknown|missing."""
    if not account:
        return "missing", "", "account not found"
    proxy = "socks5://127.0.0.1:18898" if use_proxy and _gost_alive() else None
    notes: list[str] = []

    id_plan = _plan_from_id_token(account.get("id_token") or "")
    if id_plan:
        state = _classify(id_plan)
        if state != "unknown":
            return state, id_plan, f"id_token chatgpt_plan_type={id_plan}"
        notes.append(f"id_token plan={id_plan}")

    access_token = (account.get("access_token") or "").strip()
    refresh_token = (account.get("refresh_token") or "").strip()
    if refresh_token:
        fresh_at, fresh_idt, err = _refresh_tokens(refresh_token, timeout_s, proxy)
        if err:
            notes.append(err)
        if fresh_at:
            access_token = fresh_at
            notes.append("rt→access ok")
        rt_plan = _plan_from_id_token(fresh_idt)
        if rt_plan:
            state = _classify(rt_plan)
            if state != "unknown":
                return state, rt_plan, f"fresh id_token chatgpt_plan_type={rt_plan}"
            notes.append(f"fresh id_token plan={rt_plan}")

    check_plan, check_err = _accounts_check(account, access_token, timeout_s, proxy)
    if check_plan:
        state = _classify(check_plan)
        return state, check_plan, f"accounts/check plan_type={check_plan}"
    if check_err:
        notes.append(check_err)

    sub_plan, sub_err = _subscription_source_check(access_token, timeout_s)
    if sub_plan:
        state = _classify(sub_plan)
        if state != "unknown":
            return state, sub_plan, f"subscription/check plan_type={sub_plan}"
        notes.append(f"subscription/check plan={sub_plan}")
    if sub_err:
        notes.append(sub_err)

    if id_plan:
        return "unknown", id_plan, "; ".join(notes)[-450:] or f"unrecognized id_token plan={id_plan}"
    return "unknown", "", "; ".join(notes)[-450:] or "no plan signal"


def check_account_plan_by_id(account_id: int, *, timeout_s: float = 10.0, use_proxy: bool = True) -> dict:
    db = get_db()
    acc = db.get_registered_account(int(account_id))
    if not acc:
        return {"id": int(account_id), "email": "", "status": "missing", "plan_type": "", "message": "account not found"}
    state, plan, message = check_account_plan(acc, timeout_s=timeout_s, use_proxy=use_proxy)
    db.update_account_check(int(account_id), "plan", f"plan_check:{state}:plan={plan or '-'}:{message}")
    if state in {"paid", "free"}:
        plan_value = "team" if _normalize_plan(plan) == "team" else ("plus" if state == "paid" else "free")
        try:
            raw = db.get_runtime_json("inventory_plan_overrides", {})
            overrides = raw if isinstance(raw, dict) else {}
            overrides[str(acc.get("email") or "").strip().lower()] = plan_value
            db.set_runtime_json("inventory_plan_overrides", overrides)
        except Exception:
            pass
    return {"id": int(account_id), "email": acc.get("email", ""), "status": state, "plan_type": plan, "message": message}


def check_account_plans(account_ids: Iterable[int], *, max_workers: int = 3, timeout_s: float = 10.0, use_proxy: bool = True) -> list[dict]:
    ids = [int(i) for i in account_ids if str(i).strip().lstrip("-").isdigit()]
    if not ids:
        return []
    results: list[dict] = []
    workers = max(1, min(int(max_workers), len(ids)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_account_plan_by_id, i, timeout_s=timeout_s, use_proxy=use_proxy): i for i in ids}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"id": futures[fut], "email": "", "status": "unknown", "plan_type": "", "message": f"worker error: {type(e).__name__}: {e}"})
    results.sort(key=lambda r: ids.index(int(r.get("id", -1))) if int(r.get("id", -1)) in ids else 10**9)
    return results
