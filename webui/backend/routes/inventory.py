"""Local account inventory: list, validate, delete, push to CPA."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import re
import threading
import uuid
import shutil

import requests
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from ..auth import CurrentUser, current_user_optional
from ..account_inventory import build_accounts_inventory
from ..account_validator import validate_accounts
from ..plan_checker import check_account_plans, check_account_plan_by_id
from ..db import get_db
from .. import runner, settings as s


router = APIRouter(prefix="/api/inventory", tags=["inventory"])
SHARE_META_KEY = "local_inventory_share_token"
PAYMENT_JOBS: dict[str, dict] = {}
PAYMENT_JOBS_LOCK = threading.Lock()

PAYPAL_FREE_JP_PROXY = os.getenv("PAYPAL_FREE_JP_PROXY", "")
GOPAY_FREE_PLUS_PROXY = os.getenv("GOPAY_FREE_PLUS_PROXY", "")
PAYONLY_CARD_POOL_KEY = "inventory_payonly_card_body_pool_v1"
PAYONLY_CACHE_PREFIX = "inventory_payonly_card_cache:"
PAYONLY_VERIFY_URL = "https://api.node-card.com/api/open/card/redeem"
PAYONLY_US_PROXY = os.getenv("PAYONLY_US_PROXY", "")
PAYONLY_KEY_POOL_KEY = "payonly_key_pool_v1"
PAYONLY_KEY_CACHE_KEY = "payonly_key_cache_v1"
PAYONLY_PHONE_POOL_KEY = "payonly_phone_pool_v1"
PAYONLY_PHONE_BANNED_KEY = "payonly_phone_banned_v1"
PROXY_POOL_JP_KEY = "proxy_pool_jp_v1"
PROXY_POOL_JP_STATE_KEY = "proxy_pool_jp_state_v1"
PROXY_POOL_US_KEY = "proxy_pool_us_v1"
PROXY_POOL_US_STATE_KEY = "proxy_pool_us_state_v1"


def _pick_runtime_proxy_round_robin(pool_key: str, state_key: str, fallback_path: str = "", *, require_region: str = "") -> tuple[str, int, int]:
    """Pick a proxy sequentially from runtime pool, wrapping back to 1 after the end.

    Returns (proxy, one_based_index, pool_size). If no proxy is available,
    returns ("", 0, 0).
    """
    db = get_db()
    lines = _runtime_pool_lines(pool_key, fallback_path)
    if require_region:
        needle = f"region-{require_region}".lower()
        lines = [x for x in lines if needle in x.lower()]
    if not lines:
        return "", 0, 0
    try:
        idx = int(db.get_runtime_value(state_key, "0") or "0")
    except Exception:
        idx = 0
    pos = idx % len(lines)
    try:
        db.set_runtime_value(state_key, str((pos + 1) % len(lines)))
    except Exception:
        pass
    return lines[pos], pos + 1, len(lines)


def _runtime_pool_lines(key: str, fallback_path: str = "") -> list[str]:
    db = get_db()
    raw = db.get_runtime_json(key, None)
    if raw is None:
        raw_s = db.get_runtime_value(key, "")
        if raw_s:
            raw = raw_s.splitlines()
    lines: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                line = item.strip()
            elif isinstance(item, dict):
                line = str(item.get("proxy") or item.get("url") or item.get("line") or "").strip()
            else:
                line = str(item or "").strip()
            if line and not line.startswith("#"):
                lines.append(line)
    elif isinstance(raw, str):
        lines = [x.strip() for x in raw.splitlines() if x.strip() and not x.strip().startswith("#")]
    if lines:
        return lines
    if fallback_path:
        p = Path(fallback_path)
        if p.exists():
            lines = [x.strip() for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip() and not x.strip().startswith("#")]
            if lines:
                db.set_runtime_json(key, lines)
                return lines
    return []


def _runtime_pool_json(key: str, fallback_path: str = "", default=None):
    db = get_db()
    raw = db.get_runtime_json(key, None)
    if raw is not None:
        return raw
    if fallback_path:
        p = Path(fallback_path)
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                db.set_runtime_json(key, raw)
                return raw
            except Exception:
                pass
    return default


def _seed_runtime_payment_pools_from_files() -> dict:
    root = s.ROOT
    seeded = {}
    for key, path in [
        (PROXY_POOL_JP_KEY, root / "output" / "rt_proxy_pool_1024_jp.txt"),
        (PROXY_POOL_US_KEY, root / "output" / "rt_proxy_pool_1024_us.txt"),
    ]:
        if not get_db().has_runtime_key(key):
            lines = _runtime_pool_lines(key, str(path))
            if lines:
                seeded[key] = len(lines)
    if not get_db().has_runtime_key(PROXY_POOL_US_KEY):
        lines = _runtime_pool_lines(PROXY_POOL_US_KEY, str(root / "output" / "payonly_us_proxy_pool.txt"))
        if lines:
            seeded[PROXY_POOL_US_KEY] = len(lines)
    if not get_db().has_runtime_key(PAYONLY_KEY_CACHE_KEY):
        cache = _runtime_pool_json(PAYONLY_KEY_CACHE_KEY, str(root / "scripts" / "key_cache.json"), {})
        if isinstance(cache, dict):
            seeded[PAYONLY_KEY_CACHE_KEY] = len(cache)
    if not get_db().has_runtime_key(PAYONLY_PHONE_BANNED_KEY):
        banned = _runtime_pool_lines(PAYONLY_PHONE_BANNED_KEY, str(root / "scripts" / "phone_banned.txt"))
        if banned:
            seeded[PAYONLY_PHONE_BANNED_KEY] = len(banned)
    return seeded


def _eligible_payonly_inventory_accounts(limit: int) -> list[dict]:
    db = get_db()
    fast = getattr(db, "list_payonly_eligible_registered_accounts", None)
    if callable(fast):
        try:
            return fast(limit)
        except Exception as e:
            print(f"[payonly-queue] fast eligible query failed, fallback inventory scan: {e}", flush=True)

    inv = build_accounts_inventory()
    accounts = inv.get("accounts") or []
    picked: list[dict] = []
    for item in accounts:
        if limit > 0 and len(picked) >= limit:
            break
        try:
            aid = int(item.get("id") or 0)
        except Exception:
            aid = 0
        if not aid:
            continue
        plan = str(item.get("plan_tag") or item.get("plan") or "").strip().lower()
        if plan != "free":
            continue
        if item.get("has_refresh_token"):
            continue
        status = str(item.get("last_check_status") or "").strip().lower()
        message = str(item.get("last_check_message") or "").strip().lower()
        if status in {"invalid", "dead", "banned", "disabled", "payonly_excluded", "payonly_processing"} or "payonly:" in message:
            continue
        if not item.get("pay_only_eligible"):
            continue
        acc = db.get_registered_account(aid)
        if acc:
            picked.append(acc)
    return picked


def _new_payment_job(ids: list[int], mode: str = "hosted") -> str:
    job_id = uuid.uuid4().hex[:12]
    with PAYMENT_JOBS_LOCK:
        PAYMENT_JOBS[job_id] = {
            "id": job_id,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "ids": ids,
            "mode": mode,
            "logs": [],
            "results": [],
            "summary": {},
            "error": "",
        }
        # Avoid unbounded memory growth; keep latest 30 jobs.
        if len(PAYMENT_JOBS) > 30:
            old = sorted(PAYMENT_JOBS.items(), key=lambda kv: kv[1].get("created_at", ""))[:-30]
            for k, _ in old:
                PAYMENT_JOBS.pop(k, None)
    return job_id


def _append_payment_job_log(job_id: str, line: str) -> None:
    line = str(line or "").rstrip()
    if not line:
        return
    with PAYMENT_JOBS_LOCK:
        job = PAYMENT_JOBS.get(job_id)
        if not job:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        job.setdefault("logs", []).append(f"[{ts}] {line}")
        job["logs"] = job["logs"][-1200:]
        job["updated_at"] = datetime.now(timezone.utc).isoformat()


def _set_payment_job(job_id: str, **patch) -> None:
    with PAYMENT_JOBS_LOCK:
        job = PAYMENT_JOBS.get(job_id)
        if not job:
            return
        job.update(patch)
        job["updated_at"] = datetime.now(timezone.utc).isoformat()


def _get_payment_job(job_id: str) -> dict:
    with PAYMENT_JOBS_LOCK:
        job = PAYMENT_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job 不存在或已过期")
        return json.loads(json.dumps(job, ensure_ascii=False))


def _run_payment_job(job_id: str, ids: list[int], mode: str = "hosted") -> None:
    _set_payment_job(job_id, status="running")
    results = []
    db = get_db()
    try:
        if mode == "payonly_auto":
            limit = len(ids) if ids else 0
            accounts = _eligible_payonly_inventory_accounts(limit)
            _append_payment_job_log(job_id, f"开始 PayOnly 自动队列：从库存 free 可支付账号取 {len(accounts)} 个，串行执行")
            if not accounts:
                _set_payment_job(job_id, status="done", results=[], summary={"total": 0, "ok": 0, "fail": 0})
                _append_payment_job_log(job_id, "没有符合条件的 free 库存账号：需要 free + 有 auth + 未消费 + 未有 RT")
                return
            _set_payment_job(job_id, ids=[int(a.get("id") or 0) for a in accounts])
            for idx, acc in enumerate(accounts, 1):
                aid = int(acc.get("id") or 0)
                email = acc.get("email") or ""
                _append_payment_job_log(job_id, f"[{idx}/{len(accounts)}] {email} 开始 PayOnly 支付；成功后脚本会异步补 RT")
                r = _run_payonly_script_for_account(acc, log_cb=lambda line, j=job_id: _append_payment_job_log(j, line))
                results.append(r)
                if r.get("status") == "ok":
                    _append_payment_job_log(job_id, f"[{idx}/{len(accounts)}] {email} PayOnly 脚本完成；自动 RT 由脚本根据成功标记触发")
                else:
                    _append_payment_job_log(job_id, f"[{idx}/{len(accounts)}] {email} PayOnly 失败: {(r.get('error') or '')[-220:]}")
                _set_payment_job(job_id, results=results)
            summary = {
                "total": len(results),
                "ok": sum(1 for r in results if r.get("status") == "ok"),
                "fail": sum(1 for r in results if r.get("status") != "ok"),
            }
            _set_payment_job(job_id, status="done", results=results, summary=summary)
            _append_payment_job_log(job_id, f"PayOnly 自动队列完成 ok={summary['ok']} fail={summary['fail']}")
            return

        _append_payment_job_log(job_id, f"开始生成长支付链接，mode={mode}，账号数={len(ids)}")
        for idx, aid in enumerate(ids, 1):
            _append_payment_job_log(job_id, f"[{idx}/{len(ids)}] 读取账号 #{aid}")
            acc = db.get_registered_account(int(aid))
            if not acc:
                r = {"id": aid, "email": "", "status": "missing", "url": "", "error": "账号不存在"}
                results.append(r)
                _append_payment_job_log(job_id, f"[{idx}/{len(ids)}] 账号不存在: #{aid}")
                _set_payment_job(job_id, results=results)
                continue
            if not (acc.get("session_token") or acc.get("access_token")):
                r = {"id": aid, "email": acc.get("email"), "status": "no_auth", "url": "", "error": "缺 session/access token"}
                results.append(r)
                _append_payment_job_log(job_id, f"[{idx}/{len(ids)}] {acc.get('email')} 缺 session/access token")
                _set_payment_job(job_id, results=results)
                continue
            _append_payment_job_log(job_id, f"[{idx}/{len(ids)}] {acc.get('email')} 开始调用 payment.py ({mode})")
            r = _generate_payment_link_for_account(acc, log_cb=lambda line, j=job_id: _append_payment_job_log(j, line), mode=mode)
            results.append(r)
            if r.get("status") == "ok":
                _append_payment_job_log(job_id, f"[{idx}/{len(ids)}] {acc.get('email')} 成功拿到链接 session={r.get('session_id') or '-'}")
            else:
                _append_payment_job_log(job_id, f"[{idx}/{len(ids)}] {acc.get('email')} 失败: {(r.get('error') or '')[-220:]}")
            _set_payment_job(job_id, results=results)
        summary = {
            "total": len(results),
            "ok": sum(1 for r in results if r.get("status") == "ok"),
            "fail": sum(1 for r in results if r.get("status") != "ok"),
        }
        _set_payment_job(job_id, status="done", results=results, summary=summary)
        _append_payment_job_log(job_id, f"任务完成 ok={summary['ok']} fail={summary['fail']}")
    except Exception as e:
        _set_payment_job(job_id, status="error", error=f"{type(e).__name__}: {e}", results=results)
        _append_payment_job_log(job_id, f"任务异常: {type(e).__name__}: {e}")



_PAYONLY_GEN_VISA_PREFIXES = ["4539", "4556", "4916", "4532", "4929", "4485", "4716", "4024", "4508"]
_PAYONLY_GEN_US_CITIES = [
    ("New York",     "NY", "10001"),
    ("Los Angeles",  "CA", "90001"),
    ("Chicago",      "IL", "60601"),
    ("Houston",      "TX", "77001"),
    ("Phoenix",      "AZ", "85001"),
    ("Philadelphia", "PA", "19101"),
    ("San Antonio",  "TX", "78201"),
    ("San Diego",    "CA", "92101"),
    ("Dallas",       "TX", "75201"),
    ("San Jose",     "CA", "95101"),
    ("Austin",       "TX", "78701"),
    ("Jacksonville", "FL", "32099"),
    ("Seattle",      "WA", "98101"),
    ("Denver",       "CO", "80201"),
    ("Nashville",    "TN", "37201"),
]
_PAYONLY_GEN_US_STREETS = [
    "Main St", "Oak Ave", "Maple Dr", "Cedar Blvd", "Elm St",
    "Park Ave", "Lake Dr", "Hill Rd", "River Rd", "Sunset Blvd",
    "Forest Ave", "Valley Dr", "Spring St", "Washington Blvd", "Lincoln Ave",
    "Madison St", "Jefferson Ave", "Adams St", "Monroe Dr", "Harrison Blvd",
]
_PAYONLY_GEN_FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda",
    "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen",
]
_PAYONLY_GEN_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor",
    "Thomas", "Moore", "Jackson", "Martin", "Lee", "Thompson", "White",
]


def _payonly_luhn_check_digit(partial: str) -> str:
    digits = [int(d) for d in partial]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if (i + 1) % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def _payonly_gen_visa_number() -> str:
    import random, string as _string
    prefix = random.choice(_PAYONLY_GEN_VISA_PREFIXES)
    middle = "".join(random.choices(_string.digits, k=11))
    partial = prefix + middle
    return partial + _payonly_luhn_check_digit(partial)


def _payonly_gen_us_address() -> dict:
    import random
    city, state, postal_code = random.choice(_PAYONLY_GEN_US_CITIES)
    return {
        "line1": f"{random.randint(100, 9999)} {random.choice(_PAYONLY_GEN_US_STREETS)}",
        "city": city,
        "state": state,
        "postal_code": postal_code,
        "country": "US",
    }


def _payonly_gen_card_info(generate_address: bool = False) -> dict:
    import random
    now = datetime.now(timezone.utc)
    exp_year = now.year + random.randint(2, 4)
    exp_month = random.randint(1, 12)
    name = f"{random.choice(_PAYONLY_GEN_FIRST_NAMES)} {random.choice(_PAYONLY_GEN_LAST_NAMES)}"
    info: dict = {
        "card_number": _payonly_gen_visa_number(),
        "expiry_date": f"{exp_month:02d}/{str(exp_year)[-2:]}",
        "cvv": str(random.randint(100, 999)),
        "name": name,
        "phone": "",
        "sms_api": "",
        "address": _payonly_gen_us_address() if generate_address else {},
    }
    return info


def _payonly_cache_key(account_id: int) -> str:
    return f"{PAYONLY_CACHE_PREFIX}{int(account_id)}"


def _load_payonly_pool() -> list[dict]:
    raw = get_db().get_runtime_json(PAYONLY_CARD_POOL_KEY, []) or []
    return raw if isinstance(raw, list) else []


def _save_payonly_pool(pool: list[dict]) -> None:
    get_db().set_runtime_json(PAYONLY_CARD_POOL_KEY, pool)


def _parse_payonly_pool_req(req: PayonlyPoolRequest) -> list[dict]:
    out: list[dict] = []
    for item in req.items or []:
        if isinstance(item, dict) and item:
            out.append(item)
    raw = (req.raw or "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                out.extend([x for x in parsed if isinstance(x, dict) and x])
            elif isinstance(parsed, dict):
                out.append(parsed)
        except Exception:
            # Also accept one JSON body per line for quick paste from curl bodies.
            for line in raw.splitlines():
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict) and item:
                        out.append(item)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"池子内容不是 JSON: {e}")
    return out


def _extract_payonly_card_content(data: dict) -> dict:
    content = data.get("content") if isinstance(data.get("content"), dict) else data
    if isinstance(data.get("data"), dict):
        content = data.get("data")
    if isinstance(data.get("result"), dict):
        content = data.get("result")
    if not isinstance(content, dict):
        content = {}
    return {
        "card_number": str(content.get("card_number") or content.get("cardNumber") or content.get("card_no") or content.get("cardNo") or content.get("number") or "").strip(),
        "expiry_date": str(content.get("expiry_date") or content.get("expiryDate") or content.get("expire") or content.get("expiry") or content.get("exp") or "").strip(),
        "cvv": str(content.get("cvv") or content.get("cvc") or content.get("security_code") or "").strip(),
        "phone": str(content.get("phone") or "").strip(),
        "name": str(content.get("name") or content.get("cardholder") or "").strip(),
        "address": str(
            content.get("address")
            or content.get("full_billing_address")
            or ", ".join(str(x).strip() for x in [
                content.get("street_address"),
                content.get("city"),
                content.get("state") or content.get("full_state"),
                content.get("country") or content.get("country_code"),
                content.get("postal_code") or content.get("zip"),
            ] if str(x or "").strip())
            or ""
        ).strip(),
        "sms_api": str(content.get("sms_api") or content.get("sms") or "").strip(),
    }


def _payonly_card_for_account(account: dict, log_cb=None, cfg: dict | None = None) -> dict:
    """Return cached card/info for an account, or consume one curl body from pool.

    First successful lookup binds the consumed body and returned content to this
    account. Later retries reuse only the cache, avoiding another verify API call.

    If cfg.payonly.generate_card is True, skips the pool entirely and generates
    a random Visa card locally. If cfg.payonly.generate_address is also True,
    the billing address is randomised with a US city/state/zip tuple.
    """
    account_id = int(account.get("id") or 0)
    cached = get_db().get_runtime_json(_payonly_cache_key(account_id), {}) or {}
    if isinstance(cached, dict) and cached.get("card_info"):
        if log_cb:
            log_cb("PayOnly卡信息：使用账号绑定缓存，不再请求 verify 接口")
        return cached

    if cfg is None:
        try:
            cfg = json.loads(s.PAY_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
    payonly_cfg = cfg.get("payonly") or {}
    if payonly_cfg.get("generate_card"):
        generate_address = bool(payonly_cfg.get("generate_address", False))
        card_info = _payonly_gen_card_info(generate_address=generate_address)
        payload = {
            "account_id": account_id,
            "email": account.get("email"),
            "assigned_at": datetime.now(timezone.utc).isoformat(),
            "verify_url": "generated",
            "verify_body": None,
            "verify_response": None,
            "card_info": card_info,
        }
        get_db().set_runtime_json(_payonly_cache_key(account_id), payload)
        if log_cb:
            log_cb(
                f"PayOnly卡信息：随机生成 Visa 卡 ****{card_info['card_number'][-4:]}"
                f"  到期 {card_info['expiry_date']}"
                f"  地址随机={'是' if generate_address else '否'}"
            )
        return payload

    pool = _load_payonly_pool()
    if not pool:
        raise HTTPException(status_code=400, detail="PayOnly curl 请求体池子为空：请先在页面添加 body")
    item = pool.pop(0)
    _save_payonly_pool(pool)
    if log_cb:
        log_cb(f"PayOnly卡信息：从池子取出 1 条 body，剩余 {len(pool)}；开始绑定到账号 #{account_id}")
    try:
        resp = requests.post(
            PAYONLY_VERIFY_URL,
            headers={
                "accept": "application/json;charset=utf-8",
                "accept-language": "en,zh-CN;q=0.9,zh;q=0.8",
                "content-type": "application/json;charset=utf-8",
                "origin": "https://node-card.com",
                "priority": "u=1, i",
                "referer": "https://node-card.com/",
                "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site",
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            },
            json=(item if isinstance(item, dict) and item.get("card_key") else {"card_key": str(item.get("key") if isinstance(item, dict) else item)}),
            timeout=30,
        )
        body = resp.json()
        resp.raise_for_status()
    except Exception as e:
        # Put it back because it was not successfully bound.
        pool = _load_payonly_pool()
        pool.insert(0, item)
        _save_payonly_pool(pool)
        raise HTTPException(status_code=502, detail=f"verify 接口请求失败，body 已放回池首: {type(e).__name__}: {e}")
    if isinstance(body, dict) and body.get("success") is False:
        raise HTTPException(status_code=502, detail={"message": "verify 接口返回 success=false；body 已消耗前未缓存，请检查后重新加入池子", "body": body})
    card_info = _extract_payonly_card_content(body if isinstance(body, dict) else {})
    if not card_info.get("card_number"):
        raise HTTPException(status_code=502, detail={"message": "verify 接口未返回 card_number", "body": body})
    payload = {
        "account_id": account_id,
        "email": account.get("email"),
        "assigned_at": datetime.now(timezone.utc).isoformat(),
        "verify_url": PAYONLY_VERIFY_URL,
        "verify_body": item,
        "verify_response": body,
        "card_info": card_info,
    }
    get_db().set_runtime_json(_payonly_cache_key(account_id), payload)
    if log_cb:
        log_cb(f"PayOnly卡信息：已缓存并绑定账号 #{account_id} card=****{card_info.get('card_number','')[-4:]}")
    return payload


def _payonly_card_max_success_uses() -> int:
    try:
        return int(os.getenv("PAYONLY_CARD_MAX_SUCCESS_USES", "999999") or "999999")
    except Exception:
        return 999999


def _payonly_key_use_count(item: dict) -> int:
    if not isinstance(item, dict):
        return 0
    hist = item.get("_used_accounts")
    if isinstance(hist, list):
        return len(hist)
    return 1 if item.get("_used") else 0


def _payonly_available_key_count() -> int:
    db = get_db()
    keys = db.get_runtime_json(PAYONLY_KEY_POOL_KEY, []) or []
    cache = db.get_runtime_json(PAYONLY_KEY_CACHE_KEY, {}) or {}

    # Only seed from local fallback files when the DB pool is actually missing.
    # On AWS every runtime_meta query to HK Postgres costs several seconds; the
    # old unconditional seeding path performed multiple extra has/get calls and
    # made queue_prepare_s exceed 100s.
    if not keys:
        _seed_runtime_payment_pools_from_files()
        keys = db.get_runtime_json(PAYONLY_KEY_POOL_KEY, []) or []
        cache = db.get_runtime_json(PAYONLY_KEY_CACHE_KEY, {}) or {}

    if not isinstance(keys, list):
        return 0
    if not isinstance(cache, dict):
        cache = {}
    # A key can run if it has not hit the configured success-use cap.  Default is high
    # so Ryan can run one-card-many-bind; set PAYONLY_CARD_MAX_SUCCESS_USES=1 to restore one-card-one-success.
    max_uses = _payonly_card_max_success_uses()
    return sum(
        1
        for k in keys
        if k and not (isinstance(cache.get(str(k)), dict) and max_uses > 0 and _payonly_key_use_count(cache.get(str(k), {})) >= max_uses)
    )


def _account_paypal_success_marked(email: str) -> bool:
    if not email:
        return False
    try:
        db = get_db()
        with db._conn() as c:
            row = c.execute(
                """
                SELECT last_check_status, last_check_message
                FROM registered_accounts
                WHERE lower(email)=lower(?)
                ORDER BY id DESC LIMIT 1
                """,
                (email,),
            ).fetchone()
            card_row = c.execute(
                """
                SELECT status, error
                FROM card_results
                WHERE lower(COALESCE(NULLIF(chatgpt_email,''), NULLIF(email,''), '')) = lower(?)
                ORDER BY id DESC LIMIT 1
                """,
                (email,),
            ).fetchone()
        account_marked = bool(
            row
            and str(row["last_check_status"] or "") == "plan"
            and (
                "paypal_success" in str(row["last_check_message"] or "").lower()
                or "plan_check:paid" in str(row["last_check_message"] or "").lower()
                or "plan=plus" in str(row["last_check_message"] or "").lower()
                or "plan_type=plus" in str(row["last_check_message"] or "").lower()
            )
        )
        card_marked = bool(card_row and str(card_row["status"] or "").lower() == "succeeded")
        return account_marked or card_marked
    except Exception:
        return False


def _payonly_live_plus_verified(account_id: int, log_cb=None) -> bool:
    try:
        pre = check_account_plan_by_id(int(account_id or 0), timeout_s=float(os.getenv("PAYONLY_POSTCHECK_TIMEOUT", "12") or "12"), use_proxy=True)
        if log_cb:
            log_cb(f"PayOnly包装结果：postcheck plan status={pre.get('status')} plan={pre.get('plan_type')} msg={pre.get('message')}")
        return pre.get("status") == "paid"
    except Exception as e:
        if log_cb:
            log_cb(f"PayOnly包装结果：postcheck plan failed: {type(e).__name__}: {e}")
        return False


def _mark_payonly_key_used_any_owner(active_key: str, used_reason: str = "paypal_success", account_id: int | None = None, email: str = "") -> bool:
    if not active_key:
        return False
    db = get_db()
    cache = db.get_runtime_json(PAYONLY_KEY_CACHE_KEY, {}) or {}
    if not isinstance(cache, dict):
        return False
    item = cache.get(active_key)
    if not isinstance(item, dict):
        return False
    item["_used"] = True
    item["_used_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    item["_used_reason"] = used_reason or "paypal_success"
    item.pop("_reserved_by", None)
    item.pop("_reserved_at", None)
    item.pop("_reserved_account_id", None)
    if account_id or email:
        hist = item.get("_used_accounts")
        if not isinstance(hist, list):
            hist = []
        rec = {"id": account_id, "email": email}
        if rec not in hist:
            hist.append(rec)
        item["_used_accounts"] = hist
    item["_success_use_count"] = _payonly_key_use_count(item)
    item["_max_success_uses"] = _payonly_card_max_success_uses()
    cache[active_key] = item
    db.set_runtime_json(PAYONLY_KEY_CACHE_KEY, cache)
    return True


def _extract_payonly_active_key_from_output(out: str) -> str:
    if not out:
        return ""
    matches = re.findall(r"\[key_pool\]\s+命中DB缓存\s+key=([0-9a-fA-F-]{36})", out)
    if matches:
        return matches[-1]
    matches = re.findall(r"\[key_pool\]\s+reserved\s+key=([0-9a-fA-F]+)\.\.\.", out)
    if not matches:
        return ""
    prefix = matches[-1].lower()
    cache = get_db().get_runtime_json(PAYONLY_KEY_CACHE_KEY, {}) or {}
    if isinstance(cache, dict):
        hits = [str(k) for k in cache.keys() if str(k).lower().startswith(prefix)]
        if len(hits) == 1:
            return hits[0]
    return ""


def _run_payonly_script_for_account(account: dict, log_cb=None) -> dict:
    account_id = int(account.get("id") or 0)
    if log_cb:
        log_cb("PayOnly流程：先用 JP 代理生成 Plus Free 长链接")
    link = _generate_payment_link_for_account(account, log_cb=log_cb, mode="paypal")
    if link.get("status") != "ok" or not link.get("url"):
        return {**link, "mode": "payonly_script", "status": "error", "error": "JP长链接生成失败: " + (link.get("error") or "")[-1000:]}
    _seed_runtime_payment_pools_from_files()
    try:
        _pay_cfg = json.loads(s.PAY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        _pay_cfg = {}
    if (_pay_cfg.get("payonly") or {}).get("generate_card"):
        _card_bundle = _payonly_card_for_account(account, log_cb=log_cb, cfg=_pay_cfg)
        card_info = _card_bundle.get("card_info") or {}
    else:
        card_info = {}
    script = s.ROOT / "scripts" / "payonly_us_paypal_guest_template.user.py"
    py = os.getenv("GPT_PAYMENT_PYTHON", str(s.ROOT / "venv" / "bin" / "python"))
    cmd = [py, "-u", str(script)]
    xvfb = shutil.which("xvfb-run")
    if xvfb:
        cmd = [xvfb, "-a"] + cmd
    env = dict(os.environ)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.update({
        "PAYONLY_URL": link.get("url") or "",
        "PAYONLY_ACCOUNT_ID": str(account_id),
        "PAYONLY_US_PROXY": "",
        "PAYONLY_US_PROXY_POOL_DB_KEY": PROXY_POOL_US_KEY,
        "PAYONLY_US_PROXY_STATE_DB_KEY": PROXY_POOL_US_STATE_KEY,
        "PAYONLY_KEY_POOL_DB_KEY": PAYONLY_KEY_POOL_KEY,
        "PAYONLY_KEY_CACHE_DB_KEY": PAYONLY_KEY_CACHE_KEY,
        "PAYONLY_PHONE_POOL_DB_KEY": PAYONLY_PHONE_POOL_KEY,
        "PAYONLY_PHONE_BANNED_DB_KEY": PAYONLY_PHONE_BANNED_KEY,
        "PAYONLY_CARD_INFO_JSON": json.dumps({
            "number": card_info.get("card_number") or "",
            "expiry": card_info.get("expiry_date") or "",
            "cvv": card_info.get("cvv") or "",
        }, ensure_ascii=False),
        "PAYONLY_HARDCODED_INFO_JSON": json.dumps(card_info, ensure_ascii=False),
        "PAYONLY_CARD_MAX_SUCCESS_USES": os.getenv("PAYONLY_CARD_MAX_SUCCESS_USES", "999999"),
        "PAYONLY_FETCH_CARD_FROM_VERIFY_API": "0",
        "PAYONLY_GENERATE_CARD": "1" if ((_pay_cfg.get("payonly") or {}).get("generate_card")) else "0",
    })
    if log_cb:
        log_cb("PayOnly流程：传入与 JP curl/checkout 获取一致的长链接给脚本")
        log_cb("执行脚本: " + " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=str(s.ROOT), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
    out_lines: list[str] = []
    try:
        if proc.stdout:
            for line in proc.stdout:
                line = line.rstrip("\n")
                out_lines.append(line)
                if log_cb:
                    log_cb(line)
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        out_lines.append("PayOnly脚本超时: 900s")
    out = "\n".join(out_lines)
    if log_cb:
        log_cb(f"PayOnly脚本退出码: {proc.returncode}")
    marker = "CARD_RESULT_JSON="
    payload = None
    for line in out.splitlines():
        if line.startswith(marker):
            try:
                payload = json.loads(line.split("=", 1)[1])
            except Exception:
                payload = None
    result = payload if isinstance(payload, dict) else {}
    status = "ok" if proc.returncode == 0 else "error"
    nested_status = str(result.get("status") or "").strip().lower()
    email = str(account.get("email") or "")
    result_url = str(result.get("url") or "")
    out_low = out.lower()
    redirect_succeeded = "redirect_status=succeeded" in result_url.lower() or "redirect_status=succeeded" in out_low
    returned_to_chatgpt = "chatgpt.com" in result_url.lower()
    marked_success = _account_paypal_success_marked(email)
    live_plus = False
    active_key = _extract_payonly_active_key_from_output(out)
    if (redirect_succeeded or returned_to_chatgpt) and not marked_success:
        # PayPal can emit nested paypal_guest_handoff even after final consent and
        # redirect back to Stripe/ChatGPT.  The JSON payload may only contain the
        # final ChatGPT URL, while the real Stripe success marker is in child logs.
        # Never trust the redirect alone; verify live plan before calling it paid.
        live_plus = _payonly_live_plus_verified(account_id, log_cb=log_cb)
    if marked_success or live_plus:
        # The child can successfully finish payment but emit a stale/manual nested status
        # or later fail during RT. Treat durable/live Plus evidence as payment success.
        status = "ok"
        if active_key:
            try:
                if _mark_payonly_key_used_any_owner(active_key, used_reason="paypal_success", account_id=account_id, email=email):
                    if log_cb:
                        log_cb(f"[key_pool] 成功后记录key使用(DB wrapper) key={active_key[:8]}... max_uses={_payonly_card_max_success_uses()}")
                elif log_cb:
                    log_cb(f"[key_pool] 成功但未找到 active_key 缓存，无法标记 used key={active_key[:8]}...")
            except Exception as e:
                if log_cb:
                    log_cb(f"[key_pool] 成功后标记key已使用失败 key={active_key[:8]}... err={type(e).__name__}: {e}")
        elif log_cb:
            log_cb("[key_pool] 成功但未从脚本输出解析到 active_key，无法标记 used")
        result.setdefault("status", nested_status or "paypal_success")
        result["paypal_success_marked"] = bool(marked_success)
        result["live_plus_verified"] = bool(live_plus)
        if log_cb:
            if live_plus and not marked_success:
                log_cb("PayOnly包装结果：redirect_status=succeeded 且 live plan=paid，按支付成功处理")
            else:
                log_cb("PayOnly包装结果：检测到账户已写入 paid/paypal_success，按支付成功处理（RT 后续失败不改支付结果）")
    elif nested_status in {"paypal_guest_handoff", "manual_required", "manual_handoff", "manual_challenge_failed"}:
        status = "error"
        if log_cb:
            log_cb(f"PayOnly包装结果：child rc={proc.returncode} 但 nested_status={nested_status}，且未验证到 paid，按未支付处理")
    return {
        "id": account_id,
        "email": account.get("email"),
        "status": status,
        "mode": "payonly_script",
        "url": link.get("url") or "",
        "session_id": link.get("session_id") or result.get("session_id") or "",
        "cache_bound": False,
        "card_tail": str((result.get("filled_nonpayment") or {}).get("card_tail") or ""),
        "script_result": result,
        "screenshot": result.get("screenshot") or "",
        "public_screenshot": result.get("public_screenshot") or "",
        "error": "" if status == "ok" else out[-1800:],
    }

def _share_token() -> str:
    import secrets
    db = get_db()
    tok = db.get_runtime_value(SHARE_META_KEY, "")
    if not tok:
        tok = secrets.token_urlsafe(24)
        db.set_runtime_value(SHARE_META_KEY, tok)
    return tok


class IdsRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)


class CheckRequest(IdsRequest):
    timeout_s: float = 10.0
    max_workers: int = 3


class PaymentLinkRequest(IdsRequest):
    # selected accounts; one link per account. Keeps the request explicit and bounded.
    mode: str = "hosted"
    # For payonly_auto mode, ids may be empty; limit controls how many free inventory accounts to consume.
    limit: int = 0


class PaypalPageDebugRequest(BaseModel):
    account_id: int


class PayonlyRunRequest(BaseModel):
    account_id: int


class PayonlyPoolRequest(BaseModel):
    items: list[dict] = Field(default_factory=list)
    raw: str = ""


class PlanOverrideRequest(BaseModel):
    plan: str = ""


class InventoryStatusRequest(IdsRequest):
    checked_out: bool = False


class ExportRequest(IdsRequest):
    format: str = "credentials"


class GopayPhoneRequest(BaseModel):
    phone: str = ""
    app: str = ""
    country: str = "Indonesia"
    operator: str = ""


class GopayPhoneSaveRequest(GopayPhoneRequest):
    status: str = "bound"


def _random_billing_identity(cfg: dict, account: dict) -> dict:
    import random, re, string
    first = random.choice(["JAMES", "JOHN", "MICHAEL", "WILLIAM", "DAVID", "EMILY", "SOPHIA", "EMMA", "OLIVIA", "MIA"])
    last = random.choice(["SMITH", "JOHNSON", "WILLIAMS", "BROWN", "JONES", "MILLER", "DAVIS", "MARTINEZ", "WILSON", "TAYLOR"])
    base = ((cfg.get("cards") or [{}])[0] or {})
    addr = dict(base.get("address") or {})
    line1 = addr.get("line1") or "1 Example Street"
    if line1:
        new_line1 = re.sub(r"^\d+", str(random.randint(100, 999)), line1)
        if new_line1 == line1:
            new_line1 = f"{random.randint(100, 999)} {line1}"
        line1 = new_line1
    local = "buyer" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return {
        "name": f"{first} {last}",
        "email": f"{local}@chatgmail.com",
        "address": {
            "line1": line1,
            "line2": addr.get("line2", ""),
            "city": addr.get("city") or addr.get("address_city") or "San Francisco",
            "state": addr.get("state") or "CA",
            "postal_code": addr.get("postal_code") or "94105",
            "country": addr.get("country") or "US",
        },
        "chatgpt_email": account.get("email") or "",
    }


def _account_temp_pay_config(account: dict, mode: str = "hosted") -> tuple[str, dict]:
    try:
        cfg = json.loads(s.PAY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读支付配置失败: {e}")
    paypal_like_mode = (mode or "hosted").strip().lower() in {"paypal", "paypal_link", "paypal-link"}
    gopay_freeplus_mode = (mode or "hosted").strip().lower() in {"hosted", "gopay", "gopay_freeplus", "gopay-freeplus"}
    billing = _random_billing_identity(cfg, account)
    if paypal_like_mode:
        # Keep billing aligned with the GB/GBP free checkout.  Previously the
        # plan country was GB but the card/billing address remained US, causing
        # warnings and inconsistent checkout generation.
        billing["address"].update({
            "line1": billing["address"].get("line1") or "221B Baker Street",
            "city": "London",
            "state": "",
            "postal_code": "NW1 6XE",
            "country": "GB",
        })
    elif gopay_freeplus_mode:
        # Keep billing aligned with the ID/IDR GoPay FreePlus checkout.
        billing["address"].update({
            "line1": billing["address"].get("line1") or "Jl. Sudirman No. 1",
            "city": "Jakarta",
            "state": "",
            "postal_code": "10220",
            "country": "ID",
        })
    auth = cfg.setdefault("fresh_checkout", {}).setdefault("auth", {})
    auth["mode"] = "access_token"
    auth["session_token"] = account.get("session_token") or ""
    auth["access_token"] = account.get("access_token") or ""
    auth["device_id"] = account.get("device_id") or ""
    auth["cookie_header"] = account.get("cookie_header") or ""
    auth["prefer_session_refresh"] = True
    auto = auth.get("auto_register") or {}
    auto["enabled"] = False
    auth["auto_register"] = auto
    cards = cfg.setdefault("cards", [{}])
    if not cards:
        cards.append({})
    cards[0]["name"] = billing["name"]
    cards[0]["email"] = billing["email"]
    cards[0]["address"] = billing["address"]
    cfg["randomize_identity"] = False

    fresh = cfg.setdefault("fresh_checkout", {})
    fresh["enabled"] = True
    fresh["output_url_mode"] = "provider"
    plan = fresh.setdefault("plan", {})
    plan["checkout_ui_mode"] = "hosted"
    plan["output_url_mode"] = "provider"
    if gopay_freeplus_mode and not paypal_like_mode:
        # Default inventory "生成选中长支付链接" is Ryan's GoPay FreePlus
        # long-link generator: ID/IDR Plus promo, provider hosted URL only.
        # It still stops at --fresh-only; no payment_method/confirm/charge.
        plan["plan_name"] = "chatgptplusplan"
        plan["entry_point"] = "all_plans_pricing_modal"
        plan.pop("team_plan_data", None)
        plan["billing_country"] = "ID"
        plan["billing_currency"] = "IDR"
        cfg["proxy"] = GOPAY_FREE_PLUS_PROXY
        plan["promo_campaign_id"] = "plus-1-month-free"
        plan["is_coupon_from_query_param"] = True
        plan["payment_lower_bound_amount_cents"] = 0
        plan["payment_upper_bound_amount_cents"] = 100000000
        fresh["check_coupon_after_checkout"] = True
        fresh["allow_charge_when_coupon_ineligible"] = True
    if paypal_like_mode:
        # Ryan wants Plus free, not Team. Keep this as Plus promo only.
        # If OpenAI returns not_eligible, surface that rather than silently
        # switching to team-1-month-free.
        plan["plan_name"] = "chatgptplusplan"
        plan["entry_point"] = "all_plans_pricing_modal"
        plan.pop("team_plan_data", None)
        # PayPal Plus Free eligibility has proven sensitive to the exact JP
        # 1024 session. Ryan's known-good morning runs used this fixed fallback
        # session (sid-JE5j863k) and returned coupon state=eligible; rotating
        # across the JP runtime pool can still be JP exit but return
        # not_eligible. Keep PayPal long-link generation pinned to the fixed JP
        # proxy; do not disturb GoPay/PayOnly pool behavior.
        plan["billing_country"] = "GB"
        plan["billing_currency"] = "GBP"
        cfg["proxy"] = PAYPAL_FREE_JP_PROXY
        # Be explicit: fresh ChatGPT checkout / hosted long-link generation must
        # use JP, even if later PayOnly opening/payment rewrites cfg["proxy"]
        # and stage_proxies to US. fresh_checkout.py resolves fresh["proxy"]
        # before falling back to top-level cfg["proxy"].
        fresh["proxy"] = PAYPAL_FREE_JP_PROXY
        cfg.setdefault("_proxy_pool", {})["jp"] = {"fixed": True, "source": "PAYPAL_FREE_JP_PROXY"}
        plan["promo_campaign_id"] = "plus-1-month-free"
        # Plus free often comes from a URL/query coupon entry. Mark it as such
        # so both checkout body and check_coupon use the same source semantics.
        plan["is_coupon_from_query_param"] = True
        plan["payment_lower_bound_amount_cents"] = 0
        plan["payment_upper_bound_amount_cents"] = 100000
        # Strong rule: JP generates the hosted long link, but the link is usable
        # only when the Plus free coupon is actually eligible. If coupon check
        # returns not_eligible, fail fast here and never open/confirm it later.
        fresh["check_coupon_after_checkout"] = True
        fresh["allow_charge_when_coupon_ineligible"] = False
        fresh["expected_due"] = 0
        fresh["auto_refresh_on_due_mismatch"] = False
        fresh["max_due_mismatch_refreshes"] = 0
    # Link generation only; never continue to final payment/capture.
    fd, path = tempfile.mkstemp(prefix="webui_payment_link_", suffix=".json", dir=str(s.CTF_PAY_DIR))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return path, billing


def _generate_payment_link_for_account(account: dict, log_cb=None, mode: str = "hosted") -> dict:
    repo_root = s.ROOT
    mode = (mode or "hosted").strip().lower()
    if mode not in {"hosted", "gopay", "gopay_freeplus", "gopay-freeplus", "paypal", "paypal_link", "paypal-link", "payonly", "payonly_script", "payonly-script"}:
        raise HTTPException(status_code=400, detail="未知支付链接模式")
    if mode in {"payonly", "payonly_script", "payonly-script"}:
        return _run_payonly_script_for_account(account, log_cb=log_cb)
    paypal_mode = mode in {"paypal", "paypal_link", "paypal-link"}
    gopay_freeplus_mode = mode in {"hosted", "gopay", "gopay_freeplus", "gopay-freeplus"}
    cfg_path, billing = _account_temp_pay_config(account, mode=mode)
    promo_label = ""
    try:
        _tmp_cfg_for_label = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        _plan_for_label = ((_tmp_cfg_for_label.get("fresh_checkout") or {}).get("plan") or {})
        promo_label = str(_plan_for_label.get("promo_campaign_id") or "")
    except Exception:
        promo_label = ""
    py = os.getenv("GPT_PAYMENT_PYTHON", str(repo_root / "venv" / "bin" / "python"))
    # Safety: inventory link generation must never enter Stripe confirm/payment.
    # Even --paypal-link-only creates a PayPal payment_method and calls confirm to
    # obtain a redirect, which Ryan considers "走了支付".  So both buttons use
    # --fresh-only and stop immediately after ChatGPT/Stripe creates the hosted
    # checkout URL.  mode=hosted/gopay means GoPay FreePlus ID/IDR hosted link;
    # mode=paypal means the existing PayPal Plus Free GB/GBP hosted link.
    payment_entry = repo_root / "CTF-pay" / "payment.py"
    cmd = [py, str(payment_entry), "fresh", "--fresh-only", "--config", cfg_path, "--json-result"]
    env = dict(os.environ)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    timeout_s = 300 if (paypal_mode or gopay_freeplus_mode) else 90
    try:
        if log_cb:
            try:
                tmp_cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
                plan = ((tmp_cfg.get("fresh_checkout") or {}).get("plan") or {})
                log_cb(
                    "checkout配置: "
                    f"mode={'paypal-free-hosted' if paypal_mode else 'gopay-freeplus-hosted'} "
                    f"plan={plan.get('plan_name') or '-'} "
                    f"promo={plan.get('promo_campaign_id') or '-'} "
                    f"coupon_query={plan.get('is_coupon_from_query_param')} "
                    f"country={plan.get('billing_country') or '-'} "
                    f"currency={plan.get('billing_currency') or '-'} "
                    f"ui={plan.get('checkout_ui_mode') or '-'} "
                    f"proxy={tmp_cfg.get('proxy') or '-'}"
                )
            except Exception:
                pass
            log_cb("执行命令: " + " ".join(cmd))
        proc = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout_s)
        if log_cb:
            out_tail = (proc.stdout or "").splitlines()[-80:]
            for line in out_tail:
                log_cb(line)
            log_cb(f"命令退出码: {proc.returncode}")
    finally:
        try:
            os.unlink(cfg_path)
        except Exception:
            pass
    out = proc.stdout or ""
    if paypal_mode and (
        "promo coupon" in out
        and "state=not_eligible" in out
        and "拒绝继续支付" in out
    ):
        if log_cb:
            log_cb("PayPal Plus Free coupon 未命中：按规则停止，不返回长链接、不进入 US 打开/后续操作")
    marker = "CARD_RESULT_JSON="
    payload = None
    for line in out.splitlines():
        if line.startswith(marker):
            try:
                payload = json.loads(line.split("=", 1)[1])
            except Exception:
                payload = None
    url = ""
    session_id = ""
    if isinstance(payload, dict):
        url = payload.get("url") or payload.get("checkout_url") or ""
        session_id = payload.get("session_id") or payload.get("checkout_session_id") or ""
    # Some --fresh-only paths return {"canonical_url", "fresh_url"} rather than
    # a generic "url" field. WebUI long-link generation wants the provider/raw
    # hosted link when available (pay.openai.com/c/pay/...). Without this fallback
    # the subprocess exits 0 but the WebUI marks the job as error because url is
    # empty.
    if isinstance(payload, dict) and not url:
        url = payload.get("fresh_url") or payload.get("provider_url") or payload.get("canonical_url") or ""
    if isinstance(payload, dict) and not session_id:
        session_id = payload.get("checkout_session_id") or ""
    if not url:
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                url = line
                break
    status = "ok" if proc.returncode == 0 and url else "error"
    if status == "ok":
        try:
            get_db().add_card_result({
                "ts": datetime.now(timezone.utc).isoformat(),
                "status": "payment_link",
                "chatgpt_email": account.get("email"),
                "email": account.get("email"),
                "session_id": session_id,
                "channel": "paypal_free_hosted_link" if paypal_mode else "gopay_freeplus_hosted_link",
                "entity": "openai_checkout_free_coupon" if paypal_mode else "openai_checkout_gopay_freeplus",
                "config": url,
            })
        except Exception:
            pass
    return {
        "id": account.get("id"),
        "email": account.get("email"),
        "status": status,
        "mode": "paypal_free_hosted" if paypal_mode else "gopay_freeplus_hosted",
        "payment_method": "paypal_available_checkout" if paypal_mode else "gopay_available_checkout",
        "url": url,
        "session_id": session_id,
        "billing": billing,
        "billing_text": (
            f"Name: {billing['name']}\n"
            f"Email: {billing['email']}\n"
            f"Address: {billing['address'].get('line1','')}\n"
            f"City: {billing['address'].get('city','')}\n"
            f"State: {billing['address'].get('state','')}\n"
            f"Postal: {billing['address'].get('postal_code','')}\n"
            f"Country: {billing['address'].get('country','')}"
            + (f"\nPromo: {promo_label or 'plus-1-month-free'}" if paypal_mode else "")
        ),
        "error": "" if status == "ok" else out[-1200:],
    }


def _paypal_page_debug_for_account(account: dict, log_cb=None) -> dict:
    """Generate PayPal redirect, open PayPal guest page, fill safe fields, screenshot.

    This is Ryan's page-debug path: it deliberately runs the payment.py entrypoint with
    --paypal-guest-handoff, which stops after filling non-payment PayPal guest
    fields from the configured info API. It must not fill card/CVV/password or
    click create/authorize/pay.
    """
    repo_root = s.ROOT
    cfg_path, billing = _account_temp_pay_config(account, mode="paypal")
    py = os.getenv("GPT_PAYMENT_PYTHON", str(repo_root / "venv" / "bin" / "python"))
    cmd = [
        py,
        str(repo_root / "CTF-pay" / "payment.py"),
        "fresh",
        "--paypal-guest-handoff",
        "--config",
        cfg_path,
        "--json-result",
    ]
    env = dict(os.environ)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    try:
        if log_cb:
            log_cb("PayPal页面调试：生成 Plus Free checkout → 取 PayPal redirect → 请求资料接口 → 填非支付字段 → 截图停住")
            log_cb("安全限制：不填卡号/有效期/CVV/密码，不点创建/授权/支付")
            log_cb("执行命令: " + " ".join(cmd))
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=420,
        )
        if log_cb:
            for line in (proc.stdout or "").splitlines()[-180:]:
                log_cb(line)
            log_cb(f"命令退出码: {proc.returncode}")
    finally:
        try:
            os.unlink(cfg_path)
        except Exception:
            pass
    out = proc.stdout or ""
    marker = "CARD_RESULT_JSON="
    payload = None
    for line in out.splitlines():
        if line.startswith(marker):
            try:
                payload = json.loads(line.split("=", 1)[1])
            except Exception:
                payload = None
    result = payload if isinstance(payload, dict) else {}
    screenshot = result.get("screenshot") or ""
    public_screenshot = result.get("public_screenshot") or ""
    url = result.get("url") or result.get("checkout_url") or ""
    status = "ok" if proc.returncode == 0 and (screenshot or public_screenshot or url) else "error"
    return {
        "id": account.get("id"),
        "email": account.get("email"),
        "status": status,
        "mode": "paypal_page_debug",
        "url": url,
        "screenshot": screenshot,
        "public_screenshot": public_screenshot,
        "session_id": result.get("session_id") or "",
        "filled_nonpayment": result.get("filled_nonpayment") or {},
        "title": result.get("title") or "",
        "text": result.get("text") or "",
        "billing": billing,
        "error": "" if status == "ok" else out[-1800:],
    }


GOPAY_BIND_PREFIX = "inventory_gopay_bind:"
GOPAY_PENDING_PREFIX = "inventory_gopay_pending:"
PVAPINS_BASE = "https://api.pvapins.com/user/api"


def _gopay_key(account_id: int) -> str:
    return f"{GOPAY_BIND_PREFIX}{int(account_id)}"


def _gopay_pending_key(account_id: int) -> str:
    return f"{GOPAY_PENDING_PREFIX}{int(account_id)}"


def _load_pvapins_cfg() -> dict:
    # Reuse SMS page config/API key so Ryan only stores the secret once.
    try:
        from .sms import _load_cfg as _sms_load_cfg  # type: ignore
        cfg = _sms_load_cfg()
    except Exception:
        cfg = {}
    api_key = str(cfg.get("api_key") or cfg.get("token") or "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="PVAPins API Key 未配置：请先在 SMS 接码页保存 API Key")
    return {
        "api_key": api_key,
        "country": "Indonesia",
        "base": "https://api.pvapins.com/user/api",
    }


def _pvapins_get(path: str, params: dict, timeout: float = 30.0) -> dict:
    url = f"{PVAPINS_BASE}/{path.lstrip('/')}"
    try:
        r = requests.get(url, params={k: v for k, v in params.items() if v not in (None, "")}, timeout=timeout,
                         headers={"Accept": "application/json, text/plain, */*", "User-Agent": "OpenClaw-WebUI/1.0"})
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"PVAPins 请求失败: {type(e).__name__}: {e}")
    try:
        body = r.json()
    except Exception:
        body = r.text[:4000]
    return {"status_code": r.status_code, "ok": r.ok, "body": body, "url": url, "params": params}


def _extract_phone_from_pvapins(resp: dict) -> str:
    body = resp.get("body")
    if isinstance(body, dict):
        for key in ("phone", "number", "mobile", "msisdn", "data"):
            val = str(body.get(key) or "").strip()
            if re.fullmatch(r"\+?\d{8,}", val):
                return val.lstrip("+")
        data = body.get("data")
        if isinstance(data, dict):
            for key in ("phone", "number", "mobile", "msisdn"):
                val = str(data.get(key) or "").strip()
                if re.fullmatch(r"\+?\d{8,}", val):
                    return val.lstrip("+")
    text = json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body or "")
    m = re.search(r"\+?\d{8,}", text)
    return m.group(0).lstrip("+") if m else ""


def _extract_sms_code(resp: dict) -> dict:
    body = resp.get("body")
    text = json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body or "")
    if isinstance(body, dict):
        for key in ("otp", "code", "sms", "message", "text", "data"):
            val = body.get(key)
            if isinstance(val, (dict, list)):
                val = json.dumps(val, ensure_ascii=False)
            val = str(val or "")
            m = re.search(r"(?<!\d)(\d{4,8})(?!\d)", val)
            if m:
                return {"code": m.group(1), "sms_text": val[:2000]}
    m = re.search(r"(?<!\d)(\d{4,8})(?!\d)", text)
    return {"code": m.group(1) if m else "", "sms_text": text[:2000]}


def _load_gojek_apps(force: bool = False) -> list[dict]:
    db = get_db()
    cache_key = "pvapins_gojek_apps_indonesia"
    if not force:
        cached = db.get_runtime_json(cache_key, {}) or {}
        if time.time() - float(cached.get("ts") or 0) < 3600 and cached.get("apps"):
            return cached["apps"]
    countries = _pvapins_get("load_countries.php", {})
    country_id = "106"
    if isinstance(countries.get("body"), list):
        for c in countries["body"]:
            if "indonesia" in str(c.get("full_name") or "").lower():
                country_id = str(c.get("id") or country_id)
                break
    apps_resp = _pvapins_get("load_apps.php", {"country_id": country_id})
    apps = []
    if isinstance(apps_resp.get("body"), list):
        for a in apps_resp["body"]:
            name = str(a.get("full_name") or "")
            if "gojek" in name.lower():
                try:
                    price = float(a.get("deduct") or 9999)
                except Exception:
                    price = 9999.0
                apps.append({"id": a.get("id"), "app": name, "price": price, "raw": a})
    apps.sort(key=lambda x: (x["price"], len(str(x["app"]))))
    if not apps:
        raise HTTPException(status_code=502, detail="PVAPins 未找到 Indonesia 的 Gojek 服务")
    db.set_runtime_json(cache_key, {"ts": time.time(), "apps": apps[:100]})
    return apps


def _get_account_or_404(account_id: int) -> dict:
    acc = get_db().get_registered_account(int(account_id))
    if not acc:
        raise HTTPException(status_code=404, detail="账号不存在")
    return acc


def _save_pending_phone(account_id: int, payload: dict):
    get_db().set_runtime_json(_gopay_pending_key(account_id), {**payload, "updated_at": time.time()})


def _get_pending_phone(account_id: int) -> dict:
    return get_db().get_runtime_json(_gopay_pending_key(account_id), {}) or {}


def _save_gopay_binding(account_id: int, payload: dict):
    get_db().set_runtime_json(_gopay_key(account_id), {**payload, "updated_at": time.time()})


def _get_gopay_binding(account_id: int) -> dict:
    return get_db().get_runtime_json(_gopay_key(account_id), {}) or {}


def _pvapins_cancel_success(resp: dict) -> bool:
    body = resp.get("body")
    text = json.dumps(body, ensure_ascii=False).lower() if isinstance(body, (dict, list)) else str(body or "").lower()
    # PVAPins docs list "Number Rejected." as the positive response. Some
    # variants use code/success/status fields, so accept those too.
    if ("number rejected" in text or "rejected" in text or "cancelled" in text or "canceled" in text
            or "号码已被拒绝" in text or "已被拒绝" in text or "拒绝成功" in text):
        return True
    if isinstance(body, dict):
        code = str(body.get("code") or body.get("status") or "").lower()
        msg = str(body.get("message") or body.get("msg") or body.get("data") or "").lower()
        if code in {"100", "200", "success", "ok", "true"} and not any(x in msg for x in ("not", "error", "fail")):
            return True
    return False


def _phone_variants(phone: str) -> list[str]:
    p = re.sub(r"\D", "", str(phone or ""))
    out = []
    if p:
        out.append(p)
        if p.startswith("62") and len(p) > 10:
            out.append(p[2:])
        if p.startswith("0") and len(p) > 9:
            out.append(p[1:])
    # preserve order, de-dupe
    return list(dict.fromkeys(out))


def _cancel_pvapins_phone(phone: str, app: str, country: str = "Indonesia", operator: str = "") -> dict:
    cfg = _load_pvapins_cfg()
    if not phone or not app:
        return {"ok": False, "provider_rejected": False, "skipped": True, "error": "缺 phone/app"}
    attempts = []
    # Official docs: get_reject_number.php?customer=&number=&country=&app=&operator=
    # Note also mentions alternate get_reject.php using n_id. Try both, with
    # full 62xxx and local 8xxx variants because provider UI can display either.
    app_operator_pairs = [(app, operator or "")]
    # If app is a combined service like Gojek12 and no explicit operator was
    # stored, also try app=Gojek&operator=12 (same pairing rule as docs).
    m = re.fullmatch(r"([A-Za-z._ -]+?)(\d+)", app.strip())
    if m and not operator:
        app_operator_pairs.append((m.group(1).strip(), m.group(2)))
    for num in _phone_variants(phone):
        for app_name, op in app_operator_pairs:
            for path, key in (("get_reject_number.php", "number"), ("get_reject.php", "n_id")):
                params = {"customer": cfg["api_key"], key: num, "country": country or "Indonesia", "app": app_name}
                if op:
                    params["operator"] = op
                resp = _pvapins_get(path, params)
                resp["attempt"] = {"path": path, key: num, "app": app_name, "operator": op}
                attempts.append(resp)
                if _pvapins_cancel_success(resp):
                    return {"ok": True, "provider_rejected": True, "phone": phone, "app": app, "country": country, "operator": operator, "attempts": attempts, "body": resp.get("body")}
    return {"ok": False, "provider_rejected": False, "phone": phone, "app": app, "country": country, "operator": operator, "attempts": attempts, "error": "PVAPins 未确认取消成功"}


def _load_cpa_cfg() -> dict:
    try:
        cfg = json.loads(s.PAY_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读 PAY_CONFIG_PATH 失败: {e}")
    cpa = (cfg.get("cpa") or {})
    if not cpa.get("enabled"):
        raise HTTPException(status_code=400,
                            detail="CPA 未启用：请先在 wizard Step11 填 base_url + admin_key 并启用")
    if not (cpa.get("base_url") and cpa.get("admin_key")):
        raise HTTPException(status_code=400, detail="CPA 配置缺 base_url 或 admin_key")
    return cpa


def _do_cpa_push(account: dict, cpa_cfg: dict) -> dict:
    """Run the CPA push for one account using pipeline._cpa_import_after_team.
    Records outcome to pipeline_results so inventory reflects new state."""
    import sys
    from pathlib import Path
    repo_root = Path(__file__).resolve().parents[3]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    import pipeline  # type: ignore

    email = account.get("email", "")
    rt = (account.get("refresh_token") or "").strip()
    is_free = False  # caller will set via plan_tag if needed; default False == use plan_tag
    try:
        status = pipeline._cpa_import_after_team(
            email, "", cpa_cfg, refresh_token=rt, is_free=is_free,
        )
    except Exception as e:
        status = f"error: {type(e).__name__}: {str(e)[:120]}"

    # 记一条 pipeline_results 让 inventory 的 cpa_status 能反映本次推送
    try:
        get_db().add_pipeline_result({
            "ts": datetime.now(timezone.utc).isoformat(),
            "mode": "cpa_push_manual",
            "status": "ok" if status == "ok" else "fail",
            "registration": {"status": "reused", "email": email},
            "payment": {"status": "skipped", "email": email},
            "cpa_import": status,
        })
    except Exception:
        pass
    return {"id": account.get("id"), "email": email, "status": status}


def _inventory_stock_key() -> str:
    return "inventory_stock_status_v1"


def _load_inventory_stock_map() -> dict[str, bool]:
    raw = get_db().get_runtime_json(_inventory_stock_key(), {}) or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, bool] = {}
    for k, v in raw.items():
        try:
            out[str(int(k))] = bool(v)
        except Exception:
            continue
    return out


def _set_inventory_stock(ids: list[int], checked_out: bool) -> int:
    ids = [int(x) for x in ids if str(x).strip().lstrip("-").isdigit()]
    m = _load_inventory_stock_map()
    for aid in ids:
        m[str(aid)] = bool(checked_out)
    get_db().set_runtime_json(_inventory_stock_key(), m)
    return len(ids)


def _find_mail_otp_url(email: str, password: str = "") -> str:
    email_l = str(email or "").strip().lower()
    if not email_l:
        return ""
    candidates = [
        s.ROOT / "CTF-reg" / "custom_mail_pool.txt",
        s.ROOT / "CTF-reg" / "custom_mail_pool.used.txt",
        s.ROOT / "CTF-reg" / "custom_mail_pool.txt.used",
        s.ROOT / "CTF-pay" / "custom_mail_pool.txt",
    ]
    for p in candidates:
        if not p.exists():
            continue
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if email_l not in line.lower():
                    continue
                parts = re.split(r"----|\t|,", line.strip())
                parts = [x.strip() for x in parts if x.strip()]
                for part in parts[1:]:
                    if part.startswith(("http://", "https://")):
                        return part
        except Exception:
            pass
    tpl = os.getenv("CUSTOM_MAIL_OTP_URL_TEMPLATE", "https://ms.lqqq.cc/web/{email}----{password}")
    try:
        return tpl.format(email=email_l, password=password or "")
    except Exception:
        return ""


def _cpa_export_body(account: dict) -> dict:
    import base64
    email = account.get("email", "")
    rt = (account.get("refresh_token") or "").strip() or get_db().latest_refresh_token_for_email(email)
    at = (account.get("access_token") or "").strip()
    id_tok = (account.get("id_token") or "").strip() or at
    account_id = ""
    expired_iso = ""
    if at:
        try:
            p = at.split(".")[1]
            p += "=" * ((4 - len(p) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p).decode())
            account_id = (payload.get("https://api.openai.com/auth") or {}).get("chatgpt_account_id", "") or ""
            if payload.get("exp"):
                expired_iso = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id_token": id_tok,
        "access_token": at,
        "refresh_token": rt,
        "account_id": account_id,
        "email": email,
        "last_refresh": now_iso,
        "expired": expired_iso,
        "type": "codex",
    }


def _jwt_payload(token: str) -> dict:
    import base64
    token = (token or "").strip()
    try:
        part = token.split(".")[1]
        part += "=" * ((4 - len(part) % 4) % 4)
        data = json.loads(base64.urlsafe_b64decode(part).decode())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _sub2_export_body(account: dict) -> dict:
    """Sub2API import account object."""
    email = account.get("email", "")
    password = account.get("password", "") or ""
    at = (account.get("access_token") or "").strip()
    id_tok = (account.get("id_token") or "").strip() or at
    at_payload = _jwt_payload(at)
    id_payload = _jwt_payload(id_tok)
    auth = (id_payload.get("https://api.openai.com/auth") or at_payload.get("https://api.openai.com/auth") or {})
    profile = at_payload.get("https://api.openai.com/profile") or {}
    exp = id_payload.get("exp") or at_payload.get("exp") or 0
    try:
        exp_i = int(exp or 0)
    except Exception:
        exp_i = 0
    now_ts = int(time.time())
    plan_type = auth.get("chatgpt_plan_type") or account.get("plan_tag") or account.get("plan") or ""
    otp_url = _find_mail_otp_url(email, password)
    # If the mailbox URL is shaped like .../{mailbox_key}----{mail_password}, expose the key as email_key.
    email_key = ""
    try:
        tail = otp_url.rstrip("/").split("/")[-1]
        email_key = tail.split("----", 1)[0] if tail and "@" not in tail else ""
    except Exception:
        email_key = ""
    now_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "name": email,
        "platform": "openai",
        "type": "oauth",
        "concurrency": 10,
        "priority": 1,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
        "credentials": {
            "access_token": at,
            "id_token": id_tok,
            "refresh_token": (account.get("refresh_token") or "").strip() or get_db().latest_refresh_token_for_email(email),
            "chatgpt_account_id": auth.get("chatgpt_account_id") or "",
            "chatgpt_user_id": auth.get("chatgpt_user_id") or auth.get("user_id") or "",
            "email": profile.get("email") or email,
            "plan_type": plan_type,
            "expires_at": exp_i,
            "expires_in": max(0, exp_i - now_ts) if exp_i else 0,
        },
        "extra": {
            "email": email,
            "email_key": email_key,
            "name": email_key or email,
            "auth_provider": "openai",
            "privacy_mode": "training_off",
            "source": "chatgpt_web_session",
            "last_refresh": now_iso,
        },
    }


def _sub2_export_document(rows: list[dict]) -> dict:
    return {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "proxies": [],
        "accounts": [_sub2_export_body(acc) for acc in rows],
    }


def _export_accounts(ids: list[int], fmt: str) -> Response:
    db = get_db()
    rows = []
    for aid in ids:
        acc = db.get_registered_account(int(aid))
        if acc:
            rows.append(acc)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fmt = (fmt or "credentials").strip().lower().replace("-", "_")

    if fmt in {"cpa_json", "cpajson"}:
        payload = [_cpa_export_body(acc) for acc in rows]
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return Response(content, media_type="application/json; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="inventory_cpa_{ts}.json"'})

    if fmt in {"sub2_json", "sub2json", "sub2"}:
        payload = _sub2_export_document(rows)
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return Response(content, media_type="application/json; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="inventory_sub2_{ts}.json"'})

    if fmt in {"cpa", "json", "cpa_txt", "jsonl", "cpa_card", "cpa_key"}:
        payload = [_cpa_export_body(acc) for acc in rows]
        content = "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in payload)
        if content:
            content += "\n"
        return Response(content, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="inventory_cpa_{ts}.txt"'})

    lines = []
    for acc in rows:
        email = acc.get("email", "")
        password = acc.get("password", "") or ""
        rt = (acc.get("refresh_token") or "").strip() or db.latest_refresh_token_for_email(email)
        otp_url = _find_mail_otp_url(email, password)
        lines.append(f"{email}---—{password}---—{rt}---—{otp_url}")
    content = "\n".join(lines) + ("\n" if lines else "")
    return Response(content, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="inventory_credentials_{ts}.txt"'})


@router.get("/accounts")
def get_accounts(user: str = CurrentUser):
    inv = build_accounts_inventory()
    stock = _load_inventory_stock_map()
    for acc in inv.get("accounts") or []:
        acc["inventory_checked_out"] = bool(stock.get(str(acc.get("id"))))
        acc["account_status"] = acc.get("last_check_status") or ""
    return inv




@router.get("/standalone-page", response_class=HTMLResponse)
def standalone_page(user: str | None = Depends(current_user_optional), token: str = ""):
    """Serve the standalone inventory page.

    If the browser has a valid WebUI session cookie, serve it directly. If it
    does not, fall back to the static standalone page: the page will request a
    token after login for data/actions, but the HTML itself should remain
    reachable from bookmarked public URLs.
    """
    static_path = Path("/var/www/dujiao-sitemap/local-inventory.html")
    if static_path.exists():
        html = static_path.read_text(encoding="utf-8")
    else:
        html = """<!doctype html><meta charset='utf-8'><title>Inventory</title><body><h1>Inventory standalone page missing</h1><p>/var/www/dujiao-sitemap/local-inventory.html not found.</p></body>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@router.get("/standalone-redirect")
def standalone_redirect(user: str | None = Depends(current_user_optional), token: str = ""):
    return RedirectResponse(url="/webui/api/inventory/standalone-page", status_code=302)
@router.get("/share-token")
def share_token(user: str = CurrentUser):
    """Return a per-install token for standalone static pages.

    The page itself is public static HTML, but data/actions still require either
    WebUI cookie auth or this token obtained after WebUI login.
    """
    return {"token": _share_token()}


def _standalone_authorized(token: str, user: str | None) -> bool:
    # Static standalone pages first try WebUI cookie auth; token is fallback for
    # cross-path deployments and avoids putting these pages in WebUI navigation.
    return bool(user) or bool(token and token == _share_token())


@router.get("/standalone/accounts")
def standalone_accounts(token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return get_accounts(user=user or "standalone")


@router.post("/standalone/status")
def standalone_status(req: InventoryStatusRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    return {"ok": True, "updated": _set_inventory_stock(req.ids, req.checked_out), "checked_out": req.checked_out}


@router.post("/standalone/check-fresh")
def standalone_check_fresh(req: CheckRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return check_accounts(req, user=user or "standalone")


@router.post("/standalone/check-plan")
def standalone_check_plan(req: CheckRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return check_accounts_plan(req, user=user or "standalone")


@router.post("/standalone/export")
def standalone_export(req: ExportRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 1000:
        raise HTTPException(status_code=400, detail="单次最多导出 1000 个")
    return _export_accounts(req.ids, req.format)


@router.post("/standalone/delete")
def standalone_delete_accounts(req: IdsRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 1000:
        raise HTTPException(status_code=400, detail="单次最多删除 1000 个")
    return delete_accounts(req, user=user or "standalone")


@router.post("/standalone/payment-link")
def standalone_payment_link(req: PaymentLinkRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return payment_link(req, user=user or "standalone")


@router.post("/standalone/payment-link/start")
def standalone_payment_link_start(req: PaymentLinkRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return payment_link_start(req, user=user or "standalone")


@router.post("/standalone/rt-only/start")
def standalone_rt_only_start(req: IdsRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 100:
        raise HTTPException(status_code=400, detail="单次最多选择 100 个账号补 RT")
    db = get_db()
    emails: list[str] = []
    missing: list[int] = []
    for aid in req.ids:
        acc = db.get_registered_account(int(aid))
        if not acc:
            missing.append(int(aid))
            continue
        email = str(acc.get("email") or "").strip()
        if email:
            emails.append(email)
    if not emails:
        detail = "选中账号没有可用邮箱"
        if missing:
            detail += f"；不存在 ID: {missing[:10]}"
        raise HTTPException(status_code=400, detail=detail)
    try:
        st = runner.start(
            mode="single",
            paypal=False,
            gopay=False,
            pay_only=False,
            register_only=False,
            rt_only=True,
            target_emails=emails,
            register_mode="browser",
        )
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"ok": True, "count": len(emails), "emails": emails, "missing_ids": missing, "status": st}


@router.get("/standalone/rt-only/status")
def standalone_rt_only_status(token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return runner.status()


@router.get("/standalone/rt-only/logs")
def standalone_rt_only_logs(tail: int = 300, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return {"lines": runner.get_tail(max(1, min(int(tail or 300), 1000)))}


@router.get("/standalone/payment-link/job/{job_id}")
def standalone_payment_link_job(job_id: str, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return payment_link_job(job_id, user=user or "standalone")



@router.get("/standalone/payonly/pool")
def standalone_payonly_pool(token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    pool = _load_payonly_pool()
    return {"count": len(pool), "preview": [{"index": i, "keys": sorted(list(x.keys()))[:12]} for i, x in enumerate(pool[:20])]}


@router.post("/standalone/payonly/pool")
def standalone_payonly_pool_add(req: PayonlyPoolRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    items = _parse_payonly_pool_req(req)
    if not items:
        raise HTTPException(status_code=400, detail="没有可加入池子的 JSON body")
    pool = _load_payonly_pool()
    pool.extend(items)
    _save_payonly_pool(pool)
    return {"ok": True, "added": len(items), "count": len(pool)}


@router.get("/standalone/payonly/cache/{account_id}")
def standalone_payonly_cache(account_id: int, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    cached = get_db().get_runtime_json(_payonly_cache_key(account_id), {}) or {}
    card = (cached.get("card_info") or {}) if isinstance(cached, dict) else {}
    return {
        "bound": bool(card),
        "account_id": account_id,
        "email": cached.get("email") if isinstance(cached, dict) else "",
        "assigned_at": cached.get("assigned_at") if isinstance(cached, dict) else "",
        "card_tail": str(card.get("card_number") or "")[-4:] if isinstance(card, dict) else "",
    }


@router.get("/accounts/{account_id}/gopay-phone")
def gopay_phone_get(account_id: int, user: str = CurrentUser):
    _get_account_or_404(account_id)
    return {"binding": _get_gopay_binding(account_id), "pending": _get_pending_phone(account_id)}


@router.post("/accounts/{account_id}/gopay-phone/get")
def gopay_phone_get_number(account_id: int, user: str = CurrentUser):
    _get_account_or_404(account_id)
    cfg = _load_pvapins_cfg()
    apps = _load_gojek_apps()
    errors = []
    for app in apps[:12]:
        resp = _pvapins_get("get_number.php", {"customer": cfg["api_key"], "app": app["app"], "country": "Indonesia"})
        phone = _extract_phone_from_pvapins(resp)
        if phone:
            payload = {"phone": phone, "app": app["app"], "country": "Indonesia", "operator": "", "price": app.get("price"), "status": "pending", "raw": resp}
            _save_pending_phone(account_id, payload)
            return payload
        errors.append({"app": app["app"], "price": app.get("price"), "body": resp.get("body")})
    raise HTTPException(status_code=502, detail={"message": "最便宜的 Gojek 服务暂时未取到号码", "tried": errors[:6]})


@router.post("/accounts/{account_id}/gopay-phone/poll-sms")
def gopay_phone_poll_sms(account_id: int, req: GopayPhoneRequest, user: str = CurrentUser):
    _get_account_or_404(account_id)
    cfg = _load_pvapins_cfg()
    phone = req.phone or _get_pending_phone(account_id).get("phone") or _get_gopay_binding(account_id).get("phone")
    app = req.app or _get_pending_phone(account_id).get("app") or _get_gopay_binding(account_id).get("app")
    country = req.country or "Indonesia"
    if not phone or not app:
        raise HTTPException(status_code=400, detail="缺 phone/app")
    resp = _pvapins_get("get_sms.php", {"customer": cfg["api_key"], "number": phone, "country": country, "app": app})
    parsed = _extract_sms_code(resp)
    return {**resp, **parsed, "phone": phone, "app": app, "country": country}


@router.post("/accounts/{account_id}/gopay-phone/reuse")
def gopay_phone_reuse(account_id: int, req: GopayPhoneRequest, user: str = CurrentUser):
    _get_account_or_404(account_id)
    cfg = _load_pvapins_cfg()
    phone = req.phone or _get_pending_phone(account_id).get("phone") or _get_gopay_binding(account_id).get("phone")
    app = req.app or _get_pending_phone(account_id).get("app") or _get_gopay_binding(account_id).get("app")
    country = req.country or "Indonesia"
    if not phone or not app:
        raise HTTPException(status_code=400, detail="缺 phone/app")
    resp = _pvapins_get("get_number.php", {"customer": cfg["api_key"], "app": app, "country": country, "number": phone})
    _save_pending_phone(account_id, {"phone": phone, "app": app, "country": country, "status": "pending_reuse", "raw": resp})
    return {**resp, "phone": phone, "app": app, "country": country}


@router.post("/accounts/{account_id}/gopay-phone/cancel")
def gopay_phone_cancel(account_id: int, req: GopayPhoneRequest, user: str = CurrentUser):
    _get_account_or_404(account_id)
    phone = req.phone or _get_pending_phone(account_id).get("phone") or _get_gopay_binding(account_id).get("phone")
    app = req.app or _get_pending_phone(account_id).get("app") or _get_gopay_binding(account_id).get("app")
    country = req.country or "Indonesia"
    operator = req.operator or _get_pending_phone(account_id).get("operator") or _get_gopay_binding(account_id).get("operator") or ""
    resp = _cancel_pvapins_phone(phone, app, country, operator)
    if resp.get("provider_rejected"):
        get_db().delete_runtime_key(_gopay_pending_key(account_id))
    return {**resp, "phone": phone, "app": app, "country": country}


@router.post("/accounts/{account_id}/gopay-phone/save")
def gopay_phone_save(account_id: int, req: GopayPhoneSaveRequest, user: str = CurrentUser):
    acc = _get_account_or_404(account_id)
    phone = (req.phone or _get_pending_phone(account_id).get("phone") or "").strip().lstrip("+")
    app = (req.app or _get_pending_phone(account_id).get("app") or "").strip()
    country = req.country or "Indonesia"
    operator = (req.operator or _get_pending_phone(account_id).get("operator") or "").strip()
    if not phone or not app:
        raise HTTPException(status_code=400, detail="缺 phone/app，不能保存绑定")
    local = phone
    if local.startswith("62"):
        local = local[2:]
    payload = {
        "account_id": account_id,
        "email": acc.get("email"),
        "phone": phone,
        "country_code": "62",
        "phone_number": local,
        "app": app,
        "country": country,
        "operator": operator,
        "pin": "111222",
        "status": req.status or "bound",
    }
    _save_gopay_binding(account_id, payload)
    get_db().delete_runtime_key(_gopay_pending_key(account_id))
    return {"ok": True, "binding": payload}


@router.post("/accounts/{account_id}/gopay-phone/replace")
def gopay_phone_replace(account_id: int, req: GopayPhoneRequest, user: str = CurrentUser):
    _get_account_or_404(account_id)
    old_phone = req.phone or _get_pending_phone(account_id).get("phone") or _get_gopay_binding(account_id).get("phone")
    old_app = req.app or _get_pending_phone(account_id).get("app") or _get_gopay_binding(account_id).get("app")
    old_country = req.country or "Indonesia"
    old_operator = req.operator or _get_pending_phone(account_id).get("operator") or _get_gopay_binding(account_id).get("operator") or ""
    old_cancel = _cancel_pvapins_phone(old_phone, old_app, old_country, old_operator) if old_phone and old_app else {"skipped": True, "provider_rejected": True}
    if old_phone and old_app and not old_cancel.get("provider_rejected"):
        return {"ok": False, "old_cancel": old_cancel, "error": "旧手机号未确认取消成功，已停止更换"}
    # Clear binding/pending before getting the new number.
    get_db().delete_runtime_key(_gopay_pending_key(account_id))
    get_db().delete_runtime_key(_gopay_key(account_id))
    new_payload = gopay_phone_get_number(account_id, user=user)
    return {"ok": True, "old_cancel": old_cancel, "new_phone": new_payload}


def _plan_override_key() -> str:
    return "inventory_plan_overrides"


def _load_plan_overrides() -> dict[str, str]:
    raw = get_db().get_runtime_json(_plan_override_key(), {})
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        email = str(k or "").strip().lower()
        plan = str(v or "").strip().lower()
        if email and plan in {"free", "plus", "team"}:
            out[email] = plan
    return out


@router.post("/accounts/{account_id}/plan")
def account_plan_update(account_id: int, req: PlanOverrideRequest, user: str = CurrentUser):
    acc = _get_account_or_404(account_id)
    plan = (req.plan or "").strip().lower()
    if plan not in {"free", "plus", "team"}:
        raise HTTPException(status_code=400, detail="plan 只能是 free / plus / team")
    data = _load_plan_overrides()
    data[str(acc.get("email") or "").lower()] = plan
    get_db().set_runtime_json(_plan_override_key(), data)
    return {"ok": True, "id": account_id, "email": acc.get("email"), "plan": plan}


@router.post("/standalone/accounts/{account_id}/plan")
def standalone_account_plan_update(account_id: int, req: PlanOverrideRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return account_plan_update(account_id, req, user=user or "standalone")


@router.post("/accounts/check")
def check_accounts(req: CheckRequest, user: str = CurrentUser):
    """Freshly probe each account against OpenAI and persist the result.

    This endpoint intentionally does not read/cache old `last_check_status` values;
    every call performs live credential checks before returning.
    Body: {ids: [account_id, ...], timeout_s?, max_workers?}.
    Returns per-account {id, email, status, message} (status: valid|invalid|unknown)."""
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 500:
        raise HTTPException(status_code=400, detail="单次最多 500 个")
    workers = max(1, min(int(req.max_workers), 8))
    timeout = max(2.0, min(float(req.timeout_s), 30.0))
    results = validate_accounts(req.ids, max_workers=workers, timeout_s=timeout)
    summary = {
        "total": len(results),
        "valid": sum(1 for r in results if r.get("status") == "valid"),
        "invalid": sum(1 for r in results if r.get("status") == "invalid"),
        "unknown": sum(1 for r in results if r.get("status") == "unknown"),
    }
    return {"results": results, "summary": summary, "fresh": True}


@router.post("/accounts/check-fresh")
def check_accounts_fresh(req: CheckRequest, user: str = CurrentUser):
    """Alias for UI actions that must explicitly perform live checks, not old data."""
    return check_accounts(req, user=user)


@router.post("/accounts/check-plan")
def check_accounts_plan(req: CheckRequest, user: str = CurrentUser):
    """Live paid/free plan probe for selected accounts.

    Uses OAuth id_token chatgpt_plan_type first, then refresh_token to mint a
    fresh id_token, then ChatGPT accounts/check account.plan_type /
    entitlement.subscription_plan as fallback.
    """
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 200:
        raise HTTPException(status_code=400, detail="单次最多 200 个")
    workers = max(1, min(int(req.max_workers), 8))
    timeout = max(2.0, min(float(req.timeout_s), 30.0))
    results = check_account_plans(req.ids, max_workers=workers, timeout_s=timeout)
    summary = {
        "total": len(results),
        "paid": sum(1 for r in results if r.get("status") == "paid"),
        "free": sum(1 for r in results if r.get("status") == "free"),
        "unknown": sum(1 for r in results if r.get("status") == "unknown"),
        "missing": sum(1 for r in results if r.get("status") == "missing"),
    }
    return {"results": results, "summary": summary, "fresh": True}


@router.post("/accounts/revoke-checkout")
def revoke_checkout_accounts(req: IdsRequest, user: str = CurrentUser):
    """Cancel the inventory checked-out/permission marker for selected accounts."""
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    return {"ok": True, "updated": _set_inventory_stock(req.ids, False), "checked_out": False}


@router.post("/accounts/status")
def account_status_update(req: InventoryStatusRequest, user: str = CurrentUser):
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    return {"ok": True, "updated": _set_inventory_stock(req.ids, req.checked_out), "checked_out": req.checked_out}


@router.post("/accounts/export")
def accounts_export(req: ExportRequest, user: str = CurrentUser):
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 1000:
        raise HTTPException(status_code=400, detail="单次最多导出 1000 个")
    return _export_accounts(req.ids, req.format)


@router.post("/accounts/delete")
def delete_accounts(req: IdsRequest, user: str = CurrentUser):
    """Hard-delete accounts by id. Associated pipeline_results / card_results /
    oauth_status rows are kept (audit trail; lookup by email still works)."""
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    n = get_db().delete_registered_accounts(req.ids)
    return {"deleted": n, "requested": len(req.ids)}


@router.post("/accounts/payment-link/start")
def payment_link_start(req: PaymentLinkRequest, user: str = CurrentUser):
    mode = (req.mode or "hosted").strip().lower()
    if mode in {"payonly_auto", "payonly-auto", "payonly_queue", "payonly-queue"}:
        mode = "payonly_auto"
    if not req.ids and mode != "payonly_auto":
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 20 and mode != "payonly_auto":
        raise HTTPException(status_code=400, detail="单次最多 20 个，避免触发风控")
    ids = [int(x) for x in req.ids]
    if mode not in {"hosted", "gopay", "gopay_freeplus", "gopay-freeplus", "paypal", "paypal_link", "paypal-link", "payonly", "payonly_script", "payonly-script", "payonly_auto"}:
        raise HTTPException(status_code=400, detail="库存页只允许 GoPay FreePlus / paypal / PayOnly 脚本模式")
    if mode in {"paypal_link", "paypal-link"}:
        mode = "paypal"
    if mode in {"payonly_script", "payonly-script"}:
        mode = "payonly"
    job_ids = ids
    if mode == "payonly_auto" and not job_ids:
        job_ids = [0] * max(1, min(int(req.limit or 1), 100))
    job_id = _new_payment_job(job_ids, mode=mode)
    t = threading.Thread(target=_run_payment_job, args=(job_id, job_ids, mode), daemon=True)
    t.start()
    return {"job_id": job_id, "status": "queued"}


@router.get("/accounts/payment-link/job/{job_id}")
def payment_link_job(job_id: str, user: str = CurrentUser):
    return _get_payment_job(job_id)


@router.post("/paypal-page-debug")
def paypal_page_debug(req: PaypalPageDebugRequest, user: str = CurrentUser):
    db = get_db()
    acc = db.get_registered_account(int(req.account_id))
    if not acc:
        raise HTTPException(status_code=404, detail="账号不存在")
    if not (acc.get("session_token") or acc.get("access_token")):
        raise HTTPException(status_code=400, detail="该账号缺 session/access token，不能生成 PayPal checkout")
    logs: list[str] = []

    def log_cb(line: str):
        ts = datetime.now().strftime("%H:%M:%S")
        logs.append(f"[{ts}] {line}")

    result = _paypal_page_debug_for_account(acc, log_cb=log_cb)
    return {"result": result, "logs": logs[-1200:]}


@router.post("/standalone/paypal-page-debug")
def standalone_paypal_page_debug(req: PaypalPageDebugRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return paypal_page_debug(req, user=user or "standalone")


@router.post("/accounts/payment-link")
def payment_link(req: PaymentLinkRequest, user: str = CurrentUser):
    """Generate long hosted payment links for selected inventory accounts.

    Uses each account's stored session/access token. hosted mode stops at fresh-only
    provider URL; paypal mode also stops at fresh-only hosted checkout URL with
    the free promo configured, and never enters Stripe confirm / PayPal redirect.
    """
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 20:
        raise HTTPException(status_code=400, detail="单次最多 20 个，避免触发风控")
    results = []
    db = get_db()
    for aid in req.ids:
        acc = db.get_registered_account(int(aid))
        if not acc:
            results.append({"id": aid, "email": "", "status": "missing", "url": "", "error": "账号不存在"})
            continue
        if not (acc.get("session_token") or acc.get("access_token")):
            results.append({"id": aid, "email": acc.get("email"), "status": "no_auth", "url": "", "error": "缺 session/access token"})
            continue
        results.append(_generate_payment_link_for_account(acc, mode=(req.mode or "hosted").strip().lower()))
    return {
        "results": results,
        "summary": {
            "total": len(results),
            "ok": sum(1 for r in results if r.get("status") == "ok"),
            "fail": sum(1 for r in results if r.get("status") != "ok"),
        },
    }


@router.post("/accounts/cpa-push")
def cpa_push(req: IdsRequest, user: str = CurrentUser):
    """Push selected accounts to CPA (CLIProxyAPI). Reuses
    pipeline._cpa_import_after_team. Each row's stored refresh_token (or
    fallback access_token) is used; records outcome to pipeline_results."""
    if not req.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    if len(req.ids) > 100:
        raise HTTPException(status_code=400, detail="单次最多 100 个")
    cpa_cfg = _load_cpa_cfg()
    db = get_db()
    results: list[dict] = []
    for aid in req.ids:
        acc = db.get_registered_account(int(aid))
        if not acc:
            results.append({"id": aid, "email": "", "status": "missing"})
            continue
        results.append(_do_cpa_push(acc, cpa_cfg))
    summary = {
        "total": len(results),
        "ok": sum(1 for r in results if r.get("status") == "ok"),
        "no_rt": sum(1 for r in results if r.get("status") == "no_rt"),
        "fail": sum(1 for r in results if r.get("status") not in ("ok", "no_rt", "skipped", "missing")),
    }
    return {"results": results, "summary": summary}
