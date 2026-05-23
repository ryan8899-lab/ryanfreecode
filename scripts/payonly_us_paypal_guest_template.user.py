#!/usr/bin/env python3
"""Payonly: JP proxy only for long-link generation; US proxy for opening/payment.
"""
from __future__ import annotations

import json
import os
import re
import requests
import shutil
import subprocess
import sys
import time
import random
import base64
import uuid
import fcntl
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, "/root/Gpt-Agreement-Payment")
sys.path.insert(0, "/root/Gpt-Agreement-Payment/webui")

from webui.backend.db import get_db
from webui.backend.routes.inventory import _account_temp_pay_config, _generate_payment_link_for_account

REPO = Path(__file__).resolve().parent.parent
PAYMENT_PY = REPO / "CTF-pay" / "payment.py"

PAYONLY_URL = os.getenv('PAYONLY_URL', '').strip()
US_PROXY_POOL_FILE = Path(os.getenv('PAYONLY_US_PROXY_POOL_FILE', str(REPO / 'output' / 'payonly_us_proxy_pool.txt')))
US_PROXY_STATE_FILE = Path(os.getenv('PAYONLY_US_PROXY_STATE_FILE', str(REPO / 'output' / 'payonly_us_proxy_pool.state')))
US_PROXY_POOL_DB_KEY = os.getenv('PAYONLY_US_PROXY_POOL_DB_KEY', 'proxy_pool_us_v1')
US_PROXY_STATE_DB_KEY = os.getenv('PAYONLY_US_PROXY_STATE_DB_KEY', 'proxy_pool_us_state_v1')
KEY_POOL_DB_KEY = os.getenv('PAYONLY_KEY_POOL_DB_KEY', 'payonly_key_pool_v1')
KEY_CACHE_DB_KEY = os.getenv('PAYONLY_KEY_CACHE_DB_KEY', 'payonly_key_cache_v1')
PHONE_POOL_DB_KEY = os.getenv('PAYONLY_PHONE_POOL_DB_KEY', 'payonly_phone_pool_v1')
PHONE_BANNED_DB_KEY = os.getenv('PAYONLY_PHONE_BANNED_DB_KEY', 'payonly_phone_banned_v1')
PHONE_STATE_DB_KEY = os.getenv('PAYONLY_PHONE_STATE_DB_KEY', 'payonly_phone_state_v1')
PAYONLY_BINDING_LOCK_FILE = Path(os.getenv('PAYONLY_BINDING_LOCK_FILE', str(REPO / 'output' / 'payonly_resource_binding.lock')))
PAYONLY_RESERVATION_TTL = int(os.getenv('PAYONLY_RESERVATION_TTL', '1800') or '1800')
PAYONLY_CARD_MAX_SUCCESS_USES = int(os.getenv('PAYONLY_CARD_MAX_SUCCESS_USES', '999999') or '999999')
PAYONLY_GENERATE_CARD = str(os.getenv('PAYONLY_GENERATE_CARD', '')).strip().lower() in ('1', 'true', 'yes', 'on')
PAYONLY_RUN_ID = os.getenv('PAYONLY_RUN_ID', f"payonly-{os.getpid()}-{uuid.uuid4().hex[:8]}")
US_PROXY_FALLBACK = os.getenv('PAYONLY_US_PROXY_FALLBACK', '')


_RUNTIME_CACHE: dict[str, object] = {}
_RUNTIME_DIRTY: dict[str, object] = {}
_RUNTIME_VALUE_CACHE: dict[str, str] = {}
_RUNTIME_VALUE_DIRTY: dict[str, str] = {}
_RUNTIME_LOADED_AT = time.monotonic()


def _runtime_preload() -> None:
    """Batch-load runtime keys once so AWS doesn't pay 5s per Postgres read."""
    keys = [
        US_PROXY_POOL_DB_KEY, US_PROXY_STATE_DB_KEY,
        KEY_POOL_DB_KEY, KEY_CACHE_DB_KEY,
        PHONE_POOL_DB_KEY, PHONE_BANNED_DB_KEY, PHONE_STATE_DB_KEY,
    ]
    try:
        db = get_db()
        placeholders = ",".join(["?"] * len(keys))
        with db._conn() as c:  # project DB wrapper; translated for Postgres internally
            rows = c.execute(f"SELECT key, value FROM runtime_meta WHERE key IN ({placeholders})", tuple(keys)).fetchall()
        raw = {r["key"]: r["value"] for r in rows}
        for key in keys:
            val = raw.get(key, "")
            _RUNTIME_VALUE_CACHE[key] = val
            try:
                _RUNTIME_CACHE[key] = json.loads(val) if val else None
            except Exception:
                _RUNTIME_CACHE[key] = None
        print(f"TIMING runtime_preload_s={time.monotonic() - _RUNTIME_LOADED_AT:.1f} keys={len(raw)}", flush=True)
    except Exception as e:
        print(f"[runtime_db] preload failed, fallback per-key reads: {e}", flush=True)


def _runtime_flush() -> None:
    start = time.monotonic()
    for key, value in list(_RUNTIME_DIRTY.items()):
        _db_set_json(key, value, mark_dirty=False)
    for key, value in list(_RUNTIME_VALUE_DIRTY.items()):
        try:
            get_db().set_runtime_value(key, value)
        except Exception as e:
            print(f'[runtime_db] value write failed key={key}: {e}', flush=True)
    if _RUNTIME_DIRTY or _RUNTIME_VALUE_DIRTY:
        print(f"TIMING runtime_flush_s={time.monotonic() - start:.1f} json={len(_RUNTIME_DIRTY)} value={len(_RUNTIME_VALUE_DIRTY)}", flush=True)
    _RUNTIME_DIRTY.clear(); _RUNTIME_VALUE_DIRTY.clear()


def _db_json(key: str, default=None):
    if key in _RUNTIME_CACHE:
        val = _RUNTIME_CACHE.get(key)
        return default if val is None else val
    try:
        return get_db().get_runtime_json(key, default)
    except Exception:
        return default


def _db_set_json(key: str, value, mark_dirty: bool = True) -> None:
    _RUNTIME_CACHE[key] = value
    if mark_dirty:
        _RUNTIME_DIRTY[key] = value
        return
    try:
        get_db().set_runtime_json(key, value)
    except Exception as e:
        print(f'[runtime_db] write failed key={key}: {e}', flush=True)


def _db_lines(key: str, fallback_file: Path | None = None) -> list[str]:
    raw = _db_json(key, None)
    if raw is None:
        try:
            raw_s = _RUNTIME_VALUE_CACHE.get(key)
            if raw_s is None:
                raw_s = get_db().get_runtime_value(key, '')
            if raw_s:
                raw = raw_s.splitlines()
        except Exception:
            raw = None
    lines = []
    if isinstance(raw, list):
        for x in raw:
            if isinstance(x, str):
                line = x.strip()
            elif isinstance(x, dict):
                line = str(x.get('proxy') or x.get('url') or x.get('line') or '').strip()
            else:
                line = str(x or '').strip()
            if line and not line.startswith('#'):
                lines.append(line)
    elif isinstance(raw, str):
        lines = [x.strip() for x in raw.splitlines() if x.strip() and not x.strip().startswith('#')]
    if lines:
        return lines
    if fallback_file and fallback_file.exists():
        lines = [x.strip() for x in fallback_file.read_text(encoding='utf-8', errors='ignore').splitlines() if x.strip() and not x.strip().startswith('#')]
        if lines:
            _db_set_json(key, lines)
            return lines
    return []

def _normalize_proxy_line(line: str) -> str:
    line = (line or '').strip()
    if not line or line.startswith('#'):
        return ''
    if '://' in line:
        return line
    parts = line.split(':')
    if len(parts) >= 4:
        host, port, user = parts[0], parts[1], parts[2]
        pwd = ':'.join(parts[3:])
        return f'http://{user}:{pwd}@{host}:{port}'
    return line

def _pick_us_proxy() -> str:
    env_proxy = os.getenv('PAYONLY_US_PROXY', '').strip()
    if env_proxy:
        print(f'[proxy_pool] PAYONLY_US_PROXY override: {env_proxy}', flush=True)
        return env_proxy
    proxies = [_normalize_proxy_line(x) for x in _db_lines(US_PROXY_POOL_DB_KEY, US_PROXY_POOL_FILE)]
    proxies = [x for x in proxies if x]
    if not proxies:
        # Seed from existing RT 1024 US pool if available.
        seed = REPO / 'output' / 'rt_proxy_pool_1024_us.txt'
        proxies = [_normalize_proxy_line(x) for x in _db_lines(US_PROXY_POOL_DB_KEY, seed)]
        proxies = [x for x in proxies if x]
    if not proxies:
        if US_PROXY_FALLBACK:
            print('[proxy_pool] empty, using PAYONLY_US_PROXY_FALLBACK', flush=True)
            return US_PROXY_FALLBACK
        raise RuntimeError('US proxy pool empty and PAYONLY_US_PROXY_FALLBACK is not set')
    try:
        idx = int(_RUNTIME_VALUE_CACHE.get(US_PROXY_STATE_DB_KEY, '') or _RUNTIME_CACHE.get(US_PROXY_STATE_DB_KEY) or get_db().get_runtime_value(US_PROXY_STATE_DB_KEY, '0') or '0')
    except Exception:
        try:
            idx = int((US_PROXY_STATE_FILE.read_text(encoding='utf-8') or '0').strip() or '0')
        except Exception:
            idx = 0
    proxy = proxies[idx % len(proxies)]
    try:
        _RUNTIME_VALUE_CACHE[US_PROXY_STATE_DB_KEY] = str((idx + 1) % len(proxies))
        _RUNTIME_VALUE_DIRTY[US_PROXY_STATE_DB_KEY] = str((idx + 1) % len(proxies))
    except Exception as e:
        print(f'[proxy_pool] write db state failed: {e}', flush=True)
    print(f'[proxy_pool] picked US proxy {idx % len(proxies) + 1}/{len(proxies)} from DB: {proxy}', flush=True)
    return proxy


def _mark_account_plan(email: str, status: str, message: str = "") -> None:
    if not email:
        return
    try:
        db = get_db()
        target = email.strip().lower()
        rows = [r for r in db.iter_registered_accounts() if (r.get("email") or "").lower() == target]
        if not rows:
            print(f"[account] mark plan skipped; not found in DB: {email}", flush=True)
            return
        row_id = int(rows[-1]["id"])
        ok = db.update_account_check(row_id, status, message[:500])
        print(f"[account] marked {email}: {status} {message[:120]} db_update={ok}", flush=True)
    except Exception as e:
        print(f"[account] mark plan failed {email}: {e}", flush=True)


def _start_async_rt(email: str) -> None:
    if not email:
        return
    try:
        log_dir = REPO / "output/logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / f"payonly_auto_rt_{email.replace('@','_').replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        env_rt = dict(os.environ)
        env_rt["RT_TARGET_EMAILS"] = email
        env_rt["RT_LIMIT"] = "1"
        # Use the same hardened RT path as manual backfill: refreshed Camoufox
        # fingerprint + per-account timeout. Existing environment can override.
        env_rt.setdefault("RT_CAMOUFOX_HUMANIZE", "1")
        env_rt.setdefault("RT_ACCOUNT_TIMEOUT", "650")
        cmd = [str(REPO / "venv/bin/python"), "-u", str(REPO / "scripts/run_rt_missing_with_proxy_pool.py")]
        with open(log, "w", encoding="utf-8") as f:
            p = subprocess.Popen(cmd, cwd=str(REPO), env=env_rt, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        print(f"[auto-rt] started pid={p.pid} email={email} log={log}", flush=True)
    except Exception as e:
        print(f"[auto-rt] start failed email={email}: {e}", flush=True)

_runtime_preload()
US_PROXY = _pick_us_proxy()
ACCOUNT_ID = int(os.getenv('PAYONLY_ACCOUNT_ID', '49'))
PAYPAL_CREATE_PASSWORD = "Ryan8899"

# Key 池：每个 key 对应一组卡+地址信息，命中缓存后不重复请求。
# 如果 wrapper 已按 payonly.generate_card 传入随机卡，则跳过 key 池/API。
if PAYONLY_GENERATE_CARD:
    KEY_POOL = []
else:
    KEY_POOL = _db_json(KEY_POOL_DB_KEY, None)
    if not isinstance(KEY_POOL, list):
        KEY_POOL = []
KEY_CACHE_FILE = str(Path(__file__).parent / "key_cache.json")

try:
    _ENV_HARDCODED_INFO = json.loads(os.getenv("PAYONLY_HARDCODED_INFO_JSON", "{}") or "{}")
except Exception:
    _ENV_HARDCODED_INFO = {}
try:
    _ENV_CARD_INFO = json.loads(os.getenv("PAYONLY_CARD_INFO_JSON", "{}") or "{}")
except Exception:
    _ENV_CARD_INFO = {}

HARDCODED_INFO = {
    "card_number": "",
    "expiry_date": "",
    "cvv": "",
    "name": "",
    "address": "",
}
if isinstance(_ENV_HARDCODED_INFO, dict):
    for _k in ("card_number", "expiry_date", "cvv", "name", "address"):
        if str(_ENV_HARDCODED_INFO.get(_k) or "").strip():
            HARDCODED_INFO[_k] = _ENV_HARDCODED_INFO.get(_k) or ""


def _fetch_key_info(key: str, cache_file: str, proxy_url: str = "") -> "dict | None":
    """从数据库缓存或API拉取key对应的地址+卡信息（手机号不取）。"""
    cache = _db_json(KEY_CACHE_DB_KEY, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            if os.path.exists(cache_file):
                cache = json.loads(Path(cache_file).read_text(encoding="utf-8"))
                _db_set_json(KEY_CACHE_DB_KEY, cache)
        except Exception:
            cache = {}
    if key in cache:
        item = cache[key]
        if isinstance(item, dict):
            if _key_should_skip_used(item):
                print(f"[key_pool] key已达到成功次数上限，跳过 key={key} uses={_key_success_use_count(item)}/{PAYONLY_CARD_MAX_SUCCESS_USES} reason={item.get('_used_reason','')}", flush=True)
                return None
            if item.get("_invalid"):
                print(f"[key_pool] key无效缓存，跳过API key={key} reason={item.get('_invalid_reason','')}", flush=True)
                return None
            print(f"[key_pool] 命中DB缓存 key={key}，不再请求API", flush=True)
            return item
        # Negative/invalid cache exists; do not hit the one-hour API again.
        print(f"[key_pool] 命中无效缓存，跳过API key={key}", flush=True)
        return None
    try:
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        resp = requests.post(
            "https://api.node-card.com/api/open/card/redeem",
            json={"card_key": key},
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
            timeout=30,
            proxies=proxies,
        )
        data = resp.json()
    except Exception as e:
        print(f"[key_pool] API请求失败 key={key}: {e}", flush=True)
        try:
            cache[key] = {"_invalid": True, "_invalid_reason": f"api_request_failed: {type(e).__name__}: {e}", "_cached_at": datetime.utcnow().isoformat() + "Z"}
            _db_set_json(KEY_CACHE_DB_KEY, cache)
        except Exception:
            pass
        return None
    content = data.get("content") if isinstance(data, dict) else {}
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        content = data.get("data")
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        content = data.get("result")
    if not isinstance(content, dict) or not content:
        print(f"[key_pool] API返回无效 key={key}: {data}", flush=True)
        try:
            cache[key] = {"_invalid": True, "_invalid_reason": "api_invalid_response", "_cached_at": datetime.utcnow().isoformat() + "Z", "api_response": data}
            _db_set_json(KEY_CACHE_DB_KEY, cache)
        except Exception:
            pass
        return None
    result = {
        "card_number": str(content.get("card_number") or content.get("cardNumber") or content.get("card_no") or content.get("cardNo") or content.get("number") or "").strip(),
        "expiry_date": str(content.get("expiry_date") or content.get("expiryDate") or content.get("expire") or content.get("expiry") or content.get("exp") or "").strip(),
        "cvv": str(content.get("cvv") or content.get("cvc") or "").strip(),
        "name": str(content.get("name") or "").strip(),
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
    }
    if not any(result.values()):
        print(f"[key_pool] API返回内容为空 key={key}", flush=True)
        try:
            cache[key] = {"_invalid": True, "_invalid_reason": "api_empty_content", "_cached_at": datetime.utcnow().isoformat() + "Z", "api_response": data}
            _db_set_json(KEY_CACHE_DB_KEY, cache)
        except Exception:
            pass
        return None
    try:
        cache[key] = result
        _db_set_json(KEY_CACHE_DB_KEY, cache)
        try:
            Path(cache_file).write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        print(f"[key_pool] 已缓存到DB key={key}", flush=True)
    except Exception as e:
        print(f"[key_pool] 写缓存失败: {e}", flush=True)
    return result

def _key_success_use_count(item: dict) -> int:
    """Return how many successful accounts have used this PayOnly card/key."""
    if not isinstance(item, dict):
        return 0
    hist = item.get("_used_accounts")
    if isinstance(hist, list):
        return len(hist)
    return 1 if item.get("_used") else 0


def _key_can_be_reused(item: dict) -> bool:
    return PAYONLY_CARD_MAX_SUCCESS_USES <= 0 or _key_success_use_count(item) < PAYONLY_CARD_MAX_SUCCESS_USES


def _key_should_skip_used(item: dict) -> bool:
    return bool(isinstance(item, dict) and item.get("_used") and not _key_can_be_reused(item))


# 号码池：每条 {"phone": "+1xxx...", "sms_api": "https://..."}
# 被 PayPal 拒绝（Try a different phone number）的号码会写入黑名单，下次自动跳过。
PHONE_POOL = _db_json(PHONE_POOL_DB_KEY, None)
if not isinstance(PHONE_POOL, list):
    PHONE_POOL = []
# 黑名单路径保留给 legacy payment 兼容；真实源在 DB，运行前会写入临时文件，运行后回灌 DB。
PHONE_BANNED_FILE = str(Path(__file__).parent / "phone_banned.txt")

PAYPAL_PHONE_OVERRIDE = ""
CLICK_BLUE_BUTTON = True
AUTO_SOLVE_CHALLENGE = True
YESCAPTCHA_CLIENT_KEY = os.getenv("YESCAPTCHA_CLIENT_KEY", "")
YESCAPTCHA_API_URL = "https://api.yescaptcha.com"

MANUAL_CHALLENGE_HANDOFF = True
# PayPal reCAPTCHA can keep emitting YesCaptcha activity for >60s. Do not
# abandon the run while the addon is still actively solving; payment_runner
# will watch addon signals and retry the blue button after the overlay clears.
MANUAL_CHALLENGE_WAIT_SECONDS = int(os.getenv("PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS", "240") or "240")

FILL_CARD_FIELDS = True
CARD_INFO = {"number": "", "expiry": "", "cvv": ""}
if isinstance(_ENV_CARD_INFO, dict):
    for _k in ("number", "expiry", "cvv"):
        if str(_ENV_CARD_INFO.get(_k) or "").strip():
            CARD_INFO[_k] = str(_ENV_CARD_INFO.get(_k) or "").strip()

def normalize_expiry(expiry_date: str) -> dict:
    raw = str(expiry_date or "").strip()
    nums = re.findall(r"\d+", raw)
    if len(nums) < 2: return {"mm": "01", "yy": "30", "full": "01 / 30"}
    a, b = nums[0], nums[1]
    if len(a) == 4: year, month = a[-2:], b.zfill(2)
    else: month, year = a.zfill(2), b[-2:]
    return {"mm": month, "yy": year, "full": f"{month} / {year}"}

def parse_hardcoded_identity(info: dict) -> dict:
    name = str(info.get("name") or "").strip()
    parts = name.split()
    first, last = (parts[0] if parts else ""), (" ".join(parts[1:]) if len(parts) > 1 else "")
    phone = re.sub(r"\D+", "", str(info.get("phone") or ""))
    if phone.startswith("1") and len(phone) == 11: phone = phone[1:]
    address_obj = info.get("address")
    if isinstance(address_obj, dict):
        line1 = str(address_obj.get("line1") or address_obj.get("street") or address_obj.get("street_address") or "").strip()
        city = str(address_obj.get("city") or address_obj.get("address_city") or "").strip()
        state = str(address_obj.get("state") or address_obj.get("province") or "").strip().upper()
        postal = str(address_obj.get("postal_code") or address_obj.get("zip") or address_obj.get("zipcode") or "").strip()
        country = str(address_obj.get("country") or "US").strip().upper() or "US"
        if postal:
            m = re.search(r"\d{5}(?:-\d{4})?", postal)
            postal = m.group(0)[:5] if m else postal
        full_address = ", ".join([x for x in [line1, city, state, postal, country] if x])
        return {"phone": phone, "first": first, "last": last, "line1": line1, "city": city, "state": state, "zip": postal, "full_address": full_address}
    address_raw = str(address_obj or "").strip()
    chunks = [c.strip() for c in address_raw.split(",") if c.strip()]
    line1 = chunks[0] if chunks else ""
    city, state, postal = "", "", ""
    if len(chunks) >= 5 and re.fullmatch(r"[A-Z]{2}", chunks[2], re.I) and re.fullmatch(r"\d{5}(?:-\d{4})?", chunks[4]):
        # node-card full_billing_address: "street, city, ST, US, 12345"
        city, state, postal = chunks[1], chunks[2].upper(), chunks[4][:5]
    elif len(chunks) >= 2:
        m = re.match(r"(.+?)\s+([A-Z]{2})?\s*(\d{5})(?:-\d{4})?$", chunks[1], re.I)
        if m: city, state, postal = m.group(1).strip(), (m.group(2) or "").upper(), m.group(3)
        else: city = chunks[1]
    if postal and not state:
        if postal.startswith(("430", "431", "432", "433", "434", "435", "436", "437", "438", "439", "440", "441", "442", "443", "444", "445", "446", "447", "448", "449", "450", "451", "452", "453", "454", "455", "456", "457", "458", "459")):
            state = "OH"
    full_address = ", ".join([x for x in [line1, city, state, postal, "US"] if x])
    return {"phone": phone, "first": first, "last": last, "line1": line1, "city": city, "state": state, "zip": postal, "full_address": full_address}

def _now_ts() -> int:
    return int(time.time())


def _mask_phone(phone: str) -> str:
    digits = re.sub(r"\D+", "", str(phone or ""))
    return ("***" + digits[-4:]) if digits else ""


def _mask_key(key: str) -> str:
    key = str(key or "")
    return key[:8] + "..." if len(key) > 8 else key


def _sms_api_host(api: str) -> str:
    m = re.match(r"https?://([^/?#]+)", str(api or ""), re.I)
    return m.group(1) if m else ""


def _normalize_us_phone(phone: str) -> dict:
    raw = str(phone or "").strip()
    digits = re.sub(r"\D+", "", raw)
    if digits.startswith("1") and len(digits) == 11:
        local = digits[1:]
        e164 = "+" + digits
    elif len(digits) == 10:
        local = digits
        e164 = "+1" + digits
    else:
        return {"raw": raw, "digits": digits, "local": "", "e164": ""}
    return {"raw": raw, "digits": digits, "local": local, "e164": e164}


class _PayonlyBindingLock:
    def __enter__(self):
        PAYONLY_BINDING_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(PAYONLY_BINDING_LOCK_FILE, "w")
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        self._fh.write(f"{PAYONLY_RUN_ID} {os.getpid()} {time.time()}\n")
        self._fh.flush()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
            self._fh.close()
        except Exception:
            pass


def _fresh_runtime_json(key: str, default):
    try:
        val = get_db().get_runtime_json(key, default)
    except Exception:
        val = default
    _RUNTIME_CACHE[key] = val
    return val


def _write_runtime_json_now(key: str, value) -> None:
    _RUNTIME_CACHE[key] = value
    try:
        get_db().set_runtime_json(key, value)
    except Exception as e:
        raise SystemExit(f"runtime DB write failed key={key}: {e}")


def _reservation_alive(item: dict, ttl: int = PAYONLY_RESERVATION_TTL) -> bool:
    try:
        ts = float(item.get("_reserved_at") or item.get("reserved_at") or 0)
    except Exception:
        ts = 0
    return bool(ts and (_now_ts() - ts) < ttl)


def _generated_cardholder_name(key: str, info: dict) -> str:
    """Generate a stable English cardholder name when node-card omits name."""
    first_names = [
        "JAMES", "ROBERT", "JOHN", "MICHAEL", "DAVID", "WILLIAM", "RICHARD", "JOSEPH",
        "THOMAS", "CHRISTOPHER", "CHARLES", "DANIEL", "MATTHEW", "ANTHONY", "MARK", "DONALD",
        "STEVEN", "PAUL", "ANDREW", "JOSHUA", "KENNETH", "KEVIN", "BRIAN", "GEORGE",
        "MARY", "PATRICIA", "JENNIFER", "LINDA", "ELIZABETH", "BARBARA", "SUSAN", "JESSICA",
        "SARAH", "KAREN", "NANCY", "LISA", "BETTY", "MARGARET", "SANDRA", "ASHLEY",
    ]
    last_names = [
        "SMITH", "JOHNSON", "WILLIAMS", "BROWN", "JONES", "GARCIA", "MILLER", "DAVIS",
        "RODRIGUEZ", "MARTINEZ", "HERNANDEZ", "LOPEZ", "GONZALEZ", "WILSON", "ANDERSON", "THOMAS",
        "TAYLOR", "MOORE", "JACKSON", "MARTIN", "LEE", "PEREZ", "THOMPSON", "WHITE",
        "HARRIS", "SANCHEZ", "CLARK", "RAMIREZ", "LEWIS", "ROBINSON", "WALKER", "YOUNG",
    ]
    seed = str(key or "") + "|" + str(info.get("card_number") or "")[-8:] + "|" + str(info.get("address") or "")
    n = sum((i + 1) * ord(ch) for i, ch in enumerate(seed))
    return f"{first_names[n % len(first_names)]} {last_names[(n // len(first_names)) % len(last_names)]}"


def _pick_card_binding() -> dict:
    """Reserve one complete key/card/address binding before opening PayPal."""
    with _PayonlyBindingLock():
        key_pool = _fresh_runtime_json(KEY_POOL_DB_KEY, [])
        if not isinstance(key_pool, list) or not key_pool:
            raise SystemExit("PayOnly key/card binding failed: key pool empty")
        cache = _fresh_runtime_json(KEY_CACHE_DB_KEY, {})
        if not isinstance(cache, dict):
            cache = {}
            _write_runtime_json_now(KEY_CACHE_DB_KEY, cache)
        for key in [str(x).strip() for x in key_pool if str(x or "").strip()]:
            item = cache.get(key)
            if isinstance(item, dict):
                if _key_should_skip_used(item):
                    print(f"[key_pool] skip used-limit key={_mask_key(key)} uses={_key_success_use_count(item)}/{PAYONLY_CARD_MAX_SUCCESS_USES} reason={item.get('_used_reason','')}", flush=True)
                    continue
                if item.get("_invalid"):
                    invalid_reason = str(item.get("_invalid_reason") or "")
                    if invalid_reason == "missing_required_fields:name":
                        # Older run marked this invalid before Ryan approved generated names.
                        # Re-open it and let the generated-name fallback below validate it.
                        item.pop("_invalid", None)
                        item.pop("_invalid_reason", None)
                        item.pop("_invalid_at", None)
                        cache[key] = item
                    else:
                        print(f"[key_pool] skip invalid key={_mask_key(key)} reason={item.get('_invalid_reason','')}", flush=True)
                        continue
                if item.get("_reserved_by") and item.get("_reserved_by") != PAYONLY_RUN_ID and _reservation_alive(item):
                    print(f"[key_pool] skip reserved key={_mask_key(key)} by={item.get('_reserved_by')}", flush=True)
                    continue
            _RUNTIME_CACHE[KEY_CACHE_DB_KEY] = cache
            info = _fetch_key_info(key, KEY_CACHE_FILE, US_PROXY)
            cache = _fresh_runtime_json(KEY_CACHE_DB_KEY, {})
            if not info:
                continue
            if not str(info.get("name") or "").strip():
                info = dict(info)
                info["name"] = _generated_cardholder_name(key, info)
                cache.setdefault(key, {}).update(info)
                cache[key]["_name_generated"] = True
                cache[key]["_name_generated_at"] = datetime.utcnow().isoformat() + "Z"
                print(f"[key_pool] key={_mask_key(key)} 缺name，已生成 cardholder={info['name']}", flush=True)
            missing = [f for f in ("card_number", "expiry_date", "cvv", "address") if not str(info.get(f) or "").strip()]
            ident = parse_hardcoded_identity(info)
            missing += [f"address.{f}" for f in ("line1", "city", "state", "zip") if not str(ident.get(f) or "").strip()]
            if missing:
                cache.setdefault(key, info)
                if isinstance(cache.get(key), dict):
                    cache[key]["_invalid"] = True
                    cache[key]["_invalid_reason"] = "missing_required_fields:" + ",".join(missing)
                    cache[key]["_invalid_at"] = datetime.utcnow().isoformat() + "Z"
                _write_runtime_json_now(KEY_CACHE_DB_KEY, cache)
                print(f"[key_pool] invalid key={_mask_key(key)} missing={missing}", flush=True)
                continue
            item = dict(cache.get(key) or info)
            item.update({"_reserved_by": PAYONLY_RUN_ID, "_reserved_at": _now_ts(), "_reserved_account_id": ACCOUNT_ID})
            cache[key] = item
            _write_runtime_json_now(KEY_CACHE_DB_KEY, cache)
            try:
                Path(KEY_CACHE_FILE).write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            tail = re.sub(r"\D+", "", str(info.get("card_number") or ""))[-4:]
            print(f"[key_pool] reserved key={_mask_key(key)} card_tail={tail} name={info.get('name','')} addr={ident.get('city')}/{ident.get('state')}/{ident.get('zip')} run={PAYONLY_RUN_ID}", flush=True)
            return {"key": key, "info": info, "identity": ident}
    raise SystemExit("PayOnly key/card binding failed: no usable complete key/card/address")


def _pick_paypal_phone_binding() -> dict:
    """Reserve one phone+sms_api binding before opening PayPal; safe for concurrent runners."""
    with _PayonlyBindingLock():
        pool = _fresh_runtime_json(PHONE_POOL_DB_KEY, [])
        if not isinstance(pool, list) or not pool:
            raise SystemExit("PayOnly phone binding failed: phone pool empty")
        banned_raw = _fresh_runtime_json(PHONE_BANNED_DB_KEY, [])
        banned = set()
        src = banned_raw if isinstance(banned_raw, list) else str(banned_raw or "").splitlines()
        for x in src:
            n = _normalize_us_phone(str(x or ""))
            if n.get("e164"):
                banned.add(n["e164"]); banned.add(n["local"])
            else:
                s = str(x or "").strip()
                if s: banned.add(s)
        state = _fresh_runtime_json(PHONE_STATE_DB_KEY, {})
        if not isinstance(state, dict):
            state = {}
        for idx, row in enumerate(pool):
            if not isinstance(row, dict):
                continue
            norm = _normalize_us_phone(str(row.get("phone") or ""))
            sms_api = str(row.get("sms_api") or "").strip()
            if not norm.get("local"):
                print(f"[phone_pool] skip invalid phone row index={idx}", flush=True); continue
            if not sms_api:
                print(f"[phone_pool] skip phone={_mask_phone(norm['e164'])} missing sms_api", flush=True); continue
            if norm["e164"] in banned or norm["local"] in banned:
                print(f"[phone_pool] skip banned phone={_mask_phone(norm['e164'])}", flush=True); continue
            st = state.get(norm["e164"]) or state.get(norm["local"]) or {}
            if isinstance(st, dict) and st.get("reserved_by") and st.get("reserved_by") != PAYONLY_RUN_ID and _reservation_alive(st):
                print(f"[phone_pool] skip reserved phone={_mask_phone(norm['e164'])} by={st.get('reserved_by')}", flush=True); continue
            state[norm["e164"]] = {"reserved_by": PAYONLY_RUN_ID, "reserved_at": _now_ts(), "account_id": ACCOUNT_ID, "index": idx, "sms_host": _sms_api_host(sms_api)}
            _write_runtime_json_now(PHONE_STATE_DB_KEY, state)
            print(f"[phone_pool] reserved phone={_mask_phone(norm['e164'])} sms_host={_sms_api_host(sms_api)} index={idx} run={PAYONLY_RUN_ID}", flush=True)
            return {"phone_local": norm["local"], "phone_e164": norm["e164"], "sms_api": sms_api, "index": idx}
    raise SystemExit("PayOnly phone binding failed: no usable phone with sms_api")


def _release_card_binding(active_key: str, mark_used: bool = False, used_reason: str = "") -> None:
    if not active_key: return
    with _PayonlyBindingLock():
        cache = _fresh_runtime_json(KEY_CACHE_DB_KEY, {})
        if not isinstance(cache, dict) or not isinstance(cache.get(active_key), dict): return
        item = cache[active_key]
        if item.get("_reserved_by") == PAYONLY_RUN_ID:
            item.pop("_reserved_by", None); item.pop("_reserved_at", None); item.pop("_reserved_account_id", None)
        if mark_used:
            hist = item.get("_used_accounts")
            if not isinstance(hist, list):
                hist = []
            rec = {"id": ACCOUNT_ID, "email": str(get_db().get_registered_account(ACCOUNT_ID).get("email") or "") if ACCOUNT_ID else ""}
            if rec not in hist:
                hist.append(rec)
            item["_used_accounts"] = hist
            item["_used"] = True; item["_used_at"] = datetime.utcnow().isoformat() + "Z"; item["_used_reason"] = used_reason or "paypal_success"
            item["_success_use_count"] = len(hist)
            item["_max_success_uses"] = PAYONLY_CARD_MAX_SUCCESS_USES
        cache[active_key] = item
        _write_runtime_json_now(KEY_CACHE_DB_KEY, cache)


def _mark_card_used_any_owner(active_key: str, used_reason: str = "paypal_success", account_id: int | None = None, email: str = "") -> bool:
    """Mark a PayOnly key/card consumed even if the reservation owner was not this process.

    Parent wrapper may verify Plus after the child returns paypal_guest_handoff/manual status.
    In that path the child returns without _saw_success and finally releases its reservation,
    so the wrapper must be able to burn the key after live Plus verification.  Otherwise the
    same cached card can be reused for multiple successful accounts.
    """
    if not active_key:
        return False
    with _PayonlyBindingLock():
        cache = _fresh_runtime_json(KEY_CACHE_DB_KEY, {})
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
        item["_success_use_count"] = _key_success_use_count(item)
        item["_max_success_uses"] = PAYONLY_CARD_MAX_SUCCESS_USES
        cache[active_key] = item
        _write_runtime_json_now(KEY_CACHE_DB_KEY, cache)
        return True


def _extract_active_key_from_output(out: str) -> str:
    if not out:
        return ""
    matches = re.findall(r"\[key_pool\]\s+命中DB缓存\s+key=([0-9a-fA-F-]{36})", out)
    if matches:
        return matches[-1]
    matches = re.findall(r"\[key_pool\]\s+reserved\s+key=([0-9a-fA-F]+)\.\.\.", out)
    if not matches:
        return ""
    prefix = matches[-1].lower()
    cache = _fresh_runtime_json(KEY_CACHE_DB_KEY, {})
    if isinstance(cache, dict):
        hits = [k for k in cache.keys() if str(k).lower().startswith(prefix)]
        if len(hits) == 1:
            return hits[0]
    return ""

def _release_phone_binding(phone_e164: str, rejected: bool = False) -> None:
    if not phone_e164: return
    with _PayonlyBindingLock():
        state = _fresh_runtime_json(PHONE_STATE_DB_KEY, {})
        if isinstance(state, dict) and isinstance(state.get(phone_e164), dict) and state[phone_e164].get("reserved_by") == PAYONLY_RUN_ID:
            state.pop(phone_e164, None)
            _write_runtime_json_now(PHONE_STATE_DB_KEY, state)
        if rejected:
            banned = _fresh_runtime_json(PHONE_BANNED_DB_KEY, [])
            if not isinstance(banned, list): banned = [x.strip() for x in str(banned or "").splitlines() if x.strip()]
            if phone_e164 not in banned:
                banned.append(phone_e164)
                _write_runtime_json_now(PHONE_BANNED_DB_KEY, banned)


def patch_legacy_card_for_template() -> Path | None:
    """No-op compatibility hook.

    Legacy versions temporarily patched the legacy payment module before
    launching the child. The production entrypoint is now CTF-pay/payment.py,
    and the needed PayPal guest hooks already live in payment_runner.py, so
    this script must not mutate legacy payment code at runtime.
    """
    return None


def main() -> int:
    acc = get_db().get_registered_account(ACCOUNT_ID)
    if not acc: raise SystemExit(f"account not found: {ACCOUNT_ID}")
    if not PAYONLY_URL:
        print("[template] generating PayOnly long link with JP proxy pool ...", flush=True)
        link = _generate_payment_link_for_account(acc, mode="paypal")
        if link.get("status") != "ok" or not link.get("url"):
            raise SystemExit("JP long-link generation failed: " + str(link.get("error") or link))
        payonly_url = link["url"]
        print(f"[template] generated PayOnly URL: {payonly_url[:120]}...", flush=True)
    else:
        payonly_url = PAYONLY_URL
        print("[template] using provided PAYONLY_URL; generation step skipped", flush=True)

    cfg_path, _ = _account_temp_pay_config(acc, mode="paypal")
    backup = patch_legacy_card_for_template()
    try:
        env = dict(os.environ)
        # Camoufox/Firefox refuses to launch when effective user and HOME owner mismatch.
        # AWS runs the repo from /root as ubuntu, while sudo/root runs may inherit HOME=/home/ubuntu.
        # Force HOME to the current user's real home for the child payment.py process.
        try:
            import pwd as _pwd
            env["HOME"] = _pwd.getpwuid(os.getuid()).pw_dir
        except Exception:
            env["HOME"] = str(Path.home())
        env.setdefault("XDG_CACHE_HOME", str(Path(env["HOME"]) / ".cache"))

        # 并发安全：打开 PayPal 前先绑定完整 phone/sms_api。
        # 卡信息如果由 WebUI payonly.generate_card 随机生成，则使用 wrapper 传入的
        # PAYONLY_CARD_INFO_JSON/PAYONLY_HARDCODED_INFO_JSON，跳过 DB key 池和 node-card API。
        _active_key = ""
        _active_phone_e164 = ""
        if PAYONLY_GENERATE_CARD and CARD_INFO.get("number") and HARDCODED_INFO.get("address"):
            hardcoded_identity = parse_hardcoded_identity(HARDCODED_INFO)
            print(
                f"[template] PayOnly随机卡模式：使用wrapper传入卡 ****{CARD_INFO.get('number','')[-4:]}，跳过DB key池/API",
                flush=True,
            )
        else:
            card_binding = _pick_card_binding()
            _active_key = card_binding["key"]
            for _f in ("card_number", "expiry_date", "cvv", "name", "address"):
                HARDCODED_INFO[_f] = card_binding["info"].get(_f, "")
            hardcoded_identity = card_binding["identity"]
        phone_binding = _pick_paypal_phone_binding()
        _active_phone_e164 = phone_binding["phone_e164"]
        # Keep PayPal guest screenshots on for unattended AWS runs so failures are debuggable.
        # Screenshot helpers write public debug links under /var/www/dujiao-sitemap/debug.
        env["PAYPAL_GUEST_DEBUG_SCREENSHOTS"] = os.getenv("PAYPAL_GUEST_DEBUG_SCREENSHOTS", "1")
        env["PAYPAL_GUEST_HEADLESS"] = os.getenv("PAYPAL_GUEST_HEADLESS", "1")
        env["PAYPAL_GUEST_CREATE_PASSWORD"] = PAYPAL_CREATE_PASSWORD
        env["PAYPAL_GUEST_PHONE_OVERRIDE"] = phone_binding["phone_local"]
        env["PAYPAL_GUEST_PHONE_E164"] = phone_binding["phone_e164"]
        env["PAYPAL_GUEST_SMS_API"] = phone_binding["sms_api"]
        env["PAYPAL_GUEST_PHONE_POOL_INDEX"] = str(phone_binding["index"])
        for k in ["first", "last", "line1", "city", "state", "zip"]: env[f"PAYPAL_GUEST_{k.upper()}"] = hardcoded_identity.get(k, "")
        env["PAYPAL_GUEST_FULL_ADDRESS"] = hardcoded_identity.get("full_address", "")
        print(f"[template] Parsed address: line1={hardcoded_identity.get('line1')} city={hardcoded_identity.get('city')} state={hardcoded_identity.get('state')} zip={hardcoded_identity.get('zip')} full={hardcoded_identity.get('full_address')}", flush=True)
        _audit_paypal_name = f"{hardcoded_identity.get('first', '')} {hardcoded_identity.get('last', '')}".strip()
        _audit_paypal_phone = str(env.get("PAYPAL_GUEST_PHONE_OVERRIDE") or "")
        print(
            f"[audit-fill] PayPal planned: name={_audit_paypal_name} phone={_audit_paypal_phone} "
            f"line1={hardcoded_identity.get('line1', '')} city={hardcoded_identity.get('city', '')} "
            f"state={hardcoded_identity.get('state', '')} zip={hardcoded_identity.get('zip', '')} "
            f"full={hardcoded_identity.get('full_address', '')}",
            flush=True,
        )
        env["PAYONLY_RUN_ID"] = PAYONLY_RUN_ID
        env["PAYONLY_ACCOUNT_ID"] = str(ACCOUNT_ID)
        # child 只消费已绑定好的手机号/接码地址，不再自行读号码池。
        # DB 是号码池黑名单源；写入兼容文件给 legacy payment 使用，跑完后再回灌 DB。
        _banned_lines = _db_lines(PHONE_BANNED_DB_KEY, Path(PHONE_BANNED_FILE))
        try:
            Path(PHONE_BANNED_FILE).write_text("\n".join(_banned_lines) + ("\n" if _banned_lines else ""), encoding="utf-8")
        except Exception as _e:
            print(f"[phone_pool] 写黑名单兼容文件失败: {_e}", flush=True)
        env["PAYPAL_PHONE_BANNED_FILE"] = PHONE_BANNED_FILE
        env["CLICK_BLUE_BUTTON"] = "1" if CLICK_BLUE_BUTTON else "0"
        env["PAYPAL_AUTO_CHALLENGE_SOLVE"] = "1" if AUTO_SOLVE_CHALLENGE else "0"
        env["YESCAPTCHA_CLIENT_KEY"] = YESCAPTCHA_CLIENT_KEY
        env["PAYPAL_MANUAL_CHALLENGE_HANDOFF"] = "1" if MANUAL_CHALLENGE_HANDOFF else "0"
        env["PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS"] = str(MANUAL_CHALLENGE_WAIT_SECONDS)
        # Keep manual handoff path active: wait briefly instead of aborting immediately on PayPal captcha.
        env["PAYPAL_ABORT_ON_MANUAL_CHALLENGE"] = os.getenv("PAYPAL_ABORT_ON_MANUAL_CHALLENGE", "0")
        env["FILL_CARD_FIELDS"] = "1" if FILL_CARD_FIELDS else "0"
        env["CARD_NUMBER"] = CARD_INFO.get("number") or HARDCODED_INFO.get("card_number")
        exp_data = normalize_expiry(CARD_INFO.get("expiry") or HARDCODED_INFO.get("expiry_date"))
        env["CARD_EXP_MM"] = exp_data["mm"]
        env["CARD_EXP_YY"] = exp_data["yy"]
        env["CARD_EXPIRY"] = exp_data["full"]
        env["CARD_CVV"] = CARD_INFO.get("cvv") or HARDCODED_INFO.get("cvv")

        # 随机邮箱用于 PayPal 第一步邮箱填写
        _letters = "abcdefghijklmnopqrstuvwxyz"
        _rand_name = "".join(random.choices(_letters, k=random.randint(5, 9)))
        _rand_email = f"{_rand_name}{random.randint(1000, 9999)}@chatgmail.com"
        env["PAYPAL_GUEST_EMAIL_OVERRIDE"] = _rand_email
        print(f"[template] PayPal随机邮箱: {_rand_email}", flush=True)

        cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        cfg["proxy"] = US_PROXY
        # Strong rule: the PayOnly long link is already generated with JP proxy
        # before this script starts. From here on, opening the long link and all
        # Stripe/PayPal follow-up stages must use US proxy only.
        cfg.setdefault("fresh_checkout", {})["enabled"] = False
        cfg["stage_proxies"] = {name: US_PROXY for name in [
            "fingerprint", "fetch_publishable_key", "stripe_init", "telemetry_init",
            "elements", "link_lookup", "address", "telemetry_address",
            "telemetry_card_input", "payment_method", "telemetry_confirm",
            "confirm", "verify_challenge", "three_ds_authenticate",
            "setup_intent_poll", "telemetry_poll", "poll",
        ]}
        # 用卡里的 US 地址覆盖 Stripe billing，与 PayPal 阶段保持一致
        _us_addr = {
            "line1": hardcoded_identity.get("line1", ""),
            "city": hardcoded_identity.get("city", ""),
            "state": hardcoded_identity.get("state", ""),
            "postal_code": hardcoded_identity.get("zip", ""),
            "country": "US",
        }
        if _us_addr["line1"]:
            _cards = cfg.setdefault("cards", [{}])
            if not _cards:
                _cards.append({})
            _cards[0]["address"] = _us_addr
            _cards[0]["name"] = f"{hardcoded_identity.get('first', '')} {hardcoded_identity.get('last', '')}".strip()
            print(f"[template] Stripe billing: {_us_addr['line1']}, {_us_addr['city']} {_us_addr['state']} {_us_addr['postal_code']} US", flush=True)
            print(
                f"[audit-fill] Stripe planned: name={_cards[0].get('name', '')} "
                f"line1={_us_addr.get('line1', '')} city={_us_addr.get('city', '')} "
                f"state={_us_addr.get('state', '')} zip={_us_addr.get('postal_code', '')} country={_us_addr.get('country', '')}",
                flush=True,
            )
        Path(cfg_path).write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[template] JP-generated/open URL: {payonly_url[:100]}...", flush=True)
        print(f"[template] US proxy for open/payment: {US_PROXY}", flush=True)

        # PayPal guest + YesCaptcha can legitimately spend several minutes in
        # security challenge. Keep the wrapper timeout longer than the internal
        # challenge wait so the browser can resume and finish after decoding.
        card_timeout_s = os.getenv("PAYPAL_GUEST_CARD_TIMEOUT", "720").strip() or "720"
        cmd = ["timeout", card_timeout_s, str(REPO / "venv/bin/python"), "-u", str(PAYMENT_PY), payonly_url, "--paypal-guest-handoff", "--config", cfg_path, "--json-result"]
        print(f"[template] payment.py timeout={card_timeout_s}s", flush=True)
        proc = subprocess.Popen(cmd, cwd=str(REPO), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
        _saw_success = False
        _saw_terminal_failure = False
        _saw_paypal_guest_handoff = False
        for line in proc.stdout:
            print(line, end="", flush=True)
            _low = line.lower()
            if ('paypal_guest_handoff' in _low or 'manual_required' in _low):
                _saw_paypal_guest_handoff = True
                print("[template] observed PayPal guest handoff/manual state; not treating as payment success", flush=True)
            # redirect_status=succeeded / setup_intent can appear after PayPal guest handoff,
            # but that is only the PayPal return/handoff, not verified ChatGPT Plus payment.
            if ('payments/success' in _low or
                'paypal guest 流程已提交' in _low or
                'payment_object_status": "succeeded"' in _low or '"state": "succeeded"' in _low):
                _saw_success = True
            if 'card_generic_error' in _low or 'no eligible cards on file' in _low:
                _saw_terminal_failure = True
        rc = proc.wait()
        if _saw_paypal_guest_handoff and _saw_success:
            print("[template] ignoring tentative success markers because paypal_guest_handoff/manual state was observed", flush=True)
            _saw_success = False
        if rc != 0 and _saw_success:
            print(f"[template] payment.py rc={rc}; ignoring tentative success markers from child output", flush=True)
            _saw_success = False
        if _saw_success:
            _email = str(acc.get("email") or "")
            _success_reason = f"paypal_success key={_active_key}" if _active_key else "paypal_success submitted redirect_status=succeeded"
            if _active_key:
                _release_card_binding(_active_key, mark_used=True, used_reason="paypal_success")
                print(f"[key_pool] 成功后记录key使用(DB) key={_mask_key(_active_key)} max_uses={PAYONLY_CARD_MAX_SUCCESS_USES}", flush=True)
            else:
                print("[key_pool] 支付成功但没有 active_key；仍标记账号成功，key 不做 used 标记", flush=True)
            _mark_account_plan(_email, "plan", _success_reason)
            try:
                from datetime import timezone as _timezone
                get_db().add_card_result({
                    "ts": datetime.now(_timezone.utc).isoformat(),
                    "status": "succeeded",
                    "chatgpt_email": _email,
                    "email": _email,
                    "session_id": "",
                    "channel": "paypal_guest_payonly",
                    "entity": "OpenAI OpCo, LLC",
                    "config": "payonly_us_paypal_guest_template.user.py",
                    "error": _success_reason,
                })
                print(f"[account] recorded payment success event email={_email} reason={_success_reason}", flush=True)
            except Exception as _e:
                print(f"[account] record payment success event failed email={_email}: {_e}", flush=True)
            if str(os.getenv("PAYONLY_AUTO_RT", "1")).lower() not in ("0", "false", "no", "off"):
                _start_async_rt(_email)
        elif _active_key and _saw_terminal_failure:
            print(f"[key_pool] 本次失败，key不标记已使用 key={_active_key}", flush=True)
        _runtime_flush()
        return rc
    finally:
        try:
            if locals().get("_active_key"):
                _release_card_binding(locals().get("_active_key", ""), mark_used=False)
            if locals().get("_active_phone_e164"):
                _release_phone_binding(locals().get("_active_phone_e164", ""), rejected=False)
        except Exception as _e:
            print(f"[resource_binding] release failed: {_e}", flush=True)
        try:
            banned_now = _db_lines(PHONE_BANNED_DB_KEY, Path(PHONE_BANNED_FILE))
            if Path(PHONE_BANNED_FILE).exists():
                file_lines = [x.strip() for x in Path(PHONE_BANNED_FILE).read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
                merged = []
                seen = set()
                for x in banned_now + file_lines:
                    if x not in seen:
                        seen.add(x); merged.append(x)
                _db_set_json(PHONE_BANNED_DB_KEY, merged)
                _runtime_flush()
                print(f"[phone_pool] 黑名单已回灌DB count={len(merged)}", flush=True)
        except Exception as _e:
            print(f"[phone_pool] 黑名单回灌DB失败: {_e}", flush=True)
        try: os.unlink(cfg_path)
        except Exception: pass

if __name__ == "__main__":
    raise SystemExit(main())
