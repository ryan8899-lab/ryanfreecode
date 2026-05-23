"""Payment runner extracted from legacy card.py.

This module carries the remaining CLI/run orchestration without importing the
legacy ``card.py`` module.  Lower-level behavior is provided by extracted helper
modules where available; some legacy compatibility helpers remain here until the
final cleanup pass.
"""

from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import http.server
import json
import os
import random
import re
import shutil
import socketserver
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

_REPO_DIR = Path(__file__).resolve().parents[1]
_CTF_REG_DIR = _REPO_DIR / "CTF-reg"
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))
if _CTF_REG_DIR.is_dir() and str(_CTF_REG_DIR) not in sys.path:
    sys.path.insert(0, str(_CTF_REG_DIR))

from webui.backend.db import get_db
try:
    from curl_cffi.requests import Session as CurlCffiSession
    _HAS_CURL_CFFI = True
except Exception:
    CurlCffiSession = None
    _HAS_CURL_CFFI = False

from captcha_solvers import (
    _generate_fn_sync_data as _extracted_generate_fn_sync_data,
    _remote_captcha_url,
    _solve_arkose_funcaptcha as _extracted_solve_arkose_funcaptcha,
    _solve_hcaptcha_via_vlm as _extracted_solve_hcaptcha_via_vlm,
    _solve_remote_hcaptcha_paypal as _extracted_solve_remote_hcaptcha_paypal,
    _solve_remote_recaptcha_v3 as _extracted_solve_remote_recaptcha_v3,
    configure_remote_captcha_base_url,
)
from fresh_checkout import (
    ChallengeReconfirmRequired,
    CheckoutSessionInactive,
    FreshCheckoutAuthError,
    _apply_proxy_to_http_session,
    _browser_like_session_headers,
    _build_fresh_checkout_body,
    _chatgpt_auth_headers,
    _create_chatgpt_http_session,
    _describe_proxy_cfg,
    _extract_checkout_identifiers,
    _extract_checkout_totals,
    _fetch_auth_session_with_cookie,
    _http_session_stage_proxy,
    _load_fresh_checkout_bootstrap,
    _resolve_expected_checkout_due,
    _resolve_stage_proxy_cfg,
    _should_generate_fresh_checkout,
    generate_fresh_checkout,
)
from paypal_guest import PAYPAL_GUEST_US_PROXY, paypal_guest_handoff_fill_nonpayment as _paypal_guest_handoff_fill_nonpayment
from payment_confirm import (
    _build_offline_fresh_checkout_info,
    _build_offline_terminal_result,
    _extract_terminal_payment_failure,
    _find_setup_intent,
    _normalize_terminal_result,
    confirm_payment,
    poll_result,
    solve_hcaptcha,
    solve_stripe_hcaptcha_in_browser,
)
from rt_login import (
    _build_proxy_url_from_cfg,
    _codex_oauth_client_id_from_config,
    _exchange_refresh_token_with_session,
    _fetch_openai_login_otp as _extracted_fetch_openai_login_otp,
    _rt_auto_phone_verify as _extracted_rt_auto_phone_verify,
)
from stripe_checkout import (
    DEFAULT_FRONTEND_EXECUTION,
    DEFAULT_STRIPE_HCAPTCHA_ASSET_VERSION,
    DEFAULT_STRIPE_RUNTIME_VERSION,
    HCAPTCHA_SITE_KEY_FALLBACK,
    KNOWN_PUBLISHABLE_KEYS,
    LOCALE_PROFILES,
    STRIPE_API,
    STRIPE_VERSION_BASE,
    STRIPE_VERSION_FULL,
    USER_AGENT,
    _accept_language_for_locale,
    _browser_tz_offset,
    _build_stripe_hcaptcha_url,
    _elements_options_client_payload,
    _extract_payment_method_types,
    _gen_elements_session_id,
    _gen_fingerprint,
    _locale_short,
    _stripe_headers,
    extract_hcaptcha_config,
    extract_passive_captcha_config,
    fetch_elements_session,
    fetch_publishable_key,
    init_checkout,
    lookup_consumer,
    parse_checkout_url,
    register_fingerprint,
    send_telemetry_batch,
    update_payment_page_address,
)

_OUTPUT_DIR = str(_REPO_DIR / "output")
os.makedirs(os.path.join(_OUTPUT_DIR, "logs"), exist_ok=True)
LOG_FILE = os.path.join(_OUTPUT_DIR, "logs", "payment.log")
_REMOTE_CAPTCHA_BASE_URL = ""
EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE", "NO", "IS", "LI", "CH", "GB",
}
APATA_RBA_ORG_ID = "8t63q4n4"
DEFAULT_TIMEZONE = "America/Chicago"


def _init_log():
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"{'='*80}\n")
        f.write(f"  Stripe 自动化支付 日志  —  {datetime.now().isoformat()}\n")
        f.write(f"{'='*80}\n\n")


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _log_raw(text: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(str(text) + "\n")
    except Exception:
        pass


def _log_request(*args, **kwargs):
    tag = kwargs.get("tag") or "request"
    data = kwargs.get("data")
    json_body = kwargs.get("json_body")
    if len(args) >= 3:
        label, method, url = args[:3]
    elif len(args) >= 2:
        method, url = args[:2]
        label = tag
    else:
        label, method, url = tag, "", ""
    _log(f"--> {label} {method} {url}")
    if data is not None:
        preview = data if isinstance(data, str) else urllib.parse.urlencode(data)
        _log(f"    data={preview[:500]}")
    if json_body is not None:
        try:
            preview = json.dumps(json_body, ensure_ascii=False)
        except Exception:
            preview = str(json_body)
        _log(f"    json={preview[:500]}")


def _log_response(*args, **kwargs):
    tag = kwargs.get("tag") or "response"
    resp = args[-1] if args else None
    try:
        text = resp.text or ""
    except Exception:
        text = ""
    _log(f"<-- {tag} HTTP {getattr(resp, 'status_code', '?')} body={text[:800]}")


def _describe_challenge_artifact(kind: str, value: str | None) -> str:
    if not value:
        return ""
    value = str(value)
    if len(value) <= 20:
        return value
    return f"{value[:10]}...{value[-8:]}"


def create_payment_method(
    session: requests.Session,
    pk: str,
    card: dict,
    captcha_token: str,
    session_id: str,
    stripe_ver: str = STRIPE_VERSION_BASE,
    ctx: dict = None,
) -> str:
    ctx = ctx or {}
    guid = ctx.get("guid") or _gen_fingerprint()[0]
    muid = ctx.get("muid") or _gen_fingerprint()[0]
    sid  = ctx.get("sid")  or _gen_fingerprint()[0]
    addr = card.get("address", {})

    data = {
        "billing_details[name]": card["name"],
        "billing_details[email]": card["email"],
        "billing_details[address][country]": addr.get("country", "US"),
        "billing_details[address][line1]": addr.get("line1", ""),
        "billing_details[address][city]": addr.get("city", ""),
        "billing_details[address][postal_code]": addr.get("postal_code", ""),
        "billing_details[address][state]": addr.get("state", ""),
        "type": "card",
        "card[number]": card["number"],
        "card[cvc]": card["cvc"],
        "card[exp_year]": card["exp_year"],
        "card[exp_month]": card["exp_month"],
        "allow_redisplay": "unspecified",

        "payment_user_agent": "stripe.js/5412f474d5; stripe-js-v3/5412f474d5; payment-element; deferred-intent",
        "referrer": "https://chatgpt.com",
        # time_on_page: 模拟从页面加载到提交的真实耗时 (HAR: 31368ms / 249421ms)
        "time_on_page": str(ctx.get("time_on_page", random.randint(25000, 55000))),
        "client_attribution_metadata[client_session_id]": str(uuid.uuid4()),
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "2021",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "key": pk,
        "_stripe_version": stripe_ver,
    }
    if captcha_token:
        data["radar_options[hcaptcha_token]"] = captcha_token

    url = f"{STRIPE_API}/v1/payment_methods"
    _log("[4/6] 创建支付方式 (payment_method) ...")
    _log_request("POST", url, data=data, tag="[4/6] create_payment_method")
    resp = session.post(url, data=data, headers=_stripe_headers())
    _log_response(resp, tag="[4/6] create_payment_method")
    if resp.status_code != 200:
        raise RuntimeError(f"创建 payment_method 失败 [{resp.status_code}]: {resp.text[:500]}")

    pm = resp.json()
    pm_id = pm["id"]
    brand = pm.get("card", {}).get("display_brand", "unknown")
    last4 = pm.get("card", {}).get("last4", "????")
    _log(f"      成功: {pm_id}  ({brand} ****{last4})")
    return pm_id


def create_paypal_payment_method(
    session: requests.Session,
    pk: str,
    card: dict,
    session_id: str,
    stripe_ver: str = STRIPE_VERSION_BASE,
    ctx: dict = None,
) -> str:
    """创建 type=paypal 的 payment_method（不含卡号信息）"""
    ctx = ctx or {}
    guid = ctx.get("guid") or _gen_fingerprint()[0]
    muid = ctx.get("muid") or _gen_fingerprint()[0]
    sid  = ctx.get("sid")  or _gen_fingerprint()[0]
    addr = card.get("address", {})
    runtime_version = ctx.get("runtime_version") or DEFAULT_STRIPE_RUNTIME_VERSION
    stripe_js_id = ctx.get("stripe_js_id", str(uuid.uuid4()))
    elements_session_id = ctx.get("elements_session_id", _gen_elements_session_id())
    elements_session_config_id = (
        ctx.get("elements_session_config_id")
        or str(uuid.uuid4())
    )
    payment_method_checkout_config_id = (
        ctx.get("payment_method_checkout_config_id")
        or ctx.get("config_id")
        or ""
    )

    data = {
        "type": "paypal",
        "billing_details[name]": card["name"],
        "billing_details[email]": card["email"],
        "billing_details[address][country]": addr.get("country", "US"),
        "billing_details[address][line1]": addr.get("line1", ""),
        "billing_details[address][city]": addr.get("city", ""),
        "billing_details[address][postal_code]": addr.get("postal_code", ""),
        "billing_details[address][state]": addr.get("state", ""),
        "payment_user_agent": (
            f"stripe.js/{runtime_version}; stripe-js-v3/{runtime_version}; "
            "payment-element; deferred-intent"
        ),
        "referrer": "https://chatgpt.com",
        "time_on_page": str(ctx.get("time_on_page", random.randint(25000, 55000))),
        "client_attribution_metadata[client_session_id]": stripe_js_id,
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[checkout_config_id]": payment_method_checkout_config_id,
        "client_attribution_metadata[elements_session_id]": elements_session_id,
        "client_attribution_metadata[elements_session_config_id]": elements_session_config_id,
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "2021",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "key": pk,
        "_stripe_version": stripe_ver,
    }

    url = f"{STRIPE_API}/v1/payment_methods"
    _log("[4/6] 创建 PayPal 支付方式 (payment_method type=paypal) ...")
    _log_request("POST", url, data=data, tag="[4/6] create_paypal_payment_method")
    resp = session.post(url, data=data, headers=_stripe_headers())
    _log_response(resp, tag="[4/6] create_paypal_payment_method")
    if resp.status_code != 200:
        raise RuntimeError(f"创建 PayPal payment_method 失败 [{resp.status_code}]: {resp.text[:500]}")

    pm = resp.json()
    pm_id = pm["id"]
    _log(f"      成功: {pm_id}  (paypal)")
    return pm_id


def _drive_gopay_from_redirect(
    redirect_url: str,
    cfg: dict,
    otp_file: str = "",
    session_id: str = "",
) -> None:
    """从 pm-redirects.stripe.com URL 接管 → Midtrans linking → GoPay PIN/OTP → 扣款。

    复用 gopay 模块的 GoPayCharger.run_from_redirect。OTP 从 stdin（CLI）或
    file-watch（webui runner）取。
    """
    import sys as _sys
    from pathlib import Path as _Path
    here = _Path(__file__).resolve().parent
    if str(here) not in _sys.path:
        _sys.path.insert(0, str(here))
    import gopay as _gopay

    auth_cfg = (cfg.get("fresh_checkout") or {}).get("auth") or {}
    cs_session = _gopay._build_chatgpt_session(auth_cfg)
    proxy = (cfg.get("proxy") or "").strip() or None
    gopay_cfg = cfg.get("gopay") or {}

    if otp_file:
        provider = _gopay.file_watch_otp_provider(_Path(otp_file), timeout=300.0)
    else:
        provider = _gopay.build_configured_otp_provider(
            gopay_cfg,
            fallback_provider=_gopay.cli_otp_provider,
            log=_log,
        )

    charger = _gopay.GoPayCharger(
        cs_session, gopay_cfg,
        otp_provider=provider, proxy=proxy,
        runtime_cfg=cfg.get("runtime"),
    )
    _log(f"      [gopay] 从 redirect 接管 → {redirect_url[:80]}...")
    result = charger.run_from_redirect(redirect_url, cs_id=session_id)
    _log(f"      [gopay] 完成: {result}")


def create_gopay_payment_method(
    session: requests.Session,
    pk: str,
    card: dict,
    session_id: str,
    stripe_ver: str = STRIPE_VERSION_BASE,
    ctx: dict = None,
) -> str:
    """创建 type=gopay 的 payment_method（印尼 e-wallet, ChatGPT Plus 用）"""
    ctx = ctx or {}
    guid = ctx.get("guid") or _gen_fingerprint()[0]
    muid = ctx.get("muid") or _gen_fingerprint()[0]
    sid  = ctx.get("sid")  or _gen_fingerprint()[0]
    addr = card.get("address", {}) if card else {}
    runtime_version = ctx.get("runtime_version") or DEFAULT_STRIPE_RUNTIME_VERSION
    stripe_js_id = ctx.get("stripe_js_id", str(uuid.uuid4()))
    elements_session_id = ctx.get("elements_session_id", _gen_elements_session_id())
    elements_session_config_id = (
        ctx.get("elements_session_config_id") or str(uuid.uuid4())
    )
    payment_method_checkout_config_id = (
        ctx.get("payment_method_checkout_config_id")
        or ctx.get("config_id")
        or ""
    )

    data = {
        "type": "gopay",
        "billing_details[name]": (card or {}).get("name") or "John Doe",
        "billing_details[email]": (card or {}).get("email") or "buyer@example.com",
        "billing_details[address][country]": addr.get("country") or "US",
        "billing_details[address][line1]": addr.get("line1") or "3110 Sunset Boulevard",
        "billing_details[address][city]": addr.get("city") or "Los Angeles",
        "billing_details[address][postal_code]": addr.get("postal_code") or "90026",
        "billing_details[address][state]": addr.get("state") or "CA",
        "payment_user_agent": (
            f"stripe.js/{runtime_version}; stripe-js-v3/{runtime_version}; "
            "payment-element; deferred-intent"
        ),
        "referrer": "https://chatgpt.com",
        "time_on_page": str(ctx.get("time_on_page", random.randint(25000, 55000))),
        "client_attribution_metadata[client_session_id]": stripe_js_id,
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[checkout_config_id]": payment_method_checkout_config_id,
        "client_attribution_metadata[elements_session_id]": elements_session_id,
        "client_attribution_metadata[elements_session_config_id]": elements_session_config_id,
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "2021",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "key": pk,
        "_stripe_version": stripe_ver,
    }

    url = f"{STRIPE_API}/v1/payment_methods"
    _log("[4/6] 创建 GoPay 支付方式 (payment_method type=gopay) ...")
    _log_request("POST", url, data=data, tag="[4/6] create_gopay_payment_method")
    resp = session.post(url, data=data, headers=_stripe_headers())
    _log_response(resp, tag="[4/6] create_gopay_payment_method")
    if resp.status_code != 200:
        raise RuntimeError(f"创建 GoPay payment_method 失败 [{resp.status_code}]: {resp.text[:500]}")

    pm = resp.json()
    pm_id = pm["id"]
    _log(f"      成功: {pm_id}  (gopay)")
    return pm_id


def _solve_arkose_funcaptcha(api_key: str, public_key: str, page_url: str, timeout: int = 120) -> str:
    """调用远端打码平台解 Arkose FunCaptcha"""
    if not api_key:
        _log("      未配置打码平台 API key，无法解 Arkose")
        return ""
    _log(f"      提交 FunCaptcha 到打码平台 (pk={public_key[:20]}...)")
    import requests as _req
    # 创建任务
    create_resp = _req.post(_remote_captcha_url("/createTask"), json={
        "clientKey": api_key,
        "task": {
            "type": "FunCaptchaTaskProxyless",
            "websiteURL": page_url,
            "websitePublicKey": public_key,
        }
    }, timeout=30)
    result = create_resp.json()
    if result.get("errorId"):
        _log(f"      打码平台创建任务失败: {result.get('errorDescription', '')}")
        return ""
    task_id = result.get("taskId")
    _log(f"      打码平台 taskId: {task_id}")

    # 轮询结果
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(5)
        poll_resp = _req.post(_remote_captcha_url("/getTaskResult"), json={
            "clientKey": api_key,
            "taskId": task_id,
        }, timeout=15)
        poll_result = poll_resp.json()
        status = poll_result.get("status", "")
        if status == "ready":
            token = poll_result.get("solution", {}).get("token", "")
            _log(f"      打码平台 FunCaptcha 解题成功")
            return token
        elif poll_result.get("errorId"):
            _log(f"      打码平台解题失败: {poll_result.get('errorDescription', '')}")
            return ""
        _log(f"      打码平台轮询中... status={status}")
    _log("      打码平台 FunCaptcha 超时")
    return ""


def _generate_fn_sync_data(email_text: str = "", password_text: str = "") -> str:
    """生成 PayPal fn_sync_data 设备指纹（键盘时序 + 屏幕信息）"""
    def _keystroke_timing(text: str) -> str:
        if not text:
            return ""
        parts = []
        for _ in text:
            di = random.randint(45, 170)
            ui = random.randint(25, 85)
            dk = random.randint(35, 110)
            uk = random.randint(15, 65)
            parts.append(f"Di{di}Ui{ui}Dk{dk}Uk{uk}")
        return ",".join(parts)

    payload = {
        "ts1": _keystroke_timing(email_text),
        "ts2": _keystroke_timing(password_text),
        "rDT": str(random.randint(30, 200)),
        "bP": "24",
        "wI": "1920",
        "wO": "1080",
    }
    inner = json.dumps(payload, separators=(",", ":"))
    return urllib.parse.quote(inner)


def _solve_remote_hcaptcha_paypal(
    api_key: str,
    site_key: str,
    page_url: str,
    timeout: int = 120,
) -> str:
    """通过远端打码平台解 PayPal 页面上的 hCaptcha（多策略尝试）"""
    if not api_key:
        _log("      [hCaptcha] 未配置 captcha API key")
        return ""

    # 多策略尝试：Enterprise → 普通 → 不同 URL
    strategies = [
        {"type": "HCaptchaTaskProxyless", "websiteURL": page_url,
         "websiteKey": site_key, "isEnterprise": True, "userAgent": USER_AGENT},
        {"type": "HCaptchaTaskProxyless", "websiteURL": page_url,
         "websiteKey": site_key, "userAgent": USER_AGENT},
        {"type": "HCaptchaTaskProxyless", "websiteURL": "https://www.paypal.com",
         "websiteKey": site_key, "isEnterprise": True, "userAgent": USER_AGENT},
    ]
    for idx, task_spec in enumerate(strategies):
        ent = task_spec.get("isEnterprise", False)
        _log(f"      [hCaptcha] 策略 {idx + 1}/{len(strategies)} (enterprise={ent}, url={task_spec['websiteURL'][:40]}...)")
        try:
            create_resp = requests.post(_remote_captcha_url("/createTask"), json={
                "clientKey": api_key, "task": task_spec,
            }, timeout=30)
            result = create_resp.json()
        except Exception as e:
            _log(f"      [hCaptcha] 请求异常: {e}")
            continue
        if result.get("errorId"):
            _log(f"      [hCaptcha] 创建失败: {result.get('errorDescription', '')}")
            continue
        task_id = result.get("taskId")
        _log(f"      [hCaptcha] taskId: {task_id}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(5)
            try:
                poll_resp = requests.post(_remote_captcha_url("/getTaskResult"), json={
                    "clientKey": api_key, "taskId": task_id,
                }, timeout=15)
                poll_result = poll_resp.json()
            except Exception:
                continue
            status = poll_result.get("status", "")
            if status == "ready":
                token = poll_result.get("solution", {}).get("gRecaptchaResponse", "")
                _log(f"      [hCaptcha] 解题成功 (策略 {idx + 1}, token len={len(token)})")
                return token
            elif poll_result.get("errorId"):
                _log(f"      [hCaptcha] 失败: {poll_result.get('errorDescription', '')}")
                break
            _log(f"      [hCaptcha] 轮询中... status={status}")
        else:
            _log(f"      [hCaptcha] 策略 {idx + 1} 超时")
    _log("      [hCaptcha] 所有策略均失败")
    return ""


def _solve_remote_recaptcha_v3(
    api_key: str,
    site_key: str,
    page_url: str,
    action: str = "LOGIN",
    timeout: int = 60,
) -> str:
    """通过远端打码平台解 Google reCAPTCHA Enterprise v3"""
    if not api_key:
        return ""
    _log(f"      [reCAPTCHA v3] 提交到打码平台 ...")
    create_resp = requests.post(_remote_captcha_url("/createTask"), json={
        "clientKey": api_key,
        "task": {
            "type": "RecaptchaV3EnterpriseTaskProxyless",
            "websiteURL": page_url,
            "websiteKey": site_key,
            "pageAction": action,
        }
    }, timeout=30)
    result = create_resp.json()
    if result.get("errorId"):
        _log(f"      [reCAPTCHA v3] 创建失败: {result.get('errorDescription', '')}")
        return ""
    task_id = result.get("taskId")
    _log(f"      [reCAPTCHA v3] taskId: {task_id}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        poll_resp = requests.post(_remote_captcha_url("/getTaskResult"), json={
            "clientKey": api_key, "taskId": task_id,
        }, timeout=15)
        poll_result = poll_resp.json()
        status = poll_result.get("status", "")
        if status == "ready":
            token = poll_result.get("solution", {}).get("gRecaptchaResponse", "")
            _log(f"      [reCAPTCHA v3] 解题成功")
            return token
        elif poll_result.get("errorId"):
            _log(f"      [reCAPTCHA v3] 失败: {poll_result.get('errorDescription', '')}")
            return ""
    _log("      [reCAPTCHA v3] 超时")
    return ""


def _paypal_full_login(
    http: requests.Session,
    approve_html: str,
    approve_url: str,
    paypal_cfg: dict,
    captcha_api_key: str,
    csrf: str,
    sid: str,
    flow_id: str,
    ctx_id: str,
    recaptcha_key: str,
) -> None:
    """完整 PayPal 登录（邮箱→密码→验证码→2FA）。成功后 http session 带有效 auth cookies。"""
    paypal_email = paypal_cfg["email"]
    paypal_password = paypal_cfg["password"]
    _log("      ═══════ PayPal 完整登录 ═══════")

    # [L1] POST /signin/load-resource → 建立 x-pp-s session cookie
    _log("      [L1] load-resource ...")
    lr_data = {
        "_csrf": csrf, "flowId": flow_id,
        "intent": "checkout", "_sessionID": sid,
    }
    resp_lr = http.post(
        "https://www.paypal.com/signin/load-resource", data=lr_data,
        headers={
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.paypal.com",
            "Referer": approve_url,
        }, timeout=30,
    )
    _log(f"      [L1] load-resource status={resp_lr.status_code}")
    try:
        lr_json = resp_lr.json()
        if lr_json.get("nonce"):
            csrf = lr_json["nonce"]
    except Exception:
        pass

    # [L2] POST /signin (email)
    _log(f"      [L2] 提交邮箱: {paypal_email}")
    fn_data_email = _generate_fn_sync_data(paypal_email)
    email_form = {
        "splitLoginContext": "inputEmail",
        "login_email": paypal_email,
        "_csrf": csrf,
        "_sessionID": sid,
        "intent": "checkout",
        "flowId": flow_id,
        "ctxId": ctx_id or f"xo_ctx_{flow_id}",
        "fn_sync_data": fn_data_email,
        "locale.x": "zh_XC",
    }
    resp_email = http.post(
        "https://www.paypal.com/signin", data=email_form,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.paypal.com",
            "Referer": approve_url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/html, */*",
        }, timeout=30,
    )
    _log(f"      [L2] email status={resp_email.status_code}")
    # 更新 csrf
    try:
        ej = resp_email.json()
        if ej.get("nonce"):
            csrf = ej["nonce"]
        _log(f"      [L2] next: {ej.get('splitLoginContext', '?')}")
    except Exception:
        m = re.search(r'name="_csrf"\s+value="([^"]+)"', resp_email.text)
        if m:
            csrf = m.group(1)

    # [L3] (可选) reCAPTCHA Enterprise v3 — 提升信任评分
    if recaptcha_key and captcha_api_key:
        _log("      [L3] 解 reCAPTCHA Enterprise v3 ...")
        grc_token = _solve_remote_recaptcha_v3(
            captcha_api_key, recaptcha_key,
            "https://www.paypal.com/signin", action="LOGIN", timeout=60,
        )
        if grc_token:
            resp_grc = http.post(
                "https://www.paypal.com/auth/verifygrcadenterprise",
                data={
                    "grcV3EntToken": grc_token,
                    "_sessionID": sid,
                    "_csrf": csrf,
                    "action": "LOGIN",
                },
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.paypal.com",
                }, timeout=30,
            )
            _log(f"      [L3] reCAPTCHA verify status={resp_grc.status_code}")
    else:
        _log("      [L3] 跳过 reCAPTCHA v3")

    # [L4] POST /signin (password)
    _log("      [L4] 提交密码 ...")
    fn_data_pwd = _generate_fn_sync_data(paypal_email, paypal_password)
    pwd_form = {
        "splitLoginContext": "inputPassword",
        "login_email": paypal_email,
        "login_password": paypal_password,
        "_csrf": csrf,
        "_sessionID": sid,
        "intent": "checkout",
        "flowId": flow_id,
        "ctxId": ctx_id or f"xo_ctx_{flow_id}",
        "fn_sync_data": fn_data_pwd,
        "locale.x": "zh_XC",
    }
    resp_pwd = http.post(
        "https://www.paypal.com/signin", data=pwd_form,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.paypal.com",
            "Referer": approve_url,
        },
        allow_redirects=False, timeout=30,
    )
    _log(f"      [L4] password status={resp_pwd.status_code}")

    # ── 处理密码提交后的响应 ──
    request_id = ""
    _hash = ""
    current_resp = resp_pwd

    if resp_pwd.status_code == 200:
        pwd_html = resp_pwd.text
        # debug: 页面标题 + 关键标记
        _title = re.search(r'<title>(.*?)</title>', pwd_html)
        _log(f"      [L4-debug] title={_title.group(1) if _title else 'N/A'}")
        # 调试: dump 完整 HTML
        try:
            with open("/tmp/paypal_pwd_resp.html", "w", encoding="utf-8") as _df:
                _df.write(pwd_html)
            _log("      [L4-debug] 已保存 /tmp/paypal_pwd_resp.html")
        except Exception:
            pass
        has_error = bool(re.search(r'(?:incorrectPassword|loginError|captcha)', pwd_html, re.I))
        has_hcaptcha_tag = "hcaptcha" in pwd_html.lower()
        _log(f"      [L4-debug] hasError={has_error} hasHCaptcha={has_hcaptcha_tag} len={len(pwd_html)}")
        m = re.search(r'name="_requestId"\s+value="([^"]+)"', pwd_html)
        if m:
            request_id = m.group(1)
        m = re.search(r'name="_hash"\s+value="([^"]+)"', pwd_html)
        if m:
            _hash = m.group(1)
        m = re.search(r'name="_csrf"\s+value="([^"]+)"', pwd_html)
        if m:
            csrf = m.group(1)
        _log(f"      [L4-debug] requestId={bool(request_id)} hash={bool(_hash)}")

        # 检查是否需要 hCaptcha
        needs_hcaptcha = has_hcaptcha_tag or bool(request_id)
        if needs_hcaptcha:
            if not captcha_api_key:
                raise RuntimeError("PayPal 需要 hCaptcha 但未配置验证码 API key")
            # 提取 sitekey（可能在 HTML 中）
            hcaptcha_sitekey = ""
            m = re.search(r'data-sitekey="([^"]+)"', pwd_html)
            if m:
                hcaptcha_sitekey = m.group(1)
            if not hcaptcha_sitekey:
                hcaptcha_sitekey = "bf07db68-5c2e-42e8-8779-ea8384890eea"

            _log(f"      [L5] 需要 hCaptcha (sitekey={hcaptcha_sitekey[:20]}...)")
            hcaptcha_token = _solve_remote_hcaptcha_paypal(
                captcha_api_key, hcaptcha_sitekey,
                "https://www.paypal.com/signin", timeout=120,
            )
            if not hcaptcha_token:
                raise RuntimeError("PayPal hCaptcha 解题失败")

            hcaptcha_form = {
                "_csrf": csrf,
                "_requestId": request_id,
                "_hash": _hash,
                "_sessionID": sid,
                "hcaptcha": hcaptcha_token,
                "_adsChallengeType": "visual-challenge",
                "hcaptcha_eval": str(random.randint(200, 600)),
                "hcaptcha_render": str(random.randint(100, 300)),
                "hcaptcha_verification": str(random.randint(5000, 15000)),
            }
            current_resp = http.post(
                "https://www.paypal.com/signin", data=hcaptcha_form,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.paypal.com",
                    "Referer": approve_url,
                },
                allow_redirects=False, timeout=30,
            )
            _log(f"      [L5] hCaptcha submit status={current_resp.status_code}")

    # ── 跟随重定向链 ──
    for _ in range(10):
        if current_resp.status_code not in (301, 302, 303, 307, 308):
            break
        loc = current_resp.headers.get("Location", "")
        if not loc:
            break
        if loc.startswith("/"):
            loc = f"https://www.paypal.com{loc}"
        _log(f"      → redirect: {loc[:100]}")
        current_resp = http.get(loc, allow_redirects=False, timeout=30)

    current_url = getattr(current_resp, "url", "") or ""
    current_html = current_resp.text

    # ── 处理 2FA (authflow) ──
    if "/authflow" in current_url or "authflow" in current_html[:5000]:
        _log("      [L6] 进入 2FA 流程 ...")
        af_csrf = ""
        af_sid = ""
        af_doc_id = ""
        for pat in [r'"_csrf"\s*:\s*"([^"]+)"', r'name="_csrf"\s+value="([^"]+)"',
                    r'"csrfToken"\s*:\s*"([^"]+)"']:
            m = re.search(pat, current_html)
            if m:
                af_csrf = m.group(1)
                break
        m = re.search(r'"anw_sid"\s*:\s*"([^"]+)"', current_html)
        if m:
            af_sid = m.group(1)
        for pat in [r'"authflowDocumentId"\s*:\s*"([^"]+)"',
                    r'"documentId"\s*:\s*"([^"]+)"']:
            m = re.search(pat, current_html)
            if m:
                af_doc_id = m.group(1)
                break
        _log(f"      [L6] csrf={af_csrf[:15]}... anw_sid={af_sid[:15]}... docId={af_doc_id[:15]}...")

        # SELECT email challenge
        _log("      [L6-1] 选择邮箱验证 ...")
        select_body = {
            "_csrf": af_csrf,
            "anw_sid": af_sid,
            "authflowDocumentId": af_doc_id,
            "action": "SELECT_CHALLENGE",
            "selectedChallengeType": "email",
            "isCheckoutFlow": True,
            "fn_sync_data": _generate_fn_sync_data(),
        }
        resp_select = http.put(
            "https://www.paypal.com/authflow/challenges/email",
            json=select_body,
            headers={
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://www.paypal.com",
                "Referer": current_url,
            }, timeout=30,
        )
        _log(f"      [L6-1] select status={resp_select.status_code}")
        try:
            sel_json = resp_select.json()
            af_doc_id = sel_json.get("authflowDocumentId", af_doc_id)
            af_csrf = sel_json.get("_csrf", af_csrf)
        except Exception:
            pass

        # 获取 OTP
        _log("      [L6-2] 等待 PayPal OTP ...")
        otp = _fetch_paypal_otp(paypal_cfg, timeout=90)
        if not otp:
            raise RuntimeError("PayPal 2FA OTP 获取失败")
        _log(f"      [L6-2] OTP: {otp}")

        # 提交 OTP
        answer_body = {
            "_csrf": af_csrf,
            "anw_sid": af_sid,
            "authflowDocumentId": af_doc_id,
            "action": "ANSWER",
            "answer": otp,
            "selectedChallengeType": "email",
            "isCheckoutFlow": True,
            "challengeStartTime": str(int(time.time() * 1000)),
        }
        resp_answer = http.put(
            "https://www.paypal.com/authflow/challenges/email",
            json=answer_body,
            headers={
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://www.paypal.com",
                "Referer": current_url,
            }, timeout=30,
        )
        _log(f"      [L6-3] submit OTP status={resp_answer.status_code}")
        try:
            ans_json = resp_answer.json()
            for ch in ans_json.get("challenges", []):
                if ch.get("challengeType") == "email":
                    ch_status = ch.get("status", "")
                    _log(f"      [L6-3] challenge status: {ch_status}")
                    if ch_status != "PASSED":
                        raise RuntimeError(f"PayPal 2FA 验证失败: {ch_status}")
        except RuntimeError:
            raise
        except Exception:
            _log("      [L6-3] 无法解析 OTP 响应，继续")

        # 回到 signin/return
        _log("      [L6-4] signin/return ...")
        resp_return = http.get(
            f"https://www.paypal.com/signin/return?flowFrom=anw-stepup&ctxId={ctx_id}",
            allow_redirects=True, timeout=30,
        )
        _log(f"      [L6-4] 最终 URL: {resp_return.url[:100]}")

    _log("      ═══════ PayPal 登录完成 ═══════")


def _safe_screenshot(page, path: str):
    """取截图，失败不影响主流程"""
    try:
        page.screenshot(path=path, timeout=5000)
    except Exception:
        pass


def _fetch_openai_login_otp(target_email: str, timeout: int = 180) -> str:
    """取 OpenAI/Codex 登录 OTP。

    优先支持邮箱池里的取信链接/API（CUSTOM_MAIL_POOL / CTF-reg/*.used），
    找不到对应邮箱入口时再回退 CF KV。
    """
    # 1) 自定义邮箱页面/API：兼容 ms.lqqq.cc 页面和 nineemail API。
    try:
        import re as _re
        import time as _time
        import urllib.error as _urlerr
        import urllib.parse as _uparse
        import urllib.request as _ureq
        import json as _json
        from pathlib import Path as _Path

        def _find_custom_mail_entry(email: str) -> tuple[str, str, str, str]:
            root = _Path(__file__).resolve().parents[1]
            candidates = []
            env_pool = os.getenv("CUSTOM_MAIL_POOL", "").strip()
            if env_pool:
                candidates.append(_Path(env_pool))
            candidates.extend([
                root / "CTF-reg" / "custom_mail_pool.txt",
                root / "CTF-reg" / "custom_mail_pool.txt.used",
            ])
            target = email.strip().lower()
            for path in candidates:
                try:
                    if not path.exists():
                        continue
                    for line in path.read_text(encoding="utf-8").splitlines():
                        raw = line.strip()
                        if not raw or raw.startswith("#"):
                            continue
                        parts = raw.split("----")
                        if len(parts) >= 2 and parts[0].strip().lower() == target:
                            password = parts[1].strip()
                            otp_url = parts[2].strip() if len(parts) >= 3 else ""
                            client_id = parts[3].strip() if len(parts) >= 4 else ""
                            refresh_token = parts[4].strip() if len(parts) >= 5 else ""
                            return password, otp_url, client_id, refresh_token
                except Exception:
                    continue
            return "", "", "", ""

        def _extract_otp(html: str) -> str:
            patterns = [
                r"(?:code(?:\s*is)?|verification|one[-\s]*time|verify|验证码|ChatGPT|OpenAI)[^0-9]{0,120}(\d{6})\b",
                r"\b(\d{6})\b",
            ]
            for pat in patterns:
                for m in _re.finditer(pat, html, _re.I | _re.S):
                    otp = m.group(1)
                    before = html[max(0, m.start(1) - 30):m.start(1)]
                    if "#" in before[-2:] or _re.search(r"(?:color|background|bgcolor|fill|stroke)\s*[:=]\s*[\"']?#?\s*$", before, _re.I):
                        continue
                    return otp
            return ""

        password, otp_url, client_id, refresh_token = _find_custom_mail_entry(target_email)
        strict_no_cf = os.getenv("OPENAI_RT_OTP_DISABLE_CF_FALLBACK", "1").strip().lower() not in ("0", "false", "no", "off")
        if password:
            tpl = otp_url or os.getenv("CUSTOM_MAIL_OTP_URL_TEMPLATE", "https://ms.lqqq.cc/web/{email}----{password}")
            url = tpl.format(
                email=_uparse.quote(target_email, safe=""),
                password=_uparse.quote(password, safe=""),
            )
            opener = _ureq.build_opener(_ureq.ProxyHandler({}))
            deadline = _time.time() + timeout
            last_log = 0.0
            _log(f"      [RT-OTP] 从邮箱 API/链接取 OTP -> {target_email}")
            parsed0 = _uparse.urlparse(url)
            # 兼容 3 段 nineemail 短链: https://api.nineemail.com/token=xxx
            # 页面 JS 实际调用 /api/get?token=xxx 取 email/password/client_id/refresh_token。
            if parsed0.netloc.endswith("nineemail.com") and (not client_id or not refresh_token):
                try:
                    token = ""
                    m_tok = _re.search(r"token=([^/?&#]+)", url)
                    if m_tok:
                        token = m_tok.group(1).strip()
                    if token:
                        api_get = f"{parsed0.scheme}://{parsed0.netloc}/api/get?" + _uparse.urlencode({"token": token})
                        req = _ureq.Request(api_get, headers={"Accept":"application/json", "User-Agent":"Mozilla/5.0"})
                        with opener.open(req, timeout=25) as r:
                            payload = r.read().decode("utf-8", errors="replace")
                        obj = _json.loads(payload)
                        data = obj.get("data") if isinstance(obj, dict) else {}
                        if isinstance(data, dict):
                            client_id = str(data.get("client_id") or client_id or "").strip()
                            refresh_token = str(data.get("refresh_token") or refresh_token or "").strip()
                            _log(f"      [RT-OTP] nineemail 短链已展开 client_id={'yes' if client_id else 'no'} refresh_token={'yes' if refresh_token else 'no'}")
                except Exception as e:
                    _log(f"      [RT-OTP] nineemail 短链展开失败: {type(e).__name__}: {e}")
            if parsed0.netloc.endswith("nineemail.com") and client_id and refresh_token:
                while _time.time() < deadline:
                    for mailbox in ("INBOX", "Junk"):
                        params = _uparse.urlencode({"endpoint":"mail-new","refresh_token":refresh_token,"client_id":client_id,"email":target_email,"mailbox":mailbox,"response_type":"json"})
                        api_url = "https://api.nineemail.com/api/proxy?" + params
                        try:
                            req = _ureq.Request(api_url, headers={"Accept":"application/json", "User-Agent":"Mozilla/5.0"})
                            with opener.open(req, timeout=25) as r:
                                payload = r.read().decode("utf-8", errors="replace")
                            otp = _extract_otp(payload)
                            if otp:
                                return otp
                            try:
                                obj = _json.loads(payload)
                                new_rt = obj.get("new_refresh_token") if isinstance(obj, dict) else None
                                if new_rt:
                                    refresh_token = str(new_rt)
                            except Exception:
                                pass
                        except _urlerr.HTTPError as e:
                            retry_after = 0
                            try:
                                body = e.read().decode("utf-8", "replace")
                                obj = _json.loads(body)
                                retry_after = int(obj.get("retry_after") or 0) if isinstance(obj, dict) else 0
                            except Exception:
                                pass
                            if e.code == 429 and retry_after > 0:
                                _time.sleep(min(retry_after, 8))
                                continue
                        except Exception as e:
                            if _time.time() - last_log > 10:
                                _log(f"      [RT-OTP] nineemail 轮询异常: {type(e).__name__}: {e}")
                                last_log = _time.time()
                    _time.sleep(3)
                return ""
            while _time.time() < deadline:
                try:
                    req = _ureq.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with opener.open(req, timeout=15) as r:
                        html = r.read().decode("utf-8", errors="replace")
                    otp = _extract_otp(html)
                    if otp:
                        return otp
                    links = _re.findall(r'href=["\']([^"\']*show_email/[^"\']+)["\']', html, _re.I)
                    for href in links[:5]:
                        parsed = _uparse.urlparse(url)
                        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else "https://ms.lqqq.cc"
                        detail_url = _uparse.urljoin(base_url, href)
                        req = _ureq.Request(detail_url, headers={"User-Agent": "Mozilla/5.0"})
                        with opener.open(req, timeout=15) as r:
                            detail = r.read().decode("utf-8", errors="replace")
                        if "ChatGPT" not in detail and "OpenAI" not in detail:
                            continue
                        otp = _extract_otp(detail)
                        if otp:
                            return otp
                except Exception as e:
                    if _time.time() - last_log > 10:
                        _log(f"      [RT-OTP] 自定义邮箱轮询异常: {type(e).__name__}: {e}")
                        last_log = _time.time()
                _time.sleep(2)
            _log(f"      [RT-OTP] 邮箱 API/链接等 OTP 超时 {timeout}s")
            if strict_no_cf:
                return ""
            _log("      [RT-OTP] 允许 CF fallback，继续尝试 CF KV")
        elif strict_no_cf:
            _log(f"      [RT-OTP] 未找到 {target_email} 的邮箱 API/链接条目，已禁用 CF fallback")
            return ""
    except Exception as e:
        _log(f"      [RT-OTP] 邮箱 API/链接路径异常: {e}")
        if os.getenv("OPENAI_RT_OTP_DISABLE_CF_FALLBACK", "1").strip().lower() not in ("0", "false", "no", "off"):
            return ""
        _log("      [RT-OTP] 允许 CF fallback，继续尝试 CF KV")

    # 2) CF KV fallback（默认禁用；仅 OPENAI_RT_OTP_DISABLE_CF_FALLBACK=0 时启用）。
    try:
        from cf_kv_otp_provider import CloudflareKVOtpProvider
    except ImportError as e:
        _log(f"      [RT-OTP] cf_kv_otp_provider 不可用: {e}")
        return ""
    try:
        provider = CloudflareKVOtpProvider.from_env_or_secrets()
        return provider.wait_for_otp(target_email, timeout=timeout)
    except TimeoutError:
        _log(f"      [RT-OTP] CF KV 等 OTP 超时 {timeout}s")
        return ""
    except Exception as e:
        _log(f"      [RT-OTP] CF KV 取 OTP 异常: {e}")
        return ""


_OPENAI_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"


def _resolve_codex_oauth_client_id(*values: str) -> str:
    """Return the first non-placeholder Codex OAuth client id, or the
    OpenAI Codex CLI's well-known constant as a final fallback. Treat
    ``YOUR_*`` placeholders as absent — they would 400 at authorize."""
    candidates = [os.getenv("OAUTH_CODEX_CLIENT_ID", ""), *values]
    for value in candidates:
        client_id = (value or "").strip()
        if not client_id:
            continue
        if client_id.startswith("YOUR_") or client_id.endswith("_CLIENT_ID"):
            continue
        return client_id
    return _OPENAI_CODEX_CLIENT_ID


def _codex_oauth_client_id_from_config(cfg: dict) -> str:
    """Resolve the Codex OAuth client_id from payment config/env."""
    if not isinstance(cfg, dict):
        cfg = {}
    cpa_cfg = cfg.get("cpa") or {}
    fresh_cfg = cfg.get("fresh_checkout") or {}
    auth_cfg = fresh_cfg.get("auth") or {}
    return _resolve_codex_oauth_client_id(
        (cpa_cfg or {}).get("oauth_client_id", ""),
        cfg.get("oauth_client_id", ""),
        cfg.get("codex_oauth_client_id", ""),
        auth_cfg.get("oauth_client_id", ""),
    )



SMS_META_KEY = "sms_provider_config"
SMS_SESSION_KEY = "sms_active_number"


def _rt_phone_cfg(cfg: dict | None) -> dict:
    base = {
        "enabled": False,
        "country": "US",
        "max_accounts_per_number": 3,
        "number_ttl_seconds": 20 * 60,
        "poll_seconds": 5,
        "timeout_seconds": 180,
        "continue_after_code": True,
        "max_number_attempts": 3,
    }
    if isinstance(cfg, dict):
        base.update(cfg)
    try:
        base["max_accounts_per_number"] = int(base.get("max_accounts_per_number") or 3)
    except Exception:
        base["max_accounts_per_number"] = 3
    try:
        base["number_ttl_seconds"] = int(base.get("number_ttl_seconds") or 1200)
    except Exception:
        base["number_ttl_seconds"] = 1200
    try:
        base["poll_seconds"] = max(1, int(base.get("poll_seconds") or 5))
    except Exception:
        base["poll_seconds"] = 5
    try:
        base["timeout_seconds"] = max(30, int(base.get("timeout_seconds") or 180))
    except Exception:
        base["timeout_seconds"] = 180
    try:
        base["max_number_attempts"] = max(1, int(base.get("max_number_attempts") or 3))
    except Exception:
        base["max_number_attempts"] = 3
    return base


def _rt_sms_route_helpers():
    try:
        from webui.backend.routes import sms as sms_mod
        return sms_mod
    except Exception as e:
        _log(f"      [RT-SMS] 导入 SMS 平台模块失败: {e}")
        return None


def _rt_sms_now() -> float:
    return time.time()


def _rt_sms_load_session() -> dict:
    try:
        return get_db().get_runtime_json(SMS_SESSION_KEY, {}) or {}
    except Exception:
        return {}


def _rt_sms_save_session(session: dict):
    try:
        get_db().set_runtime_json(SMS_SESSION_KEY, session or {})
    except Exception as e:
        _log(f"      [RT-SMS] 保存号码状态失败: {e}")


def _rt_sms_clear_session():
    try:
        get_db().delete_runtime_key(SMS_SESSION_KEY)
    except Exception:
        pass


def _rt_sms_phone_expired(session: dict, phone_cfg: dict) -> bool:
    if not session:
        return True
    started = float(session.get("started_at") or session.get("ts") or 0)
    if not started:
        return False
    return (_rt_sms_now() - started) >= int(phone_cfg.get("number_ttl_seconds") or 1200)


def _rt_sms_session_usable(session: dict, phone_cfg: dict) -> bool:
    if not (session.get("phone") or session.get("activation_id")):
        return False
    if _rt_sms_phone_expired(session, phone_cfg):
        return False
    count = int(session.get("receive_count") or 0)
    return count < int(phone_cfg.get("max_accounts_per_number") or 3)


def _rt_sms_get_number(phone_cfg: dict) -> dict:
    sms_mod = _rt_sms_route_helpers()
    if not sms_mod:
        return {}
    cfg = sms_mod._load_cfg()
    # RT phone verification defaults may override service/country/operator without touching WebUI config.
    if phone_cfg.get("service"):
        cfg["service"] = str(phone_cfg.get("service"))
    if phone_cfg.get("country"):
        cfg["country"] = str(phone_cfg.get("country"))
    if phone_cfg.get("operator") is not None:
        cfg["operator"] = str(phone_cfg.get("operator") or "")
    try:
        resp = sms_mod._call_template(cfg, "get_number")
        parsed = sms_mod._extract_number(resp)
        if not (parsed.get("phone") or parsed.get("activation_id")):
            body = resp.get("body")
            text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
            m = re.search(r"\+?\d{8,15}", str(text or ""))
            if m:
                parsed = {"activation_id": m.group(0), "phone": m.group(0)}
    except Exception as e:
        _log(f"      [RT-SMS] get_number 失败: {type(e).__name__}: {e}")
        return {}
    if not (parsed.get("phone") or parsed.get("activation_id")):
        _log(f"      [RT-SMS] get_number 未解析到号码: {str(resp)[:240]}")
        return {}
    session = {**parsed, "receive_count": 0, "started_at": _rt_sms_now(), "last_sms": {}}
    _rt_sms_save_session(session)
    _log(f"      [RT-SMS] 取号成功 phone={parsed.get('phone') or ''} aid={parsed.get('activation_id') or ''}")
    return session


def _rt_sms_cancel(session: dict, phone_cfg: dict):
    sms_mod = _rt_sms_route_helpers()
    if not sms_mod or not session:
        _rt_sms_clear_session()
        return
    cfg = sms_mod._load_cfg()
    if phone_cfg.get("service"):
        cfg["service"] = str(phone_cfg.get("service"))
    if phone_cfg.get("country"):
        cfg["country"] = str(phone_cfg.get("country"))
    if phone_cfg.get("operator") is not None:
        cfg["operator"] = str(phone_cfg.get("operator") or "")
    try:
        sms_mod._call_template(cfg, "cancel", {
            "activation_id": session.get("activation_id", ""),
            "phone": session.get("phone", ""),
        })
    except Exception as e:
        _log(f"      [RT-SMS] cancel 异常: {e}")
    _rt_sms_clear_session()


def _rt_sms_mark_finished(session: dict):
    if not session:
        return
    try:
        session["receive_count"] = int(session.get("receive_count") or 0) + 1
    except Exception:
        session["receive_count"] = 1
    session["last_finished_at"] = _rt_sms_now()
    _rt_sms_save_session(session)


def _rt_sms_continue(session: dict, phone_cfg: dict):
    sms_mod = _rt_sms_route_helpers()
    if not sms_mod or not session:
        return
    cfg = sms_mod._load_cfg()
    if phone_cfg.get("service"):
        cfg["service"] = str(phone_cfg.get("service"))
    if phone_cfg.get("country"):
        cfg["country"] = str(phone_cfg.get("country"))
    if phone_cfg.get("operator") is not None:
        cfg["operator"] = str(phone_cfg.get("operator") or "")
    count = int(session.get("receive_count") or 0)
    if count <= 0:
        return
    if count >= int(phone_cfg.get("max_accounts_per_number") or 3):
        _log(f"      [RT-SMS] 号码已达到复用上限 receive_count={count}")
        return
    try:
        resp = sms_mod._call_template(cfg, "continue", {
            "activation_id": session.get("activation_id", ""),
            "phone": session.get("phone", ""),
        })
        session["last_continue_at"] = _rt_sms_now()
        _rt_sms_save_session(session)
        _log(f"      [RT-SMS] continue 已调用 receive_count={count} status={resp.get('status_code')}")
    except Exception as e:
        _log(f"      [RT-SMS] continue 异常: {type(e).__name__}: {e}")


def _rt_sms_poll_code(session: dict, phone_cfg: dict, ignore_code: str = "", do_continue_after: bool = True) -> str:
    sms_mod = _rt_sms_route_helpers()
    if not sms_mod or not session:
        return ""
    cfg = sms_mod._load_cfg()
    if phone_cfg.get("service"):
        cfg["service"] = str(phone_cfg.get("service"))
    if phone_cfg.get("country"):
        cfg["country"] = str(phone_cfg.get("country"))
    if phone_cfg.get("operator") is not None:
        cfg["operator"] = str(phone_cfg.get("operator") or "")
    deadline = _rt_sms_now() + int(phone_cfg.get("timeout_seconds") or 180)
    poll_s = int(phone_cfg.get("poll_seconds") or 5)
    last_text = ""
    while _rt_sms_now() < deadline:
        try:
            resp = sms_mod._call_template(cfg, "get_sms", {
                "activation_id": session.get("activation_id", ""),
                "phone": session.get("phone", ""),
            })
            parsed = sms_mod._extract_sms(resp)
            txt = parsed.get("sms_text") or ""
            code = parsed.get("code") or ""
            if txt and txt != last_text:
                _log(f"      [RT-SMS] sms: {txt[:160]}")
                last_text = txt
            if code:
                if ignore_code and code == ignore_code:
                    _log(f"      [RT-SMS] 忽略旧验证码 {code}，继续等待新码")
                    time.sleep(poll_s)
                    continue
                session["last_sms"] = parsed
                session["last_code_at"] = _rt_sms_now()
                _rt_sms_save_session(session)
                _log(f"      [RT-SMS] 收到验证码 len={len(code)}")
                if do_continue_after and phone_cfg.get("continue_after_code", True):
                    _rt_sms_continue(session, phone_cfg)
                return code
        except Exception as e:
            _log(f"      [RT-SMS] get_sms 异常: {type(e).__name__}: {e}")
        time.sleep(poll_s)
    _log("      [RT-SMS] 等待短信超时")
    return ""


def _rt_normalize_phone_for_openai(phone: str, country: str) -> tuple[str, str]:
    raw = re.sub(r"[^0-9+]", "", str(phone or ""))
    c = (country or "US").upper()
    if c == "US":
        digits = re.sub(r"\D+", "", raw)
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        return c, digits
    if c == "PH":
        digits = re.sub(r"\D+", "", raw)
        if digits.startswith("63"):
            digits = digits[2:]
        if digits.startswith("0"):
            digits = digits[1:]
        return c, digits
    digits = re.sub(r"\D+", "", raw)
    return c, digits


def _rt_select_phone_country(page, country: str):
    country = (country or "US").upper()
    try:
        sel = page.query_selector('select:visible') or page.query_selector('select')
        if sel:
            sel.select_option(country)
            _log(f"      [RT-SMS] 国家已选 {country}")
            time.sleep(0.8)
            return
    except Exception as e:
        _log(f"      [RT-SMS] select country 失败: {e}")


def _rt_fill_phone_number(page, phone: str, country: str) -> bool:
    country, local = _rt_normalize_phone_for_openai(phone, country)
    _rt_select_phone_country(page, country)
    for sel in ['input[type="tel"]', 'input[name*=phone i]', 'input[autocomplete="tel"]', 'input[inputmode="tel"]', 'input[type="text"]']:
        try:
            el = page.query_selector(sel + ':visible') or page.query_selector(sel)
            if el and el.is_visible():
                el.click(); time.sleep(0.2); el.fill(local)
                _log(f"      [RT-SMS] 已填手机号 country={country} local={local}")
                return True
        except Exception as e:
            _log(f"      [RT-SMS] 填手机号失败 {sel}: {e}")
    return False


def _rt_click_visible(page, selectors: list[str], label: str = "") -> bool:
    for sel in selectors:
        try:
            b = page.query_selector(sel)
            if b and b.is_visible():
                b.click()
                if label:
                    _log(f"      [RT-SMS] 点击 {label}: {sel}")
                return True
        except Exception as e:
            _log(f"      [RT-SMS] 点击异常 {sel}: {e}")
    return False


def _rt_fill_otp_code(page, code: str) -> bool:
    if not code:
        return False
    try:
        single = page.query_selector('input[autocomplete="one-time-code"]:visible') or \
                 page.query_selector('input[inputmode="numeric"]:not([maxlength="1"]):visible') or \
                 page.query_selector('input[name="code"]:visible')
        if single:
            single.click(); time.sleep(0.2); single.fill(code)
            _log("      [RT-SMS] 已填验证码(single)")
            return True
    except Exception as e:
        _log(f"      [RT-SMS] 填验证码 single 异常: {e}")
    try:
        digits = page.query_selector_all('input[maxlength="1"][inputmode="numeric"]') or page.query_selector_all('input[maxlength="1"]')
        if len(digits) >= len(code):
            for i, ch in enumerate(code):
                digits[i].click(); time.sleep(0.05); digits[i].fill(ch)
            _log("      [RT-SMS] 已填验证码(digits)")
            return True
    except Exception as e:
        _log(f"      [RT-SMS] 填验证码 digits 异常: {e}")
    return False


def _rt_auto_phone_verify(page, phone_cfg: dict) -> bool:
    phone_cfg = _rt_phone_cfg(phone_cfg)
    if not phone_cfg.get("enabled"):
        return False
    country = str(phone_cfg.get("openai_country") or phone_cfg.get("country") or "US").upper()
    for attempt in range(1, int(phone_cfg.get("max_number_attempts") or 3) + 1):
        session = _rt_sms_load_session()
        if not _rt_sms_session_usable(session, phone_cfg):
            if session:
                if _rt_sms_phone_expired(session, phone_cfg):
                    try:
                        age = int(_rt_sms_now() - float(session.get("started_at") or session.get("ts") or 0))
                    except Exception:
                        age = -1
                    _log(f"      [RT-SMS] 当前号码已过期 age={age}s ttl={int(phone_cfg.get('number_ttl_seconds') or 1200)}s phone={session.get('phone') or session.get('activation_id')}; 清空后重新取号")
                    _rt_sms_clear_session()
                else:
                    _log("      [RT-SMS] 当前号码不可复用，清空后重新取号")
                    _rt_sms_clear_session()
            session = _rt_sms_get_number(phone_cfg)
        phone = session.get("phone") or session.get("activation_id") or ""
        if not phone:
            _log("      [RT-SMS] 无可用手机号")
            return False
        _log(f"      [RT-SMS] add-phone attempt={attempt} phone={phone}")
        previous_code = ""
        try:
            previous_code = ((session.get("last_sms") or {}).get("code") or "").strip()
        except Exception:
            previous_code = ""
        pre_continue = int(session.get("receive_count") or 0) > 0
        if not _rt_fill_phone_number(page, phone, country):
            _log("      [RT-SMS] 页面手机号输入框未找到")
            return False
        _rt_click_visible(page, ['button[type="submit"]', 'button:has-text("Continue")'], "phone Continue")
        try:
            page.keyboard.press("Enter")
        except Exception:
            pass
        time.sleep(6)
        if pre_continue:
            _log("      [RT-SMS] 复用号码：OpenAI 发码后再调用 provider continue 切到下一条短信")
            _rt_sms_continue(session, phone_cfg)
            # Refresh local session so receive_count/last_continue_at updates are visible below.
            session = _rt_sms_load_session() or session
            # PVAPins can keep returning the previous SMS if OpenAI does not issue
            # a fresh code after reuse. Waiting the full SMS timeout wastes minutes
            # per failed account and can blow past the provider reuse TTL.
            try:
                stale_wait = int(phone_cfg.get("reuse_stale_code_timeout_seconds") or 45)
            except Exception:
                stale_wait = 45
            if stale_wait > 0:
                phone_cfg = dict(phone_cfg)
                phone_cfg["timeout_seconds"] = min(int(phone_cfg.get("timeout_seconds") or 180), max(20, stale_wait))
                _log(f"      [RT-SMS] 复用号等待新码超时={phone_cfg['timeout_seconds']}s")
        body_text = ""
        try:
            body_text = page.evaluate("() => document.body.innerText") or ""
        except Exception:
            pass
        if "Unable to send a verification code" in body_text or "use a different number" in body_text:
            _log("      [RT-SMS] OpenAI 拒绝该手机号，取消并换号")
            _rt_sms_cancel(session, phone_cfg)
            continue
        bt_low = body_text.lower()
        if "whatsapp" in bt_low or "whats app" in bt_low:
            _log("      [RT-SMS] OpenAI 进入/提示 WhatsApp 验证，当前 SMS provider 不接 WhatsApp，取消并跳过该国家")
            _rt_sms_cancel(session, phone_cfg)
            return False
        if not ("phone-verification" in page.url or "Check your phone" in body_text):
            _log(f"      [RT-SMS] 填号后未进入验证码页 url={page.url[:120]}")
            time.sleep(3)
            try:
                body_text = page.evaluate("() => document.body.innerText") or body_text
            except Exception:
                pass
            if not ("phone-verification" in page.url or "Check your phone" in body_text):
                bt_low = body_text.lower()
                if "whatsapp" in bt_low or "whats app" in bt_low:
                    _log("      [RT-SMS] OpenAI 进入/提示 WhatsApp 验证，当前 SMS provider 不接 WhatsApp，取消并跳过该国家")
                    _rt_sms_cancel(session, phone_cfg)
                    return False
                if phone_cfg.get("poll_even_if_page_unchanged", True):
                    _log("      [RT-SMS] 页面未跳转但继续查短信；有些 add-phone 会保持原 URL")
                else:
                    continue
        code = _rt_sms_poll_code(session, phone_cfg, ignore_code=previous_code, do_continue_after=not pre_continue)
        if not code:
            return False
        if not _rt_fill_otp_code(page, code):
            _log("      [RT-SMS] 验证码输入框未找到")
            return False
        _rt_click_visible(page, ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Verify")'], "OTP Continue")
        try:
            page.keyboard.press("Enter")
        except Exception:
            pass
        time.sleep(6)
        try:
            body_text = page.evaluate("() => document.body.innerText") or ""
        except Exception:
            body_text = ""
        if "verification code" in body_text.lower() and ("invalid" in body_text.lower() or "incorrect" in body_text.lower()):
            _log("      [RT-SMS] 手机验证码被拒绝")
            return False
        _log("      [RT-SMS] 手机验证已提交")
        _rt_sms_mark_finished(session)
        return True
    return False

def _exchange_refresh_token_with_session(email: str, password: str, mail_cfg: dict,
                                          proxy_url: str = "",
                                          oauth_client_id: str = "",
                                          phone_verify_cfg: dict | None = None) -> str:
    """
    支付成功后重新登录换 refresh_token。
    流程：
      1. Camoufox 打开 Codex authorize URL
      2. 重定向到 auth.openai.com/log-in
      3. 填邮箱 → 继续 → 填密码 → 继续
      4. 可能触发 Turnstile (Camoufox 自动过) / OTP (IMAP 取)
      5. workspace/select (选择默认 workspace)
      6. 自动 authorize Codex client → localhost callback
      7. POST /oauth/token 换 refresh_token
    """
    import base64 as _b64
    import hashlib as _hashlib
    import secrets as _secrets
    import tempfile as _tmp
    import shutil as _sh
    from urllib.parse import urlparse as _urlparse, urlencode as _urlencode, parse_qs as _parse_qs
    from camoufox.sync_api import Camoufox
    from browserforge.fingerprints import Screen

    def _b64url_nopad(raw: bytes) -> str:
        return _b64.urlsafe_b64encode(raw).decode().rstrip("=")

    codex_client_id = _resolve_codex_oauth_client_id(oauth_client_id)
    codex_redirect = "http://localhost:1455/auth/callback"
    codex_state = _b64url_nopad(_secrets.token_bytes(24))
    verifier = _b64url_nopad(_secrets.token_bytes(64))
    challenge = _b64url_nopad(_hashlib.sha256(verifier.encode()).digest())
    auth_url = "https://auth.openai.com/oauth/authorize?" + _urlencode({
        "client_id": codex_client_id,
        "response_type": "code",
        "redirect_uri": codex_redirect,
        "scope": "openid email profile offline_access",
        "state": codex_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    })

    # Camoufox proxy
    cf_proxy = None
    if proxy_url:
        pp = _urlparse(proxy_url)
        if pp.scheme in ("socks5", "socks5h") and pp.username:
            import socket as _sock
            relay_port = 18899
            try:
                with _sock.create_connection(("127.0.0.1", relay_port), timeout=2):
                    pass
                cf_proxy = {"server": f"socks5://127.0.0.1:{relay_port}"}
            except Exception:
                pass
        else:
            cf_proxy = {"server": f"{pp.scheme}://{pp.hostname}:{pp.port}",
                        "username": pp.username or "", "password": pp.password or ""}

    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    tmp_profile = _tmp.mkdtemp(prefix="rt_login_")
    # Refresh the browser fingerprint aggressively for RT backfill.  OpenAI's login page can
    # silently stall on /log-in when repeated attempts reuse the same narrow Camoufox shape.
    # Keep a fresh profile per run, but also rotate screen bounds, locale, and timezone.
    _rt_fp_profiles = [
        ("en-US", "America/New_York", 1920, 1080),
        ("en-US", "America/Chicago", 1680, 1050),
        ("en-US", "America/Los_Angeles", 1600, 900),
        ("en-US", "America/Denver", 1536, 864),
        ("en-US", "America/Phoenix", 1440, 900),
    ]
    _rt_locale, _rt_tz, _rt_sw, _rt_sh = random.choice(_rt_fp_profiles)
    # Slightly jitter screen while keeping common desktop dimensions.
    _rt_sw = max(1366, _rt_sw - random.choice([0, 0, 8, 16, 24]))
    _rt_sh = max(768, _rt_sh - random.choice([0, 0, 8, 16, 24]))
    _rt_humanize = str(os.getenv("RT_CAMOUFOX_HUMANIZE", "1")).lower() not in ("0", "false", "no", "off")
    _rt_headless_env = os.getenv("RT_CAMOUFOX_HEADLESS", "").strip().lower()
    if _rt_headless_env:
        _rt_headless = _rt_headless_env in ("1", "true", "yes", "on")
    else:
        _rt_headless = not has_display
    code_captured = {"url": ""}

    try:
        with Camoufox(
            headless=_rt_headless,
            humanize=_rt_humanize,
            persistent_context=True,
            user_data_dir=tmp_profile,
            os="windows",
            screen=Screen(max_width=_rt_sw, max_height=_rt_sh),
            proxy=cf_proxy,
            geoip=True,
            locale=_rt_locale,
        ) as ctx:
            _log(f"      [RT] Camoufox fp locale={_rt_locale} tz={_rt_tz} screen={_rt_sw}x{_rt_sh} headless={_rt_headless} humanize={_rt_humanize}")
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            # localhost 拦截
            def _intercept(route):
                url = route.request.url
                if "localhost:1455" in url and "code=" in url:
                    code_captured["url"] = url
                    _log("      [RT] 拦截 callback: code=<redacted>")
                try:
                    route.fulfill(status=200, content_type="text/html", body="<html>OK</html>")
                except Exception:
                    try: route.abort()
                    except Exception: pass
            page.route("http://localhost:1455/**", _intercept)

            # [1] goto Codex authorize → 触发登录
            _log("      [RT] 打开 Codex authorize URL ...")
            try:
                page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e_nav:
                _log(f"      [RT] goto 异常: {str(e_nav)[:120]}")
            time.sleep(3)
            _log(f"      [RT] 当前 URL: {page.url[:120]}")

            # [2] 填邮箱
            try:
                page.wait_for_selector('input[type="email"], input[name="email"]',
                                       state="visible", timeout=20000)
                email_input = page.query_selector('input[type="email"]:visible') or \
                              page.query_selector('input[name="email"]:visible')
                email_input.click(); time.sleep(0.3)
                email_input.fill(email)
                time.sleep(random.uniform(0.5, 1.2))
                for sel in ['button[type="submit"]', 'button:has-text("Continue")', '#btnNext']:
                    b = page.query_selector(sel)
                    if b and b.is_visible():
                        b.click()
                        _log("      [RT] 邮箱提交")
                        break
                time.sleep(3)
            except Exception as e:
                _log(f"      [RT] 邮箱填写失败: {e}")
                return ""

            # [3] 填密码（OpenAI 现在很多场景走 passwordless，没密码框就跳过到 OTP）
            try:
                page.wait_for_selector('input[type="password"]', state="visible", timeout=20000)
                pwd_input = page.query_selector('input[type="password"]:visible')
                pwd_input.click(); time.sleep(0.3)
                pwd_input.fill(password)
                time.sleep(random.uniform(0.5, 1.2))
                for sel in ['button[type="submit"]', 'button:has-text("Continue")']:
                    b = page.query_selector(sel)
                    if b and b.is_visible():
                        b.click()
                        _log("      [RT] 密码提交")
                        break
                time.sleep(5)
            except Exception as e:
                _log(f"      [RT] 密码框超时（passwordless 路径），跳过到 OTP 等待: {str(e)[:80]}")
                _safe_screenshot(page, "/tmp/rt_pwd_skip.png")

            # [4] 处理 OTP / Turnstile / 各种中间页
            _log(f"      [RT] 密码后 URL: {page.url[:120]}")
            _safe_screenshot(page, "/tmp/rt_after_pwd.png")
            # 最长等 4 分钟看能不能到 localhost callback
            end = time.time() + 240
            otp_sent_ts = time.time()
            otp_fetched = False
            email_otp_stuck_since = 0.0
            last_url = ""
            last_log_ts = 0.0
            while time.time() < end:
                if code_captured["url"]:
                    break
                if "localhost:1455" in page.url and "code=" in page.url:
                    code_captured["url"] = page.url
                    break
                cur = page.url
                # URL 变化或每 15s 打印一次
                now = time.time()
                if cur != last_url or (now - last_log_ts) > 15:
                    _log(f"      [RT] URL: {cur[:140]}")
                    last_url = cur
                    last_log_ts = now
                # OTP 页
                if ("/email-otp" in cur or "/email-verification" in cur or "passwordless" in cur or
                    page.query_selector('input[autocomplete="one-time-code"]') or
                    page.query_selector('input[inputmode="numeric"]')):
                    if not otp_fetched:
                        _log("      [RT] 检测到 OTP 页面，从邮箱 API/链接取验证码 ...")
                        otp_code = _fetch_openai_login_otp(target_email=email, timeout=180)
                        if not otp_code:
                            _log("      [RT] OTP 获取超时")
                            return ""
                        _log(f"      [RT] OTP 已获取 (len={len(otp_code)})")
                        # 填入 OTP
                        filled = False
                        single = page.query_selector('input[autocomplete="one-time-code"]:visible') or \
                                 page.query_selector('input[inputmode="numeric"]:not([maxlength="1"]):visible')
                        if single:
                            single.click(); time.sleep(0.3); single.fill(otp_code); filled = True
                        else:
                            digits = page.query_selector_all('input[maxlength="1"][inputmode="numeric"]') or \
                                     page.query_selector_all('input[maxlength="1"]')
                            if len(digits) >= 6:
                                for i, ch in enumerate(otp_code[:6]):
                                    digits[i].click(); time.sleep(0.1); digits[i].fill(ch)
                                filled = True
                        if filled:
                            time.sleep(0.5)
                            for sel in ['button[type="submit"]', 'button:has-text("Continue")',
                                        'button:has-text("Verify")']:
                                b = page.query_selector(sel)
                                if b and b.is_visible():
                                    b.click()
                                    _log("      [RT] OTP 提交")
                                    break
                            otp_fetched = True
                            email_otp_stuck_since = time.time()
                            time.sleep(3)
                    elif "/email-verification" in cur and email_otp_stuck_since:
                        stuck_for = time.time() - email_otp_stuck_since
                        if stuck_for > 120:
                            _log("      [RT] 邮箱 OTP 提交后仍停留 email-verification >120s，提前放弃")
                            return ""
                        if stuck_for > 35 and not getattr(page, "_email_otp_stuck_logged", False):
                            _log("      [RT] 邮箱 OTP 提交后仍停留 email-verification >35s，继续等待到 120s")
                            page._email_otp_stuck_logged = True
                if "email-verification" not in cur:
                    email_otp_stuck_since = 0.0
                # /about-you 页（偶尔会出现）— 跳过
                if "/about-you" in cur:
                    for sel in ['button:has-text("Finish")', 'button:has-text("Continue")',
                                'button[type="submit"]']:
                        b = page.query_selector(sel)
                        if b and b.is_visible():
                            try:
                                b.click()
                            except Exception:
                                pass
                            break
                # /add-phone 页（OpenAI 风控强制塞这一步）— 找 Skip 按钮跳过
                if "/add-phone" in cur or "phone-number" in cur:
                    if not getattr(page, "_addphone_dumped", False):
                        try:
                            _safe_screenshot(page, "/tmp/rt_addphone.png")
                            btns = page.evaluate("""
                                () => Array.from(document.querySelectorAll('button,a[role=button],a,[role=button]')).map(b => ({
                                    text: (b.innerText||'').trim().slice(0,40),
                                    href: b.href||'',
                                    testid: b.getAttribute('data-testid')||'',
                                    type: b.getAttribute('type')||'',
                                    tag: b.tagName
                                })).filter(b => b.text || b.testid)
                            """)
                            _log(f"      [RT] add-phone 按钮列表: {btns}")
                            page._addphone_dumped = True
                        except Exception:
                            pass
                    skipped = False
                    for sel in [
                        'a:has-text("Skip")', 'button:has-text("Skip")',
                        'a:has-text("Not now")', 'button:has-text("Not now")',
                        'a:has-text("Maybe later")', 'button:has-text("Maybe later")',
                        'a:has-text("Skip for now")', 'button:has-text("Skip for now")',
                        '[data-testid*="skip"]',
                        'a[href*="skip"]',
                    ]:
                        try:
                            b = page.query_selector(sel)
                            if b and b.is_visible():
                                b.click()
                                _log(f"      [RT] add-phone 跳过: {sel}")
                                skipped = True
                                time.sleep(2)
                                break
                        except Exception:
                            pass
                    # 找不到 Skip：OpenAI 强制要求 phone 验证。Ryan 要求 RT 获取遇到 add-phone 时先别走手机号验证。
                    # 这里直接放弃本轮 RT，避免消耗号码/触发 add-phone 风控。
                    if not skipped and not getattr(page, "_addphone_gaveup", False):
                        page._addphone_gaveup = True
                        _log("      [RT] add-phone 找不到 Skip；按策略不走手机号验证，提前放弃本轮 RT")
                        break
                # Codex consent 授权页 — 自动点 Authorize
                if "/consent" in cur or "/authorize" in cur:
                    if not getattr(page, "_consent_dumped", False):
                        try:
                            _safe_screenshot(page, "/tmp/rt_consent.png")
                            btns = page.evaluate("""
                                () => Array.from(document.querySelectorAll('button,a[role=button],[role=button]')).map(b => ({
                                    text: (b.innerText||'').trim().slice(0,40),
                                    type: b.getAttribute('type')||'',
                                    testid: b.getAttribute('data-testid')||'',
                                    name: b.getAttribute('name')||'',
                                    id: b.id||'',
                                    tag: b.tagName
                                }))
                            """)
                            _log(f"      [RT] consent 页按钮列表: {btns}")
                            page._consent_dumped = True
                        except Exception as e_d:
                            _log(f"      [RT] consent dump 异常: {e_d}")
                    clicked = False
                    for sel in ['button:has-text("Authorize")',
                                'button:has-text("Allow")',
                                'button:has-text("Continue")',
                                'button:has-text("Accept")',
                                'button:has-text("Confirm")',
                                'button[type="submit"]',
                                'button[data-testid*="consent"]',
                                'button[data-testid*="authorize"]',
                                'button[data-testid*="allow"]',
                                'button[name="action"][value="accept"]',
                                'form button']:
                        b = page.query_selector(sel)
                        if b and b.is_visible():
                            try:
                                b.click()
                                _log(f"      [RT] consent 点击: {sel}")
                                clicked = True
                                time.sleep(2)
                            except Exception as e_c:
                                _log(f"      [RT] consent 点击异常 {sel}: {e_c}")
                            break
                    if not clicked:
                        # 兜底：表单 submit
                        try:
                            ok = page.evaluate("""
                                () => {
                                    const f = document.querySelector('form');
                                    if (f) { f.submit(); return true; }
                                    return false;
                                }
                            """)
                            if ok:
                                _log("      [RT] consent 走表单 submit")
                                time.sleep(2)
                        except Exception:
                            pass
                time.sleep(1)

            try:
                page.unroute("http://localhost:1455/**")
            except Exception:
                pass
    finally:
        try:
            _sh.rmtree(tmp_profile, ignore_errors=True)
        except Exception:
            pass

    cb_url = code_captured["url"]
    if not cb_url:
        _log("      [RT] 未捕获到 callback URL")
        return ""
    code = _parse_qs(_urlparse(cb_url).query).get("code", [""])[0]
    if not code:
        _log(f"      [RT] callback 无 code: {cb_url[:150]}")
        return ""
    _log(f"      [RT] 获得 code，POST /oauth/token 换 refresh_token ...")
    try:
        from curl_cffi.requests import Session as CffiSession
        http_rt = CffiSession(impersonate="chrome136")
        if proxy_url:
            _apply_proxy_to_http_session(http_rt, proxy_url)
        r = http_rt.post(
            "https://auth.openai.com/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": codex_client_id,
                "code": code,
                "redirect_uri": codex_redirect,
                "code_verifier": verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            timeout=30,
        )
        if r.status_code != 200:
            _log(f"      [RT] /oauth/token: {r.status_code} {r.text[:200]}")
            return ""
        tj = r.json()
        return tj.get("refresh_token", "") or ""
    except Exception as e_tok:
        _log(f"      [RT] /oauth/token 异常: {e_tok}")
        return ""



PAYPAL_GUEST_US_PROXY = os.getenv("PAYPAL_GUEST_US_PROXY", "")
PAYPAL_GUEST_INFO_API = "https://card.jinyao91.top/api/exchange/verify"
PAYPAL_GUEST_INFO_KEY = os.getenv("PAYPAL_GUEST_INFO_KEY", "KW-8C74-E6RRS7PR-68A9")


def _fetch_paypal_guest_nonpayment_info() -> dict:
    """Fetch non-payment identity fields for PayPal guest handoff.

    The upstream response may include card_number/expiry/cvv. Those are
    intentionally ignored by this function.
    """
    try:
        resp = requests.post(
            PAYPAL_GUEST_INFO_API,
            json={"key": PAYPAL_GUEST_INFO_KEY},
            headers={
                "accept": "*/*",
                "content-type": "application/json",
                "origin": "https://card.jinyao91.top",
                "referer": "https://card.jinyao91.top/",
                "user-agent": USER_AGENT,
            },
            timeout=30,
        )
        data = resp.json()
    except Exception as e:
        _log(f"      [Guest] 获取资料接口失败: {e}")
        data = {}
    content = data.get("content") if isinstance(data, dict) else {}
    if not isinstance(content, dict):
        content = {}
    name = str(content.get("name") or "WILLIAM WILSON").strip()
    parts = name.split()
    first = parts[0] if parts else "WILLIAM"
    last = " ".join(parts[1:]) if len(parts) > 1 else "WILSON"
    phone = re.sub(r"\D+", "", str(content.get("phone") or "4155550134"))
    if phone.startswith("1") and len(phone) == 11:
        phone = phone[1:]
    address_raw = str(content.get("address") or "123 Market Street,San Francisco 94105,US").strip()
    # Expected example: "131 PENNINGTON ROAD,PONTOTOC 38863,US"
    chunks = [c.strip() for c in address_raw.split(",") if c.strip()]
    line1 = chunks[0] if chunks else "123 Market Street"
    city = "San Francisco"
    state = "CA"
    postal = "94105"
    if len(chunks) >= 2:
        m = re.match(r"(.+?)\s+([A-Z]{2})?\s*(\d{5})(?:-\d{4})?$", chunks[1], re.I)
        if m:
            city = m.group(1).strip()
            if m.group(2):
                state = m.group(2).upper()
            postal = m.group(3)
        else:
            city = chunks[1]
    # If state not present in the address API, infer MS for the known Pontotoc example.
    if city.upper() == "PONTOTOC" and state == "CA":
        state = "MS"
    return {
        "phone": phone or "4155550134",
        "first": first,
        "last": last,
        "line1": line1,
        "city": city,
        "state": state,
        "zip": postal,
    }


def _paypal_guest_handoff_fill_nonpayment(
    redirect_url: str,
    *,
    chatgpt_email: str = "",
    proxy_url: str = "",
) -> dict:
    """Open PayPal with US proxy, enter email, fill non-payment guest fields, stop.

    Does not fill card number, expiration, CVV, password, and does not click
    Agree/Create/Pay.
    """
    from camoufox.sync_api import Camoufox
    from browserforge.fingerprints import Screen
    from urllib.parse import urlparse as _urlparse
    import pathlib as _pathlib

    email = (chatgpt_email or "").strip()
    proxy = proxy_url or PAYPAL_GUEST_US_PROXY
    pp = _urlparse(proxy) if proxy else None
    cf_proxy = None
    if pp and pp.scheme and pp.hostname:
        cf_proxy = {
            "server": f"{pp.scheme}://{pp.hostname}:{pp.port}",
            "username": pp.username or "",
            "password": pp.password or "",
        }
    out_dir = _pathlib.Path("/var/www/dujiao-sitemap/debug")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    shot = out_dir / f"paypal_guest_handoff_{stamp}.png"
    meta = out_dir / f"paypal_guest_handoff_{stamp}.json"

    info = _fetch_paypal_guest_nonpayment_info()
    if email:
        info["email"] = email
    def _apply_paypal_guest_env_overrides() -> None:
        try:
            phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
            if phone_override.startswith("1") and len(phone_override) == 11:
                phone_override = phone_override[1:]
            if phone_override:
                info["phone"] = phone_override
            email_override = os.getenv("PAYPAL_GUEST_EMAIL_OVERRIDE", "").strip()
            if email_override:
                info["email"] = email_override
            for key, env_name in [
                ("first", "PAYPAL_GUEST_FIRST"),
                ("last", "PAYPAL_GUEST_LAST"),
                ("line1", "PAYPAL_GUEST_LINE1"),
                ("city", "PAYPAL_GUEST_CITY"),
                ("state", "PAYPAL_GUEST_STATE"),
                ("zip", "PAYPAL_GUEST_ZIP"),
            ]:
                value = os.getenv(env_name, "").strip()
                if value:
                    info[key] = value
            _log(
                f"      [Guest] effective info: email={info.get('email')} phone={info.get('phone')} "
                f"name={info.get('first')} {info.get('last')} city={info.get('city')} zip={info.get('zip')}"
            )
        except Exception as exc:
            _log(f"      [Guest] env info override failed: {exc}")

    _apply_paypal_guest_env_overrides()

    def _is_payment_like(el) -> bool:
        if str(os.getenv("FILL_CARD_FIELDS", "0")).lower() in ("1", "true", "yes", "on"):
            return False
        blob = " ".join([
            (el.get_attribute("name") or "").lower(),
            (el.get_attribute("id") or "").lower(),
            (el.get_attribute("autocomplete") or "").lower(),
            (el.get_attribute("placeholder") or "").lower(),
        ])
        return any(k in blob for k in ["card", "cc-", "csc", "cvv", "expiry", "expiration", "security", "pan"])

    def _guest_pause(label="", base: float = 0.45, spread: float = 0.9):
        if str(os.getenv("PAYPAL_GUEST_HUMAN_FILL", "1")).lower() in ("0", "false", "no", "off"):
            return
        try:
            t = max(0.05, base + random.uniform(0, spread))
            _log(f"      [Guest-human] pause {label or '-'} {t:.2f}s")
            time.sleep(t)
        except Exception:
            time.sleep(base)

    def _human_fill_element(el, value, label):
        value = str(value)
        if str(os.getenv("PAYPAL_GUEST_HUMAN_FILL", "1")).lower() in ("0", "false", "no", "off"):
            el.fill(value)
            return
        try:
            el.scroll_into_view_if_needed(timeout=3000)
        except Exception:
            pass
        try:
            el.click(timeout=4000)
            time.sleep(random.uniform(0.15, 0.45))
            # Ctrl+A/Backspace 比直接 fill 更像修正输入；失败则 fallback fill。
            try:
                el.press("Control+A")
                time.sleep(random.uniform(0.04, 0.12))
                el.press("Backspace")
                time.sleep(random.uniform(0.08, 0.22))
            except Exception:
                pass
            # 短数字字段保守逐字；长卡号/邮箱也分段输入，避免一帧灌完。
            delay_ms = int(random.uniform(45, 135))
            try:
                el.type(value, delay=delay_ms)
            except Exception:
                # Playwright ElementHandle 某些版本没有 type 时回退 keyboard。
                el.fill("")
                page.keyboard.type(value, delay=delay_ms)
            time.sleep(random.uniform(0.18, 0.5))
        except Exception as e:
            _log(f"      [Guest-human] human fill blocked label={label}: {e}")
            # If PayPal's captcha overlay intercepts the click, do NOT fill behind it.
            # Stop here, let YesCaptcha finish, then resume the exact same field.
            try:
                blocked = bool(page.evaluate(r"""() => {
                    const visible = el => {
                        const r = el.getBoundingClientRect();
                        const st = getComputedStyle(el);
                        return r.width > 20 && r.height > 20 && st.visibility !== 'hidden' && st.display !== 'none' && st.opacity !== '0';
                    };
                    const sels = ['#captcha-standalone','iframe[name="recaptcha"]','iframe[src*="recaptcha" i]','iframe[src*="hcaptcha" i]','iframe[src*="captcha" i]','iframe[title*="captcha" i]','iframe[title*="challenge" i]'];
                    return sels.some(sel => Array.from(document.querySelectorAll(sel)).some(visible));
                }"""))
            except Exception:
                blocked = bool(re.search(r"captcha|recaptcha|challenge|intercepts pointer", str(e), re.I))
            if blocked:
                wait_s = int(os.getenv("PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS", "240") or "240")
                _log(f"      [Guest-Challenge] field fill paused by captcha label={label}; wait YesCaptcha up to {wait_s}s")
                last_count = -1
                try:
                    last_count = len(_yescaptcha_signal.get("events") or [])
                except Exception:
                    last_count = -1
                cleared = False
                for sec in range(wait_s):
                    time.sleep(1)
                    try:
                        events = _yescaptcha_signal.get("events") or []
                        if len(events) > last_count:
                            last_count = len(events)
                            _log(f"      [Guest-Challenge] YesCaptcha active while field paused label={label} events={last_count}")
                    except Exception:
                        pass
                    try:
                        still_blocked = bool(page.evaluate(r"""() => {
                            const visible = el => {
                                const r = el.getBoundingClientRect();
                                const st = getComputedStyle(el);
                                return r.width > 20 && r.height > 20 && st.visibility !== 'hidden' && st.display !== 'none' && st.opacity !== '0';
                            };
                            const sels = ['#captcha-standalone','iframe[name="recaptcha"]','iframe[src*="recaptcha" i]','iframe[src*="hcaptcha" i]','iframe[src*="captcha" i]','iframe[title*="captcha" i]','iframe[title*="challenge" i]'];
                            return sels.some(sel => Array.from(document.querySelectorAll(sel)).some(visible));
                        }"""))
                    except Exception:
                        still_blocked = False
                    if not still_blocked:
                        time.sleep(2)
                        try:
                            still_blocked = bool(page.evaluate(r"""() => Array.from(document.querySelectorAll('#captcha-standalone,iframe[name="recaptcha"],iframe[src*="recaptcha" i],iframe[src*="hcaptcha" i],iframe[src*="captcha" i],iframe[title*="captcha" i],iframe[title*="challenge" i]')).some(el => { const r=el.getBoundingClientRect(); const st=getComputedStyle(el); return r.width>20 && r.height>20 && st.visibility!=='hidden' && st.display!=='none' && st.opacity!=='0'; })"""))
                        except Exception:
                            still_blocked = False
                        if not still_blocked:
                            cleared = True
                            _log(f"      [Guest-Challenge] field captcha cleared label={label}; retry fill")
                            break
                    if sec and sec % 60 == 0:
                        _log(f"      [Guest-Challenge] still waiting field captcha label={label} {sec}s")
                if cleared:
                    try:
                        el.scroll_into_view_if_needed(timeout=3000)
                    except Exception:
                        pass
                    try:
                        el.click(timeout=4000)
                        time.sleep(random.uniform(0.15, 0.45))
                        try:
                            el.press("Control+A")
                            time.sleep(random.uniform(0.04, 0.12))
                            el.press("Backspace")
                        except Exception:
                            pass
                        try:
                            el.type(value, delay=int(random.uniform(45, 135)))
                        except Exception:
                            el.fill(value)
                        return
                    except Exception as e2:
                        _log(f"      [Guest-human] retry after captcha failed label={label}: {e2}")
                        raise
                raise RuntimeError(f"captcha overlay did not clear while filling {label}")
            _log(f"      [Guest-human] human fill fallback label={label}: {e}")
            el.fill(value)

    def _try_fill(page, selectors, value, label, *, retries: int = 1, retry_delay: float = 1.0):
        if not value:
            return False
        for attempt in range(max(1, retries)):
            for sel in selectors:
                try:
                    page.wait_for_selector(sel, state="attached", timeout=1500)
                except Exception:
                    pass
                try:
                    els = page.query_selector_all(sel)
                except Exception:
                    els = []
                for el in els:
                    try:
                        if el and el.is_visible():
                            if _is_payment_like(el):
                                _log(f"      [Guest] skip payment-like field label={label} sel={sel}")
                                continue
                            _guest_pause(f"before {label}", 0.25, 0.75)
                            _human_fill_element(el, value, label)
                            _log(f"      [Guest] filled {label}: {sel}")
                            _guest_pause(f"after {label}", 0.35, 1.2)
                            return True
                    except Exception as e:
                        _log(f"      [Guest] fill failed label={label} sel={sel}: {e}")
                        pass
            if attempt < max(1, retries) - 1:
                _log(f"      [Guest] field not ready: {label}; retry {attempt + 2}/{max(1, retries)}")
                time.sleep(retry_delay)
        _log(f"      [Guest] field not found after {max(1, retries)} attempts: {label}")
        return False

    def _paypal_guest_form_ready(page) -> bool:
        ready_selectors = [
            'input[type="tel"]', 'input[name*="phone" i]', 'input[id*="phone" i]',
            'input[autocomplete="given-name"]', 'input[name*="first" i]', 'input[id*="first" i]',
            'input[autocomplete="address-line1"]', 'input[name*="address" i]', 'input[id*="address" i]',
            'input[type="password"]', 'input[name*="password" i]', 'input[id*="password" i]',
        ]
        for sel in ready_selectors:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible() and not _is_payment_like(el):
                    _log(f"      [Guest] form ready via {sel}")
                    return True
            except Exception:
                pass
        return False

    def _wait_paypal_guest_form_ready(page, timeout_s: float = 45.0) -> bool:
        deadline = time.time() + timeout_s
        last_url = ""
        while time.time() < deadline:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=2500)
            except Exception:
                pass
            try:
                url = page.url or ""
                if url != last_url:
                    _log(f"      [Guest] wait form url={url[:160]}")
                    last_url = url
            except Exception:
                pass
            if _paypal_guest_form_ready(page):
                return True
            time.sleep(1.5)
        try:
            body = (page.inner_text("body", timeout=2000) or "").strip().replace("\n", " | ")[:300]
        except Exception:
            body = ""
        _log(f"      [Guest] form not ready after {timeout_s:.0f}s; continuing. body={body!r}")
        return False

    _log(f"      [Guest] 打开 PayPal guest handoff (US proxy) ...")
    _guest_camoufox_kwargs = {
        "headless": str(os.getenv("PAYPAL_GUEST_HEADLESS", "1")).lower() in ("1", "true", "yes", "on"),
        "humanize": True,
        "os": "windows",
        "screen": Screen(max_width=1920, max_height=1080),
        "proxy": cf_proxy,
        "geoip": True,
        "locale": "en-US",
    }
    # Keep the PayPal Guest browser extension wiring explicit.  The addon directory
    # existing on disk is not enough; Camoufox must receive addons=[...] for this
    # browser context or the YesCaptcha plugin is silently absent.
    if str(os.getenv("PAYPAL_GUEST_LOAD_YESCAPTCHA_ADDON", "1")).lower() in ("1", "true", "yes", "on"):
        addon_path = _pathlib.Path(os.getenv("PAYPAL_GUEST_YESCAPTCHA_ADDON", "/root/Gpt-Agreement-Payment/CTF-pay/yescaptcha-addon"))
        if addon_path.exists():
            _guest_camoufox_kwargs["addons"] = [str(addon_path)]
            _log(f"      [Guest] YesCaptcha addon loaded: {addon_path}")
        else:
            _log(f"      [Guest] YesCaptcha addon missing: {addon_path}")
    else:
        _log("      [Guest] YesCaptcha addon disabled by PAYPAL_GUEST_LOAD_YESCAPTCHA_ADDON")

    with Camoufox(**_guest_camoufox_kwargs) as browser:
        page = browser.new_page()
        _yescaptcha_signal = {"seen": False, "events": []}

        def _mark_yescaptcha_signal(source="", payload=""):
            try:
                msg = str(payload or "")[:500]
                _yescaptcha_signal["seen"] = True
                _yescaptcha_signal["events"].append({"source": source, "payload": msg, "ts": time.time()})
                _log(f"      [Guest-YesCaptcha] signal source={source} payload={msg!r}")
            except Exception as _e:
                _log(f"      [Guest-YesCaptcha] signal log failed: {_e}")

        def _console_probe(msg):
            try:
                txt = msg.text or ""
                low = txt.lower()
                if any(k in low for k in ["yescaptcha", "yescaptchaendsuccess", "isyescaptchaend", "captcha end", "captcha solved", "solved", "验证完成", "解码完成"]):
                    _mark_yescaptcha_signal("console", txt)
                elif str(os.getenv("PAYPAL_GUEST_LOG_ALL_CONSOLE", "0")).lower() in ("1", "true", "yes", "on"):
                    _log(f"      [Guest-console] {txt[:500]!r}")
            except Exception as _e:
                _log(f"      [Guest-console] handler failed: {_e}")

        try:
            page.on("console", _console_probe)
            page.expose_function("__hermesYesCaptchaSignal", lambda payload: _mark_yescaptcha_signal("postMessage", payload))
            page.add_init_script(r'''
(() => {
  const interesting = (data) => {
    try {
      if (!data) return false;
      if (typeof data === 'string') return /yescaptcha|captcha.*(end|success|solv)|ready/i.test(data);
      const t = String(data.type || data.event || data.action || '');
      const crx = String(data.crx || '');
      return /yesCaptcha/i.test(crx) || /yesCaptchaEndSuccess|isYesCaptchaEnd|captcha.*(end|success|solv)/i.test(t);
    } catch (e) { return false; }
  };
  window.addEventListener('message', (ev) => {
    try {
      if (interesting(ev.data) && window.__hermesYesCaptchaSignal) {
        window.__hermesYesCaptchaSignal(JSON.stringify(ev.data));
      }
    } catch (e) {}
  }, true);
})();
''')
            _log("      [Guest-YesCaptcha] console/postMessage listener installed")
        except Exception as _e:
            _log(f"      [Guest-YesCaptcha] listener install failed: {_e}")

        page.goto(redirect_url, wait_until="domcontentloaded", timeout=90000)
        time.sleep(6)
        # Login/entry page: fill email and click Next only.
        if email:
            _try_fill(page, [
                'input[name="login_email"]', 'input[type="email"]', 'input[name="email"]',
                'input#email', 'input[autocomplete="username"]', 'input[type="text"]'
            ], email, "entry_email")
            for sel in ['#btnNext', 'button:has-text("Next")', 'button[name="btnNext"]', 'button[type="submit"]', 'input[type="submit"]']:
                try:
                    btn = page.query_selector(sel)
                    if btn and btn.is_visible():
                        _guest_pause("before Next", 0.6, 1.4)
                        btn.click()
                        _log(f"      [Guest] clicked Next: {sel}")
                        _guest_pause("after Next", 2.5, 3.5)
                        break
                except Exception:
                    pass
            time.sleep(8)
            _wait_paypal_guest_form_ready(page, float(os.getenv("PAYPAL_GUEST_FORM_READY_TIMEOUT", "45") or "45"))

        # Fill guest/signup non-payment fields only.
        field_retries = int(os.getenv("PAYPAL_GUEST_FIELD_RETRIES", "4") or "4")
        field_retry_delay = float(os.getenv("PAYPAL_GUEST_FIELD_RETRY_DELAY", "1.5") or "1.5")
        _try_fill(page, ['input[type="email"]', 'input[name="email"]', 'input#email', 'input[autocomplete="email"]'], info.get("email"), "email", retries=field_retries, retry_delay=field_retry_delay)
        _log(
            f"      [audit-fill] PayPal actual fill values: email={info.get('email')} phone={info.get('phone')} "
            f"name={info.get('first')} {info.get('last')} line1={info.get('line1')} "
            f"city={info.get('city')} state={info.get('state')} zip={info.get('zip')}"
        )
        _try_fill(page, ['input[name*="phone" i]', 'input[id*="phone" i]', 'input[autocomplete="tel"]', 'input[type="tel"]'], info.get("phone"), "phone", retries=field_retries, retry_delay=field_retry_delay)
        _try_fill(page, ['input[name="firstName"]', 'input[name*="first" i]', 'input[id*="first" i]', 'input[autocomplete="given-name"]'], info.get("first"), "first", retries=field_retries, retry_delay=field_retry_delay)
        _try_fill(page, ['input[name="lastName"]', 'input[name*="last" i]', 'input[id*="last" i]', 'input[autocomplete="family-name"]'], info.get("last"), "last", retries=field_retries, retry_delay=field_retry_delay)
        def _guest_debug_capture(reason="debug"):
            try:
                ts = datetime.now().strftime("%Y%m%d-%H%M%S")
                safe_reason = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(reason or "debug"))[:80]
                shot = out_dir / f"paypal_guest_{safe_reason}_{ts}.png"
                page.screenshot(path=str(shot), full_page=True, timeout=10000)
                _log(f"      [Guest-debug] screenshot {reason}: {shot}")
                return str(shot)
            except Exception as _e:
                _log(f"      [Guest-debug] screenshot failed {reason}: {_e}")
                return ""

        def _paypal_challenge_overlay_visible():
            try:
                count = page.evaluate(r"""() => {
                    const visible = el => {
                        const r = el.getBoundingClientRect();
                        const st = getComputedStyle(el);
                        return r.width > 20 && r.height > 20 && st.visibility !== 'hidden' && st.display !== 'none' && st.opacity !== '0';
                    };
                    const sels = [
                        '#captcha-standalone',
                        'div[id*="captcha" i]',
                        'iframe[name="recaptcha"]',
                        'iframe[src*="recaptcha" i]',
                        'iframe[src*="hcaptcha" i]',
                        'iframe[src*="captcha" i]',
                        'iframe[title*="captcha" i]',
                        'iframe[title*="challenge" i]'
                    ];
                    return sels.reduce((n, sel) => n + Array.from(document.querySelectorAll(sel)).filter(visible).length, 0);
                }""")
                return int(count or 0) > 0
            except Exception:
                return False

        def _paypal_clear_address_suggestions(reason=""):
            try:
                page.keyboard.press("Escape")
                time.sleep(0.35)
                page.keyboard.press("Escape")
                time.sleep(0.25)
                _log(f"      [Guest-address] cleared possible suggestion overlay ({reason})")
            except Exception as _e:
                _log(f"      [Guest-address] clear suggestion overlay failed ({reason}): {_e}")

        def _paypal_click_first_address_suggestion(reason=""):
            selectors = [
                '[role="option"]',
                '[role="listbox"] [role="option"]',
                'ul li:visible',
                'div[class*="suggest" i]:visible',
                'div[class*="autocomplete" i]:visible',
                'button[class*="suggest" i]:visible',
                'li[class*="suggest" i]:visible',
            ]
            for sel in selectors:
                try:
                    els = page.query_selector_all(sel)
                except Exception:
                    els = []
                for el in els[:5]:
                    try:
                        if not el or not el.is_visible():
                            continue
                        txt = (el.inner_text(timeout=800) or "").strip().replace("\n", " | ")[:160]
                        if not txt or not re.search(r"\d|street|st\b|road|rd\b|ave|avenue|blvd|drive|dr\b|lane|ln\b", txt, re.I):
                            continue
                        el.click(timeout=2500)
                        _log(f"      [Guest-address] clicked suggestion ({reason}) sel={sel} text={txt!r}")
                        time.sleep(1.0)
                        return True
                    except Exception as _e:
                        _log(f"      [Guest-address] suggestion click failed ({reason}) sel={sel}: {_e}")
            return False

        def _guest_visible_overlay_summary():
            """Return short diagnostic list of visible captcha/challenge overlays that can block clicks."""
            overlays = []
            for _sel in [
                '#captcha-standalone',
                'div[id*="captcha" i]',
                'iframe[name="recaptcha"]',
                'iframe[src*="recaptcha" i]',
                'iframe[src*="hcaptcha" i]',
                'iframe[src*="captcha" i]',
                'iframe[src*="datadome" i]',
                'iframe[title*="captcha" i]',
                'iframe[title*="challenge" i]',
            ]:
                try:
                    _el = page.query_selector(_sel)
                    if _el and _el.is_visible():
                        try:
                            _box = _el.bounding_box() or {}
                        except Exception:
                            _box = {}
                        overlays.append(
                            f"{_sel} box={int(_box.get('x', 0))},{int(_box.get('y', 0))},"
                            f"{int(_box.get('width', 0))}x{int(_box.get('height', 0))}"
                        )
                except Exception as _e:
                    overlays.append(f"{_sel} ERR:{type(_e).__name__}")
            return overlays[:8]

        def _wait_paypal_overlay_clear_for_yescaptcha(reason="", timeout_s=None):
            """If PayPal throws reCAPTCHA, stop all form actions and wait for YesCaptcha/overlay clear.

            This is deliberately dumb and strict: challenge visible => do nothing except wait.
            Once the overlay is gone for 2s, return to the caller so normal fill/click flow continues.
            """
            if not _paypal_challenge_overlay_visible():
                return True
            wait_s = int(timeout_s or os.getenv("PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS", "240") or "240")
            _log(f"      [Guest-Challenge] pause form actions; wait YesCaptcha overlay clear reason={reason or '-'} timeout={wait_s}s overlays={_guest_visible_overlay_summary()}")
            _guest_debug_capture(f"challenge_wait_{reason or 'form'}")
            last_count = len(_yescaptcha_signal.get("events") or [])
            for sec in range(wait_s):
                time.sleep(1)
                events = _yescaptcha_signal.get("events") or []
                if len(events) > last_count:
                    last_count = len(events)
                    _log(f"      [Guest-Challenge] YesCaptcha active while paused events={last_count}; keep waiting")
                if not _paypal_challenge_overlay_visible():
                    time.sleep(2)
                    if not _paypal_challenge_overlay_visible():
                        _log(f"      [Guest-Challenge] overlay cleared after pause reason={reason or '-'}; resume normal flow")
                        return True
                    _log(f"      [Guest-Challenge] overlay reappeared during pause reason={reason or '-'}; keep waiting")
                if sec and sec % 60 == 0:
                    _log(f"      [Guest-Challenge] still paused waiting YesCaptcha {sec}s reason={reason or '-'} overlays={_guest_visible_overlay_summary()}")
            _log(f"      [Guest-Challenge] timeout waiting YesCaptcha overlay clear reason={reason or '-'} overlays={_guest_visible_overlay_summary()}")
            _guest_debug_capture(f"challenge_wait_timeout_{reason or 'form'}")
            return False

        def _paypal_fill_address_fields():
            if _paypal_challenge_overlay_visible():
                _guest_debug_capture("challenge_before_address")
                _log(f"      [Guest-address] challenge overlay visible before address; pause and wait overlays={_guest_visible_overlay_summary()}")
                if not _wait_paypal_overlay_clear_for_yescaptcha("before_address"):
                    return False
                _guest_debug_capture("after_challenge_before_address")
            _guest_debug_capture("before_address")
            address_selectors = [
                '#billingLine1',
                'input[name="billingLine1"]',
                'input[id*="billingLine1" i]',
                'input[class*="AddressLine1Autocomplete" i]',
                'input[name*="line1" i]',
                'input[name*="address1" i]',
                'input[id*="addressLine1" i]',
                'input[id*="address-line1" i]',
                'input[id*="address" i]',
                'input[autocomplete="address-line1"]',
                'input[aria-label*="address" i]',
                'input[placeholder*="address" i]',
            ]
            address_ok = _try_fill(page, address_selectors, info.get("line1"), "address", retries=field_retries, retry_delay=field_retry_delay)
            if address_ok:
                time.sleep(0.8)
                if not _paypal_click_first_address_suggestion("after_line1"):
                    _paypal_clear_address_suggestions("after_line1_no_suggestion")
            else:
                _guest_debug_capture("address_not_found")
            _try_fill(page, ['#billingCity', 'input[name="billingCity"]', 'input[id*="billingCity" i]', 'input[name*="city" i]', 'input[id*="city" i]', 'input[autocomplete="address-level2"]'], info.get("city"), "city", retries=field_retries, retry_delay=field_retry_delay)
            state_done = False
            state = info.get("state") or ""
            state_label = {
                "AL":"Alabama","AK":"Alaska","AZ":"Arizona","AR":"Arkansas","CA":"California","CO":"Colorado","CT":"Connecticut","DE":"Delaware","FL":"Florida","GA":"Georgia","HI":"Hawaii","ID":"Idaho","IL":"Illinois","IN":"Indiana","IA":"Iowa","KS":"Kansas","KY":"Kentucky","LA":"Louisiana","ME":"Maine","MD":"Maryland","MA":"Massachusetts","MI":"Michigan","MN":"Minnesota","MS":"Mississippi","MO":"Missouri","MT":"Montana","NE":"Nebraska","NV":"Nevada","NH":"New Hampshire","NJ":"New Jersey","NM":"New Mexico","NY":"New York","NC":"North Carolina","ND":"North Dakota","OH":"Ohio","OK":"Oklahoma","OR":"Oregon","PA":"Pennsylvania","RI":"Rhode Island","SC":"South Carolina","SD":"South Dakota","TN":"Tennessee","TX":"Texas","UT":"Utah","VT":"Vermont","VA":"Virginia","WA":"Washington","WV":"West Virginia","WI":"Wisconsin","WY":"Wyoming","DC":"District of Columbia"
            }.get(state.upper(), state)
            for sel in ['#billingState', 'select[name="billingState"]', 'select[id*="billingState" i]', 'select[name*="state" i]', 'select[id*="state" i]']:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        try:
                            el.select_option(value=state, timeout=2500)
                        except Exception:
                            el.select_option(label=state_label, timeout=2500)
                        _log(f"      [Guest] filled state: {sel} value={state}/{state_label}")
                        state_done = True
                        break
                except Exception as e:
                    _log(f"      [Guest] state select failed short: {e}")
            if not state_done:
                state_done = _try_fill(page, ['#billingState', 'input[name="billingState"]', 'input[id*="billingState" i]', 'input[name*="state" i]', 'input[id*="state" i]', 'input[autocomplete="address-level1"]', '[role="combobox"][aria-label*="state" i]'], state, "state", retries=2, retry_delay=0.8)
            if not state_done:
                _guest_debug_capture("state_not_filled")
            zip_ok = _try_fill(page, ['#billingPostalCode', 'input[name="billingPostalCode"]', 'input[id*="billingPostal" i]', 'input[name*="postal" i]', 'input[name*="zip" i]', 'input[id*="postal" i]', 'input[id*="zip" i]', 'input[autocomplete="postal-code"]'], info.get("zip"), "zip", retries=field_retries, retry_delay=field_retry_delay)
            _paypal_clear_address_suggestions("after_address_block")
            if not (address_ok and state_done and zip_ok):
                _guest_debug_capture("address_block_incomplete")
            return bool(address_ok and state_done and zip_ok)

        address_block_ok = _paypal_fill_address_fields()
        if not address_block_ok and _paypal_challenge_overlay_visible():
            # Challenge is still covering the page after the YesCaptcha wait window.
            # Stop immediately; do not keep filling phone/password behind a captcha iframe.
            try:
                page.screenshot(path=str(shot), full_page=True)
            except Exception:
                pass
            result = {
                "status": "paypal_guest_challenge_unsolved",
                "url": page.url,
                "title": page.title(),
                "screenshot": str(shot),
                "public_screenshot": "https://www.chatgtp.plus/debug/" + shot.name,
                "filled_nonpayment": info,
                "error": "PayPal captcha/security challenge did not clear after YesCaptcha wait window; stopped before further form actions.",
            }
            meta.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            _log(f"      [Guest-Challenge] unresolved; stopped before phone/password fill. screenshot={shot}")
            return result

        # Keep env-derived values authoritative immediately before late fields.
        _apply_paypal_guest_env_overrides()
        phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if phone_override.startswith("1") and len(phone_override) == 11:
            phone_override = phone_override[1:]

        # 重新按覆盖后的 info 填手机号，确保页面值被替换成硬编码号码。
        if phone_override:
            _try_fill(page, ['input[name*="phone" i]', 'input[id*="phone" i]', 'input[autocomplete="tel"]', 'input[type="tel"]'], info.get("phone"), "phone_override", retries=field_retries, retry_delay=field_retry_delay)

        # Ryan 学习区：创建 PayPal 账号密码。
        _try_fill(page, ['input[type="password"]', 'input[name*="password" i]', 'input[id*="password" i]', 'input[autocomplete="new-password"]'], os.getenv("PAYPAL_GUEST_CREATE_PASSWORD", "Ryan8899"), "create_password", retries=field_retries, retry_delay=field_retry_delay)

        try:
            fill_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filled_shot = out_dir / f"paypal_guest_after_fill_{fill_stamp}.png"
            page.screenshot(path=str(filled_shot), full_page=True, timeout=10000)
            _log(f"      [audit-fill] PayPal after-fill full screenshot: {filled_shot}")
        except Exception as _e:
            _log(f"      [audit-fill] PayPal after-fill screenshot failed: {_e}")

        # Ryan 学习区：卡字段预留。默认关闭，不填卡。
        # 开启方式：设置环境变量 FILL_CARD_FIELDS=1，并在脚本 CARD_INFO 中填写字段。
        if str(os.getenv("FILL_CARD_FIELDS", "0")).lower() in ("1", "true", "yes", "on"):
            _try_fill(page, ['input[name*="cardnumber" i]', 'input[name*="card-number" i]', 'input[id*="card" i]', 'input[autocomplete="cc-number"]'], os.getenv("CARD_NUMBER", ""), "card_number")
            _try_fill(page, ['input[name*="exp" i]', 'input[id*="exp" i]', 'input[autocomplete="cc-exp"]'], os.getenv("CARD_EXPIRY", ""), "card_expiry")
            _try_fill(page, ['input[name*="cvv" i]', 'input[name*="cvc" i]', 'input[id*="cvv" i]', 'input[id*="cvc" i]', 'input[autocomplete="cc-csc"]'], os.getenv("CARD_CVV", ""), "card_cvv")

        # Ryan 学习区：检测 PayPal reCAPTCHA overlay，避免按钮点击被 iframe 一直拦截。
        def _paypal_recaptcha_overlay_visible():
            for _sel in ['iframe[name="recaptcha"]', 'iframe[src*="recaptcha_v2.html"]', 'iframe[src*="recaptcha"]']:
                try:
                    _el = page.query_selector(_sel)
                    if _el and _el.is_visible():
                        _log(f"      [Guest-reCAPTCHA] overlay visible: {_sel}")
                        return True
                except Exception:
                    pass
            try:
                _body = page.inner_text("body", timeout=2000) or ""
                if "Security Challenge" in _body and "PayPal" in _body:
                    return True
            except Exception:
                pass
            return False

        def _guest_button_diagnostics(reason=""):
            """Dump visible submit/create buttons and their geometry before/after click attempts."""
            try:
                rows = page.evaluate(r"""() => Array.from(document.querySelectorAll('button,input[type=submit],input[type=button],a')).map((el, idx) => {
                    const r = el.getBoundingClientRect();
                    const cs = window.getComputedStyle(el);
                    const text = (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
                    return {
                        idx,
                        tag: el.tagName,
                        type: el.getAttribute('type') || '',
                        text: text.slice(0, 80),
                        id: el.id || '',
                        cls: (el.className || '').toString().slice(0, 80),
                        visible: !!(r.width && r.height && cs.visibility !== 'hidden' && cs.display !== 'none'),
                        disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
                        box: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)],
                        z: cs.zIndex || '',
                    };
                }).filter(x => x.visible || /agree|create|continue|pay|submit|next/i.test(x.text)).slice(0, 25)""")
                _log(f"      [Guest-ButtonDiag] {reason or '-'} url={page.url[:180]} overlays={_guest_visible_overlay_summary()}")
                for _r in rows:
                    _log(
                        "      [Guest-ButtonDiag] "
                        f"idx={_r.get('idx')} tag={_r.get('tag')} type={_r.get('type')} "
                        f"disabled={_r.get('disabled')} box={_r.get('box')} z={_r.get('z')} "
                        f"text={_r.get('text')!r} id={_r.get('id')!r} cls={_r.get('cls')!r}"
                    )
            except Exception as _e:
                _log(f"      [Guest-ButtonDiag] failed {reason}: {_e}")


        def _paypal_sms_challenge_visible():
            try:
                body = page.inner_text("body", timeout=1500) or ""
                low = body.lower()
                # Require actual SMS/OTP copy, not just PayPal's generic post-submit dialog.
                sms_words = [
                    "enter your code",
                    "6-digit code",
                    "six-digit code",
                    "verification code",
                    "security code",
                    "we sent",
                    "text message",
                    "sms",
                ]
                if ("code" in low) and any(w in low for w in sms_words):
                    return True
            except Exception:
                pass
            try:
                count = page.evaluate(r"""() => {
                    const visible = el => {
                        const r = el.getBoundingClientRect();
                        const st = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none';
                    };
                    const selectors = [
                        '[data-testid="sca-confirm-multi-field"] input[type="tel"]',
                        '#ciBasic input[type="tel"]',
                        'input[id^="ci-ciBasic-"]',
                        'input[name^="ciBasic-"]',
                        'input[aria-label$="-6"][type="tel"]'
                    ];
                    const seen = new Set();
                    let n = 0;
                    for (const sel of selectors) {
                        for (const el of Array.from(document.querySelectorAll(sel))) {
                            const key = el.id || el.name || el.getAttribute('aria-label') || `${sel}:${n}`;
                            if (seen.has(key) || !visible(el)) continue;
                            seen.add(key);
                            n += 1;
                        }
                    }
                    return n;
                }""")
                if int(count or 0) >= 6:
                    return True
                _log(f"      [Guest-SMS] SMS challenge gate: visible_otp_digit_inputs={count or 0}; not polling yet")
            except Exception as _e:
                _log(f"      [Guest-SMS] SMS challenge gate inspect failed: {_e}")
            return False

        def _handle_paypal_sms_if_needed():
            if not _paypal_sms_challenge_visible():
                _log("      [Guest-SMS] SMS challenge not visible; skip polling to avoid false wait while captcha/security challenge is still active")
                return False
            # 手机短信验证码：只消费父进程预绑定的 PAYPAL_GUEST_SMS_API。
            # 不能再读取全局 PAYPAL_SMS_API_URL / 号码池，否则并发时会串号。
            # PayPal 这里通常是 6 个单字符框，输入满 6 位会自动提交；不要去点页面上
            # 的 Agree & Create Account（那不是 OTP 提交按钮，会被验证码/表单拦截）。
            sms_api = os.getenv("PAYPAL_GUEST_SMS_API", "").strip()
            bound_phone = os.getenv("PAYPAL_GUEST_PHONE_E164", "").strip() or os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", "").strip()
            if not sms_api:
                raise RuntimeError("PAYPAL_GUEST_SMS_API missing for bound PayPal phone; stop to avoid sms/phone mismatch")
            import requests as _req
            code = ""
            sms_text = ""
            last_status = ""
            for _si in range(24):
                try:
                    sr = _req.get(sms_api, timeout=15, headers={"accept": "*/*", "user-agent": USER_AGENT})
                    last_status = str(sr.status_code)
                    sms_text = sr.text[:1000]
                    _m = re.search(r"(?<!\d)(\d{6})(?!\d)", sms_text)
                    if _m:
                        code = _m.group(1)
                        _log(f"      [Guest-SMS] got code for phone_tail={bound_phone[-4:]}: {code}")
                        break
                    _log(f"      [Guest-SMS] waiting code for phone_tail={bound_phone[-4:]}... status={sr.status_code} body={sms_text[:120]}")
                except Exception as _e:
                    last_status = type(_e).__name__
                    _log(f"      [Guest-SMS] api error for phone_tail={bound_phone[-4:]}: {_e}")
                time.sleep(5)

            if not code:
                raise RuntimeError(f"PAYPAL_GUEST_SMS_API no 6-digit code after polling phone_tail={bound_phone[-4:]} last_status={last_status} last_body={sms_text[:200]!r}")

            def _dump_paypal_otp_dom(reason="before_fill"):
                """Log OTP-area DOM metadata for PayPal's changing SMS code UI."""
                try:
                    dump_dir = Path(os.getenv("PAYPAL_GUEST_DEBUG_DIR", "/tmp/paypal_guest_debug"))
                    dump_dir.mkdir(parents=True, exist_ok=True)
                    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
                    prefix = dump_dir / f"paypal_otp_dom_{ts}_{reason}"
                    try:
                        _safe_screenshot(page, str(prefix.with_suffix(".png")))
                    except Exception:
                        pass
                    data = page.evaluate(r"""() => {
                        const clean = s => (s || '').replace(/\s+/g, ' ').trim().slice(0, 220);
                        const attrs = el => {
                            const o = {};
                            for (const a of Array.from(el.attributes || [])) {
                                if (/token|csrf|session|ba_|cookie|password/i.test(a.name)) continue;
                                o[a.name] = clean(a.value);
                            }
                            return o;
                        };
                        const box = el => {
                            const r = el.getBoundingClientRect();
                            return {x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height)};
                        };
                        const visible = el => {
                            const r = el.getBoundingClientRect();
                            const st = getComputedStyle(el);
                            return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none';
                        };
                        const all = Array.from(document.querySelectorAll('input,textarea,[contenteditable="true"],button,[role="textbox"],[role="spinbutton"],[role="button"],div,span,label'));
                        const interesting = all.filter(el => {
                            const t = clean(el.innerText || el.textContent || '');
                            const a = JSON.stringify(attrs(el));
                            const tag = el.tagName.toLowerCase();
                            const type = (el.getAttribute('type') || '').toLowerCase();
                            const r = el.getBoundingClientRect();
                            return /code|otp|verification|digit|pin|one-time|security|resend|sent|text/i.test(t + ' ' + a)
                                || tag === 'input' || tag === 'textarea' || el.isContentEditable
                                || type === 'tel' || type === 'number';
                        }).slice(0, 220).map((el, idx) => ({
                            idx,
                            tag: el.tagName.toLowerCase(),
                            type: el.getAttribute('type') || '',
                            role: el.getAttribute('role') || '',
                            visible: visible(el),
                            box: box(el),
                            attrs: attrs(el),
                            text: clean(el.innerText || el.textContent || ''),
                            value: el.tagName.toLowerCase() === 'input' || el.tagName.toLowerCase() === 'textarea' ? clean(el.value || '') : '',
                            parent: el.parentElement ? {tag: el.parentElement.tagName.toLowerCase(), attrs: attrs(el.parentElement), text: clean(el.parentElement.innerText || el.parentElement.textContent || '')} : null
                        }));
                        return {url: location.href, title: document.title, bodyText: clean(document.body.innerText || ''), interesting};
                    }""")
                    prefix.with_suffix(".json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                    _log(f"      [Guest-SMS] OTP DOM dump {reason}: {prefix.with_suffix('.json')} screenshot={prefix.with_suffix('.png')}")
                    for row in (data.get("interesting") or [])[:80]:
                        try:
                            _log(f"      [Guest-SMS-DOM] idx={row.get('idx')} tag={row.get('tag')} type={row.get('type')} role={row.get('role')} visible={row.get('visible')} box={row.get('box')} attrs={row.get('attrs')} text={row.get('text')!r} value={row.get('value')!r}")
                        except Exception:
                            pass
                    return str(prefix.with_suffix(".json"))
                except Exception as _e:
                    _log(f"      [Guest-SMS] OTP DOM dump failed {reason}: {_e}")
                    return ""

            def _visible_otp_digit_inputs():
                selectors = [
                    '#ciBasic input[type="tel"]',
                    '[data-testid="sca-confirm-multi-field"] input[type="tel"]',
                    'input[id^="ci-ciBasic-"]',
                    'input[name^="ciBasic-"]',
                    'input[aria-label$="-6"][type="tel"]',
                    'input[maxlength="1"][inputmode="numeric"]',
                    'input[maxlength="1"][autocomplete="one-time-code"]',
                    'input[maxlength="1"][aria-label*="code" i]',
                    'input[maxlength="1"][name*="code" i]',
                    'input[maxlength="1"]',
                ]
                seen = set()
                out = []
                for _sel in selectors:
                    try:
                        _els = page.query_selector_all(_sel) or []
                    except Exception:
                        _els = []
                    for _el in _els:
                        try:
                            if not _el or not _el.is_visible():
                                continue
                            box = _el.bounding_box() or {}
                            # Skip invisible layout ghosts and non-OTP text fields.
                            if float(box.get("width") or 0) <= 0 or float(box.get("height") or 0) <= 0:
                                continue
                            key = (_el.get_attribute("id") or "") or (_el.get_attribute("name") or "") or ((_el.get_attribute("aria-label") or "") + "|" + str(box))
                            if key in seen:
                                continue
                            seen.add(key)
                            out.append(_el)
                        except Exception:
                            continue
                return out

            def _read_otp_values(inputs):
                vals = []
                for _el in inputs[:6]:
                    try:
                        vals.append(str(_el.input_value() or ""))
                    except Exception:
                        vals.append("")
                return vals

            filled_otp = False
            _dump_paypal_otp_dom("before_fill")
            digit_inputs = _visible_otp_digit_inputs()
            if len(digit_inputs) >= 6:
                _log(f"      [Guest-SMS] detected {len(digit_inputs)} OTP digit boxes; filling one-by-one/autosubmit")
                try:
                    # Clear any stale/partial digits first.
                    for _el in digit_inputs[:6]:
                        try:
                            _el.click(timeout=1500)
                            page.keyboard.press("Control+A")
                            page.keyboard.press("Backspace")
                        except Exception:
                            pass
                    for i, ch in enumerate(code[:6]):
                        digit_inputs[i].click(timeout=3000)
                        time.sleep(0.08)
                        # Use keyboard.type so PayPal's per-key handlers advance focus and auto-submit.
                        page.keyboard.type(ch, delay=60)
                        time.sleep(0.12)
                    vals = _read_otp_values(digit_inputs)
                    _log(f"      [Guest-SMS] filled otp digits values={vals}")
                    filled_otp = ("".join(v[:1] for v in vals) == code[:6]) or any(v for v in vals)
                except Exception as _e:
                    _log(f"      [Guest-SMS] fill digit boxes failed: {_e}")

            if not filled_otp:
                # Fallback for single-box variants only. Avoid generic text/tel selectors because
                # PayPal has many unrelated visible text fields on the same page.
                for _sel in [
                    'input[autocomplete="one-time-code"]:not([maxlength="1"])',
                    'input[inputmode="numeric"]:not([maxlength="1"])',
                    'input[name*="code" i]:not([maxlength="1"])',
                    'input[id*="code" i]:not([maxlength="1"])',
                ]:
                    try:
                        _els = page.query_selector_all(_sel)
                    except Exception:
                        _els = []
                    for _el in _els:
                        try:
                            if _el and _el.is_visible():
                                _el.click(timeout=3000)
                                _el.fill(code)
                                _log(f"      [Guest-SMS] filled otp single-box: {_sel}")
                                filled_otp = True
                                break
                        except Exception as _e:
                            _log(f"      [Guest-SMS] fill single-box failed {_sel}: {_e}")
                    if filled_otp:
                        break

            def _complete_after_sms(_otp_reason="after_sms"):
                # This helper is intentionally defined before _click_paypal_blue_button.
                # _click_paypal_blue_button calls it after OTP; keeping a local stub here
                # avoids Python's unbound-free-variable trap when the full helper is defined
                # later in the same enclosing scope. The final sweep helper below still runs
                # after challenge handling.
                try:
                    if _paypal_challenge_visible():
                        _log(f"      [Guest] post-OTP sees challenge again; skip immediate final consent ({_otp_reason})")
                        return False
                except Exception:
                    pass
                clicked = False
                for _i in range(4):
                    try:
                        if _paypal_click_agree_and_continue_if_visible(f"{_otp_reason}_{_i+1}"):
                            clicked = True
                            time.sleep(4)
                            continue
                    except Exception as _e:
                        _log(f"      [Guest] post-OTP final consent helper failed ({_otp_reason}) attempt={_i+1}: {_e}")
                    break
                return clicked

            _paypal_complete_post_otp_flow = _complete_after_sms

            if not filled_otp:
                _dump_paypal_otp_dom("not_filled")
                raise RuntimeError(f"PayPal SMS code received but OTP input not found/filled phone_tail={bound_phone[-4:]}")

            # PayPal SMS OTP UI auto-submits after the sixth digit. Wait for navigation/state change.
            # Press Enter only as a harmless nudge; do not click Agree/Create buttons here.
            try:
                page.keyboard.press("Enter")
            except Exception:
                pass
            time.sleep(10)
            _log("      [Guest-SMS] OTP entered; waited for PayPal auto-submit")
            return True


        def _click_paypal_blue_button(reason="initial", allow_phone_replace=True):
            if str(os.getenv("CLICK_BLUE_BUTTON", "0")).lower() not in ("1", "true", "yes", "on"):
                _log(f"      [Guest] blue button click disabled by CLICK_BLUE_BUTTON ({reason})")
                return False
            _guest_button_diagnostics(f"before_click:{reason}")
            clicked = False
            for sel in [
                'button:has-text("Agree & Create Account")',
                'button:has-text("Agree and Create Account")',
                'button[type="submit"]',
                'input[type="submit"]',
            ]:
                try:
                    btn = page.query_selector(sel)
                    if not btn:
                        _log(f"      [Guest] blue candidate missing ({reason}): {sel}")
                        continue
                    try:
                        _visible = btn.is_visible()
                    except Exception as _e:
                        _visible = False
                        _log(f"      [Guest] blue candidate visible-check failed ({reason}) {sel}: {_e}")
                    try:
                        _enabled = btn.is_enabled()
                    except Exception:
                        _enabled = None
                    try:
                        _box = btn.bounding_box() or {}
                    except Exception:
                        _box = {}
                    try:
                        _txt = (btn.inner_text(timeout=1000) or "").strip()
                    except Exception:
                        _txt = ""
                    _log(
                        f"      [Guest] blue candidate ({reason}) sel={sel} visible={_visible} "
                        f"enabled={_enabled} box={int(_box.get('x',0))},{int(_box.get('y',0))},"
                        f"{int(_box.get('width',0))}x{int(_box.get('height',0))} text={_txt[:80]!r}"
                    )
                    if btn and _visible:
                        if _paypal_recaptcha_overlay_visible():
                            _log(f"      [Guest] reCAPTCHA overlay detected before blue button click ({reason}); stop clicking overlays={_guest_visible_overlay_summary()}")
                            break
                        _log(f"      [Guest] clicking blue button ({reason}): {sel}")
                        try:
                            btn.click(timeout=5000)
                        except Exception as _e:
                            if _paypal_recaptcha_overlay_visible():
                                _log(f"      [Guest] blue button blocked by reCAPTCHA overlay ({reason}): {_e}")
                                try:
                                    _safe_screenshot(page, "/tmp/paypal_recaptcha_overlay.png")
                                    _log("      [Guest] recaptcha screenshot: /tmp/paypal_recaptcha_overlay.png")
                                except Exception:
                                    pass
                                break
                            _log(f"      [Guest] blue normal click failed ({reason}) {sel}: {_e}; trying JS click")
                            try:
                                page.evaluate("el => el.click()", btn)
                                _log(f"      [Guest] blue JS click dispatched ({reason}): {sel}")
                            except Exception as _je:
                                _log(f"      [Guest] blue JS click failed ({reason}) {sel}: {_je}")
                                raise
                        clicked = True
                        _guest_pause(f"after blue button click ({reason})", 5.5, 4.5)
                        _guest_button_diagnostics(f"after_click:{reason}")
                        try:
                            sms_handled = _handle_paypal_sms_if_needed()
                        except Exception:
                            # If the SMS page was reached but no code arrived / OTP fill failed,
                            # stop here. Do not continue scanning selectors and click a second
                            # generic submit button on the same PayPal page.
                            raise
                        if sms_handled:
                            try:
                                _paypal_complete_post_otp_flow(f"after_sms_{reason}")
                            except NameError:
                                _log(f"      [Guest] post-OTP final consent helper not initialized yet ({reason}); continue")
                            break
                        if allow_phone_replace and _paypal_try_different_phone_visible():
                            if _replace_rejected_phone_and_retry():
                                break
                        _log(f"      [Guest] clicked blue but SMS challenge not ready ({reason}); continue post-click flow")
                        break
                except Exception as e:
                    _log(f"      [Guest] blue button click failed {sel} ({reason}): {e}")
                    if "PAYPAL_GUEST_SMS_API" in str(e) or "PayPal SMS code" in str(e) or "OTP input" in str(e):
                        _log(f"      [Guest] stopping blue-button retries after SMS/OTP failure ({reason})")
                        return True
            if not clicked:
                _log(f"      [Guest] blue button not clicked ({reason}); overlays={_guest_visible_overlay_summary()}")
                _guest_button_diagnostics(f"not_clicked:{reason}")
            return clicked

        def _normalize_us_phone_local(value):
            digits = re.sub(r"\D+", "", str(value or ""))
            if digits.startswith("1") and len(digits) == 11:
                digits = digits[1:]
            return digits[-10:] if len(digits) >= 10 else digits

        def _paypal_fill_phone_number(phone_local, label="phone_replace"):
            phone_local = _normalize_us_phone_local(phone_local)
            if not phone_local:
                return False
            sels = ['input[name*="phone" i]', 'input[id*="phone" i]', 'input[autocomplete="tel"]', 'input[type="tel"]']
            for sel in sels:
                try:
                    for el in page.query_selector_all(sel) or []:
                        try:
                            if not el or not el.is_visible():
                                continue
                            el.click(timeout=2500)
                            page.keyboard.press("Control+A")
                            page.keyboard.press("Backspace")
                            try:
                                el.fill(phone_local)
                            except Exception:
                                page.keyboard.type(phone_local, delay=35)
                            try:
                                val = el.input_value(timeout=1000)
                            except Exception:
                                val = ""
                            _log(f"      [Guest-Phone] {label}: filled {sel} phone_tail={phone_local[-4:]} value_tail={str(val)[-4:]}")
                            return True
                        except Exception as _e:
                            _log(f"      [Guest-Phone] {label}: fill failed {sel}: {_e}")
                except Exception:
                    pass
            _log(f"      [Guest-Phone] {label}: no visible phone input found")
            return False

        def _paypal_try_different_phone_visible():
            try:
                body = page.inner_text("body", timeout=1500) or ""
                low = body.lower()
                return ("try a different phone number" in low) or ("unable to complete your request" in low and "phone" in low)
            except Exception:
                return False

        def _paypal_dismiss_try_different_phone():
            clicked = False
            for sel in ['button:has-text("OK")', 'button:has-text("Ok")', 'button:has-text("Okay")', '[role="button"]:has-text("OK")']:
                try:
                    btn = page.query_selector(sel)
                    if btn and btn.is_visible():
                        btn.click(timeout=3000)
                        _log(f"      [Guest-Phone] dismissed Try-different-phone dialog via {sel}")
                        clicked = True
                        time.sleep(1.2)
                        break
                except Exception as _e:
                    _log(f"      [Guest-Phone] dismiss failed {sel}: {_e}")
            return clicked

        def _phone_banned_file_path():
            return os.getenv("PAYPAL_PHONE_BANNED_FILE", "").strip()

        def _append_phone_banned_file(phone_e164):
            path = _phone_banned_file_path()
            if not path or not phone_e164:
                return
            try:
                p = Path(path)
                existing = []
                if p.exists():
                    existing = [x.strip() for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
                if phone_e164 not in existing:
                    existing.append(phone_e164)
                    p.write_text("\n".join(existing) + "\n", encoding="utf-8")
                    _log(f"      [Guest-Phone] wrote rejected phone to banned file tail={_normalize_us_phone_local(phone_e164)[-4:]}")
            except Exception as _e:
                _log(f"      [Guest-Phone] write banned file failed: {_e}")

        def _reserve_replacement_phone(old_phone_e164=""):
            old_local = _normalize_us_phone_local(old_phone_e164)
            old_norm = ("+1" + old_local) if old_local else ""
            try:
                db = get_db()
                banned_raw = db.get_runtime_json("payonly_phone_banned_v1", []) or []
                banned = banned_raw if isinstance(banned_raw, list) else [x.strip() for x in str(banned_raw).splitlines() if x.strip()]
                if old_norm:
                    banned_norm = []
                    seen_banned = set()
                    for x in banned + [old_norm]:
                        local = _normalize_us_phone_local(x)
                        if not local:
                            continue
                        e164 = "+1" + local
                        if e164 not in seen_banned:
                            seen_banned.add(e164)
                            banned_norm.append(e164)
                    banned = banned_norm
                    db.set_runtime_json("payonly_phone_banned_v1", banned)
                    _append_phone_banned_file(old_norm)
                    _log(f"      [Guest-Phone] banned rejected phone=***{old_local[-4:]} db_count={len(banned)}")
                state = db.get_runtime_json("payonly_phone_state_v1", {}) or {}
                if isinstance(state, dict):
                    for k in [old_norm, old_local]:
                        if k in state:
                            state.pop(k, None)
                    db.set_runtime_json("payonly_phone_state_v1", state)
                pool = db.get_runtime_json("payonly_phone_pool_v1", []) or []
                banned_set = set()
                for x in banned:
                    local = _normalize_us_phone_local(x)
                    if local:
                        banned_set.add(local); banned_set.add("+1" + local)
                run_id = os.getenv("PAYONLY_RUN_ID", f"payment_runner-{os.getpid()}")
                for idx, row in enumerate(pool):
                    if not isinstance(row, dict):
                        continue
                    local = _normalize_us_phone_local(row.get("phone"))
                    sms_api = str(row.get("sms_api") or "").strip()
                    if not local or not sms_api:
                        continue
                    e164 = "+1" + local
                    if local in banned_set or e164 in banned_set:
                        continue
                    st = state.get(e164) or state.get(local) or {}
                    if isinstance(st, dict) and st.get("reserved_by") and st.get("reserved_by") != run_id:
                        continue
                    state[e164] = {"reserved_by": run_id, "reserved_at": datetime.utcnow().isoformat() + "Z", "account_id": os.getenv("PAYONLY_ACCOUNT_ID", ""), "index": idx, "sms_host": urllib.parse.urlparse(sms_api).netloc}
                    db.set_runtime_json("payonly_phone_state_v1", state)
                    os.environ["PAYPAL_GUEST_PHONE_OVERRIDE"] = local
                    os.environ["PAYPAL_GUEST_PHONE_E164"] = e164
                    os.environ["PAYPAL_GUEST_SMS_API"] = sms_api
                    os.environ["PAYPAL_GUEST_PHONE_POOL_INDEX"] = str(idx)
                    _log(f"      [Guest-Phone] replacement reserved phone=***{local[-4:]} index={idx}")
                    return {"phone_local": local, "phone_e164": e164, "sms_api": sms_api, "index": idx}
            except Exception as _e:
                _log(f"      [Guest-Phone] replacement reserve failed: {_e}")
            return {}

        def _replace_rejected_phone_and_retry(max_attempts=2):
            if not _paypal_try_different_phone_visible():
                return False
            for attempt in range(1, max_attempts + 1):
                old = os.getenv("PAYPAL_GUEST_PHONE_E164", "") or os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", "")
                _log(f"      [Guest-Phone] PayPal rejected phone_tail={_normalize_us_phone_local(old)[-4:]}; replacing attempt={attempt}/{max_attempts}")
                _paypal_dismiss_try_different_phone()
                binding = _reserve_replacement_phone(old)
                if not binding:
                    _log("      [Guest-Phone] no replacement phone available")
                    return False
                info["phone"] = binding["phone_local"]
                if not _paypal_fill_phone_number(binding["phone_local"], f"replacement_{attempt}"):
                    return False
                _guest_pause(f"after replacement phone fill {attempt}", 0.8, 1.4)
                clicked = _click_paypal_blue_button(f"phone_replaced_{attempt}", allow_phone_replace=False)
                if _paypal_try_different_phone_visible():
                    continue
                return clicked
            return False

        # Ryan 学习区：点击 PayPal 页面底部蓝色按钮。
        # 默认关闭：只有 CLICK_BLUE_BUTTON=True / 环境变量 CLICK_BLUE_BUTTON=1 才会点击。
        clicked_blue_button = _click_paypal_blue_button("initial")

        # Ryan 学习区：PayPal Security Challenge / DataDome / captcha 接管。
        # 目标：把旧 PayPal challenge 识别经验搬到 guest handoff：
        # - 更全面识别 hCaptcha / reCAPTCHA / DataDome / PayPal Security Challenge
        # - 识别到时输出 frame/DOM 诊断、截图
        # - 标准 hCaptcha 才尝试远端打码；其它情况保留人工接管并等待更久
        def _paypal_challenge_snapshot(reason=""):
            try:
                _safe_screenshot(page, "/tmp/paypal_security_challenge_manual.png")
                _log("      [Guest-Challenge] screenshot: /tmp/paypal_security_challenge_manual.png")
            except Exception as _e:
                _log(f"      [Guest-Challenge] screenshot failed: {_e}")
            try:
                frames = []
                for f in page.frames:
                    u = f.url or ""
                    if any(k in u.lower() for k in ["captcha", "hcaptcha", "recaptcha", "datadome", "paypal", "challenge"]):
                        frames.append(u[:220])
                _log(f"      [Guest-Challenge] reason={reason or '-'} url={page.url[:220]}")
                _log(f"      [Guest-Challenge] frames={frames[:12]}")
            except Exception as _e:
                _log(f"      [Guest-Challenge] frame dump failed: {_e}")
            try:
                body = page.inner_text("body", timeout=2500) or ""
                _log(f"      [Guest-Challenge] body_head={body[:500]!r}")
            except Exception:
                pass

        def _paypal_challenge_state():
            state = {
                "visible": False,
                "kind": "",
                "reason": "",
                "sitekey": "",
                "frame_url": "",
            }
            body = ""
            try:
                body = page.inner_text("body", timeout=2500) or ""
            except Exception:
                body = ""
            low = body.lower()
            if "security challenge" in body or "captcha" in low:
                state.update(visible=True, kind="paypal_security", reason="body_text")
            if "datadome" in low or "verify you are human" in low or "press & hold" in low:
                state.update(visible=True, kind="datadome", reason="body_text_datadome")

            selectors = [
                ("#captcha-standalone", "paypal_captcha"),
                ('div[id*="captcha" i]', "captcha_div"),
                ('iframe[src*="hcaptcha" i]', "hcaptcha"),
                ('iframe[src*="recaptcha" i]', "recaptcha"),
                ('iframe[src*="captcha" i]', "captcha_iframe"),
                ('iframe[src*="datadome" i]', "datadome"),
                ('iframe[title*="captcha" i]', "captcha_iframe"),
                ('iframe[title*="challenge" i]', "challenge_iframe"),
            ]
            for sel, kind in selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        state.update(visible=True, kind=kind, reason=sel)
                        break
                except Exception:
                    pass

            # 旧逻辑搬运：尽量从 hcaptcha frame url 提取 sitekey。
            try:
                import urllib.parse as _up
                for f in page.frames:
                    u = f.url or ""
                    ul = u.lower()
                    if "hcaptcha" in ul:
                        state.update(visible=True, kind="hcaptcha", reason="frame_url", frame_url=u[:260])
                        parsed = _up.urlparse(u)
                        params = _up.parse_qs(parsed.fragment or parsed.query)
                        site_key = (params.get("sitekey") or params.get("site_key") or [""])[0]
                        if not site_key:
                            import re as _re
                            m = _re.search(r'(?:sitekey|site_key)[=/:%3D]+([0-9a-fA-F-]{20,})', u)
                            if m:
                                site_key = m.group(1)
                        if site_key:
                            state["sitekey"] = site_key
                        break
                    if "recaptcha" in ul:
                        state.update(visible=True, kind="recaptcha", reason="frame_url", frame_url=u[:260])
                    if "datadome" in ul:
                        state.update(visible=True, kind="datadome", reason="frame_url", frame_url=u[:260])
            except Exception as _e:
                _log(f"      [Guest-Challenge] frame inspect failed: {_e}")
            return state

        def _paypal_challenge_visible():
            return bool(_paypal_challenge_state().get("visible"))

        def _do_auto_solve():
            st = _paypal_challenge_state()
            if not st.get("visible"):
                return False
            if str(os.getenv("PAYPAL_AUTO_CHALLENGE_SOLVE", "0")).lower() not in ("1", "true", "yes", "on"):
                return False

            _log(f"      [Guest-Challenge] detected kind={st.get('kind')} reason={st.get('reason')} auto solver mode")
            try:
                api_key = os.getenv("YESCAPTCHA_CLIENT_KEY", "")
                if not api_key:
                    _log("      [Guest-Challenge] skip: YESCAPTCHA_CLIENT_KEY not set")
                    return False
                if st.get("kind") != "hcaptcha":
                    _log(f"      [Guest-Challenge] auto solver unsupported kind={st.get('kind')}; manual needed")
                    return False
                site_key = st.get("sitekey") or ""
                if not site_key:
                    _log("      [Guest-Challenge] hcaptcha frame found but sitekey missing; manual needed")
                    _paypal_challenge_snapshot("hcaptcha_no_sitekey")
                    return False
                _log(f"      [Guest-Challenge] hcaptcha sitekey: {site_key}")
                token = _solve_remote_hcaptcha_paypal(
                    api_key=api_key, site_key=site_key, page_url=page.url, timeout=180
                )
                if not token:
                    return False
                _log(f"      [Guest-Challenge] token obtained, injecting...")
                page.evaluate(r"""(t) => {
                    const names = ['h-captcha-response', 'g-recaptcha-response'];
                    for (const n of names) {
                        let el = document.getElementsByName(n)[0];
                        if (!el) {
                            el = document.createElement('textarea');
                            el.name = n;
                            el.style.display = 'none';
                            document.body.appendChild(el);
                        }
                        el.value = t;
                        el.dispatchEvent(new Event('input', {bubbles:true}));
                        el.dispatchEvent(new Event('change', {bubbles:true}));
                    }
                    if (window.onHcaptchaSolved) window.onHcaptchaSolved(t);
                    if (window.hcaptcha && window.hcaptcha.getResponse) {
                        try { window.hcaptcha.getResponse = () => t; } catch(e) {}
                    }
                    const btn = document.querySelector('#captcha-submit') ||
                                document.querySelector('.captcha-submit') ||
                                Array.from(document.querySelectorAll('button,input[type=submit]')).find(b => /continue|submit|verify|next/i.test((b.innerText||b.value||'')));
                    if (btn) btn.click();
                }""", token)
                time.sleep(6)
                return not _paypal_challenge_visible()
            except Exception as _e:
                _log(f"      [Guest-Challenge] auto solver error: {_e}")
            return False

        def _paypal_click_agree_and_continue_if_visible(reason="post_otp"):
            """After SMS OTP, PayPal may show a final review/consent screen.
            Click the explicit bottom blue Continue/Agree button. PayPal often keeps a
            hidden legacy #continue at 0x0, so do not rely on query_selector's first
            match; scan visible candidates by geometry/text and prefer the lowest
            full-width blue button.
            """
            def _candidate_rows():
                return page.evaluate(r"""() => {
                    const visible = (el) => {
                        const r = el.getBoundingClientRect();
                        const cs = window.getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
                    };
                    const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
                    return Array.from(document.querySelectorAll('button,input[type=submit],input[type=button],[role="button"],a')).map((el, idx) => {
                        const r = el.getBoundingClientRect();
                        const cs = window.getComputedStyle(el);
                        const text = clean(el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '');
                        const attrs = [el.id || '', el.getAttribute('data-testid') || '', el.getAttribute('data-atomic-wait-intent') || '', el.className || ''].join(' ');
                        const blob = `${text} ${attrs}`;
                        const looks = /agree|continue|pay|review|create account/i.test(blob);
                        return {
                            idx, text, attrs: String(attrs).slice(0, 160), visible: visible(el),
                            disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
                            x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height),
                            tag: el.tagName, type: el.getAttribute('type') || '', looks
                        };
                    }).filter(r => r.looks || r.visible).filter(r => r.looks).sort((a,b) => (b.y - a.y) || (b.w - a.w));
                }""") or []

            for attempt in range(3):
                try:
                    # Final review buttons are commonly below the fold.
                    try:
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        time.sleep(0.6)
                    except Exception:
                        pass
                    rows = _candidate_rows()
                    _log(f"      [Guest] final consent candidates ({reason}) attempt={attempt+1}: {rows[:8]}")
                    visible_rows = [r for r in rows if r.get("visible") and not r.get("disabled")]
                    if not visible_rows:
                        time.sleep(1.0)
                        continue
                    # Prefer explicit bottom Continue/Agree buttons; avoid links like legal/privacy.
                    chosen = None
                    for r in visible_rows:
                        blob = f"{r.get('text','')} {r.get('attrs','')}".lower()
                        if any(k in blob for k in ["cancel", "return", "log in", "privacy", "legal", "policy"]):
                            continue
                        if any(k in blob for k in ["agree and continue", "agree & continue", "continue", "agree and pay", "agree & pay", "review_your_payment"]):
                            chosen = r
                            break
                    if not chosen:
                        chosen = visible_rows[0]
                    clicked = page.evaluate(r"""(target) => {
                        const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
                        const visible = (el) => {
                            const r = el.getBoundingClientRect();
                            const cs = window.getComputedStyle(el);
                            return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
                        };
                        const els = Array.from(document.querySelectorAll('button,input[type=submit],input[type=button],[role="button"],a'));
                        const matches = els.map((el, idx) => {
                            const r = el.getBoundingClientRect();
                            const text = clean(el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '');
                            return {el, idx, text, x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height), visible: visible(el)};
                        }).filter(x => x.visible && x.idx === target.idx && x.w === target.w && x.h === target.h);
                        const m = matches[0];
                        if (!m) return false;
                        m.el.scrollIntoView({block: 'center', inline: 'center'});
                        m.el.click();
                        return true;
                    }""", chosen)
                    if clicked:
                        _log(f"      [Guest] clicked final PayPal bottom blue button ({reason}) attempt={attempt+1}: text={chosen.get('text')!r} box={chosen.get('x')},{chosen.get('y')},{chosen.get('w')}x{chosen.get('h')} attrs={chosen.get('attrs')!r}")
                        _guest_pause(f"after final consent ({reason})", 6.0, 4.0)
                        try:
                            _guest_button_diagnostics(f"after_final_consent:{reason}")
                        except Exception:
                            pass
                        return True
                except Exception as _e:
                    _log(f"      [Guest] final PayPal bottom blue click failed ({reason}) attempt={attempt+1}: {_e}")
                time.sleep(1.0)
            return False

        def _paypal_complete_post_otp_flow(reason="post_otp", attempts=4):
            clicked_any = False
            for i in range(attempts):
                try:
                    if _paypal_challenge_visible():
                        _log(f"      [Guest] post-OTP flow sees challenge again; stop final consent clicks ({reason})")
                        break
                except Exception:
                    pass
                if _paypal_click_agree_and_continue_if_visible(f"{reason}_{i+1}"):
                    clicked_any = True
                    # PayPal/Stripe redirect may take a few seconds after final consent.
                    time.sleep(4)
                    continue
                break
            return clicked_any

        # 循环检测机制：应对短信后可能出现的验证码/PayPal challenge。
        # 旧版只等 180s 且少量 selector；新版持续诊断，人工处理后继续。
        _wait_s_default = int(os.getenv("PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS", "600") or "600")
        for _check_idx in range(20):
            st = _paypal_challenge_state()
            if st.get("visible"):
                _log(f"      [Guest-Challenge] visible kind={st.get('kind')} reason={st.get('reason')}")
                if not _do_auto_solve():
                    if str(os.getenv("PAYPAL_ABORT_ON_MANUAL_CHALLENGE", "1")).lower() not in ("0", "false", "no", "off"):
                        _log("      [Guest-Challenge] manual challenge detected; aborting immediately as failed")
                        _paypal_challenge_snapshot(st.get("kind") or "challenge_abort")
                        page.screenshot(path=str(shot), full_page=True)
                        result = {
                            "status": "manual_challenge_failed",
                            "url": page.url,
                            "title": page.title(),
                            "screenshot": str(shot),
                            "public_screenshot": "https://www.chatgtp.plus/debug/" + shot.name,
                            "filled_nonpayment": info,
                            "error": "PayPal captcha/manual challenge detected; aborted without manual handoff.",
                        }
                        meta.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                        _log(f"      [Guest-Challenge] final screenshot: {shot}")
                        _log(f"      [Guest-Challenge] public: {result['public_screenshot']}")
                        return result
                    if str(os.getenv("PAYPAL_MANUAL_CHALLENGE_HANDOFF", "0")).lower() in ("1", "true", "yes", "on"):
                        _log("      [Guest-Challenge] fallback to manual handoff")
                        _paypal_challenge_snapshot(st.get("kind") or "challenge")
                        _log(f"      [Guest-Challenge] waiting up to {_wait_s_default}s for captcha/manual resolution ...")
                        _challenge_cleared = False
                        _last_yc_count = len(_yescaptcha_signal.get("events") or [])
                        _last_yc_ts = 0.0
                        try:
                            if _yescaptcha_signal.get("events"):
                                _last_yc_ts = float((_yescaptcha_signal.get("events") or [])[-1].get("ts") or 0)
                        except Exception:
                            _last_yc_ts = 0.0
                        for _ci in range(_wait_s_default):
                            time.sleep(1)
                            _events = _yescaptcha_signal.get("events") or []
                            _yc_count = len(_events)
                            if _yc_count > _last_yc_count:
                                _last_yc_count = _yc_count
                                try:
                                    _last_yc_ts = float(_events[-1].get("ts") or time.time())
                                except Exception:
                                    _last_yc_ts = time.time()
                                _log(f"      [Guest-Challenge] YesCaptcha still active events={_yc_count}; keep waiting")
                            if _yescaptcha_signal.get("seen") and not _paypal_challenge_visible():
                                time.sleep(2)
                                if not _paypal_challenge_visible():
                                    _challenge_cleared = True
                                    _log("      [Guest-Challenge] yesCaptcha signal + challenge absent for 2s; continuing to page-state verification")
                                    break
                                _log("      [Guest-Challenge] yesCaptcha signal seen but challenge reappeared; keep waiting")
                            if not _paypal_challenge_visible():
                                time.sleep(2)
                                if not _paypal_challenge_visible():
                                    _challenge_cleared = True
                                    _log("      [Guest-Challenge] challenge absent for 2s; continuing to page-state verification")
                                    break
                                _log("      [Guest-Challenge] challenge briefly disappeared then reappeared; keep waiting")
                            if _ci and _ci % 60 == 0:
                                _log(f"      [Guest-Challenge] still waiting manual resolution... {_ci}s")
                                _paypal_challenge_snapshot("still_waiting")
                        if _challenge_cleared:
                            _guest_button_diagnostics("challenge_cleared_before_retry")
                            if _paypal_sms_challenge_visible():
                                _log("      [Guest-Challenge] resolved into SMS challenge; handle SMS without clicking blue button again")
                                try:
                                    if _handle_paypal_sms_if_needed():
                                        _paypal_complete_post_otp_flow("after_sms_challenge_clear")
                                except Exception as _e:
                                    _log(f"      [Guest-Challenge] SMS handling after challenge clear failed: {_e}")
                            else:
                                _log("      [Guest-Challenge] cleared but SMS challenge not visible; retry blue button once")
                                clicked_blue_button = _click_paypal_blue_button("yescaptcha_done" if _yescaptcha_signal.get("seen") else "after_challenge_cleared") or clicked_blue_button
                            _guest_button_diagnostics("challenge_cleared_after_retry")
                        else:
                            _log("      [Guest-Challenge] manual wait timeout; keeping final diagnostic")
                            _paypal_challenge_snapshot("manual_timeout")
                            break
                    else:
                        _paypal_challenge_snapshot("manual_handoff_disabled")
                        break
                else:
                    _log("      [Guest-Challenge] auto solver reports challenge cleared")
                    time.sleep(4)
                    clicked_blue_button = _click_paypal_blue_button("after_auto_challenge_cleared") or clicked_blue_button
            else:
                if _check_idx > 0:
                    break
                time.sleep(3)

        _paypal_complete_post_otp_flow("final_sweep")
        time.sleep(2)
        try:
            text = page.inner_text("body", timeout=5000)
        except Exception as e:
            text = f"ERR:{e}"
        try:
            page.screenshot(path=str(shot), full_page=True)
            screenshot_path = str(shot)
            public_screenshot = "https://www.chatgtp.plus/debug/" + shot.name
        except Exception as e:
            _log(f"      [Guest] final screenshot failed: {e}")
            screenshot_path = ""
            public_screenshot = ""
        try:
            current_url = page.url
        except Exception:
            current_url = ""
        try:
            current_title = page.title()
        except Exception:
            current_title = ""
        result = {
            "status": "paypal_guest_handoff",
            "url": current_url,
            "title": current_title,
            "text": text[:3000],
            "screenshot": screenshot_path,
            "public_screenshot": public_screenshot,
            "filled_nonpayment": info,
            "note": "Stopped before card/expiry/CVV/password/create/authorize.",
        }
        meta.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        if screenshot_path:
            _log(f"      [Guest] screenshot: {screenshot_path}")
        else:
            _log("      [Guest] screenshot: unavailable")
        if result.get("public_screenshot"):
            _log(f"      [Guest] public: {result['public_screenshot']}")
        return result


def _paypal_browser_authorize(
    redirect_url: str,
    paypal_cfg: dict,
    captcha_api_key: str = "",
    proxy_url: str = "",
) -> bool:
    """Playwright 浏览器完成 PayPal 授权全流程（登录+hCaptcha+2FA+授权）。
    当纯 HTTP 因 hCaptcha 失败时的回退路径。
    """
    from playwright.sync_api import sync_playwright
    import subprocess, shutil

    paypal_email = paypal_cfg.get("email", "")
    paypal_password = paypal_cfg.get("password", "")
    if not paypal_email or not paypal_password:
        raise RuntimeError("PayPal 浏览器模式需要 email + password")

    # VLM 配置（用于 hCaptcha 视觉识别）
    vlm_base_url = os.environ.get("CTF_VLM_BASE_URL", "https://YOUR_VLM_ENDPOINT/api")
    vlm_api_key = os.environ.get("CTF_VLM_API_KEY", "")
    vlm_model = os.environ.get("CTF_VLM_MODEL", "gpt-5.4")

    _log("      [Browser] 启动 Camoufox 反检测浏览器 ...")
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    _log(f"      [Browser] display={'yes' if has_display else 'no (virtual)'}")

    # 代理配置 (Camoufox 格式 — socks5 auth 需要 gost 中继)
    cf_proxy = None
    if proxy_url:
        from urllib.parse import urlparse as _urlparse
        pp = _urlparse(proxy_url)
        if pp.scheme in ("socks5", "socks5h") and pp.username:
            import socket as _sock
            relay_port = 18899
            try:
                with _sock.create_connection(("127.0.0.1", relay_port), timeout=2):
                    pass
                cf_proxy = {"server": f"socks5://127.0.0.1:{relay_port}"}
                _log(f"      [Browser] proxy: gost relay 127.0.0.1:{relay_port}")
            except Exception:
                _log(f"      [Browser] 需要 gost 中继: gost -L=socks5://:{relay_port} -F={proxy_url}")
        else:
            cf_proxy = {
                "server": f"{pp.scheme}://{pp.hostname}:{pp.port}",
                "username": pp.username or "",
                "password": pp.password or "",
            }
            _log(f"      [Browser] proxy: {pp.hostname}:{pp.port}")

    success = False
    from camoufox.sync_api import Camoufox
    from browserforge.fingerprints import Screen
    # 持久化 profile: 首次成功登录后 PayPal "Remember this computer" 生效
    # 后续跑批量时跳过 email+password+2FA，直接到 /agreements/approve
    # 保存在项目目录（/tmp 会重启丢失 + tmpfs 空间有限）
    # 若遇到损坏/DDC 失败状态，删除 CTF-pay/paypal_cf_persist 即可重置
    _persist_profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "paypal_cf_persist")
    os.makedirs(_persist_profile, exist_ok=True)
    profile_existed = any(os.scandir(_persist_profile))
    _log(f"      [Browser] 持久化 profile: {_persist_profile} (existed={profile_existed})")
    with Camoufox(
        headless=not has_display,
        humanize=False,
        persistent_context=True,
        user_data_dir=_persist_profile,
        os="windows",
        screen=Screen(max_width=1920, max_height=1080),
        proxy=cf_proxy,
        geoip=True,
        locale="zh-CN",
    ) as ctx:
        # persistent_context 返回的是 BrowserContext 而不是 Browser
        page = ctx.pages[0] if ctx.pages else ctx.new_page()

        # 不注入旧 cookies — 过期 cookies 会让 DDC 更严格

        try:
            # [B1] 跟随 Stripe redirect → PayPal
            _log("      [B1] 打开 PayPal 授权页 ...")
            page.goto(redirect_url, wait_until="domcontentloaded", timeout=60000)
            _log(f"      [B1] URL: {page.url[:100]}")

            # [B-DDC] 等待 DDC 自然通过（Camoufox 反检测指纹 + 全新 profile）
            time.sleep(3)
            _SLIDER_KWS = ("将滑块", "确认您是人类", "Slide the puzzle",
                            "move the slider", "Move the slider", "滑动到最右")
            def _slider_visible() -> bool:
                """主文档 + 所有 iframe（尤其 geo.ddc.paypal.com/captcha）里搜滑块关键字。"""
                try:
                    pt = page.inner_text("body")[:1500]
                    if any(kw in pt for kw in _SLIDER_KWS):
                        return True
                except Exception:
                    pass
                for fr in page.frames:
                    u = fr.url or ""
                    if fr.url == page.url:
                        continue
                    # 只对 DataDome 相关 iframe 取文本（其它 iframe 如 PayPal 内部 about:srcdoc 无意义）
                    if not ("ddc" in u or "captcha" in u or "datadome" in u):
                        continue
                    try:
                        txt = (fr.inner_text("body") or "")[:1500]
                    except Exception:
                        continue
                    if any(kw in txt for kw in _SLIDER_KWS):
                        return True
                return False
            ddc_frame = any("ddc" in f.url or "captcha" in f.url
                             for f in page.frames if f.url != page.url)

            def _find_ddc_iframe():
                for fr in page.frames:
                    u = fr.url or ""
                    if "ddc" in u or "captcha" in u or "datadome" in u:
                        return fr
                return None

            def _try_solve_ddc_slider(attempts: int = 2) -> bool:
                """尝试拖拽 DataDome 可见滑块。成功返回 True。"""
                for attempt in range(attempts):
                    fr = _find_ddc_iframe()
                    if not fr:
                        return False
                    # iframe 元素在主文档里的位置
                    iframe_el = None
                    for sel in ['iframe[src*="ddc"]', 'iframe[src*="captcha"]',
                                'iframe[src*="datadome"]']:
                        iframe_el = page.query_selector(sel)
                        if iframe_el: break
                    if not iframe_el:
                        return False
                    try:
                        iframe_box = iframe_el.bounding_box()
                    except Exception:
                        iframe_box = None
                    if not iframe_box:
                        return False
                    # 滑块 handle：常见 selector
                    handle = None
                    for sel in ['.slider', '[role="slider"]',
                                '.slider-handle', '.sliderIcon',
                                'div[class*="slider"]', 'button[class*="slider"]',
                                '#ddv1-captcha-container .slider']:
                        try:
                            el = fr.query_selector(sel)
                        except Exception:
                            el = None
                        if el:
                            try:
                                if el.is_visible():
                                    handle = el
                                    break
                            except Exception:
                                pass
                    if not handle:
                        return False
                    try:
                        hb = handle.bounding_box()
                    except Exception:
                        hb = None
                    if not hb:
                        return False
                    # 绝对坐标 = iframe 左上 + handle 在 iframe 内的位置
                    start_x = iframe_box["x"] + hb["x"] + hb["width"] / 2
                    start_y = iframe_box["y"] + hb["y"] + hb["height"] / 2
                    # 滑块 track 通常 iframe 宽度减去两侧边距；保守拖到距离 iframe 右边 10px
                    end_x = iframe_box["x"] + iframe_box["width"] - 10
                    end_y = start_y
                    _log(f"      [B-DDC] 拖拽 solver attempt={attempt+1} "
                          f"start=({start_x:.0f},{start_y:.0f}) → end=({end_x:.0f},{end_y:.0f})")
                    # 人类化拖动：移近 → 按下 → smoothstep 多段 → 抬起
                    try:
                        page.mouse.move(start_x - random.uniform(20, 40),
                                         start_y + random.uniform(-5, 5))
                        time.sleep(random.uniform(0.15, 0.35))
                        page.mouse.move(start_x, start_y)
                        time.sleep(random.uniform(0.08, 0.18))
                        page.mouse.down()
                        time.sleep(random.uniform(0.1, 0.22))
                        steps = random.randint(28, 42)
                        for i in range(1, steps + 1):
                            t = i / steps
                            eased = t * t * (3 - 2 * t)
                            x = start_x + (end_x - start_x) * eased
                            y = start_y + random.uniform(-1.8, 1.8)
                            page.mouse.move(x, y)
                            time.sleep(random.uniform(0.012, 0.028))
                        time.sleep(random.uniform(0.08, 0.18))
                        page.mouse.up()
                    except Exception as e:
                        _log(f"      [B-DDC] 拖拽异常: {e}")
                        continue
                    for _wt in range(8):
                        time.sleep(0.8)
                        if not _slider_visible():
                            _log(f"      [B-DDC] ✓ 滑块通过 (attempt {attempt+1})")
                            return True
                        cur = page.url
                        if any(kw in cur for kw in ("/webapps/hermes", "checkoutweb",
                                                      "/signin", "chatgpt.com")):
                            _log(f"      [B-DDC] ✓ 滑块通过 → {cur[:80]}")
                            return True
                    _log(f"      [B-DDC] attempt {attempt+1} 未通过，重试")
                    time.sleep(random.uniform(1.0, 2.0))
                return False

            slider_visible = _slider_visible()
            if slider_visible:
                _safe_screenshot(page, "/tmp/paypal_ddc_slider.png")
                _log("      [B-DDC] 检测到可见滑块，尝试 drag solver ...")
                if _try_solve_ddc_slider(attempts=2):
                    _log("      [B-DDC] drag solver 成功，继续流程")
                else:
                    _log("      [B-DDC] drag solver 失败，发 marker 交给外层")
                    _log("CARD_DATADOME_SLIDER=1")
                    raise RuntimeError("DataDome 滑块 solver 失败")
            if ddc_frame:
                _log("      [B-DDC] 检测到 DDC 隐形挑战，等待自然通过 ...")
                _safe_screenshot(page, "/tmp/paypal_ddc_detected.png")
                for _dw in range(25):
                    time.sleep(2)
                    cur = page.url
                    if any(kw in cur for kw in ["/signin", "/authflow", "/webapps/hermes",
                                                 "/pay", "chatgpt.com"]):
                        _log(f"      [B-DDC] DDC 通过! → {cur[:80]}")
                        break
                    if page.query_selector('input[name="login_email"]') or \
                       page.query_selector('#consentButton'):
                        _log("      [B-DDC] DDC 通过 (检测到页面元素)")
                        break
                    # 中途升级到可见滑块的情况
                    if _slider_visible():
                        _safe_screenshot(page, "/tmp/paypal_ddc_slider.png")
                        _log("      [B-DDC] 等待中升级为可见滑块，中止以便外层换 IP")
                        _log("CARD_DATADOME_SLIDER=1")
                        raise RuntimeError("DataDome 可见滑块，放弃当前 IP")
                    # 如果出现"重试"按钮，点击它刷新
                    retry_btn = page.query_selector('button:has-text("重试")') or \
                                page.query_selector('button:has-text("Retry")')
                    if retry_btn and retry_btn.is_visible():
                        _log("      [B-DDC] 点击重试刷新 DDC ...")
                        retry_btn.click()
                        time.sleep(3)
                    if _dw == 10:
                        _safe_screenshot(page, "/tmp/paypal_ddc_wait.png")
                        _log(f"      [B-DDC] 20s: {cur[:60]}")
                else:
                    _safe_screenshot(page, "/tmp/paypal_ddc_timeout.png")
                    _log(f"      [B-DDC] DDC 50s 超时: {page.url[:80]}")

            # [B2-onetouch] 持久化 profile 识别账号时 PayPal 会显示 "Continue as XXX" /
            # WebAuthn 等一键登录入口，此时 login_email input 仍在 DOM 但被隐藏。
            # 先尝试顺着登录态走一键登录，避免落到 B2 死等 email input 可见。
            onetouch_clicked = False
            try:
                onetouch_selectors = [
                    'button[data-testid*="one-touch"]',
                    'button[data-testid*="continue"]:not([disabled])',
                    'button[data-testid*="login-button"]',
                    'button.oneTouchLoginButton',
                    '#loginButton',
                    'button:has-text("Continue as")',
                    'a:has-text("Continue as")',
                    'button:has-text("Stay signed in")',
                    'button:has-text("以")',
                    'button:has-text("继续")',
                    'button:has-text("Log In as")',
                ]
                for sel in onetouch_selectors:
                    btn = page.query_selector(sel)
                    if btn and btn.is_visible():
                        txt = (btn.inner_text() or "")[:40]
                        _log(f"      [B2-onetouch] 一键登录按钮: {sel}  text={txt!r}")
                        try:
                            btn.click()
                            onetouch_clicked = True
                            _log("      [B2-onetouch] 已点击一键登录，等待跳转 ...")
                            time.sleep(3)
                        except Exception as e_o:
                            _log(f"      [B2-onetouch] 点击异常: {e_o}")
                        break
            except Exception as e_det:
                _log(f"      [B2-onetouch] 检测异常: {e_det}")

            # 一键登录后若仍在 /signin，说明需要进一步认证，继续走 B2
            email_visible = False
            try:
                ei = page.query_selector('input[name="login_email"]')
                email_visible = bool(ei and ei.is_visible())
            except Exception:
                pass

            # [B2] 需要填写邮箱登录的条件：没走一键登录 + (仍在 signin 页 or email input 可见)
            if (not onetouch_clicked) and ("/signin" in page.url or email_visible):
                _log("      [B2] 需要登录，填写邮箱 ...")
                page.wait_for_selector('input[name="login_email"]', state="visible", timeout=15000)
                # 先关闭 cookie 弹窗（如果有）
                for cookie_sel in ['button:has-text("接受")', 'button:has-text("Accept")', '#acceptAllButton']:
                    try:
                        cb = page.query_selector(cookie_sel)
                        if cb and cb.is_visible():
                            cb.click()
                            time.sleep(0.5)
                            break
                    except Exception:
                        pass
                # PayPal 记住账号时 email input 会被 disabled + 预填（value 已有），此时 fill 会卡住
                # 判断：input.disabled 且 value 非空 → 跳过 fill，直接走 Next/Log In
                skip_fill = False
                try:
                    ei_now = page.query_selector('input[name="login_email"]')
                    if ei_now:
                        is_disabled = ei_now.get_attribute("disabled") is not None
                        cur_val = (ei_now.get_attribute("value") or "").strip()
                        if is_disabled and cur_val:
                            skip_fill = True
                            _log(f"      [B2] email 已预填+disabled ({cur_val}),跳过 fill 直接 Next")
                except Exception:
                    pass
                if not skip_fill:
                    page.fill('input[name="login_email"]', paypal_email)
                    time.sleep(random.uniform(0.8, 1.5))

                # 点击 Next (下一步)
                _log("      [B2] 点击 Next ...")
                for btn_sel in ['#btnNext', 'button[name="signin-submit"]',
                                'button:has-text("下一步")', 'button:has-text("Next")',
                                'button[type="submit"]']:
                    btn = page.query_selector(btn_sel)
                    if btn and btn.is_visible():
                        btn.click()
                        _log(f"      [B2] 点击了: {btn_sel}")
                        break

                # [B3] 等待密码输入框变为可见
                _log("      [B3] 等待密码输入框 ...")
                try:
                    page.wait_for_selector(
                        'input[name="login_password"]',
                        state="visible", timeout=30000,
                    )
                except Exception:
                    # 可能是单页登录或需要更长等待
                    _log("      [B3] 标准等待超时，尝试等待 URL 变化 ...")
                    time.sleep(5)
                pwd_input = page.query_selector('input[name="login_password"]:visible') or \
                            page.query_selector('input[type="password"]:visible')
                if pwd_input:
                    _log("      [B3] 密码框可见，填写密码 ...")
                    pwd_input.fill(paypal_password)
                    time.sleep(random.uniform(0.5, 1))
                    for btn_sel in ['#btnLogin', 'button[name="signin-submit"]',
                                    'button:has-text("登录")', 'button:has-text("Log In")',
                                    'button[type="submit"]']:
                        btn = page.query_selector(btn_sel)
                        if btn and btn.is_visible():
                            btn.click()
                            _log(f"      [B3] 登录按钮: {btn_sel}")
                            break
                    time.sleep(4)
                else:
                    _log("      [B3] 密码框仍不可见")
                    _safe_screenshot(page, "/tmp/paypal_no_pwd.png")
                    _log("      [B3] 截图: /tmp/paypal_no_pwd.png")

            # 登录后截图 + 状态
            time.sleep(2)
            _safe_screenshot(page, "/tmp/paypal_after_login.png")
            _log(f"      [B-diag] 登录后 URL: {page.url[:100]}")
            _log(f"      [B-diag] frames: {[f.url[:60] for f in page.frames[:5]]}")
            _log(f"      [B-diag] 截图: /tmp/paypal_after_login.png")

            # [B4] 处理 hCaptcha（如果出现）
            hcaptcha_frame = None
            for _ in range(8):
                for frame in page.frames:
                    if "hcaptcha" in frame.url:
                        hcaptcha_frame = frame
                        break
                if hcaptcha_frame:
                    break
                time.sleep(1)

            if hcaptcha_frame:
                _log("      [B4] 检测到 hCaptcha，使用人类模拟点击 ...")
                # 用真实鼠标移动 + 点击（避免被检测为自动化）
                clicked = False
                try:
                    hc_iframes = page.locator('iframe[src*="hcaptcha"]')
                    for i in range(hc_iframes.count()):
                        iframe_el = hc_iframes.nth(i)
                        box = iframe_el.bounding_box()
                        if box and box["height"] < 200:  # checkbox iframe 较小
                            # 模拟人类鼠标移动: 先随机位置 → 目标附近 → checkbox
                            cx = box["x"] + box["width"] * 0.3  # checkbox 在左侧
                            cy = box["y"] + box["height"] * 0.5
                            # 先移动到随机位置
                            page.mouse.move(
                                random.uniform(100, 800),
                                random.uniform(200, 500),
                            )
                            time.sleep(random.uniform(0.3, 0.7))
                            # 分多步移动到目标
                            for step in range(5):
                                frac = (step + 1) / 5
                                mx = 400 + (cx - 400) * frac + random.uniform(-3, 3)
                                my = 350 + (cy - 350) * frac + random.uniform(-3, 3)
                                page.mouse.move(mx, my)
                                time.sleep(random.uniform(0.02, 0.06))
                            time.sleep(random.uniform(0.1, 0.3))
                            page.mouse.click(cx, cy)
                            clicked = True
                            _log(f"      [B4] 鼠标点击 hCaptcha checkbox ({cx:.0f},{cy:.0f})")
                            break
                except Exception as e:
                    _log(f"      [B4] 鼠标点击失败: {e}")
                if not clicked:
                    _log("      [B4] 回退到 JS 点击")
                    for frame in page.frames:
                        if "hcaptcha" not in frame.url:
                            continue
                        try:
                            frame.evaluate("document.querySelector('#checkbox')?.click()")
                            clicked = True
                            break
                        except Exception:
                            pass
                time.sleep(5)

                # 等待安全检查完成（最长 60 秒）
                _log("      [B4] 等待安全检查完成 ...")
                captcha_passed = False
                for wait_sec in range(25):
                    cur = page.url
                    # 检查是否跳转到 hermes/consent/2FA/pay
                    if any(kw in cur for kw in ["/webapps/hermes", "/pay/", "/pay?",
                                                 "/authflow", "checkoutweb",
                                                 "chatgpt.com", "pm-redirects"]):
                        captcha_passed = True
                        _log(f"      [B4] 安全检查通过! URL: {cur[:80]}")
                        break
                    # 检查是否还有 hcaptcha iframe（可能已消失）
                    if wait_sec > 10:
                        has_hc = any("hcaptcha" in f.url for f in page.frames)
                        if not has_hc and "signin" not in cur:
                            captcha_passed = True
                            _log(f"      [B4] hCaptcha iframe 已消失，检查通过")
                            break
                    if wait_sec == 15:
                        _safe_screenshot(page, "/tmp/paypal_b4_wait15.png")
                        _log(f"      [B4-diag] 15s: {cur[:80]}")
                    if wait_sec == 30:
                        _safe_screenshot(page, "/tmp/paypal_b4_wait30.png")
                        _log(f"      [B4-diag] 30s: {cur[:80]}")
                    time.sleep(1)

                if not captcha_passed:
                    # 可能触发了视觉挑战或仍在加载
                    _safe_screenshot(page, "/tmp/paypal_hcaptcha_timeout.png")
                    _log(f"      [B4] 60s 超时，URL: {page.url[:80]}")
                    _log("      [B4] 截图: /tmp/paypal_hcaptcha_timeout.png")
                    # 检查是否有视觉挑战
                    has_visual = page.query_selector('.task-image') or \
                                 page.query_selector('[class*="challenge"]')
                    if has_visual:
                        _log("      [B4] 检测到视觉挑战，尝试 VLM ...")
                        challenge_frame = None
                        for frame in page.frames:
                            if "hcaptcha" in frame.url:
                                challenge_frame = frame
                                break
                        if challenge_frame:
                            solved = _solve_hcaptcha_via_vlm(
                                page, challenge_frame,
                                vlm_base_url, vlm_api_key, vlm_model,
                            )
                            if solved:
                                captcha_passed = True
                    if not captcha_passed:
                        raise RuntimeError("PayPal hCaptcha 安全检查超时")

            # [B5] 处理 2FA（如果出现）
            if "/authflow" in page.url:
                _log(f"      [B5] 进入 2FA 流程: {page.url[:80]}")
                _safe_screenshot(page, "/tmp/paypal_2fa.png")
                time.sleep(3)

                # 确保 Remember this device 勾选（让 trusted device 保存到 profile）
                for sel in ['input[type="checkbox"]']:
                    cbs = page.query_selector_all(sel)
                    for cb in cbs:
                        try:
                            if cb.is_visible() and not cb.is_checked():
                                cb.check(force=True)
                                _log(f"      [B5] 勾选复选框 (Remember this device)")
                        except Exception:
                            pass

                # 点击 Next 触发 2FA（email 或 push）
                _log("      [B5] 点击 Next 触发 2FA ...")
                for sel in ['button:has-text("Next")', 'button:has-text("下一步")',
                            'button[type="submit"]', 'button[class*="primary"]']:
                    btn = page.query_selector(sel)
                    if btn and btn.is_visible():
                        btn.click()
                        _log(f"      [B5] 点击 Next: {sel}")
                        time.sleep(4)
                        break
                _safe_screenshot(page, "/tmp/paypal_2fa_after_next.png")

                # 根据 URL 判断走 email 还是 push
                cur_url = page.url
                is_email_flow = "/challenges/email" in cur_url
                is_push_flow = "/challenges/pn" in cur_url or "/challenges/push" in cur_url
                # 兼容：URL 还没变时，看页面是否有 OTP 输入框
                if not is_email_flow and not is_push_flow:
                    if page.query_selector('input[autocomplete="one-time-code"]') or \
                       page.query_selector('input[inputmode="numeric"]'):
                        is_email_flow = True
                _log(f"      [B5] 2FA 路径: email={is_email_flow} push={is_push_flow}")

                if is_push_flow:
                    _log("*" * 60)
                    _log("      [B5] ⚠️  请在手机 PayPal app 里点击确认")
                    _log("*" * 60)
                    confirmed = False
                    for _pm_wait in range(150):
                        time.sleep(2)
                        if "/authflow" not in page.url:
                            confirmed = True
                            _log(f"      [B5] ✅ 手机确认完成 → {page.url[:80]}")
                            break
                    if not confirmed:
                        _safe_screenshot(page, "/tmp/paypal_push_timeout.png")
                        raise RuntimeError("PayPal 手机推送 5 分钟未确认")
                else:
                    # 邮件 OTP 模式：等 IMAP 收码（3 分钟，PayPal 有时要 2 分钟才发）
                    _log("      [B5] 等待 PayPal 邮件 OTP (最长 180s) ...")
                    otp = _fetch_paypal_otp(paypal_cfg, timeout=180)
                    if not otp:
                        _log("      [B5] OTP 首次超时，重发 ...")
                        for sel in ['button:has-text("Resend")', 'button:has-text("重新发送")',
                                    'a:has-text("Resend")', 'button:has-text("Send again")']:
                            btn = page.query_selector(sel)
                            if btn and btn.is_visible():
                                btn.click()
                                _log(f"      [B5] 重发 OTP: {sel}")
                                break
                        time.sleep(3)
                        otp = _fetch_paypal_otp(paypal_cfg, timeout=120)
                    if not otp:
                        _safe_screenshot(page, "/tmp/paypal_2fa_timeout.png")
                        raise RuntimeError("PayPal 2FA 邮件 OTP 获取超时")
                    _log(f"      [B5] OTP: {otp}")
                    otp_filled = False
                    for sel in ['input[name="otpCode"]', 'input[autocomplete="one-time-code"]',
                                'input[inputmode="numeric"]', 'input[name="answer"]',
                                'input[type="tel"]',
                                'input[maxlength="6"]', 'input[class*="otp"]']:
                        otp_input = page.query_selector(sel)
                        if otp_input and otp_input.is_visible():
                            otp_input.fill(otp)
                            otp_filled = True
                            _log(f"      [B5] OTP 已填入: {sel}")
                            break
                    if not otp_filled:
                        digit_inputs = page.query_selector_all('input[maxlength="1"]')
                        if len(digit_inputs) >= 6:
                            for i, ch in enumerate(otp[:6]):
                                digit_inputs[i].fill(ch)
                            otp_filled = True
                            _log("      [B5] OTP 已逐位填入")
                    time.sleep(1)
                    for sel in ['button[type="submit"]', 'button:has-text("确认")',
                                'button:has-text("Confirm")', 'button:has-text("Continue")',
                                'button:has-text("Next")']:
                        btn = page.query_selector(sel)
                        if btn and btn.is_visible():
                            btn.click()
                            _log(f"      [B5] 点击确认 OTP: {sel}")
                            break
                    time.sleep(5)
                _log(f"      [B5] 2FA 完成，当前 URL: {page.url[:80]}")

            # [B6] 等待到达 consent 页面 / hermes
            _log("      [B6] 等待授权页面 ...")
            for wait_i in range(30):
                cur = page.url
                if "/webapps/hermes" in cur or "checkoutweb" in cur:
                    _log(f"      [B6] 到达授权页: {cur[:80]}")
                    break
                if "chatgpt.com" in cur or "pm-redirects" in cur:
                    _log(f"      [B6] 已完成: {cur[:80]}")
                    success = True
                    break
                # B6 原地转：check 是否卡在 DataDome 可见滑块
                if wait_i >= 5 and "/agreements/approve" in cur:
                    ddc_frame_now = any(("ddc" in (f.url or "") or
                                           "captcha" in (f.url or "") or
                                           "datadome" in (f.url or ""))
                                          for f in page.frames if f.url != cur)
                    if _slider_visible() or (wait_i >= 15 and ddc_frame_now):
                        _safe_screenshot(page, "/tmp/paypal_ddc_slider.png")
                        reason = "关键字匹配" if _slider_visible() else "agreements 原地转+DDC iframe"
                        _log(f"      [B6] 检到可见滑块 ({reason})，尝试 drag solver ...")
                        if _try_solve_ddc_slider(attempts=2):
                            _log("      [B6] drag solver 成功，继续等 hermes")
                            continue
                        _log("      [B6] drag solver 失败，发 marker 交给外层")
                        _log("CARD_DATADOME_SLIDER=1")
                        raise RuntimeError("DataDome 滑块 solver 失败")
                if wait_i == 15:
                    _safe_screenshot(page, "/tmp/paypal_b6_wait.png")
                    _log(f"      [B6-diag] 15s URL: {cur[:100]}")
                    _log(f"      [B6-diag] 截图: /tmp/paypal_b6_wait.png")
                time.sleep(1)

            if not success:
                # [B7] 到达 hermes 页面 — 提取参数，用纯 HTTP 完成 authorize + return
                _log("      [B7] 到达 hermes，提取授权参数 ...")
                hermes_html = page.content()
                hermes_url = page.url
                # 提取 cookies 供 HTTP 使用
                browser_cookies = ctx.cookies()
                http_finish = requests.Session()
                http_finish.headers.update({
                    "User-Agent": USER_AGENT,
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                })
                try:
                    http_finish.trust_env = False
                except Exception:
                    pass
                if proxy_url:
                    _apply_proxy_to_http_session(http_finish, proxy_url)
                for c in browser_cookies:
                    if "paypal.com" in c.get("domain", ""):
                        http_finish.cookies.set(
                            c["name"], c["value"],
                            domain=c.get("domain", ".paypal.com"),
                            path=c.get("path", "/"),
                        )
                _log(f"      [B7] 提取了 {len(browser_cookies)} 个 cookies")

                # 提取 fundingOptionId + EC token
                funding_m = re.search(r'"fundingOptionId"\s*:\s*"([^"]+)"', hermes_html)
                funding_id = funding_m.group(1) if funding_m else ""
                ec_token = ""
                m = re.search(r'(EC-[A-Z0-9]{17,})', hermes_html)
                if m:
                    ec_token = m.group(1)
                if not ec_token:
                    ec_token = urllib.parse.parse_qs(
                        urllib.parse.urlparse(hermes_url).query
                    ).get("token", [""])[0]
                ba_token_h = urllib.parse.parse_qs(
                    urllib.parse.urlparse(hermes_url).query
                ).get("ba_token", [""])[0]
                _log(f"      [B7] funding={funding_id} ec={ec_token} ba={ba_token_h}")

                if funding_id and ec_token:
                    # [B8] GraphQL authorize
                    _log("      [B8] GraphQL authorize ...")
                    gql = [{
                        "operationName": "authorize",
                        "variables": {
                            "billingAgreementId": ec_token,
                            "fundingPreference": {
                                "fundingOptionId": funding_id,
                                "balancePreference": "OPT_OUT",
                            },
                            "legalAgreements": {},
                        },
                        "query": (
                            "mutation authorize("
                            "$billingAgreementId: String!, $addressId: String, "
                            "$fundingPreference: billingFundingPreferenceInput, "
                            "$legalAgreements: billingLegalAgreementsInput"
                            ") { billing { authorize( "
                            "billingAgreementId: $billingAgreementId "
                            "addressId: $addressId "
                            "fundingPreference: $fundingPreference "
                            "legalAgreements: $legalAgreements "
                            ") { billingAgreementToken paymentAction "
                            "returnURL { href __typename } "
                            "buyer { userId __typename } __typename } __typename } }"
                        ),
                    }]
                    resp_gql = http_finish.post(
                        "https://www.paypal.com/graphql/", json=gql,
                        headers={
                            "Content-Type": "application/json",
                            "X-Requested-With": "fetch",
                            "X-App-Name": "checkoutuinodeweb",
                            "Origin": "https://www.paypal.com",
                            "Referer": hermes_url,
                        }, timeout=30,
                    )
                    _log(f"      [B8] GraphQL status={resp_gql.status_code}")
                    if resp_gql.status_code == 200:
                        try:
                            ret_url = resp_gql.json()[0]["data"]["billing"]["authorize"]["returnURL"]["href"]
                            _log(f"      [B8] returnURL: {ret_url[:200]}")
                            # 确保 returnURL 有完整参数
                            if "status=" not in ret_url:
                                sep = "&" if "?" in ret_url else "?"
                                ret_url += f"{sep}status=success"
                            if "ba_token=" not in ret_url and ba_token_h:
                                ret_url += f"&ba_token={ba_token_h}"
                            _log(f"      [B8] 完整 returnURL: {ret_url[:200]}")
                            # [B9] 用浏览器导航到 returnURL（保留完整 session 上下文）
                            _log("      [B9] 浏览器导航到 returnURL ...")
                            page.goto(ret_url, wait_until="domcontentloaded", timeout=30000)
                            _log(f"      [B9] 最终 URL: {page.url[:120]}")
                            for _ in range(15):
                                if "chatgpt.com" in page.url or "redirect_status=succeeded" in page.url:
                                    break
                                time.sleep(1)
                            _log(f"      [B9] Stripe 回调完成: {page.url[:120]}")
                            success = True
                        except Exception as e:
                            _log(f"      [B8] GraphQL 解析失败: {e}")
                            _log(f"      [B8] 响应: {resp_gql.text[:300]}")
                    else:
                        _log(f"      [B8] GraphQL 失败: {resp_gql.text[:300]}")
                else:
                    # 监听网络请求（捕获 pm-redirects return URL）
                    captured_return_url = []
                    def _on_request(request):
                        if "pm-redirects" in request.url and "/return/" in request.url:
                            captured_return_url.append(request.url)
                            _log(f"      [B-NET] 捕获 pm-redirects return: {request.url[:150]}")
                    page.on("request", _on_request)

                    _log("      [B7] 通过浏览器点击 consent 按钮 ...")
                    for sel in ['button#consentButton', 'button:has-text("Agree")',
                                'button:has-text("同意并继续")', 'button[type="submit"]']:
                        btn = page.query_selector(sel)
                        if btn and btn.is_visible():
                            btn.click()
                            _log(f"      [B7] 已点击: {sel}")
                            break
                    # 等待完整重定向链
                    _log("      [B8] 等待 PayPal → Stripe 重定向链 ...")
                    for wait_b8 in range(90):
                        cur = page.url
                        if "chatgpt.com" in cur or ("stripe.com" in cur and "redirect_status" in cur):
                            _log(f"      [B8] 完成: {cur[:120]}")
                            success = True
                            break
                        if wait_b8 == 30:
                            _log(f"      [B8-diag] 30s: {cur[:80]}")
                        time.sleep(1)
                    page.remove_listener("request", _on_request)
                    if captured_return_url:
                        _log(f"      [B8] 捕获到 {len(captured_return_url)} 个 pm-redirects 请求")
                    else:
                        _log("      [B8] 警告: 未捕获到 pm-redirects 请求")

        except Exception as e:
            _log(f"      [Browser] 异常: {e}")
            # 截图保存
            try:
                _safe_screenshot(page, "/tmp/paypal_browser_error.png")
                _log("      [Browser] 错误截图: /tmp/paypal_browser_error.png")
            except Exception:
                pass
            raise

        # 保存 PayPal cookies 供后续纯 HTTP 模式复用
        if success:
            try:
                all_cookies = ctx.cookies()
                pp_cookies = [c for c in all_cookies if "paypal.com" in (c.get("domain", ""))]
                if pp_cookies:
                    cookies_str = "; ".join(f"{c['name']}={c['value']}" for c in pp_cookies)
                    import json as _json_save, datetime as _dt_save
                    with open("/tmp/paypal_browser_cookies.json", "w") as _cf:
                        _json_save.dump({
                            "cookies_str": cookies_str,
                            "ts": _dt_save.datetime.now().isoformat(),
                            "email": paypal_email,
                        }, _cf)
                    _log(f"      [Browser] PayPal cookies 已保存 ({len(pp_cookies)} 个)")
            except Exception as e_save:
                _log(f"      [Browser] cookies 保存失败: {e_save}")

    # 持久化 profile 保留，下次运行复用（trusted device 生效）
    if success:
        _log("      [Browser] PayPal 浏览器授权成功!")
    return success


def _solve_hcaptcha_via_vlm(page, hcaptcha_frame, vlm_base_url, vlm_api_key, vlm_model, max_rounds=5):
    """在 Playwright 中使用 VLM 求解 hCaptcha 视觉挑战"""
    import base64
    for round_idx in range(max_rounds):
        _log(f"      [VLM-hCaptcha] 第 {round_idx + 1}/{max_rounds} 轮 ...")

        # 截图 hCaptcha 区域
        try:
            screenshot_bytes = hcaptcha_frame.locator("body").screenshot(timeout=10000)
        except Exception:
            screenshot_bytes = page.screenshot()
        b64_img = base64.b64encode(screenshot_bytes).decode()

        # 提取 prompt（挑战文字说明）
        prompt_text = ""
        try:
            prompt_el = hcaptcha_frame.query_selector(".prompt-text") or \
                        hcaptcha_frame.query_selector("[class*='prompt']")
            if prompt_el:
                prompt_text = prompt_el.inner_text()
        except Exception:
            pass
        _log(f"      [VLM-hCaptcha] prompt: {prompt_text[:60]}...")

        # 调用 VLM
        vlm_prompt = (
            f"This is a hCaptcha visual challenge screenshot. "
            f"The challenge says: '{prompt_text}'. "
            f"The image shows a 3x3 grid of tiles numbered 1-9 (left to right, top to bottom). "
            f"Which tiles match the challenge? Return ONLY a JSON: {{\"tiles\": [1, 3, 5]}} "
            f"where the numbers are the matching tile positions."
        )
        try:
            vlm_resp = requests.post(
                f"{vlm_base_url}/v1/chat/completions",
                json={
                    "model": vlm_model,
                    "messages": [{"role": "user", "content": [
                        {"type": "text", "text": vlm_prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64_img}"}},
                    ]}],
                    "max_tokens": 200,
                },
                headers={"Authorization": f"Bearer {vlm_api_key}"},
                timeout=45,
            )
            vlm_json = vlm_resp.json()
            if "error" in vlm_json:
                _log(f"      [VLM-hCaptcha] VLM 错误: {str(vlm_json['error'])[:200]}")
                continue
            if "choices" not in vlm_json:
                _log(f"      [VLM-hCaptcha] VLM 异常响应: {str(vlm_json)[:200]}")
                continue
            vlm_text = vlm_json["choices"][0]["message"]["content"]
            _log(f"      [VLM-hCaptcha] VLM 回复: {vlm_text[:100]}")

            # 解析 tiles
            m = re.search(r'\{[^}]*"tiles"\s*:\s*\[([0-9, ]+)\]', vlm_text)
            if m:
                tiles = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            else:
                # 兜底: 提取所有数字
                tiles = [int(x) for x in re.findall(r'\b([1-9])\b', vlm_text)]
            _log(f"      [VLM-hCaptcha] 选择 tiles: {tiles}")

            if not tiles:
                _log("      [VLM-hCaptcha] 无有效 tiles")
                continue

        except Exception as e:
            _log(f"      [VLM-hCaptcha] VLM 调用失败: {e}")
            continue

        # 点击对应的 tiles
        task_images = hcaptcha_frame.query_selector_all(".task-image") or \
                      hcaptcha_frame.query_selector_all("[class*='image']") or \
                      hcaptcha_frame.query_selector_all(".border-focus")
        _log(f"      [VLM-hCaptcha] 找到 {len(task_images)} 个 tile 元素")

        for tile_num in tiles:
            idx = tile_num - 1  # 1-based to 0-based
            if 0 <= idx < len(task_images):
                task_images[idx].click()
                time.sleep(random.uniform(0.3, 0.8))

        # 点击 verify/submit
        time.sleep(0.5)
        verify_btn = hcaptcha_frame.query_selector('button.verify-button') or \
                     hcaptcha_frame.query_selector('div.button-submit') or \
                     hcaptcha_frame.query_selector('[class*="submit"]')
        if verify_btn:
            verify_btn.click()
            _log("      [VLM-hCaptcha] 已点击验证按钮")

        time.sleep(3)

        # 检查是否通过
        still_has_captcha = False
        for frame in page.frames:
            if "hcaptcha" in frame.url:
                # 检查是否还有 challenge
                challenge = frame.query_selector(".challenge-container") or \
                            frame.query_selector("[class*='challenge']")
                if challenge and challenge.is_visible():
                    still_has_captcha = True
                break
        if not still_has_captcha:
            _log("      [VLM-hCaptcha] hCaptcha 已通过!")
            return True
        _log("      [VLM-hCaptcha] 未通过，重试 ...")

    return False


def _handle_paypal_redirect(
    redirect_url: str,
    paypal_cfg: dict,
    locale_profile: dict = None,
    ctx: dict = None,
) -> bool:
    """纯 HTTP 完成 PayPal 授权。
    支持两种路径：
      1. Cookied Login (ud-token) — 需要 paypal.cookies
      2. Full Login (邮箱→密码→hCaptcha→2FA) — 需要 email/password/imap
    """
    ctx = ctx or {}
    proxy_url = str(ctx.get("proxy_url") or "").strip()
    captcha_api_key = ctx.get("captcha_api_key", "")
    paypal_cookies_str = paypal_cfg.get("cookies", "")
    paypal_email = paypal_cfg.get("email", "")
    paypal_password = paypal_cfg.get("password", "")
    ud_return_url = ""

    # 尝试加载浏览器保存的 PayPal cookies
    if not paypal_cookies_str:
        try:
            import json as _json
            with open("/tmp/paypal_browser_cookies.json", "r") as _cf:
                saved = _json.load(_cf)
            saved_cookies = saved.get("cookies_str", "")
            if saved_cookies:
                paypal_cookies_str = saved_cookies
                _log(f"      [PayPal] 复用浏览器保存的 cookies ({saved.get('email', '?')})")
        except Exception:
            pass

    # ── 创建 HTTP session (curl_cffi Chrome 指纹) ──
    try:
        from curl_cffi.requests import Session as CffiSession
        http = CffiSession(impersonate="chrome136")
        _log("      [PayPal] 使用 curl_cffi (chrome136 TLS 指纹)")
    except ImportError:
        http = requests.Session()
        _log("      [PayPal] curl_cffi 不可用，使用 requests (TLS 指纹暴露风险)")
    http.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "sec-ch-ua": '"Chromium";v="146", "Google Chrome";v="146", "Not=A?Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
    })
    try:
        http.trust_env = False
    except Exception:
        pass
    if proxy_url:
        _apply_proxy_to_http_session(http, proxy_url)
    if paypal_cookies_str:
        for pair in paypal_cookies_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                http.cookies.set(k.strip(), v.strip(), domain=".paypal.com", path="/")

    # [1] 跟随 Stripe redirect → PayPal /agreements/approve
    # 默认跳过 hermes 纯 HTTP 路径——PayPal 对非浏览器 session 返回 genericError(DEFAULT)，
    # 实测 2026-04 近期所有 daemon 日志 hermes 100% 失败（55+ 次全 fallback），每次浪费 5-10s。
    # 如需保留旧路径作为逆向参考，设 SKIP_HERMES_FAST_PATH=0。
    if str(os.environ.get("SKIP_HERMES_FAST_PATH", "1")).lower() in ("1", "true", "yes", "on"):
        if paypal_email and paypal_password:
            _log("      [1] SKIP_HERMES_FAST_PATH=1，直接走浏览器模式")
            return _paypal_browser_authorize(
                redirect_url, paypal_cfg,
                captcha_api_key=captcha_api_key, proxy_url=proxy_url,
            )
    # 如果有有效 cookies，尝试纯 HTTP 路径；否则直接走浏览器（跳过必失败的 HTTP）
    if not paypal_cookies_str and paypal_email and paypal_password:
        _log("      [1] 无 PayPal cookies，直接走浏览器模式（跳过 HTTP）")
        return _paypal_browser_authorize(
            redirect_url, paypal_cfg,
            captcha_api_key=captcha_api_key, proxy_url=proxy_url,
        )
    _log("      [1] 跟随 Stripe redirect → PayPal ...")
    resp1 = http.get(redirect_url, allow_redirects=True, timeout=30)
    _log(f"      [1] 到达: {resp1.url[:120]}  status={resp1.status_code}")
    if resp1.status_code == 403:
        _log("      [1] 403 被拦截，走浏览器模式")
        return _paypal_browser_authorize(
            redirect_url, paypal_cfg,
            captcha_api_key=captcha_api_key, proxy_url=proxy_url,
        )
    html = resp1.text
    ba_token = urllib.parse.parse_qs(
        urllib.parse.urlparse(resp1.url).query
    ).get("ba_token", [""])[0]

    # 提取页面参数
    csrf = ""
    for pat in [r'name="_csrf"\s+value="([^"]+)"',
                r'"csrfNonce"\s*:\s*"([^"]+)"',
                r'"token"\s*:\s*"([^"]{20,})"']:
        m = re.search(pat, html)
        if m:
            csrf = m.group(1)
            break
    sid = ""
    for pat in [r'_sessionID.*?value="([^"]+)"', r'"_sessionID"\s*:\s*"([^"]+)"']:
        m = re.search(pat, html)
        if m:
            sid = m.group(1)
            break
    ctx_id = ""
    m = re.search(r'"ctxId"\s*:\s*"([^"]+)"', html)
    if m:
        ctx_id = m.group(1)
    flow_id = ctx_id
    m = re.search(r'"flowId"\s*:\s*"([^"]+)"', html)
    if m:
        flow_id = m.group(1)
    recaptcha_key = ""
    for rk_pat in [r'"fppAPIKey"\s*:\s*"([^"]+)"',
                   r'recaptcha[^"]*?key[^"]*?["\']\s*:\s*["\']([^"\']{20,})',
                   r'enterpriseKey["\']?\s*:\s*["\']([^"\']+)',
                   r'render/([A-Za-z0-9_-]{30,})\?']:
        m = re.search(rk_pat, html, re.I)
        if m:
            recaptcha_key = m.group(1)
            break
    _log(f"      [1] csrf={csrf[:20]}... ba_token={ba_token} reCAPTCHA_key={'yes' if recaptcha_key else 'no'}")

    # ── 判断登录状态 ──
    at_hermes = "/webapps/hermes" in resp1.url
    logged_in = at_hermes

    if not at_hermes and paypal_cookies_str:
        # 尝试 ud-token 快速登录
        _log("      [2-UD] 尝试 cookied login ...")
        ud_data = {
            "_csrf": csrf, "_sessionID": sid, "intent": "checkout",
            "ctxId": ctx_id, "flowId": flow_id,
            "returnUri": "/webapps/hermes", "locale.x": "zh_XC",
            "state": urllib.parse.urlparse(resp1.url).query,
            "fn_sync_data": "",
        }
        resp_ud = http.post(
            "https://www.paypal.com/signin/ud-token", data=ud_data,
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://www.paypal.com",
                "Referer": resp1.url,
            }, timeout=30,
        )
        _log(f"      [2-UD] ud-token status={resp_ud.status_code}")
        if resp_ud.status_code == 200:
            try:
                ud_json = resp_ud.json()
                if ud_json.get("returnUrl") or ud_json.get("email"):
                    logged_in = True
                    ud_return_url = ud_json.get("returnUrl", "")
                    _log(f"      [2-UD] cookied login 成功 (returnUrl={'yes' if ud_return_url else 'no'})")
            except Exception:
                pass
        if not logged_in:
            _log("      [2-UD] cookied login 失败，回退到完整登录")

    if not logged_in:
        if not paypal_email or not paypal_password:
            raise RuntimeError(
                "PayPal 授权需要: (1) 有效 cookies 或 (2) email + password"
            )
        try:
            _paypal_full_login(
                http, html, resp1.url, paypal_cfg, captcha_api_key,
                csrf, sid, flow_id, ctx_id, recaptcha_key,
            )
        except Exception as e:
            _log(f"      纯 HTTP 登录失败: {e}")
            _log("      回退到浏览器模式 ...")
            return _paypal_browser_authorize(
                redirect_url, paypal_cfg,
                captcha_api_key=captcha_api_key,
                proxy_url=proxy_url,
            )

    # ── [H] GET hermes ──
    # 优先使用 ud-token 返回的 URL（包含正确的 EC token）
    # 构造 hermes URL（必须包含 ba_token + EC token）
    hermes_url = (
        f"https://www.paypal.com/webapps/hermes"
        f"?flow=1-P&ulReturn=true&ba_token={ba_token}"
    )
    if flow_id:
        hermes_url += f"&token={flow_id}"
    # ud-token returnUrl 可能包含额外参数（如 ssrt/rcache）
    if ud_return_url:
        _log(f"      [H] ud-token returnUrl: {ud_return_url[:100]}")
        if "ba_token=" in ud_return_url and "token=" in ud_return_url:
            hermes_url = f"https://www.paypal.com{ud_return_url}" if ud_return_url.startswith("/") else ud_return_url
    if at_hermes:
        hermes_html = html
        hermes_final_url = resp1.url
        _log("      [H] 已在 hermes 页面")
    else:
        _log("      [H] GET hermes ...")
        resp_h = http.get(hermes_url, timeout=30)
        hermes_html = resp_h.text
        hermes_final_url = resp_h.url
        _log(f"      [H] hermes status={resp_h.status_code} url={resp_h.url[:80]}")

    # 提取 fundingOptionId + EC token
    funding_m = re.search(r'"fundingOptionId"\s*:\s*"([^"]+)"', hermes_html)
    funding_id = funding_m.group(1) if funding_m else ""
    ec_token = urllib.parse.parse_qs(
        urllib.parse.urlparse(hermes_final_url).query
    ).get("token", [""])[0]
    if not ec_token:
        m = re.search(r'(EC-[A-Z0-9]{17,})', hermes_html)
        ec_token = m.group(1) if m else ""
    _log(f"      [H] fundingOptionId={funding_id}  ec={ec_token}")

    if not funding_id or not ec_token:
        _title = re.search(r'<title>(.*?)</title>', hermes_html)
        title_text = _title.group(1) if _title else "N/A"
        _log(f"      [H] hermes title: {title_text}")
        # hermes 失败（genericError / 需要重新登录）→ 回退到浏览器
        if paypal_email and paypal_password:
            _log("      [H] hermes 失败，回退到浏览器模式 ...")
            return _paypal_browser_authorize(
                redirect_url, paypal_cfg,
                captcha_api_key=captcha_api_key, proxy_url=proxy_url,
            )
        raise RuntimeError(
            f"hermes 参数缺失 (可能需要登录): funding={funding_id} ec={ec_token}"
        )

    # ── [G] GraphQL authorize ──
    _log("      [G] graphql authorize ...")
    gql = [{
        "operationName": "authorize",
        "variables": {
            "billingAgreementId": ec_token,
            "fundingPreference": {
                "fundingOptionId": funding_id,
                "balancePreference": "OPT_OUT",
            },
            "legalAgreements": {},
        },
        "query": (
            "mutation authorize("
            "$billingAgreementId: String!, $addressId: String, "
            "$fundingPreference: billingFundingPreferenceInput, "
            "$legalAgreements: billingLegalAgreementsInput"
            ") { billing { authorize( "
            "billingAgreementId: $billingAgreementId "
            "addressId: $addressId "
            "fundingPreference: $fundingPreference "
            "legalAgreements: $legalAgreements "
            ") { billingAgreementToken paymentAction "
            "returnURL { href __typename } "
            "buyer { userId __typename } __typename } __typename } }"
        ),
    }]
    resp_gql = http.post(
        "https://www.paypal.com/graphql/", json=gql,
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "fetch",
            "X-App-Name": "checkoutuinodeweb",
            "Origin": "https://www.paypal.com",
            "Referer": hermes_final_url,
        }, timeout=30,
    )
    _log(f"      [G] graphql status={resp_gql.status_code}")
    if resp_gql.status_code != 200:
        raise RuntimeError(
            f"graphql 失败: {resp_gql.status_code} {resp_gql.text[:300]}"
        )
    try:
        ret_url = resp_gql.json()[0]["data"]["billing"]["authorize"]["returnURL"]["href"]
    except Exception:
        raise RuntimeError(f"graphql 响应异常: {resp_gql.text[:500]}")
    _log(f"      [G] return URL: {ret_url[:100]}")

    # ── [R] GET return URL → Stripe 完成 ──
    _log("      [R] 回调 Stripe ...")
    resp_ret = http.get(ret_url, allow_redirects=True, timeout=30)
    _log(f"      [R] 最终: {resp_ret.url[:100]}  status={resp_ret.status_code}")
    _log("      PayPal 授权成功!")
    return True



def _fetch_paypal_otp(paypal_cfg: dict, timeout: int = 90) -> str:
    """从 CF KV 取 PayPal 发送的 2FA OTP。

    前提：PayPal 账户绑定的邮箱（`paypal_cfg["email"]`）已迁移到 catch-all
    域名，PayPal 发的 OTP 邮件就会落进 otp-relay Worker 写到 KV。
    若仍是 IMAP 邮箱（QQ 等），KV 里取不到，会超时返回空串。
    """
    target = (paypal_cfg.get("email") or "").strip()
    if not target:
        _log("      [PayPal OTP] 缺 paypal.email 配置")
        return ""
    try:
        from cf_kv_otp_provider import CloudflareKVOtpProvider
    except ImportError as e:
        _log(f"      [PayPal OTP] cf_kv_otp_provider 不可用: {e}")
        return ""
    try:
        provider = CloudflareKVOtpProvider.from_env_or_secrets()
        otp = provider.wait_for_otp(target, timeout=timeout)
        _log(f"      [PayPal OTP] 收到 {otp} (key={target})")
        return otp
    except TimeoutError:
        _log(f"      [PayPal OTP] CF KV 等 OTP 超时 {timeout}s key={target}")
        return ""
    except Exception as e:
        _log(f"      [PayPal OTP] CF KV 取异常: {e}")
        return ""


def confirm_payment(
    session: requests.Session,
    pk: str,
    session_id: str,
    pm_id: str,
    card: dict | None,
    captcha_token: str,
    init_resp: dict,
    stripe_ver: str = STRIPE_VERSION_BASE,
    captcha_cfg: dict = None,
    captcha_ekey: str = "",
    ctx: dict = None,
    locale_profile: dict = None,
) -> dict:
    ctx = ctx or {}
    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    guid = ctx.get("guid") or _gen_fingerprint()[0]
    muid = ctx.get("muid") or _gen_fingerprint()[0]
    sid  = ctx.get("sid")  or _gen_fingerprint()[0]
    runtime_version = ctx.get("runtime_version") or DEFAULT_STRIPE_RUNTIME_VERSION
    locale_short = ctx.get("locale") or _locale_short(locale_profile)
    top_checkout_config_id = ctx.get("top_checkout_config_id") or ctx.get("config_id", "")
    elements_session_config_id = (
        ctx.get("elements_session_config_id")
        or str(uuid.uuid4())
    )
    confirm_mode = ctx.get("confirm_mode", "inline_payment_method_data")

    # 优先从 total_summary.due 获取金额（最准确）
    expected_amount = "0"
    total_summary = init_resp.get("total_summary", {})
    if total_summary.get("due") is not None:
        expected_amount = str(total_summary["due"])
    elif init_resp.get("invoice", {}).get("amount_due") is not None:
        expected_amount = str(init_resp["invoice"]["amount_due"])
    else:
        line_items = init_resp.get("line_items", [])
        if line_items:
            total = sum(item.get("amount", 0) for item in line_items)
            expected_amount = str(total)


    init_checksum = init_resp.get("init_checksum", "")
    stripe_js_id = ctx.get("stripe_js_id", str(uuid.uuid4()))
    elements_session_id = ctx.get("elements_session_id", _gen_elements_session_id())
    stripe_hosted_url = (
        ctx.get("stripe_hosted_url")
        or init_resp.get("stripe_hosted_url")
        or ""
    )
    success_return_url = (
        ctx.get("return_url")
        or init_resp.get("return_url")
        or init_resp.get("url")
        or ""
    )
    checkout_url = stripe_hosted_url or success_return_url
    if stripe_hosted_url and success_return_url:
        parsed_hosted = urllib.parse.urlsplit(stripe_hosted_url)
        hosted_query = urllib.parse.urlencode(
            [
                ("returned_from_redirect", "true"),
                ("ui_mode", "custom"),
                ("return_url", success_return_url),
            ]
        )
        checkout_url = urllib.parse.urlunsplit(
            (
                parsed_hosted.scheme,
                parsed_hosted.netloc,
                parsed_hosted.path,
                hosted_query,
                parsed_hosted.fragment,
            )
        )


    ver = STRIPE_VERSION_FULL

    data = {
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "expected_amount": expected_amount,
        "expected_payment_method_type": ctx.get("payment_method_type", "card"),
        "key": pk,
        "_stripe_version": ver,
  
        "init_checksum": init_checksum,
     
        "version": runtime_version,
      
        "return_url": checkout_url,
    
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": stripe_js_id,
        "elements_session_client[locale]": locale_short,
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_session_client[session_id]": elements_session_id,
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
  
        "client_attribution_metadata[client_session_id]": stripe_js_id,
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[checkout_config_id]": top_checkout_config_id,
        "client_attribution_metadata[elements_session_id]": elements_session_id,
        "client_attribution_metadata[elements_session_config_id]": elements_session_config_id,
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "custom",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
    }
    consent_behavior = ctx.get("include_terms_of_service_consent")
    if consent_behavior is None:
        consent_collection = init_resp.get("consent_collection", {}) or {}
        consent_behavior = consent_collection.get("terms_of_service") not in (None, "", "none")
    if consent_behavior:
        data["consent[terms_of_service]"] = "accepted"

    data.update(ctx.get("elements_options_client") or _elements_options_client_payload())

    if ctx.get("js_checksum"):
        data["js_checksum"] = ctx["js_checksum"]
    if ctx.get("rv_timestamp"):
        data["rv_timestamp"] = ctx["rv_timestamp"]

  
    if captcha_token:
        data["passive_captcha_token"] = captcha_token
    if captcha_ekey:
        data["passive_captcha_ekey"] = captcha_ekey

    if confirm_mode == "inline_payment_method_data":
        if not card:
            raise RuntimeError("inline confirm 模式缺少 card 数据")
        if not data.get("js_checksum") or not data.get("rv_timestamp"):
            raise RuntimeError("inline confirm 需要 runtime.js_checksum 与 runtime.rv_timestamp")
        data.update(_build_inline_payment_method_fields(card, session_id, ctx, runtime_version))
    else:
        if not pm_id:
            raise RuntimeError("shared_payment_method 模式缺少 payment_method")
        data["payment_method"] = pm_id
  

    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/confirm"
    _log("[5/6] 确认支付 (confirm) ...")
    _log_request("POST", url, data=data, tag="[5/6] confirm")
    resp = session.post(url, data=data, headers=_stripe_headers())
    _log_response(resp, tag="[5/6] confirm")
    if (
        resp.status_code == 400
        and "consent[terms_of_service]" not in data
        and "terms of service" in (resp.text or "").lower()
    ):
        _log("      confirm 提示需要接受 merchant terms of service，自动补 consent 后重试一次 ...")
        data["consent[terms_of_service]"] = "accepted"
        ctx["include_terms_of_service_consent"] = True
        _log_request("POST", url, data=data, tag="[5/6] confirm(retry_tos)")
        resp = session.post(url, data=data, headers=_stripe_headers())
        _log_response(resp, tag="[5/6] confirm(retry_tos)")
    if resp.status_code != 200:
        raise RuntimeError(f"confirm 失败 [{resp.status_code}]: {resp.text[:500]}")

    confirm_data = resp.json()

    # 从顶层、payment_intent 或 setup_intent 提取 next_action
    next_action = confirm_data.get("next_action")
    if not next_action:
        pi_obj = confirm_data.get("payment_intent")
        if pi_obj and isinstance(pi_obj, dict):
            next_action = pi_obj.get("next_action")
    if not next_action:
        seti = _find_setup_intent(confirm_data)
        if seti and isinstance(seti, dict):
            next_action = seti.get("next_action")

    if next_action and next_action.get("type") == "use_stripe_sdk":
        _log("      触发 3DS/challenge 验证，正在处理 ...")
        _handle_3ds(session, pk, confirm_data, captcha_token, stripe_ver, captcha_cfg,
                    locale_profile=locale_profile, ctx=ctx)

    return confirm_data


def _extract_terminal_payment_failure(intent_obj: dict, source_kind: str = "setup_intent") -> dict | None:
    """把 Stripe 已经明确给出的终态失败对象标准化，避免继续误判成“要重试/继续轮询”."""
    if not isinstance(intent_obj, dict):
        return None

    status = intent_obj.get("status", "")
    error = intent_obj.get("last_setup_error") or intent_obj.get("last_payment_error") or {}
    if status != "requires_payment_method" or not error:
        return None

    err_code = (error.get("code") or "").lower()
    err_msg = (error.get("message") or "").lower()
    if "captcha" in err_msg or "authentication_failure" in err_code:
        return None

    return {
        "state": "failed",
        "payment_object_status": status,
        "source_kind": source_kind,
        "error": error,
        source_kind: intent_obj,
    }


def _find_setup_intent(data: dict) -> dict | None:
    si = data.get("setup_intent")
    if si:
        return si
    pm_obj = data.get("payment_method_object")
    if pm_obj and isinstance(pm_obj, dict):
        return pm_obj.get("setup_intent")
    raw = json.dumps(data)
    m = re.search(r"seti_[A-Za-z0-9]+", raw)
    if m:
        return {"id": m.group(0)}
    return None


def _build_3ds_browser_payload(locale_profile: dict, ctx: dict) -> dict:
    return {
        "fingerprintAttempted": False,
        "fingerprintData": None,
        "challengeWindowSize": None,
        "threeDSCompInd": "Y",
        "browserJavaEnabled": False,
        "browserJavascriptEnabled": True,
        "browserLanguage": locale_profile.get("browser_language", "en-US"),
        "browserColorDepth": str(locale_profile.get("color_depth", 24)),
        "browserScreenHeight": str(locale_profile.get("screen_h", 1080)),
        "browserScreenWidth": str(locale_profile.get("screen_w", 1920)),
        "browserTZ": str(_browser_tz_offset(locale_profile)),
        "browserUserAgent": USER_AGENT,
    }


def _handle_3ds(
    session: requests.Session,
    pk: str,
    confirm_data: dict,
    captcha_token: str,
    stripe_ver: str = STRIPE_VERSION_BASE,
    captcha_cfg: dict = None,
    locale_profile: dict = None,
    ctx: dict = None,
):
    """处理 3DS2 认证流程 (模拟浏览器: captcha → verify_challenge → Apata指纹 → 3ds2/authenticate)"""
    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    ctx = ctx or {}
    browser_challenge_cfg = ctx.get("browser_challenge") or {}
    stage_proxy_cfg = ctx.get("stage_proxies") or {}
    raw = json.dumps(confirm_data)

    # 查找 setatt_ (直接在 confirm 响应中)
    source_match = re.search(r"(setatt_[A-Za-z0-9]+)", raw)
    source = source_match.group(1) if source_match else None
    _log(f"      3DS: setatt_ = {source}")

    # 查找 seti_ 和 client_secret
    seti_match = re.search(r"(seti_[A-Za-z0-9]+)", raw)
    seti_id = seti_match.group(1) if seti_match else None
    _log(f"      3DS: seti_id = {seti_id}")

    client_secret = None
    if seti_id:
        cs_match = re.search(rf"({re.escape(seti_id)}_secret_[A-Za-z0-9]+)", raw)
        if cs_match:
            client_secret = cs_match.group(1)
    _log(f"      3DS: client_secret = {client_secret[:40] + '...' if client_secret else None}")


    challenge_site_key = None
    challenge_rqdata = ""
    challenge_verify_url = None
    intent_id = None
    intent_client_secret = None

    # 优先从 payment_intent 提取 challenge 信息
    pi_obj = confirm_data.get("payment_intent")
    if pi_obj and isinstance(pi_obj, dict):
        intent_id = pi_obj.get("id")
        intent_client_secret = pi_obj.get("client_secret")
        na = pi_obj.get("next_action", {})
        sdk_info = na.get("use_stripe_sdk", {})
        stripe_js = sdk_info.get("stripe_js", {})
        if stripe_js.get("site_key"):
            challenge_site_key = stripe_js["site_key"]
            challenge_rqdata = stripe_js.get("rqdata", "")
            challenge_verify_url = stripe_js.get("verification_url", "")
            _log(f"      检测到 payment_intent confirmation challenge (site_key: {challenge_site_key[:20]}...)")

    # 如果 payment_intent 没有，再从 setup_intent 提取
    if not challenge_site_key:
        seti_obj = _find_setup_intent(confirm_data)
        if seti_obj and isinstance(seti_obj, dict):
            na = seti_obj.get("next_action", {})
            sdk_info = na.get("use_stripe_sdk", {})
            stripe_js = sdk_info.get("stripe_js", {})
            if stripe_js.get("site_key"):
                challenge_site_key = stripe_js["site_key"]
                challenge_rqdata = stripe_js.get("rqdata", "")
                challenge_verify_url = stripe_js.get("verification_url", "")
                _log(f"      检测到 setup_intent confirmation challenge (site_key: {challenge_site_key[:20]}...)")

    # 用于 verify_challenge 的 intent 标识（兼容 pi_ 和 seti_）
    if not intent_id:
        intent_id = seti_id
    if not intent_client_secret:
        intent_client_secret = client_secret

    merchant_id = (
        confirm_data.get("account_settings", {}).get("account_id")
        or ctx.get("merchant_account_id")
        or ""
    )
    effective_browser_challenge_cfg = dict(browser_challenge_cfg or {})
    verify_browser_proxy = _resolve_stage_proxy_cfg(stage_proxy_cfg, "verify_challenge_browser")
    if verify_browser_proxy is not _PROXY_OVERRIDE_SENTINEL:
        effective_browser_challenge_cfg["proxy_url"] = _build_proxy_url_from_cfg(verify_browser_proxy)

    if challenge_site_key and intent_id and intent_client_secret and (captcha_cfg or browser_challenge_cfg.get("enabled")):
        # 构建 verify_challenge URL
        if challenge_verify_url and challenge_verify_url.startswith("/"):
            actual_verify_url = f"{STRIPE_API}{challenge_verify_url}"
        elif intent_id.startswith("pi_"):
            actual_verify_url = f"{STRIPE_API}/v1/payment_intents/{intent_id}/verify_challenge"
        else:
            actual_verify_url = f"{STRIPE_API}/v1/setup_intents/{intent_id}/verify_challenge"

        challenge_hcaptcha_cfg = {
            "site_key": challenge_site_key,
            "rqdata": challenge_rqdata,
            "is_invisible": False,
            "website_url": _build_stripe_hcaptcha_url(invisible=False),
        }

        _log("      解 challenge captcha ...")
        browser_verify_result = None
        verify_form_base = {
            "client_secret": intent_client_secret,
            "captcha_vendor_name": "hcaptcha",
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        if browser_challenge_cfg.get("enabled"):
            effective_browser_challenge_cfg = dict(effective_browser_challenge_cfg or {})
            if not effective_browser_challenge_cfg.get("external_solver"):
                bundled_solver = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "hcaptcha_auto_solver.py",
                )
                python_candidates = [
                    str(os.environ.get("CTFML_PYTHON") or "").strip(),
                    "~/.venvs/ctfml/bin/python",
                    sys.executable,
                ]
                solver_python = next((p for p in python_candidates if p and os.path.exists(p)), sys.executable)
                auto_vlm_cfg = {
                    "enabled": True,
                    "model": "gpt-5.4",
                    "base_url": "https://YOUR_VLM_ENDPOINT/api",
                    "api_key": "",
                    "timeout_s": 45,
                }
                effective_browser_challenge_cfg["external_solver"] = {
                    "enabled": True,
                    "python": solver_python,
                    "script": bundled_solver,
                    "out_dir": "/tmp/hcaptcha_auto_solver_live",
                    "timeout_s": max(180, int(effective_browser_challenge_cfg.get("timeout_ms", 300000) / 1000)),
                    "headed": not bool(effective_browser_challenge_cfg.get("headless", False)),
                    "vlm": auto_vlm_cfg,
                }
            challenge_token, challenge_ekey, browser_verify_result = solve_stripe_hcaptcha_in_browser(
                challenge_hcaptcha_cfg,
                merchant_id=merchant_id,
                locale=locale_profile.get("browser_locale", "en-US"),
                browser_cfg=effective_browser_challenge_cfg,
                verify_url=actual_verify_url,
                verify_form_base=verify_form_base,
            )
        else:
            challenge_token, challenge_ekey = solve_hcaptcha(
                captcha_cfg,
                challenge_hcaptcha_cfg,
                max_retries=3,
                session=session,
            )

        _log(f"      {_describe_challenge_artifact('challenge_response_token', challenge_token)}")
        if challenge_ekey:
            _log(f"      {_describe_challenge_artifact('challenge_response_ekey', challenge_ekey)}")
        else:
            _log("      challenge_response_ekey: <empty>")
        _log(f"      verify_challenge ({intent_id[:30]}...) ...")
        verify_data = {
            **verify_form_base,
            "challenge_response_token": challenge_token,
        }
        if challenge_ekey:
            verify_data["challenge_response_ekey"] = challenge_ekey

        verify_status_code = 0
        verify_text = ""
        if browser_verify_result and int(browser_verify_result.get("status") or 0):
            verify_status_code = int(browser_verify_result.get("status") or 0)
            verify_text = str(browser_verify_result.get("text") or "")
            _log_request("POST", actual_verify_url, data=verify_data, tag="[5/6] verify_challenge(browser)")
            _log(f"      使用浏览器内 verify_challenge 响应，跳过 Python requests verify")
        else:
            _log_request("POST", actual_verify_url, data=verify_data, tag="[5/6] verify_challenge")
            with _http_session_stage_proxy(session, stage_proxy_cfg, "verify_challenge"):
                resp = session.post(actual_verify_url, data=verify_data, headers=_stripe_headers())
            _log_response(resp, tag="[5/6] verify_challenge")
            verify_status_code = resp.status_code
            verify_text = resp.text

        if verify_status_code != 200:
            err_text = verify_text[:300]
            _log(f"      verify_challenge 返回 {verify_status_code}: {err_text}")
            if "no valid challenge" in err_text.lower():
                raise ChallengeReconfirmRequired(
                    f"challenge 已失效 (Stripe 返回 {verify_status_code}), 需要重新 confirm 获取新的 challenge"
                )
            raise RuntimeError(f"verify_challenge 失败 [{verify_status_code}]: {err_text}")

        verify_result = (
            browser_verify_result.get("json")
            if browser_verify_result and isinstance(browser_verify_result.get("json"), dict)
            else json.loads(verify_text)
        )
        verify_status = verify_result.get("status", "unknown")
        _log(f"      verify_challenge 状态: {verify_status}")

        # 检测 captcha challenge 失败（payment_intent 用 last_payment_error，setup_intent 用 last_setup_error）
        payment_error = verify_result.get("last_payment_error", {})
        setup_error = verify_result.get("last_setup_error", {})
        error_to_check = payment_error if payment_error else setup_error
        if error_to_check:
            err_code = error_to_check.get("code", "")
            err_msg = error_to_check.get("message", "")
            err_decline = error_to_check.get("decline_code", "")
            _log(
                "      verify_challenge error: "
                f"code={err_code or '-'} decline_code={err_decline or '-'} msg={err_msg or '-'}"
            )
            if "captcha" in err_msg.lower() or "authentication_failure" in err_code:
                raise ChallengeReconfirmRequired(
                    f"challenge captcha 被 Stripe 拒绝: [{err_code}] {err_msg}"
                )

        source_kind = "payment_intent" if intent_id.startswith("pi_") else "setup_intent"
        terminal_failure = _extract_terminal_payment_failure(verify_result, source_kind=source_kind)
        if terminal_failure:
            ctx["terminal_result"] = terminal_failure
            err = terminal_failure.get("error", {})
            _log(
                "      verify_challenge 已落到终态失败: "
                f"[{err.get('code', '?')}] {err.get('decline_code', '')} {err.get('message', '')}".strip()
            )
            return

        if verify_status == "requires_payment_method":
            raise ChallengeReconfirmRequired(
                "verify_challenge 后 setup_intent 进入 requires_payment_method，需要重新 confirm 获取新的 challenge"
            )

        # verify 成功, 从响应中提取 setatt_
        verify_raw = json.dumps(verify_result)
        new_source = re.search(r"(setatt_[A-Za-z0-9]+)", verify_raw)
        if new_source:
            source = new_source.group(1)
            _log(f"      从 verify 响应中获取 setatt_: {source[:30]}...")

    elif seti_id and client_secret and not source:
        # 没有 challenge 但也没有 setatt_, 尝试原始 verify_challenge
        verify_url = f"{STRIPE_API}/v1/setup_intents/{seti_id}/verify_challenge"
        _log(f"      verify_challenge (seti: {seti_id[:30]}...) ...")
        verify_data = {
            "client_secret": client_secret,
            "challenge_response_token": captcha_token,
            "captcha_vendor_name": "hcaptcha",
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        if browser_challenge_cfg.get("enabled"):
            fallback_hcaptcha_cfg = {
                "site_key": challenge_site_key or HCAPTCHA_SITE_KEY_FALLBACK,
                "rqdata": challenge_rqdata,
                "is_invisible": False,
                "website_url": _build_stripe_hcaptcha_url(invisible=False),
            }
            challenge_token, challenge_ekey, _ = solve_stripe_hcaptcha_in_browser(
                fallback_hcaptcha_cfg,
                merchant_id=merchant_id,
                locale=locale_profile.get("browser_locale", "en-US"),
                browser_cfg=browser_challenge_cfg,
            )
            verify_data["challenge_response_token"] = challenge_token
            if challenge_ekey:
                verify_data["challenge_response_ekey"] = challenge_ekey
        elif captcha_cfg:
            fallback_hcaptcha_cfg = {
                "site_key": challenge_site_key or HCAPTCHA_SITE_KEY_FALLBACK,
                "rqdata": challenge_rqdata,
                "is_invisible": False,
                "website_url": _build_stripe_hcaptcha_url(invisible=False),
            }
            challenge_token, challenge_ekey = solve_hcaptcha(
                captcha_cfg,
                fallback_hcaptcha_cfg,
                max_retries=3,
                session=session,
            )
            verify_data["challenge_response_token"] = challenge_token
            if challenge_ekey:
                verify_data["challenge_response_ekey"] = challenge_ekey
        _log(f"      {_describe_challenge_artifact('challenge_response_token', verify_data.get('challenge_response_token', ''))}")
        if verify_data.get("challenge_response_ekey"):
            _log(f"      {_describe_challenge_artifact('challenge_response_ekey', verify_data['challenge_response_ekey'])}")
        else:
            _log("      challenge_response_ekey: <empty>")
        _log_request("POST", verify_url, data=verify_data, tag="[5/6] verify_challenge(fallback)")
        with _http_session_stage_proxy(session, stage_proxy_cfg, "verify_challenge"):
            resp = session.post(verify_url, data=verify_data, headers=_stripe_headers())
        _log_response(resp, tag="[5/6] verify_challenge(fallback)")
        if resp.status_code == 200:
            si_result = resp.json()
            _log(f"      verify_challenge 状态: {si_result.get('status', 'unknown')}")
            # 检测 captcha challenge 失败
            setup_error = si_result.get("last_setup_error", {})
            if setup_error:
                err_code = setup_error.get("code", "")
                err_msg = setup_error.get("message", "")
                err_decline = setup_error.get("decline_code", "")
                _log(
                    "      verify_challenge error: "
                    f"code={err_code or '-'} decline_code={err_decline or '-'} msg={err_msg or '-'}"
                )
                if "captcha" in err_msg.lower() or "authentication_failure" in err_code:
                    raise ChallengeReconfirmRequired(f"challenge captcha 被 Stripe 拒绝: [{err_code}] {err_msg}")
            verify_raw = json.dumps(si_result)
            new_source = re.search(r"(setatt_[A-Za-z0-9]+)", verify_raw)
            if new_source:
                source = new_source.group(1)
        else:
            _log(f"      verify_challenge 返回 {resp.status_code}: {resp.text[:300]}")
            if "no valid challenge" in resp.text.lower():
                raise ChallengeReconfirmRequired(
                    f"challenge 已失效 (Stripe 返回 {resp.status_code}), 需要重新 confirm 获取新的 challenge"
                )

    if source:
        auth_url = f"{STRIPE_API}/v1/3ds2/authenticate"
        _log(f"      3DS2 authenticate (source: {source[:30]}...) ...")
        auth_data = {
            "source": source,
            "browser": json.dumps(_build_3ds_browser_payload(locale_profile, ctx)),
            "one_click_authn_device_support[hosted]": "false",
            "one_click_authn_device_support[same_origin_frame]": "false",
            "one_click_authn_device_support[spc_eligible]": "true",
            "one_click_authn_device_support[webauthn_eligible]": "true",
            "one_click_authn_device_support[publickey_credentials_get_allowed]": "true",
            "frontend_execution": ctx.get("frontend_execution", DEFAULT_FRONTEND_EXECUTION),
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        _log_request("POST", auth_url, data=auth_data, tag="[5/6] 3ds2/authenticate")
        with _http_session_stage_proxy(session, stage_proxy_cfg, "three_ds_authenticate"):
            resp = session.post(auth_url, data=auth_data, headers=_stripe_headers())
        _log_response(resp, tag="[5/6] 3ds2/authenticate")
        if resp.status_code == 200:
            result = resp.json()
            state = result.get("state", "unknown")
            trans_status = result.get("ares", {}).get("transStatus", "?")
            _log(f"      3DS2 结果: state={state}, transStatus={trans_status}")
            ctx["three_ds_result"] = {
                "state": state,
                "trans_status": trans_status,
                "source": result.get("source") or source,
                "acs_url": result.get("ares", {}).get("acsURL"),
                "creq": result.get("creq"),
                "three_ds_server_trans_id": result.get("ares", {}).get("threeDSServerTransID"),
            }
            if state == "challenge_required":
                _log("      3DS2 进入 challenge_required；这不是废卡，后续需要浏览器侧完成 challenge。")
                return
        else:
            _log(f"      3DS2 authenticate 返回 {resp.status_code}: {resp.text[:200]}")
    else:
        _log("      ⚠ 没有 setatt_ source, 跳过 3DS2 authenticate")
        raise RuntimeError("3DS 验证失败: 未获取到 setatt_ source, 无法完成认证")

  
    if seti_id and client_secret:
        time.sleep(3)
        poll_url = f"{STRIPE_API}/v1/setup_intents/{seti_id}"
        poll_params = {
            "client_secret": client_secret,
            "is_stripe_sdk": "false",
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        _log(f"      查询 setup_intent 最终状态 ...")
        _log_request("GET", poll_url, params=poll_params, tag="[5/6] setup_intent状态")
        with _http_session_stage_proxy(session, stage_proxy_cfg, "setup_intent_poll"):
            poll_resp = session.get(poll_url, params=poll_params, headers=_stripe_headers())
        _log_response(poll_resp, tag="[5/6] setup_intent状态")
        if poll_resp.status_code == 200:
            si_data = poll_resp.json()
            si_status = si_data.get("status", "unknown")
            _log(f"      setup_intent 状态: {si_status}")
            terminal_failure = _extract_terminal_payment_failure(si_data, source_kind="setup_intent")
            if terminal_failure:
                ctx["terminal_result"] = terminal_failure
                err = terminal_failure.get("error", {})
                _log(
                    "      setup_intent 已落到终态失败: "
                    f"[{err.get('code', '?')}] {err.get('decline_code', '')} {err.get('message', '')}".strip()
                )
        else:
            _log("      ⚠ 无 seti_id / client_secret, 跳过 setup_intent 查询")


def poll_result(session: requests.Session, pk: str, session_id: str, stripe_ver: str = STRIPE_VERSION_BASE) -> dict:
    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/poll"
    params = {
        "key": pk,
        "_stripe_version": stripe_ver,
    }

    _log("[6/6] 轮询支付结果 ...")
    for attempt in range(30):
        time.sleep(2)
        _log_request("GET", url, params=params, tag=f"[6/6] poll({attempt+1}/30)")
        resp = session.get(url, params=params, headers=_stripe_headers())
        _log_response(resp, tag=f"[6/6] poll({attempt+1}/30)")
        if resp.status_code != 200:
            _log(f"      poll 返回 {resp.status_code}, 重试 ...")
            continue

        data = resp.json()
        state = data.get("state", "unknown")
        payment_status = data.get("payment_object_status", "unknown")

        if state == "succeeded":
            return_url = data.get("return_url", "")
            _log(f"\n{'='*60}")
            _log(f"  支付成功!")
            _log(f"  state:          {state}")
            _log(f"  payment_status: {payment_status}")
            _log(f"  mode:           {data.get('mode', '?')}")
            _log(f"  return_url:     {return_url}")
            _log(f"{'='*60}\n")
            return data

        if state in ("failed", "expired", "canceled"):
            _log(f"\n  支付失败: state={state}")
            _log_raw(f"  完整 poll 响应: {json.dumps(data, ensure_ascii=False, indent=4)}")
            return data

        _log(f"      state={state}, payment_status={payment_status} ({attempt + 1}/30)")

    raise TimeoutError("轮询超时 (60s)")



def _record_result(
    status: str,
    chatgpt_email: str = "",
    session_id: str = "",
    payment_channel: str = "card",
    processor_entity: str = "",
    config_path: str = "",
    error_msg: str = "",
    extra: dict = None,
):
    """把支付结果写入 SQLite 运行时数据库。"""
    record = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "chatgpt_email": chatgpt_email,
        "session_id": session_id,
        "channel": payment_channel,
        "entity": processor_entity,
        "config": os.path.basename(config_path) if config_path else "",
    }
    if error_msg:
        record["error"] = error_msg[:200]
    if extra:
        # 只保留 refresh_token 和 team_account_id，不落盘 access_token/session_token
        allowed = {"refresh_token", "team_account_id"}
        for k, v in extra.items():
            if k in allowed and v:
                record[k] = v
    try:
        get_db().add_card_result(record)
    except Exception:
        pass


def load_config(path: str) -> dict:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = []

    def _add_candidate(candidate: str):
        if candidate and candidate not in candidates:
            candidates.append(candidate)

    _add_candidate(path)
    if not os.path.isabs(path):
        _add_candidate(os.path.join(script_dir, path))
    _add_candidate(os.path.join(script_dir, "config.auto.json"))

    for candidate in candidates:
        if os.path.exists(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            cfg["_loaded_from"] = candidate
            # 同步打码平台 base URL 到 module-level，让 helper 函数能拿到
            global _REMOTE_CAPTCHA_BASE_URL
            _REMOTE_CAPTCHA_BASE_URL = (
                (cfg.get("captcha", {}) or {}).get("api_url") or ""
            ).rstrip("/")
            return cfg

    raise FileNotFoundError(
        f"未找到配置文件。已尝试: {', '.join(candidates)}"
    )


def _resolve_config_relative_path(cfg: dict, path_value: str, default_value: str = "") -> str:
    candidate = str(path_value or default_value or "").strip()
    if not candidate:
        return ""
    if os.path.isabs(candidate):
        return candidate

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dirs = []
    loaded_from = str(cfg.get("_loaded_from") or "").strip()
    if loaded_from:
        base_dirs.append(os.path.dirname(os.path.abspath(loaded_from)))
    base_dirs.append(script_dir)
    base_dirs.append(os.path.dirname(script_dir))

    seen = set()
    for base_dir in base_dirs:
        if not base_dir or base_dir in seen:
            continue
        seen.add(base_dir)
        resolved = os.path.abspath(os.path.join(base_dir, candidate))
        if os.path.exists(resolved):
            return resolved

    first_base = base_dirs[0] if base_dirs else script_dir
    return os.path.abspath(os.path.join(first_base, candidate))


def _normalize_terminal_result(payload: dict | None) -> dict:
    data = json.loads(json.dumps(payload or {}))
    data.setdefault("source_kind", "setup_intent")
    data.setdefault("payment_object_status", "requires_payment_method")
    err = data.setdefault("error", {})
    err.setdefault("code", "card_declined")
    err.setdefault("decline_code", "generic_decline")
    err.setdefault("message", "Your card was declined.")
    return data


def _build_offline_terminal_result(offline_cfg: dict) -> dict:
    explicit = offline_cfg.get("terminal_result")
    if explicit:
        return _normalize_terminal_result(explicit)

    scenario = str(offline_cfg.get("scenario") or "3ds_succeeded_card_declined").strip().lower()
    if scenario == "challenge_failed":
        return _normalize_terminal_result(
            {
                "source_kind": "setup_intent",
                "payment_object_status": "requires_payment_method",
                "error": {
                    "code": "setup_intent_authentication_failure",
                    "decline_code": "",
                    "message": "Captcha challenge failed. Try again with a different payment method.",
                },
            }
        )
    if scenario in {"no_3ds_card_declined", "direct_decline"}:
        return _normalize_terminal_result(
            {
                "source_kind": "payment_intent",
                "payment_object_status": "requires_payment_method",
                "error": {
                    "code": "card_declined",
                    "decline_code": "generic_decline",
                    "message": "Your card was declined.",
                },
            }
        )

    return _normalize_terminal_result(
        {
            "source_kind": "setup_intent",
            "payment_object_status": "requires_payment_method",
            "error": {
                "code": "card_declined",
                "decline_code": "generic_decline",
                "message": "Your card was declined.",
            },
        }
    )


def _build_offline_fresh_checkout_info(cfg: dict) -> dict:
    fresh_cfg = cfg.get("fresh_checkout") or {}
    offline_cfg = cfg.get("offline_replay") or {}
    flows_path = _resolve_config_relative_path(
        cfg,
        offline_cfg.get("flows_path") or fresh_cfg.get("flows_path"),
        "../flows",
    )
    bootstrap = _load_fresh_checkout_bootstrap(flows_path)
    body = _build_fresh_checkout_body(fresh_cfg, bootstrap)
    checkout_resp = bootstrap.get("checkout_response") or {}
    checkout_session_id, processor_entity, checkout_url = _extract_checkout_identifiers(checkout_resp)
    if not checkout_url and checkout_session_id and processor_entity:
        checkout_url = f"https://chatgpt.com/checkout/{processor_entity}/{checkout_session_id}"
    if not checkout_url:
        raise FreshCheckoutAuthError("离线回放未能从 flows 还原 checkout_url")

    return {
        "url": checkout_url,
        "session_id": checkout_session_id,
        "processor_entity": processor_entity,
        "body": body,
        "bootstrap": bootstrap,
    }


def _run_offline_replay(
    checkout_input: str,
    *,
    cfg: dict,
    card: dict,
    locale_profile: dict,
    force_fresh: bool = False,
    fresh_only: bool = False,
):
    offline_cfg = cfg.get("offline_replay") or {}
    scenario = str(offline_cfg.get("scenario") or "3ds_succeeded_card_declined").strip().lower()
    _log("      [offline] 已启用离线回放模式：仅使用本地 flows / fixture，不发起外部网络请求")

    effective_checkout_input = checkout_input
    fresh_info = None
    if _should_generate_fresh_checkout(checkout_input, force_fresh):
        fresh_info = _build_offline_fresh_checkout_info(cfg)
        effective_checkout_input = fresh_info["url"]

        body = fresh_info.get("body") or {}
        team_plan_data = body.get("team_plan_data") or {}
        billing_details = body.get("billing_details") or {}
        promo_campaign = body.get("promo_campaign") or {}
        _log("[fresh/offline] 从本地 flows 重建 checkout 创建参数 ...")
        _log(
            "      request: "
            f"plan_name={body.get('plan_name') or '?'} "
            f"workspace_name={team_plan_data.get('workspace_name') or '?'} "
            f"seat_quantity={team_plan_data.get('seat_quantity') or '?'} "
            f"country={billing_details.get('country') or '?'} "
            f"currency={billing_details.get('currency') or '?'} "
            f"promo={promo_campaign.get('promo_campaign_id') or ''} "
            f"checkout_ui_mode={body.get('checkout_ui_mode') or '?'}"
        )
        _log(f"      fresh checkout: {fresh_info['url']}")
        if fresh_only:
            _log(f"\n日志已保存到: {LOG_FILE}")
            print(fresh_info["url"])
            return fresh_info

    _log("[1/6] 解析 checkout session ID ...")
    session_id, stripe_checkout_url = parse_checkout_url(effective_checkout_input)
    _log(f"      session_id: {session_id}")
    if "chatgpt.com" in effective_checkout_input:
        _log("      输入格式: ChatGPT 嵌入式链接 → 转换为 Stripe URL")
    elif _should_generate_fresh_checkout(checkout_input, force_fresh):
        _log("      输入格式: fresh/auto → 已从本地 flows 重建 checkout")
    _log(f"      stripe_url: {stripe_checkout_url}")

    _log("[2/6] 初始化结账会话 (offline replay) ...")
    _log("      [offline] 跳过指纹、elements、Link、地址上报与遥测请求")
    _log(
        "      [offline] 使用卡: "
        f"****{card['number'][-4:]}  ({card['name']})  "
        f"locale={locale_profile.get('browser_locale', 'en-US')}"
    )

    trace_steps: list[dict] = []

    def _trace(step: str, **extra):
        trace_steps.append(
            {
                "step": step,
                "ts": int(time.time()),
                **extra,
            }
        )

    if scenario in {"challenge_failed", "challenge_pass_then_decline", "3ds_succeeded_card_declined"}:
        _log("[3/6] 进入 challenge/3DS 离线回放链路 ...")
        _trace("confirm", phase="challenge_entry")
        _log("[5/6] 确认支付 (offline replay) ...")
        _log("      触发 3DS/challenge 验证，正在处理 ...")
        _trace("challenge_detected", source_kind="setup_intent")
        if scenario == "challenge_failed":
            _log("      [offline] 模拟浏览器 challenge 结果: network_checkcaptcha(pass=true)=false")
            _log("      verify_challenge 状态: requires_payment_method")
            _log(
                "      challenge captcha 被 Stripe 拒绝: "
                "[setup_intent_authentication_failure] "
                "Captcha challenge failed. Try again with a different payment method."
            )
            _trace(
                "verify_challenge",
                status="requires_payment_method",
                error_code="setup_intent_authentication_failure",
            )
        else:
            _log("      [offline] 模拟浏览器 challenge 结果: network_checkcaptcha(pass=true)")
            _log("      verify_challenge 状态: requires_action")
            _log("      3DS2 authenticate (offline replay) ...")
            _log("      3DS2 结果: state=succeeded, transStatus=Y")
            _log("      查询 setup_intent 最终状态 ...")
            _log("      setup_intent 状态: requires_payment_method")
            _trace("network_checkcaptcha", pass_result=True)
            _trace("verify_challenge", status="requires_action")
            _trace("3ds2_authenticate", state="succeeded", trans_status="Y")
            _trace("setup_intent_terminal", status="requires_payment_method")
    elif scenario in {"no_3ds_card_declined", "direct_decline"}:
        _log("[3/6] 进入非 3DS 离线回放链路 ...")
        _trace("confirm", phase="direct_decline")
        _log("[5/6] 确认支付 (offline replay) ...")
        _log("      [offline] 未触发 3DS/challenge，直接进入支付终态")
        _trace("terminal_without_3ds", status="requires_payment_method")
    else:
        _log(f"[3/6] 未知 offline scenario={scenario!r}，回退到 challenge_pass_then_decline")
        _trace("scenario_fallback", scenario=scenario, fallback="challenge_pass_then_decline")
        _log("[5/6] 确认支付 (offline replay) ...")
        _log("      触发 3DS/challenge 验证，正在处理 ...")
        _log("      [offline] 模拟浏览器 challenge 结果: network_checkcaptcha(pass=true)")
        _log("      verify_challenge 状态: requires_action")
        _log("      3DS2 authenticate (offline replay) ...")
        _log("      3DS2 结果: state=succeeded, transStatus=Y")
        _log("      查询 setup_intent 最终状态 ...")
        _log("      setup_intent 状态: requires_payment_method")
        _trace("network_checkcaptcha", pass_result=True)
        _trace("verify_challenge", status="requires_action")
        _trace("3ds2_authenticate", state="succeeded", trans_status="Y")
        _trace("setup_intent_terminal", status="requires_payment_method")

    terminal_result = _build_offline_terminal_result(offline_cfg)
    err = terminal_result.get("error", {})
    if scenario not in {"challenge_failed"}:
        _log(
            "      setup_intent 已落到终态失败: "
            f"[{err.get('code', '?')}] {err.get('decline_code', '')} {err.get('message', '')}".rstrip()
        )
    artifact_path = (
        _resolve_config_relative_path(
            cfg,
            offline_cfg.get("artifact_path"),
            "/tmp/ctf_offline_replay_latest.json",
        )
        if offline_cfg.get("artifact_path", "/tmp/ctf_offline_replay_latest.json")
        else ""
    )
    if artifact_path:
        try:
            artifact = {
                "scenario": scenario,
                "checkout_input": effective_checkout_input,
                "trace_steps": trace_steps,
                "terminal_result": terminal_result,
            }
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump(artifact, f, ensure_ascii=False, indent=2)
            _log(f"      [offline] 回放工件已写入: {artifact_path}")
        except Exception as e:
            _log(f"      [offline] 回放工件写入失败，忽略: {e}")

    _log(f"\n{'='*60}")
    _log("  支付已落到终态失败")
    _log(f"  source_kind:     {terminal_result.get('source_kind', '?')}")
    _log(f"  payment_status:  {terminal_result.get('payment_object_status', '?')}")
    _log(f"  code:            {err.get('code', '?')}")
    _log(f"  decline_code:    {err.get('decline_code', '?')}")
    _log(f"  message:         {err.get('message', '')}")
    _log(f"{'='*60}\n")
    _log(f"\n日志已保存到: {LOG_FILE}")
    return terminal_result


def _run_local_mock_gateway(
    checkout_input: str,
    *,
    cfg: dict,
    card: dict,
    locale_profile: dict,
    force_fresh: bool = False,
    fresh_only: bool = False,
):
    from local_mock_gateway import LocalMockGateway

    mock_cfg = cfg.get("local_mock") or {}
    scenario = str(
        mock_cfg.get("scenario")
        or (cfg.get("offline_replay") or {}).get("scenario")
        or "challenge_pass_then_decline"
    ).strip().lower()
    terminal_result = _build_offline_terminal_result(
        {
            "scenario": scenario,
            "terminal_result": mock_cfg.get("terminal_result"),
        }
    )
    amount_due = int(
        mock_cfg.get("due")
        if mock_cfg.get("due") is not None
        else ((cfg.get("fresh_checkout") or {}).get("expected_due") or 0)
    )

    effective_checkout_input = checkout_input
    fresh_info = None
    if _should_generate_fresh_checkout(checkout_input, force_fresh):
        fresh_info = _build_offline_fresh_checkout_info(cfg)
        effective_checkout_input = fresh_info["url"]

    session_id = ""
    processor_entity = "openai_llc"
    if effective_checkout_input and not _should_generate_fresh_checkout(checkout_input, force_fresh):
        session_id, _ = parse_checkout_url(effective_checkout_input)
    elif fresh_info:
        session_id = fresh_info.get("session_id") or ""
        processor_entity = fresh_info.get("processor_entity") or "openai_llc"

    artifact_path = _resolve_config_relative_path(
        cfg,
        mock_cfg.get("artifact_path"),
        "/tmp/ctf_local_mock_latest.json",
    )

    gateway = LocalMockGateway(
        scenario=scenario,
        terminal_result=terminal_result,
        checkout_url=effective_checkout_input if effective_checkout_input and "chatgpt.com/checkout/" in effective_checkout_input else "",
        checkout_session_id=session_id,
        processor_entity=processor_entity,
        due=amount_due,
    )
    base_url = gateway.start()

    def _request_json(method: str, path: str, payload: dict | None = None, tag: str = "") -> dict:
        url = urllib.parse.urljoin(base_url + "/", path.lstrip("/"))
        _log_request(method, url, data=payload, tag=tag)
        if method.upper() == "GET":
            resp = requests.get(url, timeout=10)
        else:
            resp = requests.post(url, json=payload or {}, timeout=10)
        _log_response(resp, tag=tag)
        resp.raise_for_status()
        return resp.json()

    try:
        _log("      [local-mock] 已启用本地 HTTP mock gateway：所有请求仅发往 127.0.0.1")
        _log(f"      [local-mock] gateway: {base_url}  scenario={scenario}")

        if fresh_info is None:
            _log("[0/6] 向本地 mock 生成 fresh checkout ...")
            body = _build_fresh_checkout_body(cfg.get("fresh_checkout") or {}, {"checkout_response": {}})
            fresh_info = {
                "body": body,
            }

        checkout_body = fresh_info.get("body") or {}
        checkout_resp = _request_json(
            "POST",
            "/backend-api/payments/checkout",
            payload=checkout_body,
            tag="local-mock fresh_checkout",
        )
        effective_checkout_input = (checkout_resp.get("checkout_url") or "").strip() or effective_checkout_input
        if not effective_checkout_input:
            raise RuntimeError("local mock 未返回 checkout_url")

        if fresh_only:
            _log(f"      [local-mock] fresh checkout: {effective_checkout_input}")
            print(effective_checkout_input)
            return checkout_resp

        _log("[1/6] 解析 checkout session ID ...")
        session_id, stripe_checkout_url = parse_checkout_url(effective_checkout_input)
        _log(f"      session_id: {session_id}")
        _log("      输入格式: local mock fresh checkout")
        _log(f"      stripe_url: {stripe_checkout_url}")

        _log("[2/6] 初始化结账会话 (local mock) ...")
        init_data = _request_json(
            "GET",
            f"/v1/checkout/sessions/{session_id}/init",
            tag="local-mock init",
        )
        total_summary = init_data.get("total_summary") or {}
        _log(
            "      商户: "
            f"{init_data.get('merchant', '?')}  |  模式: {init_data.get('mode', '?')}  |  due={total_summary.get('due', '?')}"
        )
        _log(
            "      [local-mock] 使用卡: "
            f"****{card['number'][-4:]}  ({card['name']})  locale={locale_profile.get('browser_locale', 'en-US')}"
        )

        _log("[3/6] 提交 confirm 到本地 mock ...")
        confirm_payload = {
            "payment_method_data": {
                "type": "card",
                "billing_details": {
                    "name": card.get("name") or "",
                    "email": card.get("email") or "",
                    "address": card.get("address") or {},
                },
                "card": {
                    "last4": str(card.get("number") or "")[-4:],
                    "exp_month": card.get("exp_month"),
                    "exp_year": card.get("exp_year"),
                },
            }
        }
        seti_id = gateway.seti_id
        confirm_resp = _request_json(
            "POST",
            f"/v1/setup_intents/{seti_id}/confirm",
            payload=confirm_payload,
            tag="local-mock confirm",
        )

        if scenario in {"no_3ds_card_declined", "direct_decline"}:
            _log("[5/6] 未触发 3DS/challenge，直接进入终态 ...")
        else:
            _log("[5/6] 触发 challenge，提交 verify_challenge 到本地 mock ...")
            next_action = confirm_resp.get("next_action") or {}
            captcha_action = next_action.get("captcha_challenge") or {}
            _log(
                "      challenge: "
                f"site_key={captcha_action.get('site_key', '?')} "
                f"ekey={captcha_action.get('ekey', '?')}"
            )
            verify_resp = _request_json(
                "POST",
                f"/v1/setup_intents/{seti_id}/verify_challenge",
                payload={
                    "client_secret": gateway.client_secret,
                    "challenge_response_token": "mock-solved-token",
                    "challenge_response_ekey": captcha_action.get("ekey") or "",
                },
                tag="local-mock verify_challenge",
            )
            verify_status = verify_resp.get("status") or "?"
            _log(f"      verify_challenge 状态: {verify_status}")
            if verify_status == "requires_action":
                auth_resp = _request_json(
                    "POST",
                    "/v1/3ds2/authenticate",
                    payload={
                        "source": ((verify_resp.get("next_action") or {}).get("use_stripe_sdk") or {}).get("source") or gateway.source_id,
                        "browser": {"locale": locale_profile.get("browser_locale", "en-US")},
                    },
                    tag="local-mock 3ds2_authenticate",
                )
                _log(
                    "      3DS2 结果: "
                    f"state={auth_resp.get('state', '?')}, transStatus={((auth_resp.get('ares') or {}).get('transStatus') or '?')}"
                )
                setup_intent_resp = _request_json(
                    "GET",
                    f"/v1/setup_intents/{seti_id}",
                    tag="local-mock setup_intent retrieve",
                )
                _log(f"      setup_intent 状态: {setup_intent_resp.get('status', '?')}")
            else:
                last_setup_error = verify_resp.get("last_setup_error") or {}
                _log(
                    "      challenge 被拒绝: "
                    f"[{last_setup_error.get('code', '?')}] {last_setup_error.get('message', '')}"
                )

        poll_resp = _request_json(
            "GET",
            f"/v1/checkout/sessions/{session_id}/poll",
            tag="local-mock poll",
        )
        terminal_result = _normalize_terminal_result(poll_resp.get("terminal_result") or {})
        err = terminal_result.get("error", {})

        if artifact_path:
            try:
                artifact = {
                    "scenario": scenario,
                    "checkout_input": effective_checkout_input,
                    "gateway_state": gateway.export_state(),
                    "poll_response": poll_resp,
                    "terminal_result": terminal_result,
                }
                with open(artifact_path, "w", encoding="utf-8") as f:
                    json.dump(artifact, f, ensure_ascii=False, indent=2)
                _log(f"      [local-mock] 回放工件已写入: {artifact_path}")
            except Exception as e:
                _log(f"      [local-mock] 回放工件写入失败，忽略: {e}")

        _log(f"\n{'='*60}")
        _log("  支付已落到终态失败")
        _log(f"  source_kind:     {terminal_result.get('source_kind', '?')}")
        _log(f"  payment_status:  {terminal_result.get('payment_object_status', '?')}")
        _log(f"  code:            {err.get('code', '?')}")
        _log(f"  decline_code:    {err.get('decline_code', '?')}")
        _log(f"  message:         {err.get('message', '')}")
        _log(f"{'='*60}\n")
        _log(f"\n日志已保存到: {LOG_FILE}")
        return terminal_result
    finally:
        gateway.stop()


def run(
    checkout_input: str,
    card_index: int = 0,
    config_path: str = "config.json",
    manual_token: str = "",
    force_fresh: bool = False,
    fresh_only: bool = False,
    offline_replay: bool = False,
    local_mock: bool = False,
    use_paypal: bool = False,
    use_gopay: bool = False,
    gopay_otp_file: str = "",
    paypal_link_only: bool = False,
    paypal_guest_handoff: bool = False,
):
    _init_log()  # 初始化日志文件

    cfg = load_config(config_path)
    runtime_cfg = cfg.get("runtime", {})
    behavior_cfg = cfg.get("behavior", {})
    pre_solve_passive_captcha = cfg.get("pre_solve_passive_captcha", True)
    browser_challenge_cfg = cfg.get("browser_challenge", {})
    cards = cfg["cards"]
    if card_index >= len(cards):
        raise ValueError(f"卡索引 {card_index} 超出范围，共 {len(cards)} 张卡")
    card = json.loads(json.dumps(cards[card_index]))
    captcha_cfg = cfg["captcha"]
    resolved_config_path = cfg.get("_loaded_from", config_path)
    if offline_replay:
        cfg.setdefault("offline_replay", {})
        cfg["offline_replay"]["enabled"] = True
    if local_mock:
        cfg.setdefault("local_mock", {})
        cfg["local_mock"]["enabled"] = True

    # PayPal / GoPay 模式校验
    if use_paypal and use_gopay:
        raise ValueError("--paypal 与 --gopay 互斥")
    paypal_cfg = cfg.get("paypal") or {}
    if use_paypal:
        has_login_creds = paypal_cfg.get("email") and paypal_cfg.get("password")
        has_cookies = paypal_cfg.get("cookies")
        if not paypal_guest_handoff and not has_login_creds and not has_cookies:
            raise ValueError("PayPal 模式需要提供 paypal.email + paypal.password，或 paypal.cookies")
        billing_country = card.get("address", {}).get("country", "").upper()
        if billing_country and billing_country not in EU_COUNTRIES:
            _log(
                f"  [警告] PayPal 通常仅支持欧盟国家地址，当前 billing country={billing_country}。"
                f"继续尝试，但可能被 Stripe 拒绝。"
            )
    if use_gopay:
        gopay_cfg = cfg.get("gopay") or {}
        if not all(gopay_cfg.get(k) for k in ("country_code", "phone_number", "pin")):
            raise ValueError("GoPay 模式需 cfg.gopay 提供 country_code / phone_number / pin")

    _FIRST_NAMES = [
        "JAMES", "JOHN", "ROBERT", "MICHAEL", "WILLIAM", "DAVID", "RICHARD", "JOSEPH",
        "THOMAS", "CHARLES", "DANIEL", "MATTHEW", "ANTHONY", "MARK", "STEVEN",
        "MARY", "PATRICIA", "JENNIFER", "LINDA", "ELIZABETH", "BARBARA", "SUSAN",
        "JESSICA", "SARAH", "KAREN", "NANCY", "LISA", "BETTY", "MARGARET", "SANDRA",
    ]
    _LAST_NAMES = [
        "SMITH", "JOHNSON", "WILLIAMS", "BROWN", "JONES", "GARCIA", "MILLER",
        "DAVIS", "RODRIGUEZ", "MARTINEZ", "WILSON", "ANDERSON", "TAYLOR", "THOMAS",
        "MOORE", "JACKSON", "MARTIN", "LEE", "THOMPSON", "WHITE", "HARRIS", "CLARK",
    ]
    _EMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com",
    ]

    def _gen_name() -> str:
        return f"{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}"

    def _gen_email() -> str:
        email_user = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 12))
        )
        return f"{email_user}@{random.choice(_EMAIL_DOMAINS)}"

    addr = dict(card.get("address", {}) or {})
    card["address"] = addr

    if cfg.get("randomize_identity", False):
        card["name"] = _gen_name()
        card["email"] = _gen_email()
        line1 = addr.get("line1", "")
        if line1:
            new_line1 = re.sub(r"^\d+", str(random.randint(100, 999)), line1)
            if new_line1 == line1:
                new_line1 = f"{random.randint(100, 999)} {line1}"
            addr["line1"] = new_line1
    else:
        if not card.get("name"):
            card["name"] = _gen_name()
        if not card.get("email"):
            card["email"] = _gen_email()

    locale_key = cfg.get("locale", addr.get("country", "US")).upper()
    locale_profile = LOCALE_PROFILES.get(locale_key, LOCALE_PROFILES["US"])
    _log(f"  地域: {locale_key} (tz={locale_profile['browser_timezone']}, lang={locale_profile['browser_locale']})")

    _log(f"\n{'='*60}")
    if use_paypal:
        _log(f"  Stripe 自动化支付 (PayPal 渠道)")
        _log(f"  PayPal 账号: {paypal_cfg.get('email') or '<cookies>'}")
    else:
        _log(f"  Stripe 自动化支付")
        _log(f"  使用卡: ****{card['number'][-4:]}  ({card['name']})")
    _log(f"  邮箱: {card['email']}")
    _log(f"  地址: {addr.get('line1', '')} ({addr.get('country', '')})")
    _log(f"  配置文件: {resolved_config_path}")
    _log(f"{'='*60}\n")

    if (cfg.get("offline_replay") or {}).get("enabled", False):
        return _run_offline_replay(
            checkout_input,
            cfg=cfg,
            card=card,
            locale_profile=locale_profile,
            force_fresh=force_fresh,
            fresh_only=fresh_only,
        )
    if (cfg.get("local_mock") or {}).get("enabled", False):
        return _run_local_mock_gateway(
            checkout_input,
            cfg=cfg,
            card=card,
            locale_profile=locale_profile,
            force_fresh=force_fresh,
            fresh_only=fresh_only,
        )

    http = requests.Session()
    http.headers.update(_browser_like_session_headers(locale_profile["browser_locale"]))
    stage_proxy_cfg = cfg.get("stage_proxies") or {}

    # 代理配置
    proxy_cfg = cfg.get("proxy")
    if proxy_cfg:
        proxy_url = _build_proxy_url_from_cfg(proxy_cfg)
        _apply_proxy_to_http_session(http, proxy_url)
        _log(f"      代理: {_describe_proxy_cfg(proxy_cfg)}")
    else:
        _log("      代理: 无 (直连)")
    if stage_proxy_cfg:
        _log("      stage_proxies:")
        for stage_name in sorted(stage_proxy_cfg):
            _log(f"        - {stage_name}: {_describe_proxy_cfg(stage_proxy_cfg.get(stage_name))}")

    with _http_session_stage_proxy(http, stage_proxy_cfg, "fingerprint"):
        reg_guid, reg_muid, reg_sid = register_fingerprint(http)

    fresh_info = None
    fresh_info = None
    fresh_info = None
    fresh_info = None
    fresh_info = None
    effective_checkout_input = checkout_input
    fresh_cfg = cfg.get("fresh_checkout") or {}
    if _should_generate_fresh_checkout(checkout_input, force_fresh):
        fresh_info = generate_fresh_checkout(http, cfg, locale_profile=locale_profile)
        effective_checkout_input = fresh_info["url"]
        if fresh_only:
            _log(f"\n日志已保存到: {LOG_FILE}")
            print(fresh_info["url"])
            return fresh_info

    init_attempt = 0
    inactive_refresh_limit = 2 if fresh_cfg.get("auto_refresh_on_inactive", False) else 1
    inactive_refresh_count = 0
    expected_due = _resolve_expected_checkout_due(fresh_cfg) if fresh_cfg.get("enabled", False) else None
    due_refresh_limit = int(fresh_cfg.get("max_due_mismatch_refreshes", 3) or 0)
    if not fresh_cfg.get("auto_refresh_on_due_mismatch", True):
        due_refresh_limit = 0
    due_refresh_count = 0
    while True:
        init_attempt += 1
        _log("[1/6] 解析 checkout session ID ...")
        session_id, stripe_checkout_url = parse_checkout_url(effective_checkout_input)
        _log(f"      session_id: {session_id}")
        if "chatgpt.com" in effective_checkout_input:
            _log("      输入格式: ChatGPT 嵌入式链接 → 转换为 Stripe URL")
        elif _should_generate_fresh_checkout(checkout_input, force_fresh):
            _log("      输入格式: fresh/auto → 已从 ChatGPT 后端生成新的 checkout")
        _log(f"      stripe_url: {stripe_checkout_url}")

        try:
            with _http_session_stage_proxy(http, stage_proxy_cfg, "fetch_publishable_key"):
                pk = fetch_publishable_key(http, session_id, stripe_checkout_url)
            with _http_session_stage_proxy(http, stage_proxy_cfg, "stripe_init"):
                init_resp, stripe_ver, init_ctx = init_checkout(http, session_id, pk, locale_profile=locale_profile)
            pricing = _extract_checkout_totals(init_resp)
            _log(
                "      pricing: "
                f"due={pricing.get('due')} "
                f"subtotal={pricing.get('subtotal')} "
                f"total={pricing.get('total')} "
                f"currency={pricing.get('currency') or '?'}"
            )
            if expected_due is not None:
                actual_due = pricing.get("due")
                if actual_due is None:
                    raise RuntimeError("无法从 Stripe init 响应提取 due，无法校验优惠链路")
                if actual_due != expected_due:
                    if due_refresh_count < due_refresh_limit and fresh_cfg.get("enabled", False):
                        due_refresh_count += 1
                        _log(
                            "      fresh checkout 金额未命中预期，"
                            f"expected_due={expected_due} actual_due={actual_due}，"
                            f"自动重刷 fresh checkout ({due_refresh_count}/{due_refresh_limit}) ..."
                        )
                        fresh_info = generate_fresh_checkout(http, cfg, locale_profile=locale_profile)
                        effective_checkout_input = fresh_info["url"]
                        continue
                    raise RuntimeError(
                        f"fresh checkout 金额未命中预期: expected_due={expected_due}, actual_due={actual_due}"
                    )
            init_ctx["pricing"] = pricing
            break
        except CheckoutSessionInactive as e:
            if (inactive_refresh_count + 1) >= inactive_refresh_limit or not fresh_cfg.get("enabled", False):
                raise
            inactive_refresh_count += 1
            _log(f"      {e}")
            _log("      当前 checkout 已失活，自动生成 fresh checkout 后重试 ...")
            fresh_info = generate_fresh_checkout(http, cfg, locale_profile=locale_profile)
            effective_checkout_input = fresh_info["url"]
            continue
    init_ctx["guid"] = reg_guid
    init_ctx["muid"] = reg_muid
    init_ctx["sid"] = reg_sid
    init_ctx["page_load_ts"] = int(time.time() * 1000)
    init_ctx["runtime_version"] = runtime_cfg.get("version") or DEFAULT_STRIPE_RUNTIME_VERSION
    init_ctx["js_checksum"] = runtime_cfg.get("js_checksum", "")
    init_ctx["rv_timestamp"] = runtime_cfg.get("rv_timestamp", "")
    http.headers.update(_browser_like_session_headers(init_ctx.get("locale") or locale_profile["browser_locale"]))
    init_ctx["top_checkout_config_id"] = (
        runtime_cfg.get("top_checkout_config_id")
        or init_ctx.get("config_id", "")
    )
    init_ctx["payment_method_checkout_config_id"] = (
        runtime_cfg.get("payment_method_checkout_config_id")
        or init_ctx.get("config_id", "")
    )
    if use_paypal:
        # PayPal 必须走 shared_payment_method 模式（先创建 pm，再 confirm 引用）
        init_ctx["confirm_mode"] = "shared_payment_method"
    elif use_gopay:
        init_ctx["confirm_mode"] = "shared_payment_method"
        init_ctx["payment_method_type"] = "gopay"
    else:
        init_ctx["confirm_mode"] = runtime_cfg.get("confirm_mode", "inline_payment_method_data")
    # 把 processor_entity 透传给 manual_approval 阶段；默认 openai_llc（IDR/Plus 用）
    if fresh_info and fresh_info.get("processor_entity"):
        init_ctx["processor_entity"] = fresh_info["processor_entity"]
        init_ctx["processor_entity"] = fresh_info["processor_entity"]
    init_ctx["frontend_execution"] = (
        runtime_cfg.get("frontend_execution")
        or DEFAULT_FRONTEND_EXECUTION
    )
    init_ctx["pasted_fields"] = behavior_cfg.get("pasted_fields", "number")
    init_ctx["min_time_on_page_ms"] = int(behavior_cfg.get("min_time_on_page_ms", 0) or 0)
    init_ctx["include_terms_of_service_consent"] = behavior_cfg.get("include_terms_of_service_consent")
    init_ctx["merchant_account_id"] = init_resp.get("account_settings", {}).get("account_id", "")
    # 全局代理 URL 传入 ctx，供 PayPal Playwright 浏览器使用
    if proxy_cfg:
        init_ctx["proxy_url"] = _build_proxy_url_from_cfg(proxy_cfg)
    init_ctx["captcha_api_key"] = captcha_cfg.get("api_key", "")
    init_ctx["stage_proxies"] = stage_proxy_cfg
    effective_external_solver_cfg = dict(browser_challenge_cfg.get("external_solver") or {})
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    should_autofill_external_solver = (
        browser_challenge_cfg.get("enabled", True)
        and not effective_external_solver_cfg
        and (not browser_challenge_cfg.get("auto_launch_browser", True) or not has_display)
    )
    if should_autofill_external_solver:
        bundled_solver = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hcaptcha_auto_solver.py")
        python_candidates = [
            str(os.environ.get("CTFML_PYTHON") or "").strip(),
            "~/.venvs/ctfml/bin/python",
            sys.executable,
        ]
        solver_python = next((p for p in python_candidates if p and os.path.exists(p)), sys.executable)
        effective_external_solver_cfg = {
            "enabled": True,
            "python": solver_python,
            "script": bundled_solver,
            "out_dir": "/tmp/hcaptcha_auto_solver_live",
            "timeout_s": max(180, int(browser_challenge_cfg.get("timeout_ms", 300000) / 1000)),
            "headed": not bool(browser_challenge_cfg.get("headless", False)),
        }
        _log(
            "      未显式配置 browser_challenge.external_solver，"
            "已自动启用项目内置 solver"
        )
    effective_vlm_cfg = dict(effective_external_solver_cfg.get("vlm") or {})
    effective_vlm_cfg.setdefault("enabled", True)
    effective_vlm_cfg.setdefault("model", "gpt-5.4")
    effective_vlm_cfg.setdefault("base_url", "https://YOUR_VLM_ENDPOINT/api")
    effective_vlm_cfg.setdefault("api_key", "")
    effective_vlm_cfg.setdefault("timeout_s", 45)
    effective_external_solver_cfg["vlm"] = effective_vlm_cfg
    init_ctx["browser_challenge"] = {
        "enabled": browser_challenge_cfg.get("enabled", True),
        "auto_launch_browser": browser_challenge_cfg.get("auto_launch_browser", True),
        "headless": browser_challenge_cfg.get("headless", False),
        "use_for_passive_captcha": browser_challenge_cfg.get("use_for_passive_captcha", True),
        "passive_headless": browser_challenge_cfg.get("passive_headless", True),
        "passive_timeout_ms": int(browser_challenge_cfg.get("passive_timeout_ms", 90000)),
        "timeout_ms": int(browser_challenge_cfg.get("timeout_ms", 300000)),
        "auto_click_checkbox": browser_challenge_cfg.get("auto_click_checkbox", True),
        "viewport": browser_challenge_cfg.get("viewport") or {"width": 1280, "height": 960},
        "external_solver": effective_external_solver_cfg,
        "proxy_url": str(browser_challenge_cfg.get("proxy_url") or "").strip(),
    }
    mode = init_resp.get("mode", "unknown")
    display_name = init_resp.get("account_settings", {}).get("display_name", "?")
    _log(f"      商户: {display_name}  |  模式: {mode}")
    _log(
        "      runtime: "
        f"confirm_mode={init_ctx['confirm_mode']}, "
        f"version={init_ctx['runtime_version']}, "
        f"js_checksum={'yes' if init_ctx.get('js_checksum') else 'no'}, "
        f"rv_timestamp={'yes' if init_ctx.get('rv_timestamp') else 'no'}"
    )
    if init_ctx["browser_challenge"]["enabled"]:
        _log(
            "      browser_challenge: "
            f"enabled(auto_launch={init_ctx['browser_challenge']['auto_launch_browser']}, "
            f"headless={init_ctx['browser_challenge']['headless']}, "
            f"timeout_ms={init_ctx['browser_challenge']['timeout_ms']})"
        )
        if init_ctx["browser_challenge"]["external_solver"].get("enabled"):
            _log(
                "      browser_challenge.external_solver: "
                f"python={init_ctx['browser_challenge']['external_solver'].get('python') or sys.executable}, "
                f"script={init_ctx['browser_challenge']['external_solver'].get('script') or 'hcaptcha_auto_solver.py'}"
            )
            vlm_cfg = init_ctx["browser_challenge"]["external_solver"].get("vlm") or {}
            _log(
                "      browser_challenge.external_solver.vlm: "
                f"enabled={bool(vlm_cfg.get('enabled', True))}, "
                f"model={vlm_cfg.get('model') or 'gpt-5.4'}, "
                f"base_url={vlm_cfg.get('base_url') or 'https://YOUR_VLM_ENDPOINT/api'}"
            )


    with _http_session_stage_proxy(http, stage_proxy_cfg, "telemetry_init"):
        send_telemetry_batch(http, session_id, init_ctx, phase="init")

   
    _log("[2c/6] 获取 elements session ...")
    with _http_session_stage_proxy(http, stage_proxy_cfg, "elements"):
        elements_resp = fetch_elements_session(
            http, pk, session_id, init_ctx, stripe_ver=stripe_ver, locale_profile=locale_profile
        )

   
    _log("[2d/6] 查询 Link 消费者 ...")
    with _http_session_stage_proxy(http, stage_proxy_cfg, "link_lookup"):
        lookup_consumer(
            http,
            pk,
            card["email"],
            session_id,
            stripe_ver=stripe_ver,
            ctx=init_ctx,
            init_resp=init_resp,
        )

  
    _log("[2e/6] 逐字段提交地址 ...")
    with _http_session_stage_proxy(http, stage_proxy_cfg, "address"):
        update_payment_page_address(http, pk, session_id, card, init_ctx, stripe_ver=stripe_ver)

    
    with _http_session_stage_proxy(http, stage_proxy_cfg, "telemetry_address"):
        send_telemetry_batch(http, session_id, init_ctx, phase="address")


    init_ctx["time_on_page"] = int(time.time() * 1000) - init_ctx.get("page_load_ts", int(time.time() * 1000))

    hcaptcha_cfg = extract_hcaptcha_config(init_resp)
    passive_captcha_cfg = extract_passive_captcha_config(init_resp, elements_resp)
    _log(f"      hCaptcha site_key: {hcaptcha_cfg['site_key']}")
    if hcaptcha_cfg.get("rqdata"):
        _log(f"      hCaptcha rqdata: {hcaptcha_cfg['rqdata'][:50]}...")
    _log(f"      passive captcha site_key: {passive_captcha_cfg['site_key']}")
    if passive_captcha_cfg.get("rqdata"):
        _log(f"      passive captcha rqdata: {passive_captcha_cfg['rqdata'][:50]}...")

    with _http_session_stage_proxy(http, stage_proxy_cfg, "telemetry_card_input"):
        send_telemetry_batch(http, session_id, init_ctx, phase="card_input")

    def _submit_confirm(captcha_token: str, captcha_ekey: str):
        measured_time_on_page = int(time.time() * 1000) - init_ctx.get(
            "page_load_ts", int(time.time() * 1000)
        )
        min_time_on_page_ms = int(init_ctx.get("min_time_on_page_ms") or 0)
        if min_time_on_page_ms > 0 and measured_time_on_page < min_time_on_page_ms:
            _log(
                f"      [behavior] time_on_page 从 {measured_time_on_page}ms 提升到最小阈值 {min_time_on_page_ms}ms"
            )
            measured_time_on_page = min_time_on_page_ms
        init_ctx["time_on_page"] = measured_time_on_page
        pm_id = ""
        if use_paypal:
            # PayPal 模式: 创建 type=paypal 的 payment_method，走 shared 模式
            init_ctx["payment_method_type"] = "paypal"
            with _http_session_stage_proxy(http, stage_proxy_cfg, "payment_method"):
                pm_id = create_paypal_payment_method(
                    http, pk, card, session_id, stripe_ver, ctx=init_ctx
                )
        elif use_gopay:
            with _http_session_stage_proxy(http, stage_proxy_cfg, "payment_method"):
                pm_id = create_gopay_payment_method(
                    http, pk, card, session_id, stripe_ver, ctx=init_ctx
                )
        elif init_ctx.get("confirm_mode") != "inline_payment_method_data":
            with _http_session_stage_proxy(http, stage_proxy_cfg, "payment_method"):
                pm_id = create_payment_method(
                    http, pk, card, captcha_token, session_id, stripe_ver, ctx=init_ctx
                )
        with _http_session_stage_proxy(http, stage_proxy_cfg, "telemetry_confirm"):
            send_telemetry_batch(http, session_id, init_ctx, phase="confirm")
        with _http_session_stage_proxy(http, stage_proxy_cfg, "confirm"):
            confirm_data = confirm_payment(
                http,
                pk,
                session_id,
                pm_id,
                card if (not use_paypal and not use_gopay and init_ctx.get("confirm_mode") == "inline_payment_method_data") else None,
                captcha_token,
                init_resp,
                stripe_ver,
                captcha_cfg,
                captcha_ekey=captcha_ekey,
                ctx=init_ctx,
                locale_profile=locale_profile,
            )

        # PayPal 模式: 检测 redirect_to_url 并启动浏览器授权
        if use_paypal or use_gopay:
            next_action = None
            for source_key in ("next_action", "payment_intent", "setup_intent"):
                obj = confirm_data.get(source_key)
                if isinstance(obj, dict):
                    na = obj.get("next_action") if source_key != "next_action" else obj
                    if isinstance(na, dict) and na.get("type") == "redirect_to_url":
                        next_action = na
                        break
            if not next_action:
                # 也检查 _find_setup_intent
                seti = _find_setup_intent(confirm_data)
                if seti and isinstance(seti, dict):
                    na = seti.get("next_action")
                    if isinstance(na, dict) and na.get("type") == "redirect_to_url":
                        next_action = na

            if next_action:
                redirect_info = next_action.get("redirect_to_url", {})
                paypal_redirect_url = redirect_info.get("url", "")
                if paypal_redirect_url:
                    _log(f"      redirect URL: {paypal_redirect_url[:100]}...")
                    if use_paypal and paypal_guest_handoff:
                        guest_result = _paypal_guest_handoff_fill_nonpayment(
                            paypal_redirect_url,
                            chatgpt_email=(cfg.get("fresh_checkout") or {}).get("_chatgpt_email") or card.get("email", ""),
                            proxy_url=PAYPAL_GUEST_US_PROXY,
                        )
                        guest_result["session_id"] = session_id
                        guest_result["payment_method"] = "paypal"
                        init_ctx["terminal_result"] = guest_result
                        return guest_result
                    if use_paypal and paypal_link_only:
                        paypal_link_result = {
                            "status": "paypal_link",
                            "url": paypal_redirect_url,
                            "checkout_url": paypal_redirect_url,
                            "session_id": session_id,
                            "payment_method": "paypal",
                        }
                        # _submit_confirm is a nested helper; returning here only
                        # returns from the helper. Store a terminal result so the
                        # outer run() stops before poll_result instead of timing out.
                        init_ctx["terminal_result"] = paypal_link_result
                        return paypal_link_result
                    if use_gopay:
                        _drive_gopay_from_redirect(
                            paypal_redirect_url, cfg, gopay_otp_file,
                            session_id=session_id,
                        )
                        _log("      GoPay 授权 + 扣款完成，继续 poll 结果 ...")
                    else:
                        success = _handle_paypal_redirect(
                            paypal_redirect_url,
                            paypal_cfg,
                            locale_profile=locale_profile,
                            ctx=init_ctx,
                        )
                        if not success:
                            raise RuntimeError("PayPal 授权失败或超时")
                        _log("      PayPal 授权完成，继续 poll 结果 ...")
                else:
                    raise RuntimeError("PayPal confirm 返回了 redirect_to_url 但缺少 url 字段")
            else:
                # manual_approval beta 新流程：
                #   1. confirm 返回 requires_approval 和 submission_attempt
                #   2. 调用 ChatGPT 的 /backend-api/payments/checkout/approve 批准
                #   3. 再 GET /payment_pages/<session>?client_betas=... 取 redirect_to_url
                submission = confirm_data.get("submission_attempt") or {}
                if submission.get("state") == "requires_approval":
                    _log("      [manual_approval] 调 ChatGPT approve 端点 ...")
                    try:
                        fresh_cfg = cfg.get("fresh_checkout") or {}
                        auth_cfg = fresh_cfg.get("auth") or {}
                        access_token = (auth_cfg.get("access_token") or "").strip()
                        oai_device_id = (
                            auth_cfg.get("oai_device_id")
                            or auth_cfg.get("device_id")
                            or ""
                        ).strip()
                        cookie_header = (auth_cfg.get("cookie_header") or "").strip()
                        processor_entity = init_ctx.get("processor_entity") or "openai_ie"
                        # 推断: processor_entity 可能在 init_resp 或 fresh_info
                        if not processor_entity:
                            processor_entity = init_resp.get("merchant_of_record_country", "openai_ie")
                        approve_headers = {
                            "content-type": "application/json",
                            "accept": "*/*",
                            "authorization": f"Bearer {access_token}",
                            "origin": "https://chatgpt.com",
                            "referer": f"https://chatgpt.com/checkout/{processor_entity}/{session_id}",
                            "x-openai-target-path": "/backend-api/payments/checkout/approve",
                            "x-openai-target-route": "/backend-api/payments/checkout/approve",
                        }
                        if oai_device_id:
                            approve_headers["oai-device-id"] = oai_device_id
                        if isinstance(cookie_header, str) and cookie_header:
                            approve_headers["cookie"] = cookie_header
                        approve_body = {
                            "checkout_session_id": session_id,
                            "processor_entity": processor_entity,
                        }
                        # 创建独立 HTTP session 走 ChatGPT 代理
                        chatgpt_http_for_approve, _transport = _create_chatgpt_http_session(cfg)
                        ar = chatgpt_http_for_approve.post(
                            "https://chatgpt.com/backend-api/payments/checkout/approve",
                            json=approve_body, headers=approve_headers, timeout=20,
                        )
                        _log(f"      [manual_approval] ChatGPT approve: {ar.status_code} body={ar.text[:200]}")
                        if ar.status_code != 200:
                            raise RuntimeError(f"ChatGPT approve 失败: {ar.status_code} {ar.text[:200]}")
                        try:
                            approve_payload = ar.json() or {}
                        except Exception:
                            approve_payload = {}
                        approve_result = str(approve_payload.get("result") or "").lower()
                        if approve_result and approve_result != "approved":
                            # result=blocked is the signal that this confirm path needs
                            # an hCaptcha-backed retry. Surface the literal word so the
                            # outer confirm retry handler falls into the existing solver
                            # path instead of polling Stripe until timeout.
                            raise RuntimeError(f"manual_approval approve blocked: result={approve_result}")
                    except Exception as e_ap:
                        _log(f"      [manual_approval] approve 异常: {e_ap}")
                        raise

                    _log("      [manual_approval] 再 GET 取 redirect ...")
                    get_params = {
                        "key": pk,
                        "_stripe_version": STRIPE_VERSION_FULL,
                        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
                        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
                        "elements_session_client[elements_init_source]": "custom_checkout",
                        "elements_session_client[referrer_host]": "chatgpt.com",
                    }
                    got_redirect = False
                    for poll_i in range(15):
                        gr = http.get(
                            f"https://api.stripe.com/v1/payment_pages/{session_id}",
                            params=get_params, timeout=20,
                        )
                        if gr.status_code != 200:
                            _log(f"      [manual_approval] GET {gr.status_code}")
                            time.sleep(1); continue
                        try:
                            gj = gr.json()
                        except Exception:
                            time.sleep(1); continue
                        na = None
                        for src in ("next_action", "setup_intent", "payment_intent"):
                            obj = gj.get(src)
                            if isinstance(obj, dict):
                                candidate = obj.get("next_action") if src != "next_action" else obj
                                if isinstance(candidate, dict) and candidate.get("type") == "redirect_to_url":
                                    na = candidate
                                    break
                        if not na:
                            seti = _find_setup_intent(gj)
                            if seti and isinstance(seti, dict):
                                c2 = seti.get("next_action")
                                if isinstance(c2, dict) and c2.get("type") == "redirect_to_url":
                                    na = c2
                        if na:
                            url = (na.get("redirect_to_url") or {}).get("url", "")
                            if url:
                                _log(f"      [manual_approval] 拿到 redirect: {url[:100]}")
                                if use_paypal and paypal_guest_handoff:
                                    guest_result = _paypal_guest_handoff_fill_nonpayment(
                                        url,
                                        chatgpt_email=(cfg.get("fresh_checkout") or {}).get("_chatgpt_email") or card.get("email", ""),
                                        proxy_url=PAYPAL_GUEST_US_PROXY,
                                    )
                                    guest_result["session_id"] = session_id
                                    guest_result["payment_method"] = "paypal"
                                    init_ctx["terminal_result"] = guest_result
                                    return guest_result
                                if use_paypal and paypal_link_only:
                                    paypal_link_result = {
                                        "status": "paypal_link",
                                        "url": url,
                                        "checkout_url": url,
                                        "session_id": session_id,
                                        "payment_method": "paypal",
                                    }
                                    init_ctx["terminal_result"] = paypal_link_result
                                    return paypal_link_result
                                if use_gopay:
                                    _drive_gopay_from_redirect(
                                        url, cfg, gopay_otp_file,
                                        session_id=session_id,
                                    )
                                    got_redirect = True
                                    break
                                success = _handle_paypal_redirect(
                                    url, paypal_cfg,
                                    locale_profile=locale_profile, ctx=init_ctx,
                                )
                                if not success:
                                    raise RuntimeError("PayPal 授权失败或超时")
                                got_redirect = True
                                break
                        sa2 = (gj.get("submission_attempt") or {}).get("state")
                        _log(f"      [manual_approval] poll {poll_i+1}: sub_state={sa2}")
                        if sa2 and sa2 not in ("requires_approval",):
                            break
                        time.sleep(1)
                    if not got_redirect:
                        raise RuntimeError("manual_approval approve 后仍未拿到 redirect_to_url")
                else:
                    _log("      PayPal confirm 未返回 redirect，可能不需要授权 (直接完成)")

        return confirm_data

    def _solve_passive_confirm_captcha() -> tuple[str, str]:
        if manual_token:
            return manual_token, ""
        if not pre_solve_passive_captcha:
            return "", ""
        _log("      预先解 passive captcha ...")

        passive_browser_cfg = dict(init_ctx.get("browser_challenge") or {})
        passive_browser_enabled = bool(
            passive_browser_cfg.get("enabled")
            and passive_browser_cfg.get("use_for_passive_captcha", True)
        )
        if passive_browser_enabled:
            auto_browser_cfg = dict(passive_browser_cfg)
            auto_browser_cfg["auto_launch_browser"] = True
            auto_browser_cfg["headless"] = bool(
                passive_browser_cfg.get("passive_headless", True)
            )
            auto_browser_cfg["auto_click_checkbox"] = False
            auto_browser_cfg["timeout_ms"] = int(
                passive_browser_cfg.get("passive_timeout_ms", 90000)
            )
            auto_browser_cfg["proxy_url"] = str(
                passive_browser_cfg.get("passive_proxy_url")
                or ""
            ).strip()
            try:
                token, ekey, _ = solve_stripe_hcaptcha_in_browser(
                    passive_captcha_cfg,
                    merchant_id=init_ctx.get("merchant_account_id", ""),
                    locale=locale_profile.get("browser_locale", "en-US"),
                    browser_cfg=auto_browser_cfg,
                )
                return token, ekey
            except Exception as e:
                _log(f"      浏览器 passive captcha 未拿到 token，回退打码平台: {e}")

        return solve_hcaptcha(
            captcha_cfg,
            passive_captcha_cfg,
            session=http,
        )

    if manual_token:
        _log(f"[3/6] 使用手动传入的 token (长度: {len(manual_token)})")
        max_confirm_attempts = 3
        for confirm_attempt in range(1, max_confirm_attempts + 1):
            try:
                captcha_token, captcha_ekey = _solve_passive_confirm_captcha()
                _submit_confirm(captcha_token, captcha_ekey)
                break
            except ChallengeReconfirmRequired as e:
                if confirm_attempt >= max_confirm_attempts:
                    raise
                _log(f"      {e}")
                _log(f"      重新 confirm 获取新的 challenge ({confirm_attempt}/{max_confirm_attempts}) ...")
    else:
        if pre_solve_passive_captcha:
            _log("[3/6] 先按真实链路解 passive captcha，再提交 confirm ...")
        else:
            _log("[3/6] 尝试不带 hCaptcha 直接提交 ...")
        max_confirm_attempts = 3
        for confirm_attempt in range(1, max_confirm_attempts + 1):
            try:
                captcha_token, captcha_ekey = _solve_passive_confirm_captcha()
                _submit_confirm(captcha_token, captcha_ekey)
                break
            except ChallengeReconfirmRequired as e:
                if confirm_attempt >= max_confirm_attempts:
                    raise
                _log(f"      {e}")
                _log(f"      重新 confirm 获取新的 challenge ({confirm_attempt}/{max_confirm_attempts}) ...")
                continue
            except RuntimeError as e:
                err_msg = str(e).lower()
                if any(kw in err_msg for kw in ["captcha", "hcaptcha", "blocked", "denied", "radar", "challenge_response"]):
                    _log("      需要 captcha，开始解题 ...")
                    captcha_token, captcha_ekey = solve_hcaptcha(
                        captcha_cfg,
                        passive_captcha_cfg,
                        session=http,
                    )
                    try:
                        _submit_confirm(captcha_token, captcha_ekey)
                        break
                    except ChallengeReconfirmRequired as challenge_error:
                        if confirm_attempt >= max_confirm_attempts:
                            raise
                        _log(f"      {challenge_error}")
                        _log(f"      重新 confirm 获取新的 challenge ({confirm_attempt}/{max_confirm_attempts}) ...")
                        continue
                raise

  
    with _http_session_stage_proxy(http, stage_proxy_cfg, "telemetry_poll"):
        send_telemetry_batch(http, session_id, init_ctx, phase="poll")

    terminal_result = init_ctx.get("terminal_result")
    if terminal_result:
        err = terminal_result.get("error", {})
        _log(f"\n{'='*60}")
        _log("  支付已落到终态失败")
        _log(f"  source_kind:     {terminal_result.get('source_kind', '?')}")
        _log(f"  payment_status:  {terminal_result.get('payment_object_status', '?')}")
        _log(f"  code:            {err.get('code', '?')}")
        _log(f"  decline_code:    {err.get('decline_code', '?')}")
        _log(f"  message:         {err.get('message', '')}")
        _log(f"{'='*60}\n")
        _log(f"\n日志已保存到: {LOG_FILE}")
        return terminal_result

    # Step 6
    with _http_session_stage_proxy(http, stage_proxy_cfg, "poll"):
        result = poll_result(http, pk, session_id, stripe_ver)

    # 记录结果
    chatgpt_email = fresh_cfg.get("_chatgpt_email", card.get("email", ""))
    payment_channel = "gopay" if use_gopay else ("paypal" if use_paypal else "card")
    result_state = result.get("state", "unknown")

    # 从数据库查最近一条匹配 email 的账号凭证。
    extra_info = {}
    # 支付成功时记录 Team workspace account_id
    try:
        ru = result.get("return_url", "") if isinstance(result, dict) else ""
        if ru:
            import urllib.parse as _up
            qs = _up.parse_qs(_up.urlparse(ru).query)
            aid = (qs.get("account_id") or [""])[0]
            if aid:
                extra_info["team_account_id"] = aid
    except Exception:
        pass

    # 支付成功才拿 refresh_token（失败不拿）
    # auto-loop 不需要 RT，可设 SKIP_PAY_RT_EXCHANGE=1 跳过整段。
    if (
        result_state == "succeeded"
        and chatgpt_email
        and str(os.environ.get("SKIP_PAY_RT_EXCHANGE", "")).strip().lower() not in ("1", "true", "yes", "on")
    ):
        try:
            # 从 SQLite 主存储取本账号的 password。
            import os as _os
            _password = ""
            try:
                _password = (get_db().find_latest_registered_account(chatgpt_email) or {}).get("password", "") or ""
            except Exception:
                _password = ""

            # 加载 CTF-reg/config.paypal-proxy.json 里的 mail 配置（供 IMAP 取 OTP）
            _mail_cfg = {}
            reg_cfg_path = _os.path.join(
                _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                "CTF-reg", "config.paypal-proxy.json",
            )
            if _os.path.exists(reg_cfg_path):
                try:
                    with open(reg_cfg_path, "r", encoding="utf-8") as rf:
                        _reg_cfg = json.load(rf)
                    _mail_cfg = _reg_cfg.get("mail", {}) or {}
                except Exception as e:
                    _log(f"      [RT] 读取 mail 配置失败: {e}")

            # passwordless_signup 账号 DB 里 password=""——但浏览器流程在
            # card.py:5240 已有 passwordless 分支（找不到密码框就跳到 OTP 等
            # 邮件再 callback）。所以 password 不再是硬条件，mail_cfg 够就启动。
            if _mail_cfg:
                if _password:
                    _log("      [RT] 支付成功，重新登录拿 refresh_token ...")
                else:
                    _log("      [RT] 支付成功，账号无 password (passwordless_signup)，走 OTP 登录路径...")
                rt_value = _exchange_refresh_token_with_session(
	                    email=chatgpt_email,
	                    password=_password,
	                    mail_cfg=_mail_cfg,
	                    proxy_url=_build_proxy_url_from_cfg(cfg.get("proxy")) if isinstance(cfg, dict) else "",
	                    oauth_client_id=_codex_oauth_client_id_from_config(cfg),
	                )
                if rt_value:
                    extra_info["refresh_token"] = rt_value
                    _log(f"      [RT] ✅ 获得 refresh_token 长度={len(rt_value)}")
                else:
                    _log("      [RT] ❌ refresh_token 获取失败（不影响支付结果）")
            else:
                _log(f"      [RT] 缺少 mail_cfg，跳过（无邮件渠道接 OTP）")
        except Exception as e:
            _log(f"      [RT] 获取异常: {e}")

    _record_result(
        status=result_state,
        chatgpt_email=chatgpt_email,
        session_id=session_id,
        payment_channel=payment_channel,
        processor_entity=init_resp.get("account_settings", {}).get("display_name", ""),
        config_path=resolved_config_path,
        extra=extra_info if extra_info else None,
    )
    _log(f"\n日志已保存到: {LOG_FILE}")
    return result



def main():
    parser = argparse.ArgumentParser(
        description="Stripe Checkout 自动化支付",
        epilog=(
            "示例:\n"
            "  python payment.py cs_live_xxx\n"
            "  python payment.py fresh --fresh-only\n"
            "  python payment.py auto --config config.auto.json"
        ),
    )
    parser.add_argument(
        "session_id",
        nargs="?",
        default="fresh",
        help="Checkout Session URL / cs_live_xxx；传 fresh/auto 则自动生成新的 checkout",
    )
    parser.add_argument("--card", type=int, default=0, help="使用第 N 张卡 (0-based, 默认 0)")
    parser.add_argument("--config", default="config.json", help="配置文件路径 (默认 config.json)")
    parser.add_argument("--token", default="", help="手动传入 hCaptcha token (跳过打码平台)")
    parser.add_argument("--fresh", action="store_true", help="忽略传入 session，先生成 fresh checkout")
    parser.add_argument("--fresh-only", action="store_true", help="只生成并输出 fresh checkout URL")
    parser.add_argument(
        "--offline-replay",
        action="store_true",
        help="仅使用本地 flows/fixture 回放，不发起外部网络请求",
    )
    parser.add_argument(
        "--local-mock",
        action="store_true",
        help="启动本地 HTTP mock gateway，并仅通过 127.0.0.1 回放 checkout/challenge/3DS 状态机",
    )
    parser.add_argument(
        "--paypal",
        action="store_true",
        help="使用 PayPal 支付（需要配置文件中包含 paypal 段，仅支持欧盟国家地址）",
    )
    parser.add_argument(
        "--paypal-link-only",
        action="store_true",
        help="只生成 PayPal redirect/checkout URL，不进入 PayPal 登录授权，不实际付款",
    )
    parser.add_argument(
        "--paypal-guest-handoff",
        action="store_true",
        help="走到 PayPal guest/signup 页，填非支付字段后截图停住；不填卡/CVV/密码，不创建/授权",
    )
    parser.add_argument(
        "--gopay",
        action="store_true",
        help="使用 GoPay tokenization (印尼 e-wallet, ChatGPT Plus)",
    )
    parser.add_argument(
        "--gopay-otp-file",
        default="",
        help="webui 模式: gopay 从这个文件读 WhatsApp OTP",
    )
    parser.add_argument(
        "--json-result",
        action="store_true",
        help="输出结构化 JSON 结果到 stdout（供 pipeline 解析）",
    )
    args = parser.parse_args()

    try:
        result = run(
            args.session_id,
            card_index=args.card,
            config_path=args.config,
            manual_token=args.token,
            force_fresh=args.fresh,
            fresh_only=args.fresh_only,
            offline_replay=args.offline_replay,
            local_mock=args.local_mock,
            use_paypal=args.paypal or args.paypal_link_only or args.paypal_guest_handoff,
            use_gopay=args.gopay,
            gopay_otp_file=args.gopay_otp_file,
            paypal_link_only=args.paypal_link_only,
            paypal_guest_handoff=args.paypal_guest_handoff,
        )
        if args.json_result and result:
            print("CARD_RESULT_JSON=" + json.dumps(result, ensure_ascii=False), flush=True)
    except Exception as e:
        import traceback as _tb
        err_msg = f"\n[ERROR] {type(e).__name__}: {e}\n{_tb.format_exc()}"
        print(err_msg, file=sys.stderr)
        # 记录失败
        _record_result(
            status="error",
            payment_channel="paypal" if (args.paypal or args.paypal_link_only or args.paypal_guest_handoff) else "card",
            config_path=args.config,
            error_msg=str(e),
        )
        # 也写入日志
        try:
            import traceback
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n{'!'*60}\n")
                f.write(err_msg + "\n")
                f.write(traceback.format_exc())
                f.write(f"{'!'*60}\n")
        except Exception:
            pass
        sys.exit(1)
