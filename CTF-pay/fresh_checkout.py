"""Fresh ChatGPT checkout generation extracted from legacy payment code.

This module owns the ChatGPT auth/session warmup and fresh Stripe checkout
creation path.  It is designed to be imported by ``payment.py`` without loading
``card.py``.
"""

from __future__ import annotations

import base64
import copy
import glob
import hashlib
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

_REPO_DIR = Path(__file__).resolve().parents[1]
_CTF_REG_DIR = _REPO_DIR / "CTF-reg"
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))
if _CTF_REG_DIR.is_dir() and str(_CTF_REG_DIR) not in sys.path:
    sys.path.insert(0, str(_CTF_REG_DIR))

try:
    from curl_cffi.requests import Session as CurlCffiSession
    _HAS_CURL_CFFI = True
except Exception:
    CurlCffiSession = None
    _HAS_CURL_CFFI = False

_OUTPUT_DIR = _REPO_DIR / "output"
(_OUTPUT_DIR / "logs").mkdir(parents=True, exist_ok=True)
LOG_FILE = str(_OUTPUT_DIR / "logs" / "fresh_checkout.log")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
DEFAULT_TIMEZONE = "America/Chicago"


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _log_raw(text: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        pass


def _log_request(method: str, url: str, data=None, params=None, tag: str = "") -> None:
    """Record sanitized HTTP request details to the payment log."""
    _log_raw(f"\n{'─'*70}")
    _log_raw(f">>> REQUEST  {tag}")
    _log_raw(f"    {method} {url}")
    if params:
        _log_raw(f"    PARAMS: {json.dumps(params, ensure_ascii=False, indent=6)}")
    if data:
        safe = dict(data) if isinstance(data, dict) else {}
        for key in list(safe):
            low = str(key).lower()
            if "card[number]" in low or low.endswith("number"):
                safe[key] = "****" + str(safe[key])[-4:]
            elif "card[cvc]" in low or "cvv" in low or "cvc" in low:
                safe[key] = "***"
        _log_raw(f"    BODY: {json.dumps(safe, ensure_ascii=False, indent=6)}")


def _log_response(resp, tag: str = "") -> None:
    """Record HTTP response details to the payment log."""
    _log_raw(f"<<< RESPONSE {tag}  status={getattr(resp, 'status_code', '-')}")
    try:
        body = resp.json()
        _log_raw(f"    BODY: {json.dumps(body, ensure_ascii=False, indent=6)}")
    except Exception:
        _log_raw(f"    BODY(raw): {getattr(resp, 'text', '')[:2000]}")
    _log_raw(f"{'─'*70}\n")


def _record_already_paid(email: str, message: str = "User is already paid (fresh_checkout 400)") -> None:
    """Persist an already-paid marker so PayOnly inventory skips this account next runs."""
    email = str(email or "").strip()
    if not email:
        return
    try:
        from webui.backend.db import get_db
        db = get_db()
        with db._conn() as c:
            row = c.execute(
                "SELECT id FROM registered_accounts WHERE lower(email)=lower(?) ORDER BY id DESC LIMIT 1",
                (email,),
            ).fetchone()
        if row:
            db.update_account_check(int(row["id"]), "plan", message)
        db.add_card_result({
            "ts": datetime.utcnow().isoformat() + "Z",
            "status": "succeeded",
            "chatgpt_email": email,
            "email": email,
            "channel": "fresh_checkout_already_paid",
            "entity": "openai_checkout",
            "config": "fresh_checkout.py",
            "error": message,
        })
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc


class ChallengeReconfirmRequired(RuntimeError):
    """当前 challenge 已失效或被拒，需要重新 confirm 获取新的 challenge。"""
    pass


class CheckoutSessionInactive(RuntimeError):
    """当前 Checkout Session 已失活，需要生成新的 session。"""
    pass


class FreshCheckoutAuthError(RuntimeError):
    """无法通过 ChatGPT 侧生成 fresh checkout。"""
    pass


def _build_proxy_url_from_cfg(proxy_cfg) -> str:
    if not proxy_cfg:
        return ""

    if isinstance(proxy_cfg, str):
        return proxy_cfg.strip()

    if not isinstance(proxy_cfg, dict):
        return ""

    host = str(proxy_cfg.get("host") or "").strip()
    if not host:
        return ""
    port = proxy_cfg.get("port")
    user = str(proxy_cfg.get("user") or "").strip()
    pwd = str(proxy_cfg.get("pass") or "").strip()

    if port in (None, ""):
        return f"http://{host}"
    if user and pwd:
        return f"http://{user}:{pwd}@{host}:{port}"
    return f"http://{host}:{port}"


def _apply_proxy_to_http_session(session_obj, proxy_url: str):
    try:
        session_obj.trust_env = False
    except Exception:
        pass

    if not hasattr(session_obj, "proxies"):
        return

    if proxy_url:
        normalized_proxy = proxy_url
        if _HAS_CURL_CFFI and proxy_url.startswith("socks5://"):
            normalized_proxy = "socks5h://" + proxy_url[len("socks5://"):]
        session_obj.proxies = {"http": normalized_proxy, "https": normalized_proxy}
    else:
        session_obj.proxies = {"http": "", "https": ""}


_PROXY_OVERRIDE_SENTINEL = object()


def _resolve_proxy_cfg(cfg: dict, proxy_cfg_override=_PROXY_OVERRIDE_SENTINEL):
    if proxy_cfg_override is _PROXY_OVERRIDE_SENTINEL:
        return cfg.get("proxy")
    return proxy_cfg_override


def _create_chatgpt_http_session(
    cfg: dict,
    user_agent: str = "",
    proxy_cfg_override=_PROXY_OVERRIDE_SENTINEL,
) -> tuple[object, str]:
    proxy_url = _build_proxy_url_from_cfg(_resolve_proxy_cfg(cfg, proxy_cfg_override))

    if _HAS_CURL_CFFI:
        http = CurlCffiSession(impersonate="chrome136")
        _apply_proxy_to_http_session(http, proxy_url)
        if user_agent:
            http.headers.update({"user-agent": user_agent})
        return http, "curl_cffi(chrome136)"

    http = requests.Session()
    _apply_proxy_to_http_session(http, proxy_url)
    if user_agent:
        http.headers.update({"user-agent": user_agent})
    return http, "requests"


def _describe_proxy_cfg(proxy_cfg) -> str:
    proxy_url = _build_proxy_url_from_cfg(proxy_cfg)
    if not proxy_url:
        return "无 (直连)"

    try:
        parsed = urllib.parse.urlsplit(proxy_url)
        host = parsed.hostname or ""
        port = parsed.port
        user = urllib.parse.unquote(parsed.username or "")
        if host:
            desc = f"{host}:{port}" if port else host
            if user:
                desc += f" (user={user})"
            return desc
    except Exception:
        pass
    return proxy_url


def _resolve_stage_proxy_cfg(stage_proxy_cfg: dict | None, stage_name: str):
    if not isinstance(stage_proxy_cfg, dict) or stage_name not in stage_proxy_cfg:
        return _PROXY_OVERRIDE_SENTINEL
    return stage_proxy_cfg.get(stage_name)


@contextmanager
def _http_session_stage_proxy(session_obj, stage_proxy_cfg: dict | None, stage_name: str):
    proxy_cfg = _resolve_stage_proxy_cfg(stage_proxy_cfg, stage_name)
    if proxy_cfg is _PROXY_OVERRIDE_SENTINEL:
        yield
        return

    prev_proxies = dict(getattr(session_obj, "proxies", {}) or {})
    _apply_proxy_to_http_session(session_obj, _build_proxy_url_from_cfg(proxy_cfg))
    _log(f"      [proxy] stage={stage_name} → {_describe_proxy_cfg(proxy_cfg)}")
    try:
        yield
    finally:
        if hasattr(session_obj, "proxies"):
            session_obj.proxies = prev_proxies


def _extract_api_error(resp) -> tuple[str, str]:
    try:
        data = resp.json()
    except Exception:
        return "", ""

    if not isinstance(data, dict):
        return "", ""
    error = data.get("error")
    if not isinstance(error, dict):
        return "", ""
    code = str(error.get("code") or "").strip()
    message = str(error.get("message") or "").strip()
    return code, message


def _resolve_existing_path(path: str, candidates: list[str]) -> str:
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(path or candidates[0] or "")


def _persist_json(path: str, payload: dict):
    if not path:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _build_cfg_with_fresh_auth(
    cfg: dict,
    provisioned_auth: dict,
    *,
    forced_mode: str = "access_token",
    mark_auto_register_used: bool = True,
) -> dict:
    cloned = json.loads(json.dumps(cfg))
    if cfg.get("_loaded_from"):
        cloned["_loaded_from"] = cfg["_loaded_from"]

    fresh_cfg = cloned.setdefault("fresh_checkout", {})
    auth_cfg = fresh_cfg.setdefault("auth", {})
    device_id = (
        provisioned_auth.get("device_id")
        or provisioned_auth.get("oai_device_id")
        or ""
    )
    cookie_header = provisioned_auth.get("cookie_header", "") or ""
    auth_cfg["access_token"] = provisioned_auth.get("access_token", "")
    auth_cfg["session_token"] = provisioned_auth.get("session_token", "")
    auth_cfg["device_id"] = device_id
    auth_cfg["oai_device_id"] = device_id
    auth_cfg["cookie_header"] = cookie_header
    if provisioned_auth.get("openai_sentinel_token"):
        auth_cfg["openai_sentinel_token"] = provisioned_auth.get("openai_sentinel_token", "")
    auth_cfg["mode"] = forced_mode
    auth_cfg["_auto_register_used"] = bool(mark_auto_register_used)
    if provisioned_auth.get("email"):
        auth_cfg["_last_registered_email"] = provisioned_auth["email"]
    return cloned


def _load_existing_auth_from_local_bundle_config(cfg: dict, fresh_cfg: dict) -> dict:
    """从本地 CTF-reg 配置中读取现成登录态。

    目标：
    - 优先复用已经在本地 bundle 中拿到的 `session_token/access_token/device_id`
    - 仅当 bundle 中完全没有可用认证信息，或后续 fresh checkout 返回 401 时，
      再回退到真正的新注册流程
    """
    auth_cfg = fresh_cfg.get("auth") or {}
    auto_cfg = (auth_cfg.get("auto_register") or fresh_cfg.get("auto_register") or {})
    auth_bundle_dir = (
        auto_cfg.get("project_dir")
        or auto_cfg.get("auth_bundle_dir")
        or auto_cfg.get("abcard_dir")
        or "./CTF-reg"
    )
    loaded_from = os.path.dirname(os.path.abspath(cfg.get("_loaded_from") or __file__))
    config_path_raw = (
        auto_cfg.get("config_path")
        or auto_cfg.get("auth_bundle_config")
        or auto_cfg.get("abcard_config")
        or os.path.join(auth_bundle_dir, "config.noproxy.json")
    )
    config_path = _resolve_existing_path(
        config_path_raw,
        [
            config_path_raw if os.path.isabs(config_path_raw) else os.path.join(loaded_from, config_path_raw),
            config_path_raw if os.path.isabs(config_path_raw) else os.path.join(auth_bundle_dir, config_path_raw),
            os.path.join(auth_bundle_dir, "config.noproxy.json"),
            os.path.join(auth_bundle_dir, "config.json"),
            os.path.join(auth_bundle_dir, "config.example.json"),
        ],
    )
    persist_to = (auto_cfg.get("persist_to") or "").strip()
    if persist_to and not os.path.isabs(persist_to):
        persist_to = os.path.abspath(os.path.join(loaded_from, persist_to))

    candidate_paths: list[str] = []
    for candidate in (persist_to, config_path):
        if candidate and candidate not in candidate_paths:
            candidate_paths.append(candidate)

    for candidate_path in candidate_paths:
        if not os.path.exists(candidate_path):
            continue
        try:
            with open(candidate_path, "r", encoding="utf-8") as f:
                bundle_cfg = json.load(f)
        except Exception as e:
            _log(f"      [fresh] 读取本地登录态失败，跳过 {candidate_path}: {e}")
            continue

        access_token = (bundle_cfg.get("access_token") or "").strip()
        session_token = (bundle_cfg.get("session_token") or "").strip()
        device_id = (bundle_cfg.get("device_id") or "").strip()
        cookie_header = (bundle_cfg.get("cookie_header") or "").strip()
        if not cookie_header:
            cookie_header = _compose_cookie_header(
                "",
                session_token=session_token,
                device_id=device_id,
            )

        if not access_token and not session_token:
            continue
        if access_token and _is_access_token_expired(access_token):
            if session_token:
                _log(
                    "      [fresh] 本地 bundle 的 access_token 已过期，"
                    "但检测到 session_token，改为走 session 刷新 ..."
                )
                access_token = ""
            else:
                _log(
                    "      [fresh] 跳过本地现成登录态: "
                    f"{candidate_path} 的 access_token 已过期，且没有 session_token"
                )
                continue

        email = _extract_email_from_access_token(access_token) if access_token else ""
        _log(
            "      [fresh] 检测到本地 bundle 现成登录态: "
            f"config={candidate_path} "
            f"email={email or '?'} "
            f"access_token_len={len(access_token)} "
            f"session_token_len={len(session_token)} "
            f"device_id={'yes' if device_id else 'no'}"
        )
        return {
            "email": email,
            "access_token": access_token,
            "session_token": session_token,
            "device_id": device_id,
            "oai_device_id": device_id,
            "cookie_header": cookie_header,
        }

    return {}


def _provision_openai_auth_via_local_bundle(cfg: dict, fresh_cfg: dict) -> dict:
    auth_cfg = fresh_cfg.get("auth") or {}
    auto_cfg = (auth_cfg.get("auto_register") or fresh_cfg.get("auto_register") or {})
    login_email = (auto_cfg.get("login_email") or "").strip()
    login_password = auto_cfg.get("login_password")
    prefer_existing_account_login = bool(
        auto_cfg.get("prefer_existing_account_login", False) or login_email
    )

    auth_bundle_dir = (
        auto_cfg.get("project_dir")
        or auto_cfg.get("auth_bundle_dir")
        or auto_cfg.get("abcard_dir")
        or "./CTF-reg"
    )
    loaded_from = os.path.dirname(os.path.abspath(cfg.get("_loaded_from") or __file__))
    config_path_raw = (
        auto_cfg.get("config_path")
        or auto_cfg.get("auth_bundle_config")
        or auto_cfg.get("abcard_config")
        or os.path.join(auth_bundle_dir, "config.noproxy.json")
    )
    config_path = _resolve_existing_path(
        config_path_raw,
        [
            config_path_raw if os.path.isabs(config_path_raw) else os.path.join(loaded_from, config_path_raw),
            config_path_raw if os.path.isabs(config_path_raw) else os.path.join(auth_bundle_dir, config_path_raw),
            os.path.join(auth_bundle_dir, "config.noproxy.json"),
            os.path.join(auth_bundle_dir, "config.json"),
            os.path.join(auth_bundle_dir, "config.example.json"),
        ],
    )

    if not os.path.isdir(auth_bundle_dir):
        raise FreshCheckoutAuthError(f"本地认证目录不存在: {auth_bundle_dir}")
    if not os.path.exists(config_path):
        raise FreshCheckoutAuthError(f"本地认证配置不存在: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        ab_cfg = json.load(f)

    # 强制走“新注册拿 fresh token”链路，避免复用已失效凭证。
    if not auto_cfg.get("reuse_existing_auth", False):
        ab_cfg["session_token"] = ""
        ab_cfg["access_token"] = ""
        ab_cfg["device_id"] = ""

    plan_cfg = fresh_cfg.get("plan") or {}
    team_plan = ab_cfg.setdefault("team_plan", {})
    if plan_cfg.get("plan_name"):
        team_plan["plan_name"] = plan_cfg["plan_name"]
    if plan_cfg.get("workspace_name"):
        team_plan["workspace_name"] = plan_cfg["workspace_name"]
    if plan_cfg.get("price_interval"):
        team_plan["price_interval"] = plan_cfg["price_interval"]
    if plan_cfg.get("seat_quantity") is not None:
        team_plan["seat_quantity"] = int(plan_cfg["seat_quantity"])
    if "promo_campaign_id" in plan_cfg and plan_cfg.get("promo_campaign_id") is not None:
        team_plan["promo_campaign_id"] = plan_cfg.get("promo_campaign_id")

    billing = ab_cfg.setdefault("billing", {})
    if plan_cfg.get("billing_country"):
        billing["country"] = str(plan_cfg["billing_country"]).upper()
    if plan_cfg.get("billing_currency"):
        billing["currency"] = str(plan_cfg["billing_currency"]).upper()

    mail_cfg = ab_cfg.setdefault("mail", {})
    # IMAP/SMTP 字段已废弃（OTP 走 CF Email Worker → KV，见 cf_kv_otp_provider）；
    # 这里只保留 catch_all_domain / catch_all_domains / auto_provision。
    for key in ("catch_all_domain", "catch_all_domains", "auto_provision"):
        if key in auto_cfg and auto_cfg.get(key) not in (None, ""):
            mail_cfg[key] = auto_cfg.get(key)
    if isinstance(auto_cfg.get("mail"), dict):
        for key, value in auto_cfg["mail"].items():
            if value not in (None, ""):
                mail_cfg[key] = value

    fresh_proxy_cfg = fresh_cfg["proxy"] if "proxy" in fresh_cfg else _PROXY_OVERRIDE_SENTINEL
    proxy_url = _build_proxy_url_from_cfg(_resolve_proxy_cfg(cfg, fresh_proxy_cfg))
    if auto_cfg.get("use_ctf_proxy", True):
        ab_cfg["proxy"] = proxy_url or ""
    elif auto_cfg.get("proxy") not in (None, ""):
        ab_cfg["proxy"] = auto_cfg.get("proxy")

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    default_env_overrides = {
        "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
        "OAUTH_CODEX_RT_EXCHANGE": "0",
        "OAUTH_SECONDARY_AUTHORIZE_EXCHANGE": "0",
        "OAUTH_EXCHANGE_BEFORE_CALLBACK": "0",
    }
    if auto_cfg.get("auth_http_trace") is not None:
        default_env_overrides["AUTH_HTTP_TRACE"] = "1" if auto_cfg.get("auth_http_trace") else "0"
    if auto_cfg.get("otp_timeout") not in (None, ""):
        default_env_overrides["OTP_TIMEOUT"] = str(auto_cfg.get("otp_timeout"))
    custom_env = auto_cfg.get("env") or {}
    for key, value in {**default_env_overrides, **custom_env}.items():
        if value is None:
            continue
        env[str(key)] = str(value)
    env["LOCALAUTH_PREFER_EXISTING_ACCOUNT_LOGIN"] = "1" if prefer_existing_account_login else "0"
    env["LOCALAUTH_LOGIN_EMAIL"] = login_email
    env["LOCALAUTH_LOGIN_PASSWORD"] = "" if login_password is None else str(login_password)

    script = r"""
import json
import logging
import os
import sys

auth_bundle_dir = sys.argv[1]
config_path = sys.argv[2]
sys.path.insert(0, auth_bundle_dir)

from config import Config
from auth_flow import AuthFlow
from mail_provider import MailProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

cfg = Config.from_file(config_path)
mail = MailProvider(cfg.mail.catch_all_domain)
flow = AuthFlow(cfg)
login_email = (os.getenv("LOCALAUTH_LOGIN_EMAIL") or "").strip()
login_password = os.getenv("LOCALAUTH_LOGIN_PASSWORD", "")
prefer_existing = os.getenv("LOCALAUTH_PREFER_EXISTING_ACCOUNT_LOGIN", "0") == "1"
if prefer_existing and login_email:
    result = flow.run_protocol_login(mail, email=login_email, password=login_password)
else:
    result = flow.run_register(mail)
print("LOCALAUTH_RESULT_JSON=" + json.dumps(result.to_dict(), ensure_ascii=False), flush=True)
"""

    persist_to = auto_cfg.get("persist_to") or ""
    if persist_to and not os.path.isabs(persist_to):
        persist_to = os.path.abspath(os.path.join(loaded_from, persist_to))

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="abcard_register_cfg_",
        delete=False,
        dir="/tmp",
    ) as tmp_cfg:
        json.dump(ab_cfg, tmp_cfg, ensure_ascii=False, indent=2)
        tmp_cfg.write("\n")
        tmp_cfg_path = tmp_cfg.name

    _log(f"      [fresh] 本地注册配置: {config_path}")
    _log(f"      [fresh] 本地认证目录: {auth_bundle_dir}")
    if prefer_existing_account_login and login_email:
        _log(f"      [fresh] 本地认证模式: 协议登录已有账号 ({login_email})")
    else:
        _log("      [fresh] 本地认证模式: 新注册")
    if ab_cfg.get("proxy"):
        _log(f"      [fresh] 本地注册代理: {ab_cfg.get('proxy')}")
    else:
        _log("      [fresh] 本地注册代理: 无 (直连)")

    max_register_attempts = int(auto_cfg.get("max_register_attempts", 3) or 3)
    last_tail_lines: list[str] = []
    child_result = None

    try:
        for attempt in range(1, max_register_attempts + 1):
            if max_register_attempts > 1:
                _log(f"      [fresh] 本地认证尝试 {attempt}/{max_register_attempts} ...")

            proc = subprocess.Popen(
                [sys.executable, "-c", script, auth_bundle_dir, tmp_cfg_path],
                cwd=auth_bundle_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            child_result = None
            tail_lines: list[str] = []
            assert proc.stdout is not None
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                if line.startswith("LOCALAUTH_RESULT_JSON="):
                    payload = line.split("=", 1)[1]
                    try:
                        child_result = json.loads(payload)
                    except Exception as e:
                        raise FreshCheckoutAuthError(f"解析本地注册结果失败: {e}") from e
                    continue
                tail_lines.append(line)
                if len(tail_lines) > 60:
                    tail_lines = tail_lines[-60:]
                _log(f"      [local-auth] {line}")

            rc = proc.wait()
            last_tail_lines = tail_lines
            if rc == 0:
                break

            tail_text = "\n".join(tail_lines).lower()
            retryable = any(
                marker in tail_text
                for marker in (
                    "等待 otp 超时",
                    "timeouterror",
                    "invalid_state",
                    "failed to create account. please try again.",
                    "passwordless 发码失败",
                )
            )
            if attempt < max_register_attempts and retryable:
                _log(
                    "      [fresh] 本地认证本轮失败，但属于可重试场景，"
                    f"准备重新开号重试 ({attempt}/{max_register_attempts}) ..."
                )
                continue

            fallback_auth = _load_existing_auth_from_local_bundle_config(cfg, fresh_cfg)
            if fallback_auth:
                _log(
                    "      [fresh] 本地注册流程失败，"
                    "回退使用 bundle 中现成登录态继续 ..."
                )
                child_result = fallback_auth
                break

            raise FreshCheckoutAuthError(
                "本地注册流程失败"
                + (f" (exit={rc})" if rc else "")
                + (f": {tail_lines[-1]}" if tail_lines else "")
            )
    finally:
        try:
            os.unlink(tmp_cfg_path)
        except Exception:
            pass

    if not isinstance(child_result, dict):
        raise FreshCheckoutAuthError(
            "本地注册流程未返回有效 JSON 结果"
            + (f": {last_tail_lines[-1]}" if last_tail_lines else "")
        )

    access_token = (child_result.get("access_token") or "").strip()
    session_token = (child_result.get("session_token") or "").strip()
    device_id = (child_result.get("device_id") or "").strip()
    if not access_token or not session_token:
        raise FreshCheckoutAuthError("本地注册完成，但未拿到有效 access_token/session_token")

    masked = {
        "email": child_result.get("email", ""),
        "device_id": device_id,
        "access_token_len": len(access_token),
        "session_token_len": len(session_token),
        "cookie_header_len": len((child_result.get("cookie_header") or "").strip()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if persist_to:
        try:
            _persist_json(
                persist_to,
                {
                    **masked,
                    "access_token": access_token,
                    "session_token": session_token,
                    "cookie_header": child_result.get("cookie_header", ""),
                },
            )
            _log(f"      [fresh] 已保存最新本地注册凭证 → {persist_to}")
        except Exception as e:
            _log(f"      [fresh] 保存最新本地注册凭证失败: {e}")

    _log(
        "      [fresh] 本地注册成功: "
        f"email={masked['email']} device_id={device_id} "
        f"access_token_len={masked['access_token_len']} "
        f"session_token_len={masked['session_token_len']} "
        f"cookie_header_len={masked['cookie_header_len']}"
    )
    return child_result


def _browser_tz_offset(locale_profile: dict) -> int:
    """返回与浏览器 `Date.getTimezoneOffset()` 一致的分钟偏移。"""
    tz_name = locale_profile["browser_timezone"]
    now = datetime.now(ZoneInfo(tz_name))
    offset = now.utcoffset()
    if offset is None:
        return 0
    return int(-(offset.total_seconds() // 60))


def _locale_short(locale_profile: dict) -> str:
    return locale_profile["browser_locale"].split("-")[0]


def _accept_language_for_locale(locale_value: str | None) -> str:
    """把 `zh` / `en-US` 之类的 locale 转成更像真实浏览器的 Accept-Language。"""
    normalized = (locale_value or "").strip()
    lowered = normalized.lower()
    if lowered.startswith("zh"):
        return "zh-CN,zh;q=0.9"
    if lowered.startswith("en"):
        return "en-US,en;q=0.9"
    if lowered.startswith("es"):
        return "es-ES,es;q=0.9"
    if normalized:
        short = normalized.split("-")[0]
        return f"{normalized},{short};q=0.9"
    return "en-US,en;q=0.9"


def _browser_like_session_headers(locale_value: str | None) -> dict:
    """补一组更接近 flows 的浏览器请求头。"""
    return {
        "User-Agent": USER_AGENT,
        "Accept-Language": _accept_language_for_locale(locale_value),
        "Sec-CH-UA": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Priority": "u=1, i",
    }


def _should_generate_fresh_checkout(checkout_input: str | None, force_fresh: bool = False) -> bool:
    if force_fresh:
        return True
    normalized = (checkout_input or "").strip().lower()
    return normalized in {"", "fresh", "auto", "new", "generate", "checkout:auto"}


def _cookie_header_from_flow_request(request) -> str:
    cookie_lines = request.headers.get_all("cookie") or []
    if cookie_lines:
        return "; ".join(cookie_lines)
    return request.headers.get("cookie", "")


def _extract_cookie_value(cookie_header: str, name: str) -> str:
    if not cookie_header:
        return ""
    m = re.search(rf"(?:^|;\s*){re.escape(name)}=([^;]+)", cookie_header)
    if not m:
        return ""
    return urllib.parse.unquote(m.group(1))


def _decode_jwt_payload(token: str) -> dict:
    if not token or token.count(".") < 2:
        return {}
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(decoded)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _extract_email_from_access_token(token: str) -> str:
    payload = _decode_jwt_payload(token)
    profile = payload.get("https://api.openai.com/profile", {})
    if isinstance(profile, dict):
        return profile.get("email", "") or ""
    return ""


def _extract_plan_type_from_access_token(token: str) -> str:
    payload = _decode_jwt_payload(token)
    auth_claim = payload.get("https://api.openai.com/auth", {})
    if isinstance(auth_claim, dict):
        return auth_claim.get("chatgpt_plan_type", "") or ""
    return ""


def _is_access_token_expired(token: str, skew_seconds: int = 120) -> bool:
    payload = _decode_jwt_payload(token)
    exp = payload.get("exp")
    try:
        exp_ts = int(exp)
    except Exception:
        return False
    return (time.time() + max(0, int(skew_seconds))) >= exp_ts


def _compose_cookie_header(
    cookie_header: str = "",
    session_token: str = "",
    device_id: str = "",
) -> str:
    cookie_parts = []
    seen = set()

    for raw_part in (cookie_header or "").split(";"):
        part = raw_part.strip()
        if not part or "=" not in part:
            continue
        name = part.split("=", 1)[0].strip()
        if name in seen:
            continue
        seen.add(name)
        cookie_parts.append(part)

    def _append(name: str, value: str):
        if not value or name in seen:
            return
        seen.add(name)
        cookie_parts.append(f"{name}={value}")

    _append("__Secure-next-auth.session-token", session_token)
    _append("oai-did", device_id)
    return "; ".join(cookie_parts)


def _merge_cookie_headers(*cookie_headers: str) -> str:
    merged_parts = []
    seen = set()
    for cookie_header in cookie_headers:
        for raw_part in (cookie_header or "").split(";"):
            part = raw_part.strip()
            if not part or "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            if not name or name in seen:
                continue
            seen.add(name)
            merged_parts.append(part)
    return "; ".join(merged_parts)


def _seed_session_cookies_from_header(session_obj, cookie_header: str, domain: str = ".chatgpt.com"):
    if not cookie_header or not hasattr(session_obj, "cookies"):
        return
    for raw_part in (cookie_header or "").split(";"):
        part = raw_part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not name or not value:
            continue
        try:
            session_obj.cookies.set(name, value, domain=domain)
        except Exception:
            continue


def _cookie_header_from_session(session_obj, domain_keyword: str = "chatgpt.com") -> str:
    if not hasattr(session_obj, "cookies"):
        return ""
    cookie_parts = []
    seen = set()
    try:
        jar_iter = list(session_obj.cookies)
    except Exception:
        jar_iter = []
    for cookie in jar_iter:
        try:
            name = (getattr(cookie, "name", "") or "").strip()
            value = getattr(cookie, "value", "") or ""
            domain = (getattr(cookie, "domain", "") or "").strip().lower()
        except Exception:
            continue
        if not name or not value:
            continue
        if domain_keyword and domain_keyword not in domain:
            continue
        if name in seen:
            continue
        seen.add(name)
        cookie_parts.append(f"{name}={value}")
    return "; ".join(cookie_parts)


def _chatgpt_auth_headers(
    *,
    access_token: str = "",
    cookie_header: str = "",
    user_agent: str = "",
    accept_language: str = "",
    oai_device_id: str = "",
    accept: str = "application/json",
    include_origin: bool = False,
) -> dict:
    headers = {
        "user-agent": user_agent or USER_AGENT,
        "accept": accept,
        "accept-language": accept_language or "en-US,en;q=0.9",
        "referer": "https://chatgpt.com/",
    }
    if include_origin:
        headers["origin"] = "https://chatgpt.com"
    if access_token:
        headers["authorization"] = f"Bearer {access_token}"
    if cookie_header:
        headers["cookie"] = cookie_header
    if oai_device_id:
        headers["oai-device-id"] = oai_device_id
    return headers


def _warm_chatgpt_checkout_context(
    session_obj,
    *,
    access_token: str,
    session_token: str,
    cookie_header: str,
    user_agent: str,
    accept_language: str,
    locale_profile: dict,
    oai_device_id: str,
    billing_country: str,
    include_home_bounce: bool = True,
) -> dict:
    """
    在 fresh checkout 之前补齐 flows 中真实出现的 ChatGPT 侧预热请求：
    - 首页 / auth/session
    - accounts/check
    - domain-density-eligibility
    - checkout_pricing_config
    - （可选）home 页面的一组后台接口

    目的不是“证明本地像浏览器”，而是尽量补齐服务端在生成 checkout 前
    依赖的 cookie / eligibility / pricing 上下文。
    """
    if not access_token:
        return {
            "cookie_header": cookie_header,
            "session_token": session_token,
            "access_token": access_token,
            "device_id": oai_device_id,
        }

    _seed_session_cookies_from_header(session_obj, cookie_header, domain=".chatgpt.com")
    billing_country = str(billing_country or "US").upper()
    tz_offset = _browser_tz_offset(locale_profile)

    def _merged_cookie() -> str:
        return _merge_cookie_headers(cookie_header, _cookie_header_from_session(session_obj, "chatgpt.com"))

    def _session_cookie(name: str) -> str:
        try:
            return session_obj.cookies.get(name, "")
        except Exception:
            return ""

    auth_session_data = {}
    domain_density_data = {}
    warm_steps = [
        (
            "home",
            "GET",
            "https://chatgpt.com/",
            None,
            _chatgpt_auth_headers(
                access_token=access_token,
                cookie_header=_merged_cookie(),
                user_agent=user_agent,
                accept_language=accept_language,
                oai_device_id=oai_device_id,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            ),
        ),
        (
            "auth_session",
            "GET",
            "https://chatgpt.com/api/auth/session",
            None,
            _chatgpt_auth_headers(
                cookie_header=_merged_cookie(),
                user_agent=user_agent,
                accept_language=accept_language,
                oai_device_id=oai_device_id,
                accept="application/json",
            ),
        ),
        (
            "accounts_check",
            "GET",
            f"https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min={tz_offset}",
            None,
            _chatgpt_auth_headers(
                access_token=access_token,
                cookie_header=_merged_cookie(),
                user_agent=user_agent,
                accept_language=accept_language,
                oai_device_id=oai_device_id,
                accept="application/json",
                include_origin=True,
            ),
        ),
        (
            "domain_density",
            "GET",
            "https://chatgpt.com/backend-api/accounts/domain-density-eligibility",
            None,
            _chatgpt_auth_headers(
                access_token=access_token,
                cookie_header=_merged_cookie(),
                user_agent=user_agent,
                accept_language=accept_language,
                oai_device_id=oai_device_id,
                accept="application/json",
                include_origin=True,
            ),
        ),
        (
            "pricing_countries",
            "GET",
            "https://chatgpt.com/backend-api/checkout_pricing_config/countries",
            None,
            _chatgpt_auth_headers(
                access_token=access_token,
                cookie_header=_merged_cookie(),
                user_agent=user_agent,
                accept_language=accept_language,
                oai_device_id=oai_device_id,
                accept="application/json",
                include_origin=True,
            ),
        ),
        (
            "pricing_config",
            "GET",
            f"https://chatgpt.com/backend-api/checkout_pricing_config/configs/{billing_country}",
            None,
            _chatgpt_auth_headers(
                access_token=access_token,
                cookie_header=_merged_cookie(),
                user_agent=user_agent,
                accept_language=accept_language,
                oai_device_id=oai_device_id,
                accept="application/json",
                include_origin=True,
            ),
        ),
    ]

    if include_home_bounce:
        warm_steps.extend(
            [
                (
                    "conversation_init",
                    "POST",
                    "https://chatgpt.com/backend-api/conversation/init",
                    {
                        "gizmo_id": None,
                        "requested_default_model": None,
                        "conversation_id": None,
                        "timezone_offset_min": tz_offset,
                    },
                    _chatgpt_auth_headers(
                        access_token=access_token,
                        cookie_header=_merged_cookie(),
                        user_agent=user_agent,
                        accept_language=accept_language,
                        oai_device_id=oai_device_id,
                        accept="application/json",
                        include_origin=True,
                    ) | {"content-type": "application/json"},
                ),
                (
                    "sources_dropdown",
                    "GET",
                    "https://chatgpt.com/backend-api/apps/sources_dropdown",
                    None,
                    _chatgpt_auth_headers(
                        access_token=access_token,
                        cookie_header=_merged_cookie(),
                        user_agent=user_agent,
                        accept_language=accept_language,
                        oai_device_id=oai_device_id,
                        accept="application/json",
                        include_origin=True,
                    ),
                ),
                (
                    "user_segments",
                    "GET",
                    "https://chatgpt.com/backend-api/user_segments",
                    None,
                    _chatgpt_auth_headers(
                        access_token=access_token,
                        cookie_header=_merged_cookie(),
                        user_agent=user_agent,
                        accept_language=accept_language,
                        oai_device_id=oai_device_id,
                        accept="application/json",
                        include_origin=True,
                    ),
                ),
                (
                    "beacons_home",
                    "GET",
                    "https://chatgpt.com/backend-api/beacons/home",
                    None,
                    _chatgpt_auth_headers(
                        access_token=access_token,
                        cookie_header=_merged_cookie(),
                        user_agent=user_agent,
                        accept_language=accept_language,
                        oai_device_id=oai_device_id,
                        accept="application/json",
                        include_origin=True,
                    ),
                ),
                (
                    "realtime_status",
                    "POST",
                    "https://chatgpt.com/realtime/status",
                    {
                        "conversation_id": None,
                        "requested_voice_mode": "advanced",
                        "gizmo_id": None,
                        "voice": "cove",
                        "requested_default_model": "auto",
                        "timezone_offset_min": tz_offset,
                        "nonce": oai_device_id,
                        "voice_status_request_id": str(uuid.uuid4()).upper(),
                    },
                    _chatgpt_auth_headers(
                        access_token=access_token,
                        cookie_header=_merged_cookie(),
                        user_agent=user_agent,
                        accept_language=accept_language,
                        oai_device_id=oai_device_id,
                        accept="application/json",
                        include_origin=True,
                    ) | {"content-type": "application/json"},
                ),
            ]
        )

    before_names = {
        part.split("=", 1)[0].strip()
        for part in (cookie_header or "").split(";")
        if "=" in part
    }

    _log("      [fresh] 预热 ChatGPT 结账上下文 ...")
    for step_name, method, url, payload, headers in warm_steps:
        try:
            if method == "GET":
                resp = session_obj.get(url, headers=headers, timeout=20)
            else:
                resp = session_obj.post(url, headers=headers, json=payload, timeout=20)
            _log(f"      [fresh:warm] {step_name} → {resp.status_code}")
            if step_name == "auth_session" and resp.status_code == 200:
                try:
                    auth_session_data = resp.json() if resp is not None else {}
                except Exception:
                    auth_session_data = {}
            elif step_name == "domain_density":
                try:
                    domain_density_data = resp.json() if resp is not None else {}
                except Exception:
                    domain_density_data = {}
        except Exception as e:
            _log(f"      [fresh:warm] {step_name} 异常: {e}")

    warmed_cookie = _merge_cookie_headers(cookie_header, _cookie_header_from_session(session_obj, "chatgpt.com"))
    warmed_session_token = (
        _extract_cookie_value(warmed_cookie, "__Secure-next-auth.session-token")
        or _session_cookie("__Secure-next-auth.session-token")
        or session_token
    )
    warmed_device_id = (
        _extract_cookie_value(warmed_cookie, "oai-did")
        or _session_cookie("oai-did")
        or oai_device_id
    )
    warmed_access_token = (
        (auth_session_data.get("accessToken") or "").strip()
        if isinstance(auth_session_data, dict)
        else ""
    ) or access_token

    after_names = {
        part.split("=", 1)[0].strip()
        for part in warmed_cookie.split(";")
        if "=" in part
    }
    added_names = sorted(name for name in after_names - before_names if name)
    if added_names:
        _log(f"      [fresh:warm] 新增 cookies: {', '.join(added_names)}")
    if isinstance(domain_density_data, dict) and domain_density_data:
        _log(
            "      [fresh:warm] domain-density: "
            f"eligible={domain_density_data.get('eligible')} "
            f"domain_user_count={domain_density_data.get('domain_user_count')}"
        )

    return {
        "cookie_header": warmed_cookie,
        "session_token": warmed_session_token,
        "access_token": warmed_access_token,
        "device_id": warmed_device_id,
        "oai_device_id": warmed_device_id,
        "domain_density": domain_density_data,
    }


def _extract_checkout_identifiers(data: dict) -> tuple[str, str, str]:
    cs_id = (data.get("checkout_session_id") or data.get("session_id") or "").strip()
    processor_entity = (data.get("processor_entity") or "").strip()
    checkout_url = (
        data.get("checkout_url")
        or data.get("url")
        or data.get("openai_checkout_url")
        or ""
    ).strip()

    candidate_texts = [
        checkout_url,
        data.get("success_url", ""),
        data.get("cancel_url", ""),
        data.get("return_url", ""),
        data.get("client_secret", ""),
    ]

    if not cs_id:
        for text in candidate_texts:
            m = re.search(r"(cs_(?:live|test)_[A-Za-z0-9]+)", text or "")
            if m:
                cs_id = m.group(1)
                break

    if not processor_entity:
        for text in candidate_texts:
            m = re.search(r"/checkout/([^/]+)/cs_(?:live|test)_[A-Za-z0-9]+", text or "")
            if m:
                processor_entity = m.group(1)
                break
        if not processor_entity:
            m = re.search(r"processor_entity=([A-Za-z0-9_]+)", " ".join(candidate_texts))
            if m:
                processor_entity = m.group(1)

    if not checkout_url and cs_id and processor_entity:
        checkout_url = f"https://chatgpt.com/checkout/{processor_entity}/{cs_id}"

    return cs_id, processor_entity, checkout_url


def _select_fresh_checkout_url(
    *,
    provider_url: str,
    canonical_url: str,
    fresh_cfg: dict,
    checkout_payload: dict,
) -> str:
    """Choose which checkout URL should be exposed to callers.

    ChatGPT's checkout API may return a provider/hosted URL (for example the
    long hosted checkout URL) while the automation can also reconstruct the
    canonical in-app URL:

        https://chatgpt.com/checkout/{processor_entity}/{cs_live...}

    Historically we always rewrote the API response to the canonical URL. That
    is correct for embedded/custom checkout replay, but it hides the real
    hosted/long link when the request was created with hosted checkout mode.

    Selection is config driven:
      - fresh_checkout.output_url_mode or fresh_checkout.plan.output_url_mode
        can be provider/raw/long/hosted or canonical/chatgpt/short.
      - If omitted, checkout_ui_mode=hosted defaults to provider; everything
        else defaults to canonical.
    """

    provider_url = (provider_url or "").strip()
    canonical_url = (canonical_url or "").strip()
    plan_cfg = fresh_cfg.get("plan") or {}
    explicit_mode = str(
        plan_cfg.get("output_url_mode")
        or fresh_cfg.get("output_url_mode")
        or ""
    ).strip().lower()
    checkout_ui_mode = str(
        plan_cfg.get("checkout_ui_mode")
        or checkout_payload.get("checkout_ui_mode")
        or ""
    ).strip().lower()

    provider_modes = {"provider", "raw", "long", "hosted", "pay_openai", "pay.openai.com"}
    canonical_modes = {"canonical", "chatgpt", "short", "custom", "embedded"}

    if explicit_mode in provider_modes:
        return provider_url or canonical_url
    if explicit_mode in canonical_modes:
        return canonical_url or provider_url

    if checkout_ui_mode in {"hosted", "hosted_checkout", "redirect"}:
        return provider_url or canonical_url
    return canonical_url or provider_url


def _extract_checkout_totals(payload: dict | None) -> dict:
    payload = payload or {}
    total_summary = payload.get("total_summary") or {}
    invoice = payload.get("invoice") or {}

    def _to_int(value):
        if value in (None, ""):
            return None
        try:
            return int(value)
        except Exception:
            return None

    return {
        "due": _to_int(total_summary.get("due", invoice.get("amount_due"))),
        "subtotal": _to_int(total_summary.get("subtotal", invoice.get("subtotal"))),
        "total": _to_int(total_summary.get("total", invoice.get("total"))),
        "currency": (
            payload.get("currency")
            or invoice.get("currency")
            or ""
        ).lower(),
    }


def _resolve_expected_checkout_due(fresh_cfg: dict) -> int | None:
    candidates = [
        fresh_cfg.get("expected_due"),
        ((fresh_cfg.get("pricing_expectation") or {}).get("expected_due")),
    ]
    for candidate in candidates:
        if candidate in (None, ""):
            continue
        try:
            return int(candidate)
        except Exception:
            raise FreshCheckoutAuthError(f"expected_due 配置非法: {candidate!r}")
    return None


def _check_coupon_eligibility(
    session_obj,
    *,
    access_token: str,
    cookie_header: str,
    user_agent: str,
    accept_language: str,
    oai_device_id: str,
    coupon: str,
    is_coupon_from_query_param: bool,
    referer_url: str = "",
) -> dict:
    if not coupon:
        return {}

    url = "https://chatgpt.com/backend-api/promo_campaign/check_coupon"
    params = {
        "coupon": coupon,
        "is_coupon_from_query_param": "true" if is_coupon_from_query_param else "false",
    }
    headers = _chatgpt_auth_headers(
        access_token=access_token,
        cookie_header=cookie_header,
        user_agent=user_agent,
        accept_language=accept_language,
        oai_device_id=oai_device_id,
        accept="application/json",
        include_origin=True,
    )
    headers["referer"] = referer_url or "https://chatgpt.com/"

    _log_request("GET", url, params=params, tag="[fresh] check_coupon")
    try:
        resp = session_obj.get(url, params=params, headers=headers, timeout=20)
    except Exception as e:
        _log(f"      [fresh] check_coupon 异常: {e}")
        return {}

    _log_response(resp, tag="[fresh] check_coupon")
    if resp.status_code != 200:
        _log(f"      [fresh] check_coupon 非 200: {resp.status_code}")
        return {}

    try:
        data = resp.json()
    except Exception as e:
        _log(f"      [fresh] check_coupon JSON 解析失败: {e}")
        return {}

    redemption = data.get("redemption") or {}
    _log(
        "      [fresh] check_coupon: "
        f"state={data.get('state')} "
        f"user_redeemed={redemption.get('redeemed_by_user')} "
        f"workspace_redeemed={redemption.get('redeemed_by_workspace')}"
    )
    return data if isinstance(data, dict) else {}


def _is_checkout_inactive_text(text: str) -> bool:
    lower = (text or "").lower()
    markers = (
        "checkout_not_active_session",
        "this checkout session is no longer active",
        "checkout session is no longer active",
        "session is no longer active",
    )
    return any(marker in lower for marker in markers)


def _raise_if_checkout_inactive_response(resp: requests.Response, context: str):
    if _is_checkout_inactive_text(resp.text):
        try:
            payload = resp.json()
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            message = error.get("message") or resp.text[:300]
        except Exception:
            message = resp.text[:300]
        raise CheckoutSessionInactive(f"{context}: {message}")


def _load_fresh_checkout_bootstrap(flows_path: str) -> dict:
    try:
        from mitmproxy.io import FlowReader
    except Exception as e:
        raise FreshCheckoutAuthError(f"读取 flows 需要 mitmproxy: {e}") from e

    if not os.path.exists(flows_path):
        raise FreshCheckoutAuthError(f"flows 不存在: {flows_path}")

    latest_auth = None
    latest_checkout = None
    latest_sentinel = None

    with open(flows_path, "rb") as f:
        for idx, flow in enumerate(FlowReader(f).stream()):
            req = getattr(flow, "request", None)
            if not req or req.host != "chatgpt.com":
                continue

            base_url = req.pretty_url.split("?", 1)[0]
            if req.method == "GET" and base_url == "https://chatgpt.com/api/auth/session":
                latest_auth = (idx, flow)
                continue

            if req.method == "POST" and base_url == "https://chatgpt.com/backend-api/payments/checkout":
                latest_checkout = (idx, flow)
                continue

            if req.method == "POST" and base_url == "https://chatgpt.com/backend-api/sentinel/req":
                try:
                    body = json.loads(req.get_text(strict=False) or "{}")
                except Exception:
                    body = {}
                if body.get("flow") == "chatgpt_checkout":
                    latest_sentinel = (idx, flow)

    if not latest_checkout:
        raise FreshCheckoutAuthError("flows 中未找到 /backend-api/payments/checkout 请求")

    checkout_req = latest_checkout[1].request
    checkout_resp = latest_checkout[1].response
    checkout_body = {}
    try:
        checkout_body = json.loads(checkout_req.get_text(strict=False) or "{}")
    except Exception:
        checkout_body = {}

    checkout_resp_json = {}
    try:
        checkout_resp_json = checkout_resp.json() if checkout_resp else {}
    except Exception:
        checkout_resp_json = {}

    auth_req = latest_auth[1].request if latest_auth else checkout_req
    sentinel_req = latest_sentinel[1].request if latest_sentinel else None

    cookie_header = _cookie_header_from_flow_request(checkout_req)
    bootstrap = {
        "flows_path": flows_path,
        "cookie_header": cookie_header,
        "user_agent": checkout_req.headers.get("user-agent")
        or auth_req.headers.get("user-agent")
        or USER_AGENT,
        "accept_language": checkout_req.headers.get("accept-language")
        or auth_req.headers.get("accept-language")
        or "zh-CN,zh;q=0.9",
        "oai_language": checkout_req.headers.get("oai-language", ""),
        "oai_device_id": checkout_req.headers.get("oai-device-id")
        or auth_req.headers.get("oai-device-id")
        or _extract_cookie_value(cookie_header, "oai-did"),
        "oai_client_version": checkout_req.headers.get("oai-client-version", ""),
        "oai_client_build_number": checkout_req.headers.get("oai-client-build-number", ""),
        "openai_sentinel_token": checkout_req.headers.get("openai-sentinel-token", ""),
        "checkout_body": checkout_body,
        "checkout_response": checkout_resp_json,
    }

    if sentinel_req is not None:
        bootstrap["sentinel_url"] = sentinel_req.pretty_url
        bootstrap["sentinel_body"] = sentinel_req.get_text(strict=False) or ""
        bootstrap["sentinel_headers"] = {
            "content-type": sentinel_req.headers.get("content-type", "text/plain;charset=UTF-8"),
            "origin": sentinel_req.headers.get("origin", "https://chatgpt.com"),
            "referer": sentinel_req.headers.get(
                "referer",
                "https://chatgpt.com/backend-api/sentinel/frame.html",
            ),
            "user-agent": sentinel_req.headers.get("user-agent") or bootstrap["user_agent"],
            "accept-language": sentinel_req.headers.get("accept-language", bootstrap["accept_language"]),
            "sec-ch-ua": sentinel_req.headers.get("sec-ch-ua", ""),
            "sec-ch-ua-mobile": sentinel_req.headers.get("sec-ch-ua-mobile", ""),
            "sec-ch-ua-platform": sentinel_req.headers.get("sec-ch-ua-platform", ""),
            "oai-device-id": sentinel_req.headers.get("oai-device-id", bootstrap["oai_device_id"]),
        }

    return bootstrap


def _build_abcard_checkout_payload(fresh_cfg: dict) -> dict:
    plan_cfg = fresh_cfg.get("plan") or {}
    billing_country = str(plan_cfg.get("billing_country") or "US").upper()
    payload = {
        "plan_type": plan_cfg.get("plan_name") or "chatgptteamplan",
        "payment_lower_bound_amount_cents": int(
            plan_cfg.get("payment_lower_bound_amount_cents", 0) or 0
        ),
        "payment_upper_bound_amount_cents": int(
            plan_cfg.get("payment_upper_bound_amount_cents", 100000) or 100000
        ),
        "billing_country_code": billing_country,
        "billing_currency_code": str(plan_cfg.get("billing_currency") or "USD").upper(),
        "workspace_name": str(plan_cfg.get("workspace_name") or "MyWorkspace"),
        "seat_quantity": int(plan_cfg.get("seat_quantity", 5) or 5),
    }
    promo_campaign_id = plan_cfg.get("promo_campaign_id")
    if promo_campaign_id:
        payload["promo_campaign_id"] = promo_campaign_id
    # 非 US 国家强制指定 processor_entity 为 openai_ie（爱尔兰实体）
    processor_entity = plan_cfg.get("processor_entity", "")
    if not processor_entity and billing_country != "US":
        processor_entity = "openai_ie"
    if processor_entity:
        payload["processor_entity"] = processor_entity
    return payload


def _build_fresh_checkout_body(fresh_cfg: dict, bootstrap: dict) -> dict:
    base = json.loads(json.dumps(bootstrap.get("checkout_body") or {}))
    plan_cfg = fresh_cfg.get("plan") or {}

    plan_name = plan_cfg.get("plan_name") or (base.get("plan_name") if base else None) or "chatgptteamplan"
    is_plus = "plus" in str(plan_name).lower()
    default_entry = "all_plans_pricing_modal" if is_plus else "team_workspace_purchase_modal"

    if not base:
        base = {
            "entry_point": default_entry,
            "plan_name": plan_name,
            "billing_details": {
                "country": "US",
                "currency": "USD",
            },
            "cancel_url": "https://chatgpt.com/#pricing",
            "checkout_ui_mode": "custom",
            "promo_campaign": {
                "promo_campaign_id": "plus-1-month-free" if is_plus else "team-1-month-free",
                "is_coupon_from_query_param": False,
            },
        }
        if not is_plus:
            base["team_plan_data"] = {
                "workspace_name": "MyWorkspace",
                "price_interval": "month",
                "seat_quantity": 5,
            }

    if plan_cfg.get("entry_point"):
        base["entry_point"] = plan_cfg["entry_point"]
    base.setdefault("entry_point", default_entry)

    if plan_cfg.get("plan_name"):
        base["plan_name"] = plan_cfg["plan_name"]
    base.setdefault("plan_name", plan_name)

    if is_plus:
        # Plus 没有 workspace/seat 概念，删掉防止后端拒绝
        base.pop("team_plan_data", None)
    else:
        team_plan_data = dict(base.get("team_plan_data") or {})
        if plan_cfg.get("workspace_name"):
            team_plan_data["workspace_name"] = str(plan_cfg["workspace_name"])
        team_plan_data.setdefault("workspace_name", "MyWorkspace")
        if plan_cfg.get("price_interval"):
            team_plan_data["price_interval"] = plan_cfg["price_interval"]
        team_plan_data.setdefault("price_interval", "month")
        if "seat_quantity" in plan_cfg and plan_cfg["seat_quantity"] is not None:
            team_plan_data["seat_quantity"] = int(plan_cfg["seat_quantity"])
        team_plan_data.setdefault("seat_quantity", 5)
        base["team_plan_data"] = team_plan_data

    billing_details = dict(base.get("billing_details") or {})
    if plan_cfg.get("billing_country"):
        billing_details["country"] = str(plan_cfg["billing_country"]).upper()
    billing_details.setdefault("country", "US")
    if plan_cfg.get("billing_currency"):
        billing_details["currency"] = str(plan_cfg["billing_currency"]).upper()
    billing_details.setdefault("currency", "USD")
    base["billing_details"] = billing_details

    base["cancel_url"] = plan_cfg.get("cancel_url") or base.get("cancel_url") or "https://chatgpt.com/#pricing"
    base["checkout_ui_mode"] = (
        plan_cfg.get("checkout_ui_mode")
        or base.get("checkout_ui_mode")
        or "custom"
    )

    promo_campaign_id = plan_cfg.get("promo_campaign_id")
    if promo_campaign_id == "":
        base.pop("promo_campaign", None)
    else:
        promo_campaign = dict(base.get("promo_campaign") or {})
        effective_promo_id = promo_campaign_id or promo_campaign.get("promo_campaign_id")
        if effective_promo_id:
            promo_campaign["promo_campaign_id"] = effective_promo_id
            promo_campaign["is_coupon_from_query_param"] = bool(
                plan_cfg.get(
                    "is_coupon_from_query_param",
                    promo_campaign.get("is_coupon_from_query_param", False),
                )
            )
            base["promo_campaign"] = promo_campaign

    return base


def _fetch_auth_session_with_cookie(
    session: requests.Session,
    cookie_header: str,
    user_agent: str,
    accept_language: str,
) -> dict:
    if not cookie_header:
        return {}
    auth_headers = {
        "user-agent": user_agent,
        "accept": "application/json",
        "referer": "https://chatgpt.com/",
        "accept-language": accept_language,
        "cookie": cookie_header,
    }
    resp = session.get("https://chatgpt.com/api/auth/session", headers=auth_headers, timeout=30)
    if resp.status_code != 200:
        raise FreshCheckoutAuthError(
            f"/api/auth/session 失败 [{resp.status_code}]: {resp.text[:300]}"
        )
    try:
        data = resp.json()
    except Exception as e:
        raise FreshCheckoutAuthError(f"/api/auth/session JSON 解析失败: {e}") from e
    return data if isinstance(data, dict) else {}


def _refresh_openai_sentinel_token(session: requests.Session, cookie_header: str, bootstrap: dict) -> str:
    sentinel_url = bootstrap.get("sentinel_url")
    sentinel_body = bootstrap.get("sentinel_body")
    if not sentinel_url or not sentinel_body:
        return bootstrap.get("openai_sentinel_token", "")

    headers = {
        k: v
        for k, v in (bootstrap.get("sentinel_headers") or {}).items()
        if v
    }
    headers["cookie"] = cookie_header

    _log("      [fresh] 刷新 openai-sentinel-token ...")
    resp = session.post(sentinel_url, headers=headers, data=sentinel_body, timeout=30)
    if resp.status_code != 200:
        _log(f"      [fresh] sentinel/req 失败 [{resp.status_code}]，回退使用 bootstrap token")
        return bootstrap.get("openai_sentinel_token", "")

    try:
        data = resp.json()
    except Exception as e:
        _log(f"      [fresh] sentinel/req JSON 解析失败: {e}，回退使用 bootstrap token")
        return bootstrap.get("openai_sentinel_token", "")

    token = data.get("token", "")
    if token:
        _log(f"      [fresh] sentinel token 已刷新 ({len(token)} chars)")
        return token

    _log("      [fresh] sentinel/req 未返回 token，回退使用 bootstrap token")
    return bootstrap.get("openai_sentinel_token", "")


def generate_fresh_checkout(
    session: requests.Session,
    cfg: dict,
    locale_profile: dict | None = None,
) -> dict:
    fresh_cfg = cfg.get("fresh_checkout") or {}
    if not fresh_cfg.get("enabled", False):
        raise FreshCheckoutAuthError("fresh_checkout 未启用")

    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    cfg_dir = os.path.dirname(os.path.abspath(cfg.get("_loaded_from") or __file__))
    auth_cfg = fresh_cfg.get("auth") or {}
    fresh_proxy_cfg = fresh_cfg["proxy"] if "proxy" in fresh_cfg else _PROXY_OVERRIDE_SENTINEL
    auto_register_cfg = (auth_cfg.get("auto_register") or fresh_cfg.get("auto_register") or {})
    auth_mode = (auth_cfg.get("mode") or "").strip().lower()
    request_style = (fresh_cfg.get("request_style") or "").strip().lower()
    access_token = (auth_cfg.get("access_token") or "").strip()
    session_token = (auth_cfg.get("session_token") or "").strip()
    bootstrap_cookie_header = (auth_cfg.get("cookie_header") or "").strip()
    oai_device_id = (
        (auth_cfg.get("device_id") or "").strip()
        or (auth_cfg.get("oai_device_id") or "").strip()
    )
    auto_register_enabled = bool(
        auto_register_cfg.get("enabled", False)
        or auth_mode in {"auto_register", "register", "abcard_register", "abcard_auth"}
    )
    auto_register_forced = auth_mode in {"auto_register", "register", "abcard_register", "abcard_auth"}
    auto_register_used = bool(auth_cfg.get("_auto_register_used", False))

    if not any((access_token, session_token, bootstrap_cookie_header)) and not auto_register_used:
        prefer_existing_bundle_auth = auto_register_cfg.get("prefer_existing_bundle_auth")
        if prefer_existing_bundle_auth is None:
            prefer_existing_bundle_auth = True
        if prefer_existing_bundle_auth:
            existing_bundle_auth = _load_existing_auth_from_local_bundle_config(cfg, fresh_cfg)
            if existing_bundle_auth:
                _log("[0/6] 自动复用本地 bundle 现成登录态生成 fresh checkout ...")
                refreshed_cfg = _build_cfg_with_fresh_auth(
                    cfg,
                    existing_bundle_auth,
                    forced_mode="access_token",
                    mark_auto_register_used=False,
                )
                return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)

    if auto_register_forced and not auto_register_used:
        prefer_existing_bundle_auth = auto_register_cfg.get("prefer_existing_bundle_auth")
        if prefer_existing_bundle_auth is None:
            prefer_existing_bundle_auth = True
        if prefer_existing_bundle_auth:
            existing_bundle_auth = _load_existing_auth_from_local_bundle_config(cfg, fresh_cfg)
            if existing_bundle_auth:
                _log("[0/6] 优先复用本地 bundle 现成登录态生成 fresh checkout ...")
                refreshed_cfg = _build_cfg_with_fresh_auth(
                    cfg,
                    existing_bundle_auth,
                    forced_mode="access_token",
                    mark_auto_register_used=False,
                )
                return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)

        _log("[0/6] 先通过本地注册流程获取 fresh 登录态 ...")
        provisioned_auth = _provision_openai_auth_via_local_bundle(cfg, fresh_cfg)
        refreshed_cfg = _build_cfg_with_fresh_auth(
            cfg,
            provisioned_auth,
            forced_mode="access_token",
            mark_auto_register_used=True,
        )
        return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)

    if not auth_mode:
        auth_mode = "access_token" if (access_token or session_token or bootstrap_cookie_header) else "flows"
    if not request_style:
        request_style = "abcard" if auth_mode == "access_token" else "modern"

    bootstrap = {}
    should_load_bootstrap = bool(
        fresh_cfg.get("bootstrap_from_flows", True)
        and (
            auth_mode == "flows"
            or fresh_cfg.get("use_flows_for_templates", False)
            or request_style in {"modern", "flow"}
        )
    )

    flows_path = fresh_cfg.get("flows_path", "../flows")
    if should_load_bootstrap:
        if not os.path.isabs(flows_path):
            candidate_paths = [
                os.path.abspath(os.path.join(cfg_dir, flows_path)),
                os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), flows_path)),
                os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "flows")),
            ]
            flows_path = next((path for path in candidate_paths if os.path.exists(path)), candidate_paths[0])
        _log("[0/6] 生成 fresh checkout（flows 模板 / access_token 模式） ...")
        _log(f"      [fresh] bootstrap flows: {flows_path}")
        bootstrap = _load_fresh_checkout_bootstrap(flows_path)
    else:
        _log("[0/6] 生成 fresh checkout（access_token 模式） ...")

    cookie_header = _compose_cookie_header(
        bootstrap_cookie_header or bootstrap.get("cookie_header", ""),
        session_token=session_token,
        device_id=oai_device_id or bootstrap.get("oai_device_id", ""),
    )
    user_agent = auth_cfg.get("user_agent") or bootstrap.get("user_agent") or USER_AGENT
    accept_language = (
        auth_cfg.get("accept_language")
        or bootstrap.get("accept_language")
        or _accept_language_for_locale(locale_profile["browser_locale"])
    )
    oai_device_id = (
        oai_device_id
        or bootstrap.get("oai_device_id")
        or _extract_cookie_value(cookie_header, "oai-did")
        or str(uuid.uuid4())
    )
    cookie_header = _compose_cookie_header(
        cookie_header,
        session_token=session_token,
        device_id=oai_device_id,
    )
    chatgpt_http, fresh_transport = _create_chatgpt_http_session(
        cfg,
        user_agent=user_agent,
        proxy_cfg_override=fresh_proxy_cfg,
    )
    _log(f"      [fresh] ChatGPT transport: {fresh_transport}")
    resolved_fresh_proxy_url = _build_proxy_url_from_cfg(_resolve_proxy_cfg(cfg, fresh_proxy_cfg))
    if resolved_fresh_proxy_url:
        _log(f"      [fresh] ChatGPT proxy: {resolved_fresh_proxy_url}")
    elif fresh_proxy_cfg is not _PROXY_OVERRIDE_SENTINEL:
        _log("      [fresh] ChatGPT proxy: 无 (fresh_checkout.proxy 显式直连)")

    auth_data = {}
    prefer_session_refresh = bool(auth_cfg.get("prefer_session_refresh", True))
    if session_token and prefer_session_refresh:
        _log("      [fresh] 使用 session_token 刷新 access_token (/api/auth/session) ...")
        try:
            auth_data = _fetch_auth_session_with_cookie(
                chatgpt_http,
                cookie_header=cookie_header,
                user_agent=user_agent,
                accept_language=accept_language,
            )
            refreshed_access_token = (auth_data.get("accessToken") or "").strip()
            if refreshed_access_token:
                access_token = refreshed_access_token
                _log("      [fresh] access_token 已通过 session_token 刷新")
        except Exception as e:
            _log(f"      [fresh] session_token 刷新 access_token 失败: {e}")
    elif (not access_token) and cookie_header:
        _log("      [fresh] 通过 cookie / session 获取 access_token (/api/auth/session) ...")
        auth_data = _fetch_auth_session_with_cookie(
            chatgpt_http,
            cookie_header=cookie_header,
            user_agent=user_agent,
            accept_language=accept_language,
        )
        access_token = (auth_data.get("accessToken") or "").strip()

    if not access_token:
        if auto_register_enabled and not auto_register_used:
            _log("      [fresh] 未拿到可用 access_token，尝试通过本地注册流程新开号 ...")
            provisioned_auth = _provision_openai_auth_via_local_bundle(cfg, fresh_cfg)
            refreshed_cfg = _build_cfg_with_fresh_auth(cfg, provisioned_auth)
            return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)
        raise FreshCheckoutAuthError(
            "未提供 fresh_checkout.auth.access_token，且也无法通过 session_token/cookie 刷新"
        )

    user_email = (auth_data.get("user") or {}).get("email", "") or _extract_email_from_access_token(access_token) or "?"
    plan_type = (auth_data.get("account") or {}).get("planType", "") or _extract_plan_type_from_access_token(access_token) or "?"
    _log(
        "      [fresh] 凭证来源: "
        f"access_token={'yes' if access_token else 'no'} "
        f"session_token={'yes' if session_token else 'no'} "
        f"cookie={'yes' if cookie_header else 'no'}"
    )
    _log(f"      [fresh] 当前账号: {user_email}  |  planType={plan_type}")
    # 保存到上下文供后续记录
    fresh_cfg["_chatgpt_email"] = user_email

    attempt_specs = []
    plan_cfg = fresh_cfg.get("plan") or {}
    if fresh_cfg.get("warmup_chatgpt_context", True):
        warm_result = _warm_chatgpt_checkout_context(
            chatgpt_http,
            access_token=access_token,
            session_token=session_token,
            cookie_header=cookie_header,
            user_agent=user_agent,
            accept_language=accept_language,
            locale_profile=locale_profile,
            oai_device_id=oai_device_id,
            billing_country=plan_cfg.get("billing_country") or bootstrap.get("billing_details", {}).get("country") or "US",
            include_home_bounce=bool(fresh_cfg.get("warmup_home_bounce", True)),
        )
        cookie_header = warm_result.get("cookie_header") or cookie_header
        session_token = warm_result.get("session_token") or session_token
        access_token = warm_result.get("access_token") or access_token
        oai_device_id = warm_result.get("device_id") or oai_device_id
        _log(
            "      [fresh] 预热后凭证: "
            f"access_token={'yes' if access_token else 'no'} "
            f"session_token={'yes' if session_token else 'no'} "
            f"cookie_count={len([p for p in cookie_header.split(';') if '=' in p])}"
        )

    if request_style in {"abcard", "legacy", "auto"}:
        legacy_payload = _build_abcard_checkout_payload(fresh_cfg)
        _log(
            "      [fresh] legacy 参数: "
            f"plan_type={legacy_payload.get('plan_type')} "
            f"workspace={legacy_payload.get('workspace_name')} "
            f"seats={legacy_payload.get('seat_quantity')} "
            f"country={legacy_payload.get('billing_country_code')} "
            f"currency={legacy_payload.get('billing_currency_code')} "
            f"promo={legacy_payload.get('promo_campaign_id', '')}"
        )
        legacy_headers = {
            "user-agent": user_agent,
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {access_token}",
            "origin": "https://chatgpt.com",
            "referer": "https://chatgpt.com/",
            "accept-language": accept_language,
        }
        if cookie_header:
            legacy_headers["cookie"] = cookie_header
        if oai_device_id:
            legacy_headers["oai-device-id"] = oai_device_id

        legacy_endpoints = fresh_cfg.get("legacy_endpoints") or [
            "https://chatgpt.com/backend-api/payments/checkout",
            "https://chatgpt.com/backend-api/subscriptions/checkout",
        ]
        for url in legacy_endpoints:
            attempt_specs.append(
                {
                    "label": "abcard",
                    "url": url,
                    "headers": legacy_headers,
                    "payload": legacy_payload,
                    "json_mode": True,
                }
            )

    if request_style in {"modern", "flow"} or (request_style == "auto" and bootstrap):
        sentinel_token = (
            auth_cfg.get("openai_sentinel_token")
            or _refresh_openai_sentinel_token(chatgpt_http, cookie_header, bootstrap)
            or bootstrap.get("openai_sentinel_token")
        )
        modern_payload = _build_fresh_checkout_body(fresh_cfg, bootstrap)
        team_plan_data = modern_payload.get("team_plan_data", {})
        billing_details = modern_payload.get("billing_details", {})
        _log(
            "      [fresh] Modern 参数: "
            f"plan_name={modern_payload.get('plan_name')} "
            f"workspace={team_plan_data.get('workspace_name')} "
            f"interval={team_plan_data.get('price_interval')} "
            f"seats={team_plan_data.get('seat_quantity')} "
            f"country={billing_details.get('country')} "
            f"currency={billing_details.get('currency')} "
            f"promo={((modern_payload.get('promo_campaign') or {}).get('promo_campaign_id') or '')} "
            f"coupon_from_query_param={((modern_payload.get('promo_campaign') or {}).get('is_coupon_from_query_param'))}"
        )

        modern_headers = {
            "authorization": f"Bearer {access_token}",
            "content-type": "application/json",
            "accept": "*/*",
            "origin": "https://chatgpt.com",
            "referer": "https://chatgpt.com/",
            "user-agent": user_agent,
            "accept-language": accept_language,
            "oai-language": auth_cfg.get("oai_language") or bootstrap.get("oai_language") or locale_profile["browser_locale"],
            "oai-session-id": str(uuid.uuid4()),
            "oai-device-id": oai_device_id,
            "x-openai-target-path": "/backend-api/payments/checkout",
            "x-openai-target-route": "/backend-api/payments/checkout",
        }
        if cookie_header:
            modern_headers["cookie"] = cookie_header
        if bootstrap.get("oai_client_version"):
            modern_headers["oai-client-version"] = bootstrap["oai_client_version"]
        if bootstrap.get("oai_client_build_number"):
            modern_headers["oai-client-build-number"] = str(bootstrap["oai_client_build_number"])
        if bootstrap.get("user_agent") or auth_cfg.get("sec_ch_ua"):
            modern_headers["sec-ch-ua"] = auth_cfg.get("sec_ch_ua") or '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'
            modern_headers["sec-ch-ua-mobile"] = auth_cfg.get("sec_ch_ua_mobile") or "?0"
            modern_headers["sec-ch-ua-platform"] = auth_cfg.get("sec_ch_ua_platform") or '"Windows"'
        if sentinel_token:
            modern_headers["openai-sentinel-token"] = sentinel_token

        attempt_specs.append(
            {
                "label": "modern",
                "url": "https://chatgpt.com/backend-api/payments/checkout",
                "headers": modern_headers,
                "payload": modern_payload,
                "json_mode": True,
            }
        )

    if not attempt_specs:
        raise FreshCheckoutAuthError("fresh checkout 没有可用的请求模式；请检查 request_style 配置")

    errors = []
    saw_401 = False
    saw_token_invalidated = False
    saw_account_deactivated = False
    last_401_code = ""
    last_401_message = ""
    last_response_data = None

    for spec in attempt_specs:
        label = spec["label"]
        checkout_url = spec["url"]
        payload = spec["payload"]
        headers = spec["headers"]

        _log(f"      [fresh] 尝试 {label} checkout → {checkout_url}")
        _log_request("POST", checkout_url, data=payload, tag=f"[fresh:{label}] checkout")
        resp = chatgpt_http.post(
            checkout_url,
            headers=headers,
            json=payload if spec.get("json_mode", True) else None,
            data=None if spec.get("json_mode", True) else payload,
            timeout=30,
        )
        _log_response(resp, tag=f"[fresh:{label}] checkout")

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception as e:
                errors.append(f"{label} JSON 解析失败: {e}")
                continue

            last_response_data = data
            session_id, processor_entity, fresh_url = _extract_checkout_identifiers(data)
            if session_id:
                if not processor_entity:
                    billing_country = str(
                        billing_details.get("country")
                        if label == "modern"
                        else plan_cfg.get("billing_country", "US")
                    ).upper()
                    processor_entity = "openai_llc" if billing_country == "US" else "openai_ie"
                provider_url = fresh_url
                canonical_chatgpt_url = (
                    f"https://chatgpt.com/checkout/{processor_entity}/{session_id}"
                    if processor_entity else ""
                )
                fresh_url = _select_fresh_checkout_url(
                    provider_url=provider_url,
                    canonical_url=canonical_chatgpt_url,
                    fresh_cfg=fresh_cfg,
                    checkout_payload=payload,
                )

                _log(f"      [fresh] session_id: {session_id}")
                if provider_url and provider_url != fresh_url:
                    _log(f"      [fresh] provider_url: {provider_url}")
                if canonical_chatgpt_url and canonical_chatgpt_url != fresh_url:
                    _log(f"      [fresh] canonical_url: {canonical_chatgpt_url}")
                if fresh_url:
                    _log(f"      [fresh] fresh_url: {fresh_url}")

                coupon_check = {}
                if label == "modern":
                    promo_campaign = modern_payload.get("promo_campaign") or {}
                    promo_coupon = (promo_campaign.get("promo_campaign_id") or "").strip()
                    should_check_coupon = fresh_cfg.get("check_coupon_after_checkout")
                    if should_check_coupon is None:
                        should_check_coupon = bool(promo_coupon)
                    if promo_coupon and should_check_coupon:
                        coupon_check = _check_coupon_eligibility(
                            chatgpt_http,
                            access_token=access_token,
                            cookie_header=cookie_header,
                            user_agent=user_agent,
                            accept_language=accept_language,
                            oai_device_id=oai_device_id,
                            coupon=promo_coupon,
                            is_coupon_from_query_param=bool(
                                promo_campaign.get("is_coupon_from_query_param")
                            ),
                            referer_url=canonical_chatgpt_url or provider_url or fresh_url,
                        )
                        # Promo 优惠不生效就直接 abort，避免真扣款。
                        # 原项目仅把 check_coupon 当观测信号（README 说明），
                        # 但这会导致 promo 失效时静默走完支付流程真扣 IDR ~35w。
                        # 默认行为改成 fail-fast；要绕过设
                        # `fresh_checkout.allow_charge_when_coupon_ineligible=true`
                        # 或环境变量 `ALLOW_CHARGE_WHEN_COUPON_INELIGIBLE=1`。
                        coupon_state = (coupon_check.get("state") or "").strip().lower()
                        allow_override = bool(fresh_cfg.get("allow_charge_when_coupon_ineligible"))
                        if not allow_override:
                            allow_override = str(
                                os.environ.get("ALLOW_CHARGE_WHEN_COUPON_INELIGIBLE", "")
                            ).strip().lower() in ("1", "true", "yes", "on")
                        if coupon_state and coupon_state != "eligible" and not allow_override:
                            redemption = coupon_check.get("redemption") or {}
                            raise RuntimeError(
                                f"promo coupon '{promo_coupon}' state={coupon_state} "
                                f"(user_redeemed={redemption.get('redeemed_by_user')} "
                                f"workspace_redeemed={redemption.get('redeemed_by_workspace')}) "
                                "→ 拒绝继续支付以免真扣款；要强行继续设 "
                                "fresh_checkout.allow_charge_when_coupon_ineligible=true"
                            )

                if fresh_cfg.get("warmup_route_data", True) and canonical_chatgpt_url and cookie_header:
                    route_data_url = (
                        f"https://chatgpt.com/checkout/{processor_entity}/{session_id}.data"
                        "?_routes=routes%2Fcheckout.%24entity.%24checkoutId"
                    )
                    route_headers = {
                        "user-agent": user_agent,
                        "accept-language": accept_language,
                        "referer": "https://chatgpt.com/",
                        "cookie": cookie_header,
                    }
                    try:
                        route_resp = chatgpt_http.get(route_data_url, headers=route_headers, timeout=20)
                        _log(f"      [fresh] route data warmup → {route_resp.status_code}")
                    except Exception as e:
                        _log(f"      [fresh] route data warmup 异常: {e}")

                return {
                    "url": fresh_url,
                    "checkout_session_id": session_id,
                    "processor_entity": processor_entity,
                    "provider_url": provider_url,
                    "canonical_url": canonical_chatgpt_url,
                    "publishable_key": data.get("publishable_key", ""),
                    "client_secret": data.get("client_secret", ""),
                    "coupon_check": coupon_check,
                    "raw": data,
                }

            errors.append(f"{label} 返回 200 但未提取到 checkout_session_id: {json.dumps(data, ensure_ascii=False)[:400]}")
            continue

        if resp.status_code == 401:
            saw_401 = True
            err_code, err_message = _extract_api_error(resp)
            if not err_code and "token_invalidated" in resp.text:
                saw_token_invalidated = True
            if err_code == "token_invalidated":
                saw_token_invalidated = True
            if err_code == "account_deactivated":
                saw_account_deactivated = True
            if err_code:
                last_401_code = err_code
            if err_message:
                last_401_message = err_message
            suffix = f"[{err_code}] " if err_code else ""
            detail = err_message or resp.text[:240]
            errors.append(f"{label} 401{suffix}: {detail}")
            continue

        errors.append(f"{label} [{resp.status_code}]: {resp.text[:300]}")

    if saw_account_deactivated:
        if auto_register_enabled and not auto_register_used and auto_register_cfg.get("retry_on_auth_error", True):
            _log("      [fresh] 当前账号已停用，尝试通过本地注册流程新开号后重试 ...")
            provisioned_auth = _provision_openai_auth_via_local_bundle(cfg, fresh_cfg)
            refreshed_cfg = _build_cfg_with_fresh_auth(
                cfg,
                provisioned_auth,
                forced_mode="access_token",
                mark_auto_register_used=True,
            )
            return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)
        msg = last_401_message or "当前 OpenAI 账号已被停用，无法生成优惠 checkout"
        raise FreshCheckoutAuthError(
            f"checkout 401[account_deactivated]：{msg}"
        )
    if saw_token_invalidated:
        if auto_register_enabled and not auto_register_used and auto_register_cfg.get("retry_on_auth_error", True):
            _log("      [fresh] 当前登录态已失效，尝试通过本地注册流程新开号后重试 ...")
            provisioned_auth = _provision_openai_auth_via_local_bundle(cfg, fresh_cfg)
            refreshed_cfg = _build_cfg_with_fresh_auth(
                cfg,
                provisioned_auth,
                forced_mode="access_token",
                mark_auto_register_used=True,
            )
            return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)
        raise FreshCheckoutAuthError(
            "checkout 401[token_invalidated]：当前 access_token / session_token 登录态已被撤销或失效"
        )
    if saw_401:
        retryable_codes = {"token_expired", "token_invalidated", "account_deactivated", "session_expired", "invalid_session"}
        if auto_register_enabled and not auto_register_used and auto_register_cfg.get("retry_on_auth_error", True):
            if (not last_401_code) or (last_401_code in retryable_codes):
                _log("      [fresh] 当前凭证不可用，尝试通过本地注册流程新开号后重试 ...")
                provisioned_auth = _provision_openai_auth_via_local_bundle(cfg, fresh_cfg)
                refreshed_cfg = _build_cfg_with_fresh_auth(
                    cfg,
                    provisioned_auth,
                    forced_mode="access_token",
                    mark_auto_register_used=True,
                )
                return generate_fresh_checkout(session, refreshed_cfg, locale_profile=locale_profile)
        if last_401_code or last_401_message:
            suffix = f"[{last_401_code}]" if last_401_code else ""
            sep = "：" if suffix or last_401_message else ""
            raise FreshCheckoutAuthError(
                f"checkout 401{suffix}{sep}{last_401_message or '当前 access_token 无效或已过期，无法生成 fresh checkout'}"
            )
        raise FreshCheckoutAuthError(
            "checkout 401：当前 access_token 无效或已过期，无法生成 fresh checkout"
        )

    if last_response_data is not None:
        raise FreshCheckoutAuthError(
            f"fresh checkout 返回无法解析的 200 响应: {json.dumps(last_response_data, ensure_ascii=False)[:400]}"
        )

    # 提前识别「User is already paid」并落库带 email 标记 → 下次 pay-only
    # `_paid_or_consumed_emails()` 能匹配到，跳过这个账号不再重试。
    # 之前所有 raise 都不带 email，导致同一已付费账号反复被选中。
    error_blob = " | ".join(errors[:8])
    if "user is already paid" in error_blob.lower():
        _email = fresh_cfg.get("_chatgpt_email") or ""
        if _email:
            try:
                _record_already_paid(_email, "User is already paid (fresh_checkout 400)")
                _log(f"      [fresh] ⚠ {_email} 已是 Plus 付费账号，标记 inventory 跳过")
            except Exception as _e:
                _log(f"      [fresh] 标记 already-paid 失败: {_e}")

    raise FreshCheckoutAuthError(
        "生成 fresh checkout 失败: " + " | ".join(errors[:4])
    )
