"""RT/Codex OAuth refresh-token login helpers extracted from legacy payment code.

This module is intentionally importable without executing the monolithic
``card.py`` entrypoint.  It owns the RT-only browser login, email OTP polling,
add-phone/SMS flow, and Codex OAuth token exchange.
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

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

_OUTPUT_DIR = _REPO_DIR / "output"
(_OUTPUT_DIR / "logs").mkdir(parents=True, exist_ok=True)
LOG_FILE = str(_OUTPUT_DIR / "logs" / "rt_login.log")


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _safe_screenshot(page, path: str):
    try:
        page.screenshot(path=path, timeout=5000)
    except Exception:
        pass


def _rt_debug_dump(page, label: str):
    """Dump a small, privacy-safe-ish snapshot of the current auth page for diagnosis."""
    try:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(label or "page"))[:80]
        _safe_screenshot(page, f"/tmp/rt_{safe}.png")
    except Exception:
        pass
    try:
        info = page.evaluate("""
            () => ({
              url: location.href,
              title: document.title,
              active: document.activeElement ? {
                tag: document.activeElement.tagName,
                type: document.activeElement.getAttribute('type') || '',
                name: document.activeElement.getAttribute('name') || '',
                id: document.activeElement.id || '',
                aria: document.activeElement.getAttribute('aria-label') || '',
                value_len: (document.activeElement.value || '').length
              } : null,
              inputs: Array.from(document.querySelectorAll('input')).slice(0, 20).map((i, idx) => {
                const r = i.getBoundingClientRect();
                return {
                  idx,
                  type: i.getAttribute('type') || '',
                  name: i.getAttribute('name') || '',
                  id: i.id || '',
                  autocomplete: i.getAttribute('autocomplete') || '',
                  inputmode: i.getAttribute('inputmode') || '',
                  maxlength: i.getAttribute('maxlength') || '',
                  aria: i.getAttribute('aria-label') || '',
                  placeholder: i.getAttribute('placeholder') || '',
                  visible: !!(r.width && r.height),
                  disabled: !!i.disabled,
                  readonly: !!i.readOnly,
                  value_len: (i.value || '').length
                };
              }),
              buttons: Array.from(document.querySelectorAll('button,a[role=button],input[type=submit]')).slice(0, 20).map((b, idx) => {
                const r = b.getBoundingClientRect();
                return {
                  idx,
                  tag: b.tagName,
                  text: (b.innerText || b.value || '').trim().slice(0, 60),
                  type: b.getAttribute('type') || '',
                  aria: b.getAttribute('aria-label') || '',
                  disabled: !!b.disabled || b.getAttribute('aria-disabled') === 'true',
                  visible: !!(r.width && r.height)
                };
              }),
              text: (document.body && document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 500)
            })
        """)
        _log(f"      [RT-DUMP:{label}] {json.dumps(info, ensure_ascii=False)[:2500]}")
    except Exception as e:
        _log(f"      [RT-DUMP:{label}] failed: {str(e)[:160]}")


def _rt_fill_email_otp(page, otp_code: str) -> tuple[bool, str]:
    """Fill OpenAI email OTP and verify DOM value lengths before claiming success."""
    code = re.sub(r"\D", "", str(otp_code or ""))
    if not code:
        return False, "empty_code"
    selectors = [
        'input[autocomplete="one-time-code"]:visible',
        'input[name="code"]:visible',
        'input[inputmode="numeric"]:not([maxlength="1"]):visible',
        'input[type="tel"]:visible',
        'input[type="text"][inputmode="numeric"]:visible',
    ]
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible(timeout=800):
                loc.click(timeout=3000)
                try:
                    loc.fill(code, timeout=5000)
                except Exception:
                    page.keyboard.press("Control+A")
                    page.keyboard.type(code, delay=35)
                try:
                    value_len = loc.evaluate("el => (el.value || '').length")
                except Exception:
                    value_len = 0
                if value_len >= min(6, len(code)):
                    return True, f"single:{sel}:value_len={value_len}"
                _log(f"      [RT] OTP single 填入后 value_len={value_len} 不足，selector={sel}")
        except Exception as e:
            _log(f"      [RT] OTP single selector 失败 {sel}: {str(e)[:100]}")
    try:
        digits = page.locator('input[maxlength="1"][inputmode="numeric"], input[maxlength="1"]')
        n = digits.count()
        if n >= min(6, len(code)):
            for i, ch in enumerate(code[:n]):
                inp = digits.nth(i)
                if not inp.is_visible(timeout=800):
                    continue
                inp.click(timeout=3000)
                try:
                    inp.fill(ch, timeout=2000)
                except Exception:
                    page.keyboard.type(ch, delay=35)
            vals = digits.evaluate_all("els => els.map(e => e.value || '')")
            joined_len = sum(1 for v in vals if v)
            if joined_len >= min(6, len(code)):
                return True, f"digits:n={n}:filled={joined_len}"
            return False, f"digits_value_len={joined_len}/{n}"
    except Exception as e:
        _log(f"      [RT] OTP digits 填入异常: {str(e)[:120]}")
    return False, "no_visible_otp_input_or_value_not_set"


def _rt_submit_email_otp(page) -> tuple[bool, str]:
    selectors = [
        'button[type="submit"]:visible',
        'button:has-text("Continue"):visible',
        'button:has-text("Verify"):visible',
        'input[type="submit"]:visible',
    ]
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible(timeout=800):
                disabled = False
                try:
                    disabled = bool(loc.evaluate("el => !!el.disabled || el.getAttribute('aria-disabled') === 'true'"))
                except Exception:
                    disabled = False
                if disabled:
                    _log(f"      [RT] OTP 提交按钮 disabled，selector={sel}")
                    continue
                loc.click(timeout=5000)
                return True, sel
        except Exception as e:
            _log(f"      [RT] OTP submit selector 失败 {sel}: {str(e)[:100]}")
    try:
        page.keyboard.press("Enter")
        return True, "keyboard:Enter"
    except Exception as e:
        return False, f"enter_failed:{str(e)[:80]}"


def _rt_page_text(page, limit: int = 1200) -> str:
    try:
        txt = page.evaluate("() => (document.body && document.body.innerText || '')") or ""
        return re.sub(r"\s+", " ", str(txt)).strip()[:limit]
    except Exception:
        return ""


def _rt_detect_auth_terminal_error(page) -> str:
    """Return a stable failure label when auth page already shows a terminal account error."""
    txt = _rt_page_text(page, 1500)
    low = txt.lower()
    if not low:
        return ""
    if "account_deactivated" in low or "deleted or deactivated" in low or "account has been deleted" in low:
        return "account_deactivated"
    if "invalid_username_or_password" in low or "login failed" in low:
        return "invalid_username_or_password"
    if "too many requests" in low or "rate limit" in low:
        return "rate_limited"
    if "wrong code" in low or "invalid code" in low or "incorrect code" in low:
        return "wrong_email_otp_code"
    return ""


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


def _fetch_openai_login_otp(target_email: str, timeout: int = 180, issued_after: float | None = None) -> str:
    """取 OpenAI/Codex 登录 OTP。

    优先支持邮箱池里的取信链接/API（CUSTOM_MAIL_POOL / CTF-reg/*.used），
    找不到对应邮箱入口时再回退 CF KV。

    issued_after 用于 RT 补领场景：刚触发 resend/send 后，邮箱里可能还留着
    上一轮 challenge 的 6 位码。自定义邮箱 API 通常不给可靠时间戳，所以这里
    先短暂采样并标记已存在的旧码，后续只接受新出现的 OTP，避免 invalid_state /
    wrong_email_otp_code。
    """
    stale_codes: set[str] = set()
    last_stale_otp = ""
    try:
        stale_window = max(0.0, float(os.getenv("RT_OTP_STALE_SNAPSHOT_SECONDS", "5") or "5"))
    except Exception:
        stale_window = 5.0
    stale_until = (float(issued_after or 0) + stale_window) if issued_after else 0.0

    def _accept_fresh_otp(otp: str) -> str:
        nonlocal last_stale_otp
        otp = (otp or "").strip()
        if not otp:
            return ""
        if issued_after and time.time() < stale_until:
            stale_codes.add(otp)
            last_stale_otp = otp
            return ""
        if issued_after and otp in stale_codes:
            last_stale_otp = otp
            return ""
        return otp
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
                            otp = _accept_fresh_otp(_extract_otp(payload))
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
                    otp = _accept_fresh_otp(_extract_otp(html))
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
                        otp = _accept_fresh_otp(_extract_otp(detail))
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
        if issued_after:
            return provider.wait_for_otp(target_email, timeout=timeout, issued_after=issued_after)
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

            def _is_email_otp_page() -> bool:
                try:
                    cur = page.url or ""
                    if "/email-otp" in cur or "/email-verification" in cur or "passwordless" in cur:
                        return True
                    if page.query_selector('input[autocomplete="one-time-code"]') or \
                       page.query_selector('input[inputmode="numeric"]') or \
                       page.query_selector('input[name="code"]'):
                        return True
                    body = ""
                    try:
                        body = (page.locator("body").inner_text(timeout=2000) or "").lower()
                    except Exception:
                        body = ""
                    return any(x in body for x in (
                        "verify your email", "check your email", "enter the code",
                        "verification code", "one-time code", "email verification",
                    ))
                except Exception:
                    return False

            already_otp_before_email = False

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
                _safe_screenshot(page, "/tmp/rt_email_wait_fail.png")
                if _is_email_otp_page():
                    already_otp_before_email = True
                    _log(f"      [RT] 邮箱框未出现，但当前已是 OTP/邮箱验证页，跳过邮箱填写: {page.url[:140]}")
                else:
                    _log(f"      [RT] 邮箱填写失败: {e}")
                    return ""

            # [3] 填密码（OpenAI 现在很多场景走 passwordless，没密码框就跳过到 OTP）
            if already_otp_before_email:
                _log("      [RT] 已在 OTP 页面，跳过密码框等待")
                _safe_screenshot(page, "/tmp/rt_pwd_skip.png")
            else:
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
            # 如果页面在邮箱框阶段就已经进入 OTP，验证码可能已经发出；不要用当前时间
            # 过滤“旧码”，否则会把本轮有效 OTP 当 stale code 丢掉。
            otp_sent_ts = 0.0 if already_otp_before_email else time.time()
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
                        otp_code = _fetch_openai_login_otp(
                            target_email=email,
                            timeout=180,
                            issued_after=max(0, otp_sent_ts - 10),
                        )
                        if not otp_code:
                            _log("      [RT] OTP 获取超时")
                            return ""
                        _log(f"      [RT] OTP 已获取 (len={len(otp_code)})")
                        _rt_debug_dump(page, "otp_before_fill")
                        filled, fill_detail = _rt_fill_email_otp(page, otp_code)
                        if filled:
                            _log(f"      [RT] OTP 已填入: {fill_detail}")
                            time.sleep(0.5)
                            _rt_debug_dump(page, "otp_after_fill")
                            submitted, submit_detail = _rt_submit_email_otp(page)
                            if submitted:
                                _log(f"      [RT] OTP 提交: {submit_detail}")
                            else:
                                _log(f"      [RT] OTP 未能提交: {submit_detail}")
                                _rt_debug_dump(page, "otp_submit_failed")
                                return ""
                            otp_fetched = True
                            email_otp_stuck_since = time.time()
                            time.sleep(3)
                            _rt_debug_dump(page, "otp_after_submit_wait3")
                            terminal_error = _rt_detect_auth_terminal_error(page)
                            if terminal_error:
                                _log(f"      [RT] OTP 提交后认证终止错误: {terminal_error}，提前放弃")
                                return ""
                        else:
                            _log(f"      [RT] OTP 未填入: {fill_detail}")
                            _rt_debug_dump(page, "otp_fill_failed")
                            return ""
                    elif "/email-verification" in cur and email_otp_stuck_since:
                        terminal_error = _rt_detect_auth_terminal_error(page)
                        if terminal_error:
                            _log(f"      [RT] 邮箱 OTP 后认证终止错误: {terminal_error}，提前放弃")
                            return ""
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
                    # 先做 authorize 刷新重试；仍拿不到 callback 再放弃，避免消耗号码/触发 add-phone 风控。
                    if not skipped and not getattr(page, "_addphone_gaveup", False):
                        page._addphone_gaveup = True
                        if str(os.getenv("RT_BROWSER_ADD_PHONE_REFRESH_RETRY", "1")).lower() not in ("0", "false", "no", "off"):
                            try:
                                retry_count = max(1, int(os.getenv("RT_BROWSER_ADD_PHONE_REFRESH_RETRY_COUNT", "3")))
                            except Exception:
                                retry_count = 3
                            try:
                                retry_sleep = max(0.0, float(os.getenv("RT_BROWSER_ADD_PHONE_REFRESH_SLEEP", "1.2")))
                            except Exception:
                                retry_sleep = 1.2
                            _log(f"      [RT] add-phone 找不到 Skip；执行 authorize 刷新重试 count={retry_count} sleep={retry_sleep:.1f}s")
                            retry_url = auth_url
                            if "prompt=login" in retry_url:
                                retry_url = retry_url.replace("prompt=login&", "").replace("&prompt=login", "")
                            for _i in range(retry_count):
                                try:
                                    page.goto(retry_url, wait_until="domcontentloaded", timeout=30000)
                                    time.sleep(retry_sleep)
                                    if code_captured["url"] or ("localhost:1455" in page.url and "code=" in page.url):
                                        if not code_captured["url"]:
                                            code_captured["url"] = page.url
                                        break
                                    if "/add-phone" not in page.url and "phone-number" not in page.url:
                                        _log(f"      [RT] add-phone 刷新重试跳出 add-phone: {page.url[:120]}")
                                        break
                                except Exception as e_r:
                                    _log(f"      [RT] add-phone 刷新重试异常: {str(e_r)[:100]}")
                            if code_captured["url"]:
                                break
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
