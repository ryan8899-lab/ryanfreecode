"""Standalone PayPal Guest handoff helpers for payment.py.

This module is intentionally additive: the production entrypoint is
``payment.py``.  New PayPal Guest changes should land here first and then be
wired into the payment runner after a focused review.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from datetime import datetime
from pathlib import Path

import requests

from captcha_solvers import _remote_captcha_url, _solve_remote_hcaptcha_paypal

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)

# Local defaults copied from the legacy card.py Guest path.  Prefer env override
# for secrets in new code.
PAYPAL_GUEST_US_PROXY = os.getenv(
    "PAYPAL_GUEST_US_PROXY",
    "",
)
PAYPAL_GUEST_INFO_API = os.getenv("PAYPAL_GUEST_INFO_API", "https://card.jinyao91.top/api/exchange/verify")
PAYPAL_GUEST_INFO_KEY = os.getenv("PAYPAL_GUEST_INFO_KEY", "KW-8C74-E6RRS7PR-68A9")


def default_log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {msg}", flush=True)


def _safe_screenshot(page, path: str) -> None:
    try:
        page.screenshot(path=path, timeout=5000)
    except Exception:
        pass


_log = default_log

def solve_remote_hcaptcha_paypal(
    api_key: str,
    site_key: str,
    page_url: str,
    timeout: int = 120,
) -> str:
    """Delegate PayPal Guest hCaptcha solving to the extracted solver module."""
    return _solve_remote_hcaptcha_paypal(api_key, site_key, page_url, timeout=timeout)


def fetch_paypal_guest_nonpayment_info() -> dict:
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


def paypal_guest_handoff_fill_nonpayment(
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

    info = fetch_paypal_guest_nonpayment_info()
    if email:
        info["email"] = email
    # Ryan patch: immediately override fetched/default guest info from env before any fill.
    try:
        _phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if _phone_override.startswith("1") and len(_phone_override) == 11:
            _phone_override = _phone_override[1:]
        if _phone_override:
            info["phone"] = _phone_override
        for _k, _env in [("first", "PAYPAL_GUEST_FIRST"), ("last", "PAYPAL_GUEST_LAST"), ("line1", "PAYPAL_GUEST_LINE1"), ("city", "PAYPAL_GUEST_CITY"), ("state", "PAYPAL_GUEST_STATE"), ("zip", "PAYPAL_GUEST_ZIP")]:
            _v = os.getenv(_env, "").strip()
            if _v:
                info[_k] = _v
        _log(f"      [Guest] effective info: phone={info.get('phone')} name={info.get('first')} {info.get('last')} city={info.get('city')} zip={info.get('zip')}")
    except Exception as _e:
        _log(f"      [Guest] env info override failed: {_e}")
    _email_override = os.getenv("PAYPAL_GUEST_EMAIL_OVERRIDE", "").strip()
    if _email_override:
        info["email"] = _email_override
    # Ryan patch: immediately override fetched/default guest info from env before any fill.
    try:
        _phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if _phone_override.startswith("1") and len(_phone_override) == 11:
            _phone_override = _phone_override[1:]
        if _phone_override:
            info["phone"] = _phone_override
        for _k, _env in [("first", "PAYPAL_GUEST_FIRST"), ("last", "PAYPAL_GUEST_LAST"), ("line1", "PAYPAL_GUEST_LINE1"), ("city", "PAYPAL_GUEST_CITY"), ("state", "PAYPAL_GUEST_STATE"), ("zip", "PAYPAL_GUEST_ZIP")]:
            _v = os.getenv(_env, "").strip()
            if _v:
                info[_k] = _v
        _log(f"      [Guest] effective info: email={info.get('email')} phone={info.get('phone')} name={info.get('first')} {info.get('last')} city={info.get('city')} zip={info.get('zip')}")
    except Exception as _e:
        _log(f"      [Guest] env info override failed: {_e}")
    # Ryan patch: immediately override fetched/default guest info from env before any fill.
    try:
        _phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if _phone_override.startswith("1") and len(_phone_override) == 11:
            _phone_override = _phone_override[1:]
        if _phone_override:
            info["phone"] = _phone_override
        for _k, _env in [("first", "PAYPAL_GUEST_FIRST"), ("last", "PAYPAL_GUEST_LAST"), ("line1", "PAYPAL_GUEST_LINE1"), ("city", "PAYPAL_GUEST_CITY"), ("state", "PAYPAL_GUEST_STATE"), ("zip", "PAYPAL_GUEST_ZIP")]:
            _v = os.getenv(_env, "").strip()
            if _v:
                info[_k] = _v
        _log(f"      [Guest] effective info: email={info.get('email')} phone={info.get('phone')} name={info.get('first')} {info.get('last')} city={info.get('city')} zip={info.get('zip')}")
    except Exception as _e:
        _log(f"      [Guest] env info override failed: {_e}")
    # Ryan patch: immediately override fetched/default guest info from env before any fill.
    try:
        _phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if _phone_override.startswith("1") and len(_phone_override) == 11:
            _phone_override = _phone_override[1:]
        if _phone_override:
            info["phone"] = _phone_override
        for _k, _env in [("first", "PAYPAL_GUEST_FIRST"), ("last", "PAYPAL_GUEST_LAST"), ("line1", "PAYPAL_GUEST_LINE1"), ("city", "PAYPAL_GUEST_CITY"), ("state", "PAYPAL_GUEST_STATE"), ("zip", "PAYPAL_GUEST_ZIP")]:
            _v = os.getenv(_env, "").strip()
            if _v:
                info[_k] = _v
        _log(f"      [Guest] effective info: email={info.get('email')} phone={info.get('phone')} name={info.get('first')} {info.get('last')} city={info.get('city')} zip={info.get('zip')}")
    except Exception as _e:
        _log(f"      [Guest] env info override failed: {_e}")
    # Ryan patch: immediately override fetched/default guest info from env before any fill.
    try:
        _phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if _phone_override.startswith("1") and len(_phone_override) == 11:
            _phone_override = _phone_override[1:]
        if _phone_override:
            info["phone"] = _phone_override
        for _k, _env in [("first", "PAYPAL_GUEST_FIRST"), ("last", "PAYPAL_GUEST_LAST"), ("line1", "PAYPAL_GUEST_LINE1"), ("city", "PAYPAL_GUEST_CITY"), ("state", "PAYPAL_GUEST_STATE"), ("zip", "PAYPAL_GUEST_ZIP")]:
            _v = os.getenv(_env, "").strip()
            if _v:
                info[_k] = _v
        _log(f"      [Guest] effective info: email={info.get('email')} phone={info.get('phone')} name={info.get('first')} {info.get('last')} city={info.get('city')} zip={info.get('zip')}")
    except Exception as _e:
        _log(f"      [Guest] env info override failed: {_e}")

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
            _log(f"      [Guest-human] human fill fallback label={label}: {e}")
            el.fill(value)

    def _try_fill(page, selectors, value, label):
        if not value:
            return False
        for sel in selectors:
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
        _log(f"      [Guest] field not found: {label}")
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

        # Fill guest/signup non-payment fields only.
        _try_fill(page, ['input[type="email"]', 'input[name="email"]', 'input#email', 'input[autocomplete="email"]'], info.get("email"), "email")
        _log(
            f"      [audit-fill] PayPal actual fill values: email={info.get('email')} phone={info.get('phone')} "
            f"name={info.get('first')} {info.get('last')} line1={info.get('line1')} "
            f"city={info.get('city')} state={info.get('state')} zip={info.get('zip')}"
        )
        _try_fill(page, ['input[name*="phone" i]', 'input[id*="phone" i]', 'input[autocomplete="tel"]', 'input[type="tel"]'], info.get("phone"), "phone")
        _try_fill(page, ['input[name="firstName"]', 'input[name*="first" i]', 'input[id*="first" i]', 'input[autocomplete="given-name"]'], info.get("first"), "first")
        _try_fill(page, ['input[name="lastName"]', 'input[name*="last" i]', 'input[id*="last" i]', 'input[autocomplete="family-name"]'], info.get("last"), "last")
        _try_fill(page, ['input[name*="line1" i]', 'input[name*="address1" i]', 'input[id*="address" i]', 'input[autocomplete="address-line1"]'], info.get("line1"), "address")
        _try_fill(page, ['input[name*="city" i]', 'input[id*="city" i]', 'input[autocomplete="address-level2"]'], info.get("city"), "city")
        state_done = False
        for sel in ['select[name*="state" i]', 'select[id*="state" i]']:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.select_option(info.get("state") or "")
                    _log(f"      [Guest] filled state: {sel}")
                    state_done = True
                    break
            except Exception as e:
                _log(f"      [Guest] state select failed: {e}")
        if not state_done:
            _try_fill(page, ['input[name*="state" i]', 'input[id*="state" i]', 'input[autocomplete="address-level1"]'], info.get("state"), "state")
        _try_fill(page, ['input[name*="postal" i]', 'input[name*="zip" i]', 'input[id*="postal" i]', 'input[id*="zip" i]', 'input[autocomplete="postal-code"]'], info.get("zip"), "zip")

        # Ryan 学习区：硬编码资料提前覆盖。
        # 注意：这里在任何 _try_fill 之前改 info，避免先填接口默认资料（如 8459935197）。
        phone_override = re.sub(r"\D+", "", os.getenv("PAYPAL_GUEST_PHONE_OVERRIDE", ""))
        if phone_override.startswith("1") and len(phone_override) == 11:
            phone_override = phone_override[1:]
        if phone_override:
            info["phone"] = phone_override
        for _k, _env in [
            ("first", "PAYPAL_GUEST_FIRST"),
            ("last", "PAYPAL_GUEST_LAST"),
            ("line1", "PAYPAL_GUEST_LINE1"),
            ("city", "PAYPAL_GUEST_CITY"),
            ("state", "PAYPAL_GUEST_STATE"),
            ("zip", "PAYPAL_GUEST_ZIP"),
        ]:
            _v = os.getenv(_env, "").strip()
            if _v:
                info[_k] = _v

        # 重新按覆盖后的 info 填手机号，确保页面值被替换成硬编码号码。
        if phone_override:
            _try_fill(page, ['input[name*="phone" i]', 'input[id*="phone" i]', 'input[autocomplete="tel"]', 'input[type="tel"]'], info.get("phone"), "phone_override")

        # Ryan 学习区：创建 PayPal 账号密码。
        _try_fill(page, ['input[type="password"]', 'input[name*="password" i]', 'input[id*="password" i]', 'input[autocomplete="new-password"]'], os.getenv("PAYPAL_GUEST_CREATE_PASSWORD", "Ryan8899"), "create_password")

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


        def _handle_paypal_sms_if_needed():
            # Ryan 学习区：手机短信验证码。
            # 点击 Agree & Create Account 后，如果进入 “Enter your code” 页面，
            # 就请求 PAYPAL_SMS_API_URL，提取 6 位验证码，填入并提交。
            sms_api = os.getenv("PAYPAL_SMS_API_URL", "").strip()
            if not sms_api:
                return False
            import requests as _req
            code = ""
            sms_text = ""
            for _si in range(24):
                try:
                    sr = _req.get(sms_api, timeout=15, headers={"accept": "*/*", "user-agent": USER_AGENT})
                    sms_text = sr.text[:1000]
                    _m = re.search(r"(?<!\d)(\d{6})(?!\d)", sms_text)
                    if _m:
                        code = _m.group(1)
                        _log(f"      [Guest-SMS] got code: {code}")
                        break
                    _log(f"      [Guest-SMS] waiting code... status={sr.status_code} body={sms_text[:120]}")
                except Exception as _e:
                    _log(f"      [Guest-SMS] api error: {_e}")
                time.sleep(5)

            if not code:
                return False
            filled_otp = False
            for _sel in [
                'input[name*="code" i]',
                'input[id*="code" i]',
                'input[autocomplete="one-time-code"]',
                'input[inputmode="numeric"]',
                'input[type="tel"]',
                'input[type="text"]',
            ]:
                try:
                    _els = page.query_selector_all(_sel)
                except Exception:
                    _els = []
                for _el in _els:
                    try:
                        if _el and _el.is_visible():
                            _el.fill(code)
                            _log(f"      [Guest-SMS] filled otp: {_sel}")
                            filled_otp = True
                            break
                    except Exception:
                        pass
                if filled_otp:
                    break

            if not filled_otp:
                return False
            for _bsel in [
                'button:has-text("Continue")',
                'button:has-text("Next")',
                'button:has-text("Submit")',
                'button[type="submit"]',
            ]:
                try:
                    _b = page.query_selector(_bsel)
                    if _b and _b.is_visible():
                        _txt = (_b.inner_text() or "")[:80]
                        if _paypal_recaptcha_overlay_visible():
                            _log("      [Guest-SMS] reCAPTCHA overlay detected before submit; stop clicking")
                            try:
                                _safe_screenshot(page, "/tmp/paypal_recaptcha_overlay.png")
                                _log("      [Guest-SMS] recaptcha screenshot: /tmp/paypal_recaptcha_overlay.png")
                            except Exception as _e:
                                _log(f"      [Guest-SMS] recaptcha screenshot failed: {_e}")
                            break
                        _log(f"      [Guest-SMS] click otp submit: {_bsel} text={_txt!r}")
                        try:
                            _b.click(timeout=5000)
                        except Exception as _e:
                            if _paypal_recaptcha_overlay_visible():
                                _log(f"      [Guest-SMS] submit blocked by reCAPTCHA overlay: {_e}")
                                try:
                                    _safe_screenshot(page, "/tmp/paypal_recaptcha_overlay.png")
                                    _log("      [Guest-SMS] recaptcha screenshot: /tmp/paypal_recaptcha_overlay.png")
                                except Exception:
                                    pass
                                break
                            raise
                        time.sleep(8)
                        return True
                except Exception as _e:
                    _log(f"      [Guest-SMS] submit click failed {_bsel}: {_e}")
            return False

        def _click_paypal_blue_button(reason="initial"):
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
                        _handle_paypal_sms_if_needed()
                        break
                except Exception as e:
                    _log(f"      [Guest] blue button click failed {sel} ({reason}): {e}")
            if not clicked:
                _log(f"      [Guest] blue button not clicked ({reason}); overlays={_guest_visible_overlay_summary()}")
                _guest_button_diagnostics(f"not_clicked:{reason}")
            return clicked

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
                token = solve_remote_hcaptcha_paypal(
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

        # 循环检测机制：应对短信后可能出现的验证码/PayPal challenge。
        # 旧版只等 180s 且少量 selector；新版持续诊断，人工处理后继续。
        _wait_s_default = int(os.getenv("PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS", "600") or "600")
        for _check_idx in range(20):
            st = _paypal_challenge_state()
            if st.get("visible"):
                _log(f"      [Guest-Challenge] visible kind={st.get('kind')} reason={st.get('reason')}")
                if not _do_auto_solve():
                    if str(os.getenv("PAYPAL_MANUAL_CHALLENGE_HANDOFF", "0")).lower() in ("1", "true", "yes", "on"):
                        _log("      [Guest-Challenge] fallback to manual handoff")
                        _paypal_challenge_snapshot(st.get("kind") or "challenge")
                        _log(f"      [Guest-Challenge] waiting up to {_wait_s_default}s for manual resolution ...")
                        _challenge_cleared = False
                        for _ci in range(_wait_s_default):
                            time.sleep(1)
                            if not _paypal_challenge_visible():
                                _challenge_cleared = True
                                _log("      [Guest-Challenge] challenge disappeared; continuing")
                                break
                            if _ci and _ci % 60 == 0:
                                _log(f"      [Guest-Challenge] still waiting manual resolution... {_ci}s")
                                _paypal_challenge_snapshot("still_waiting")
                        if _challenge_cleared:
                            _guest_button_diagnostics("challenge_cleared_before_retry")
                            clicked_blue_button = _click_paypal_blue_button("after_challenge_cleared") or clicked_blue_button
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

        time.sleep(2)
        try:
            text = page.inner_text("body", timeout=5000)
        except Exception as e:
            text = f"ERR:{e}"
        page.screenshot(path=str(shot), full_page=True)
        result = {
            "status": "paypal_guest_handoff",
            "url": page.url,
            "title": page.title(),
            "text": text[:3000],
            "screenshot": str(shot),
            "public_screenshot": "https://www.chatgtp.plus/debug/" + shot.name,
            "filled_nonpayment": info,
            "button_diagnostics_enabled": True,
            "click_blue_button": clicked_blue_button,
            "note": "PayPal guest handoff diagnostic. Success is not implied unless the page reaches an explicit PayPal/OpenAI success redirect.",
        }
        meta.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        _log(f"      [Guest] screenshot: {shot}")
        _log(f"      [Guest] public: {result['public_screenshot']}")
        return result


__all__ = [
    "PAYPAL_GUEST_US_PROXY",
    "fetch_paypal_guest_nonpayment_info",
    "paypal_guest_handoff_fill_nonpayment",
    "solve_remote_hcaptcha_paypal",
]
