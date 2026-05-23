"""Stripe Checkout client helpers extracted from legacy payment code.

This module owns Stripe Checkout session parsing, publishable-key lookup, init,
elements session, Link consumer lookup, address update, telemetry, and APATA
fingerprint submission.  It imports no legacy ``card.py`` code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import string
import time
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output"
(_OUTPUT_DIR / "logs").mkdir(parents=True, exist_ok=True)
LOG_FILE = str(_OUTPUT_DIR / "logs" / "stripe_checkout.log")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
DEFAULT_TIMEZONE = "America/Chicago"

STRIPE_API = "https://api.stripe.com"
STRIPE_VERSION_FULL = "2025-03-31.basil; checkout_server_update_beta=v1; checkout_manual_approval_preview=v1"
STRIPE_VERSION_BASE = "2025-03-31.basil"
HCAPTCHA_SITE_KEY_FALLBACK = "c7faac4c-1cd7-4b1b-b2d4-42ba98d09c7a"
DEFAULT_STRIPE_RUNTIME_VERSION = "6f8494a281"
DEFAULT_STRIPE_HCAPTCHA_ASSET_VERSION = "v32.5"
DEFAULT_FRONTEND_EXECUTION = base64.b64encode(
    json.dumps({"fingerprintOutcome": "not_supported"}, separators=(",", ":")).encode()
).decode()
KNOWN_PUBLISHABLE_KEYS = {
    "1Pj377KslHRdbaPg": "pk_live_51Pj377KslHRdbaPgTJYjThzH3f5dt1N1vK7LUp0qh0yNSarhfZ6nfbG7FFlh8KLxVkvdMWN5o6Mc4Vda6NHaSnaV00C2Sbl8Zs",
    "1HOrSwC6h1nxGoI3": "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n",
}
LOCALE_PROFILES = {
    "US": {"browser_locale": "en-US", "browser_timezone": "America/Chicago", "browser_language": "en-US", "color_depth": 24, "screen_w": 1920, "screen_h": 1080, "dpr": 1},
    "CN": {"browser_locale": "zh-CN", "browser_timezone": "Asia/Shanghai", "browser_language": "zh-CN", "color_depth": 32, "screen_w": 1272, "screen_h": 716, "dpr": 1},
    "ZH": {"browser_locale": "zh-CN", "browser_timezone": "Asia/Shanghai", "browser_language": "zh-CN", "color_depth": 32, "screen_w": 1272, "screen_h": 716, "dpr": 1},
    "ES": {"browser_locale": "es-ES", "browser_timezone": "Europe/Madrid", "browser_language": "es-ES", "color_depth": 24, "screen_w": 1366, "screen_h": 768, "dpr": 1},
    "IE": {"browser_locale": "en-IE", "browser_timezone": "Europe/Dublin", "browser_language": "en-IE", "color_depth": 24, "screen_w": 1920, "screen_h": 1080, "dpr": 1},
    "DE": {"browser_locale": "de-DE", "browser_timezone": "Europe/Berlin", "browser_language": "de-DE", "color_depth": 24, "screen_w": 1920, "screen_h": 1080, "dpr": 1},
    "FR": {"browser_locale": "fr-FR", "browser_timezone": "Europe/Paris", "browser_language": "fr-FR", "color_depth": 24, "screen_w": 1920, "screen_h": 1080, "dpr": 1},
    "NL": {"browser_locale": "nl-NL", "browser_timezone": "Europe/Amsterdam", "browser_language": "nl-NL", "color_depth": 24, "screen_w": 1920, "screen_h": 1080, "dpr": 1},
}
APATA_RBA_ORG_ID = "8t63q4n4"


class CheckoutSessionInactive(RuntimeError):
    """当前 Checkout Session 已失活，需要生成新的 session。"""
    pass


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _log_request(method: str, url: str, headers=None, data=None, json_body=None, params=None, tag: str = ""):
    label = tag or "http"
    _log(f"--> {label} {method} {url}")
    if params is not None:
        preview = urllib.parse.urlencode(params) if isinstance(params, dict) else str(params)
        _log(f"    params={preview[:500]}")
    if data is not None:
        preview = data if isinstance(data, str) else urllib.parse.urlencode(data)
        _log(f"    data={preview[:500]}")
    if json_body is not None:
        try:
            preview = json.dumps(json_body, ensure_ascii=False)
        except Exception:
            preview = str(json_body)
        _log(f"    json={preview[:500]}")


def _log_response(resp, tag: str = ""):
    try:
        text = resp.text or ""
    except Exception:
        text = ""
    label = tag or "http"
    _log(f"<-- {label} HTTP {getattr(resp, 'status_code', '?')} body={text[:800]}")


def _is_checkout_inactive_text(text: str) -> bool:
    lowered = (text or "").lower()
    return (
        "checkout session is no longer active" in lowered
        or "session is no longer active" in lowered
        or "no such checkout.session" in lowered
    )


def _raise_if_checkout_inactive_response(resp, context: str = "checkout"):
    if resp is None:
        return
    text = getattr(resp, "text", "") or ""
    if getattr(resp, "status_code", 0) in (400, 404, 410) and _is_checkout_inactive_text(text):
        raise CheckoutSessionInactive(f"{context}: Checkout Session 已失活，请重新生成 fresh checkout")


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


def _elements_options_client_payload() -> dict:
    return {
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
    }


def _build_stripe_hcaptcha_url(
    invisible: bool = True,
    frame_id: str | None = None,
    origin: str = "https://js.stripe.com",
) -> str:
    hcaptcha_frame_id = frame_id or str(uuid.uuid4())
    page_name = "HCaptchaInvisible.html" if invisible else "HCaptcha.html"
    return (
        "https://b.stripecdn.com/stripethirdparty-srv/assets/"
        f"{DEFAULT_STRIPE_HCAPTCHA_ASSET_VERSION}/{page_name}"
        f"?id={hcaptcha_frame_id}&origin={urllib.parse.quote(origin, safe='')}"
    )


def _extract_payment_method_types(payload: dict) -> list[str]:
    payment_method_types = payload.get("payment_method_types")
    if isinstance(payment_method_types, list) and payment_method_types:
        return [pm for pm in payment_method_types if isinstance(pm, str)]

    specs = payload.get("payment_method_specs")
    if isinstance(specs, list):
        out = []
        for spec in specs:
            if isinstance(spec, dict) and spec.get("type"):
                out.append(spec["type"])
        if out:
            return out

    return ["card"]

def _build_browser_fingerprint(locale_profile: dict) -> dict:
    """构建 RecordBrowserInfo 的完整设备指纹 payload"""
    sw = locale_profile["screen_w"]
    sh = locale_profile["screen_h"]
    dpr = locale_profile["dpr"]
    cd = locale_profile["color_depth"]
    lang = locale_profile["browser_language"]
    tz_name = locale_profile["browser_timezone"]
    tz_offset = _browser_tz_offset(locale_profile)

    # 可用高度 = 屏幕高度 - 任务栏 (48-60px)
    avail_h = sh - random.randint(40, 60)

    return {
        "navigator": {
            "mediaDevices": {"audioinput": random.randint(1, 3), "videoinput": random.randint(0, 2),
                             "audiooutput": random.randint(1, 3)},
            "battery": {"charging": True, "chargingTime": 0, "dischargingTime": None,
                        "level": round(random.uniform(0.5, 1.0), 2)},
            "appCodeName": "Mozilla", "appName": "Netscape",
            "appVersion": USER_AGENT.replace("Mozilla/", ""),
            "cookieEnabled": True, "doNotTrack": None,
            "hardwareConcurrency": random.choice([8, 12, 16, 32]),
            "language": lang,
            "languages": [lang, lang.split("-")[0]],
            "maxTouchPoints": 0, "onLine": True,
            "platform": "Win32", "product": "Gecko", "productSub": "20030107",
            "userAgent": USER_AGENT,
            "vendor": "Google Inc.", "vendorSub": "",
            "webdriver": False,
            "deviceMemory": random.choice([4, 8, 16]),
            "pdfViewerEnabled": True, "javaEnabled": False,
            "plugins": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
            "connections": {
                "effectiveType": "4g",
                "downlink": round(random.uniform(1.0, 10.0), 2),
                "rtt": random.choice([50, 100, 150, 200, 250, 300, 350, 400]),
                "saveData": False,
            },
        },
        "screen": {
            "availHeight": avail_h, "availWidth": sw,
            "availLeft": 0, "availTop": 0,
            "colorDepth": cd, "height": sh, "width": sw,
            "pixelDepth": cd,
            "orientation": "landscape-primary",
            "devicePixelRatio": dpr,
        },
        "timezone": {"offset": tz_offset, "timezone": tz_name},
        "canvas": hashlib.sha256(os.urandom(32)).hexdigest(),
        "permissions": {
            "geolocation": "denied", "notifications": "denied",
            "midi": "denied", "camera": "denied", "microphone": "denied",
            "background-fetch": "prompt", "background-sync": "granted",
            "persistent-storage": "granted", "accelerometer": "granted",
            "gyroscope": "granted", "magnetometer": "granted",
            "clipboard-read": "denied", "clipboard-write": "denied",
            "screen-wake-lock": "denied", "display-capture": "denied",
            "idle-detection": "denied",
        },
        "audio": {"sum": 124.04347527516074},
        "browserBars": {
            "locationbar": True, "menubar": True, "personalbar": True,
            "statusbar": True, "toolbar": True, "scrollbars": True,
        },
        "sensors": {
            "accelerometer": True, "gyroscope": True, "linearAcceleration": True,
            "absoluteOrientation": True, "relativeOrientation": True,
            "magnetometer": False, "ambientLight": False, "proximity": False,
        },
        "storage": {
            "localStorage": True, "sessionStorage": True,
            "indexedDB": True, "openDatabase": False,
        },
        "webGl": {
            "dataHash": hashlib.sha256(os.urandom(32)).hexdigest(),
            "vendor": "Google Inc. (NVIDIA)",
            "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 (0x00002882) Direct3D11 vs_5_0 ps_5_0, D3D11)",
        },
        "adblock": False,
        "clientRects": {
            "x": round(-10004 + random.uniform(-1, 1), 10),
            "y": round(2.35 + random.uniform(-0.01, 0.01), 10),
            "width": round(111.29 + random.uniform(-0.01, 0.01), 10),
            "height": round(111.29 + random.uniform(-0.01, 0.01), 10),
            "top": round(2.35 + random.uniform(-0.01, 0.01), 10),
            "bottom": round(113.64 + random.uniform(-0.01, 0.01), 10),
            "left": round(-10004 + random.uniform(-1, 1), 10),
            "right": round(-9893 + random.uniform(-1, 1), 10),
        },
        "fonts": {"installed_count": random.randint(40, 60), "not_installed_count": 0},
    }


def _gen_fingerprint():
    def _id():
        return str(uuid.uuid4()).replace("-", "") + uuid.uuid4().hex[:6]
    return _id(), _id(), _id()



_PLUGINS_STR = (
    "PDF Viewer,internal-pdf-viewer,application/pdf,pdf++text/pdf,pdf, "
    "Chrome PDF Viewer,internal-pdf-viewer,application/pdf,pdf++text/pdf,pdf, "
    "Chromium PDF Viewer,internal-pdf-viewer,application/pdf,pdf++text/pdf,pdf, "
    "Microsoft Edge PDF Viewer,internal-pdf-viewer,application/pdf,pdf++text/pdf,pdf, "
    "WebKit built-in PDF,internal-pdf-viewer,application/pdf,pdf++text/pdf,pdf"
)
_CANVAS_FPS = [
    "0100100101111111101111101111111001110010110111110111111",
    "0100100101111111101111101111111001110010110111110111110",
    "0100100101111111101111101111111001110010110111110111101",
]
_AUDIO_FPS = [
    "d331ca493eb692cfcd19ae5db713ad4b",
    "a7c5f72e1b3d4e8f9c0d2a6b7e8f1c3d",
    "e4b8d6f2a0c3d5e7f9b1c3d5e7f9a0b2",
]


def _encode_m6(payload: dict) -> str:
    """JSON → urlencode → base64 (m.stripe.com/6 编码格式)"""
    raw = json.dumps(payload, separators=(",", ":"))
    return base64.b64encode(urllib.parse.quote(raw, safe="").encode()).decode()


def _b64url_seg(n: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(n)).rstrip(b"=").decode()


def register_fingerprint(http: "requests.Session") -> tuple[str, str, str]:
    """向 m.stripe.com/6 发送 4 次指纹上报, 返回服务端分配的 (guid, muid, sid)。
    如果请求失败, 返回本地随机生成的值。
    """
    # 本地备用值
    guid, muid, sid = _gen_fingerprint()
    fp_id = uuid.uuid4().hex

    # 屏幕参数 (US 常见配置)
    screens = [(1920, 1080, 1), (1536, 864, 1.25), (2560, 1440, 1), (1440, 900, 1)]
    sw, sh, dpr = random.choice(screens)
    vh = sh - random.randint(40, 70)  # viewport = screen - chrome
    cpu = random.choice([4, 8, 12, 16])
    canvas_fp = random.choice(_CANVAS_FPS)
    audio_fp = random.choice(_AUDIO_FPS)

    def _build_full(v2: int, inc_ids: bool) -> dict:
        s1, s2, s3, s4, s5 = (_b64url_seg() for _ in range(5))
        ts_now = int(time.time() * 1000)
        return {
            "v2": v2, "id": fp_id,
            "t": round(random.uniform(3, 120), 1),
            "tag": "$npm_package_version", "src": "js",
            "a": {
                "a": {"v": "true", "t": 0},
                "b": {"v": "true", "t": 0},
                "c": {"v": "en-US", "t": 0},
                "d": {"v": "Win32", "t": 0},
                "e": {"v": _PLUGINS_STR, "t": round(random.uniform(0, 0.5), 1)},
                "f": {"v": f"{sw}w_{vh}h_24d_{dpr}r", "t": 0},
                "g": {"v": str(cpu), "t": 0},
                "h": {"v": "false", "t": 0},
                "i": {"v": "sessionStorage-enabled, localStorage-enabled", "t": round(random.uniform(0.5, 2), 1)},
                "j": {"v": canvas_fp, "t": round(random.uniform(5, 120), 1)},
                "k": {"v": "", "t": 0},
                "l": {"v": USER_AGENT, "t": 0},
                "m": {"v": "", "t": 0},
                "n": {"v": "false", "t": round(random.uniform(3, 50), 1)},
                "o": {"v": audio_fp, "t": round(random.uniform(20, 30), 1)},
            },
            "b": {
                "a": f"https://{s1}.{s2}.{s3}/",
                "b": f"https://{s1}.{s3}/{s4}/{s5}/{_b64url_seg()}",
                "c": _b64url_seg(),
                "d": muid if inc_ids else "NA",
                "e": sid if inc_ids else "NA",
                "f": False, "g": True, "h": True,
                "i": ["location"], "j": [],
                "n": round(random.uniform(800, 2000), 1),
                "u": "chatgpt.com", "v": "auth.openai.com",
                "w": f"{ts_now}:{hashlib.sha256(os.urandom(32)).hexdigest()}",
            },
            "h": os.urandom(10).hex(),
        }

    def _build_mouse(source: str) -> dict:
        return {
            "muid": muid, "sid": sid,
            "url": f"https://{_b64url_seg()}.{_b64url_seg()}/{_b64url_seg()}/{_b64url_seg()}/{_b64url_seg()}",
            "source": source,
            "data": [random.randint(1, 8) for _ in range(10)],
        }

    m6_headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Origin": "https://m.stripe.network",
        "Referer": "https://m.stripe.network/",
    }
    m6_url = "https://m.stripe.com/6"
    _log("      [指纹] 向 m.stripe.com/6 注册设备指纹 ...")

    # #1 完整指纹 (v2=1, 无 ID)
    try:
        r1 = http.post(m6_url, data=_encode_m6(_build_full(1, False)), headers=m6_headers, timeout=10)
        if r1.status_code == 200:
            j = r1.json()
            muid = j.get("muid", muid)
            guid = j.get("guid", guid)
            sid = j.get("sid", sid)
            _log(f"      [指纹] #1 OK → muid={muid[:20]}...")
    except Exception as e:
        _log(f"      [指纹] #1 失败: {e}")

    # #2 完整指纹 (v2=2, 带 ID)
    try:
        r2 = http.post(m6_url, data=_encode_m6(_build_full(2, True)), headers=m6_headers, timeout=10)
        if r2.status_code == 200:
            j = r2.json()
            guid = j.get("guid", guid)
            _log(f"      [指纹] #2 OK → guid={guid[:20]}...")
    except Exception as e:
        _log(f"      [指纹] #2 失败: {e}")

    # #3 鼠标行为 (mouse-timings-10-v2)
    try:
        http.post(m6_url, data=_encode_m6(_build_mouse("mouse-timings-10-v2")), headers=m6_headers, timeout=10)
        _log("      [指纹] #3 OK (mouse-timings-v2)")
    except Exception:
        pass

    # #4 鼠标行为 (mouse-timings-10)
    try:
        http.post(m6_url, data=_encode_m6(_build_mouse("mouse-timings-10")), headers=m6_headers, timeout=10)
        _log("      [指纹] #4 OK (mouse-timings)")
    except Exception:
        pass

    _log(f"      [指纹] 完成 → guid={guid[:25]}... muid={muid[:25]}... sid={sid[:25]}...")
    return guid, muid, sid


def _gen_elements_session_id():
    """生成类似 elements_session_15hfldlRpSm 的 session id"""
    import random, string
    chars = string.ascii_letters + string.digits
    return "elements_session_" + "".join(random.choices(chars, k=11))


def _stripe_headers():
    return {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
    }
def parse_checkout_url(raw: str) -> tuple[str, str]:
    """解析输入，返回 (session_id, stripe_checkout_url)

    支持以下格式:
      - 裸 session_id: cs_live_xxx / cs_test_xxx
      - Stripe URL: https://checkout.stripe.com/c/pay/cs_live_xxx
      - ChatGPT URL: https://chatgpt.com/checkout/openai_llc/cs_live_xxx
    """
    raw = raw.strip()
    m = re.search(r"(cs_(?:live|test)_[A-Za-z0-9]+)", raw)
    if not m:
        raise ValueError(f"无法从输入中提取 checkout_session_id: {raw[:120]}...")
    session_id = m.group(1)

    # 构建用于 Playwright 等回退方案的 Stripe checkout URL
    # 如果输入是 checkout.stripe.com 的链接则直接使用，否则用标准格式构建
    if "checkout.stripe.com" in raw:
        stripe_url = raw
    else:
        stripe_url = f"https://checkout.stripe.com/c/pay/{session_id}"

    return session_id, stripe_url


def fetch_publishable_key(session: requests.Session, session_id: str, stripe_checkout_url: str) -> str:
    checkout_url = stripe_checkout_url

    _log("[2/6] 获取 publishable_key ...")

    for acct_id_part, known_pk in KNOWN_PUBLISHABLE_KEYS.items():
        try:
            url = f"{STRIPE_API}/v1/payment_pages/{session_id}/init"
            post_data = {"key": known_pk, "_stripe_version": STRIPE_VERSION_BASE,
                      "browser_locale": "en-US"}
            _log_request("POST", url, data=post_data, tag="[2/6] pk探测")
            test_resp = session.post(url, data=post_data, headers=_stripe_headers(), timeout=15)
            _log_response(test_resp, tag="[2/6] pk探测")
            _raise_if_checkout_inactive_response(test_resp, "publishable_key 探测")
            if test_resp.status_code == 200:
                _log(f"      publishable_key: {known_pk[:30]}... (已知)")
                return known_pk
        except Exception as e:
            _log(f"      pk探测异常: {e}")

    pk = _fetch_pk_playwright(checkout_url)
    if pk:
        _log(f"      publishable_key: {pk[:30]}... (playwright)")
        return pk

    raise RuntimeError("无法提取 publishable_key")


def _fetch_pk_playwright(checkout_url: str) -> str | None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    pk = None

    def on_request(request):
        nonlocal pk
        if pk:
            return
        if "api.stripe.com" in request.url and "init" in request.url:
            post = request.post_data or ""
            m = re.search(r"key=(pk_(?:live|test)_[A-Za-z0-9]+)", post)
            if m:
                pk = m.group(1)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("request", on_request)
            try:
                page.goto(checkout_url, wait_until="domcontentloaded", timeout=20000)
                for _ in range(10):
                    if pk:
                        break
                    page.wait_for_timeout(1000)
            except Exception:
                pass
            browser.close()
    except Exception:
        return None

    return pk


def init_checkout(session: requests.Session, session_id: str, pk: str, locale_profile: dict = None) -> tuple[dict, str, dict]:
    """返回 (init_resp, stripe_ver, ctx) — ctx 包含后续步骤需要的上下文"""
    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/init"
    stripe_js_id = str(uuid.uuid4())
    elements_session_id = _gen_elements_session_id()
    elements_options = _elements_options_client_payload()

    for version in [STRIPE_VERSION_BASE, STRIPE_VERSION_FULL]:
        data = {
            "browser_locale": locale_profile["browser_locale"],
            "browser_timezone": locale_profile["browser_timezone"],
            "elements_session_client[elements_init_source]": "custom_checkout",
            "elements_session_client[referrer_host]": "chatgpt.com",
            "elements_session_client[stripe_js_id]": stripe_js_id,
            "elements_session_client[locale]": locale_profile["browser_locale"],
            "elements_session_client[is_aggregation_expected]": "false",
            "key": pk,
            "_stripe_version": version,
        }
        data.update(elements_options)
        if version == STRIPE_VERSION_FULL:
            data["elements_session_client[client_betas][0]"] = "custom_checkout_server_updates_1"
            data["elements_session_client[client_betas][1]"] = "custom_checkout_manual_approval_1"

        _log(f"      初始化结账会话 (init) ... version={version[:30]}")
        _log_request("POST", url, data=data, tag="[2b/6] init")
        resp = session.post(url, data=data, headers=_stripe_headers())
        _log_response(resp, tag="[2b/6] init")
        _raise_if_checkout_inactive_response(resp, "init")
        if resp.status_code == 200:
            init_data = resp.json()
            ctx = {
                "stripe_js_id": stripe_js_id,
                "elements_session_id": elements_session_id,
                "elements_options_client": elements_options,
                "browser_locale": locale_profile["browser_locale"],
                "locale": init_data.get("locale") or _locale_short(locale_profile),
                "currency": (init_data.get("currency") or "usd").lower(),
                "checkout_amount": (
                    (init_data.get("total_summary") or {}).get("due")
                    if (init_data.get("total_summary") or {}).get("due") is not None
                    else (init_data.get("invoice") or {}).get("amount_due")
                ),
                "payment_method_types": _extract_payment_method_types(init_data),
                "config_id": init_data.get("config_id", ""),
                "init_checksum": init_data.get("init_checksum", ""),
                "return_url": init_data.get("return_url") or "",
                "stripe_hosted_url": init_data.get("stripe_hosted_url") or "",
            }
            return init_data, version, ctx
        if resp.status_code == 400 and "beta" in resp.text.lower():
            _log(f"      版本 {version[:20]}... 不支持 beta, 尝试下一个 ...")
            continue
        raise RuntimeError(f"init 失败 [{resp.status_code}]: {resp.text[:500]}")

    raise RuntimeError("init 失败: 所有 Stripe API 版本均不可用")


def extract_hcaptcha_config(init_resp: dict) -> dict:
    raw = json.dumps(init_resp)
    result = {
        "site_key": HCAPTCHA_SITE_KEY_FALLBACK,
        "rqdata": "",
        "is_invisible": True,
        "website_url": _build_stripe_hcaptcha_url(invisible=True),
    }

    if init_resp.get("site_key"):
        result["site_key"] = init_resp["site_key"]
    m = re.search(r'"hcaptcha_site_key"\s*:\s*"([^"]+)"', raw)
    if m and not init_resp.get("site_key"):
        result["site_key"] = m.group(1)

    m = re.search(r'"hcaptcha_rqdata"\s*:\s*"([^"]+)"', raw)
    if m:
        result["rqdata"] = m.group(1)

    return result


def extract_passive_captcha_config(init_resp: dict, elements_resp: dict | None = None) -> dict:
    """优先使用 elements/sessions 返回的 passive_captcha，其次回退到 init 响应。"""
    passive = (elements_resp or {}).get("passive_captcha") or {}
    site_key = passive.get("site_key") or init_resp.get("site_key") or HCAPTCHA_SITE_KEY_FALLBACK
    rqdata = passive.get("rqdata")
    if rqdata is None:
        rqdata = init_resp.get("rqdata", "")
    return {
        "site_key": site_key,
        "rqdata": rqdata or "",
        "is_invisible": True,
        "website_url": _build_stripe_hcaptcha_url(invisible=True),
    }


def fetch_elements_session(
    session: requests.Session,
    pk: str,
    session_id: str,
    ctx: dict,
    stripe_ver: str = STRIPE_VERSION_FULL,
    locale_profile: dict = None,
) -> dict:
    """调用 elements/sessions, 返回响应 dict 并更新 ctx 中的 elements_session_id"""
    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    locale_short = ctx.get("locale") or _locale_short(locale_profile)  # HAR: "zh" 而非 "zh-CN"
    stripe_js_id = ctx.get("stripe_js_id", str(uuid.uuid4()))
    currency = (ctx.get("currency") or "usd").lower()
    deferred_amount = ctx.get("checkout_amount")
    if deferred_amount is None:
        deferred_amount = 0
    payment_method_types = ctx.get("payment_method_types") or ["card"]
    url = f"{STRIPE_API}/v1/elements/sessions"
    params = {
        "client_betas[0]": "custom_checkout_server_updates_1",
        "client_betas[1]": "custom_checkout_manual_approval_1",
        "deferred_intent[mode]": "subscription",
        "deferred_intent[amount]": str(int(deferred_amount)),
        "deferred_intent[currency]": currency,
        "deferred_intent[setup_future_usage]": "off_session",
        "currency": currency,
        "key": pk,
        "_stripe_version": stripe_ver,
        "elements_init_source": "custom_checkout",
        "referrer_host": "chatgpt.com",
        "stripe_js_id": stripe_js_id,
        "locale": locale_short,
        "type": "deferred_intent",
        "checkout_session_id": session_id,
    }
    for idx, payment_method_type in enumerate(payment_method_types):
        params[f"deferred_intent[payment_method_types][{idx}]"] = payment_method_type
    _log("      [elements] GET /v1/elements/sessions ...")
    _log_request("GET", url, params=params, tag="[2c] elements/sessions")
    resp = session.get(url, params=params, headers=_stripe_headers())
    _log_response(resp, tag="[2c] elements/sessions")

    if resp.status_code == 200:
        data = resp.json()
        # 提取真实的 elements_session_id (如果有)
        real_es_id = data.get("session_id") or data.get("id")
        if real_es_id:
            ctx["elements_session_id"] = real_es_id
            _log(f"      [elements] 真实 session_id: {real_es_id}")
        # 提取 config_id
        config_id = data.get("config_id")
        if config_id:
            ctx["elements_session_config_id"] = config_id
            _log(f"      [elements] config_id: {config_id}")
        passive_captcha = data.get("passive_captcha")
        if isinstance(passive_captcha, dict):
            ctx["passive_captcha"] = passive_captcha
        element_payment_types = []
        for spec in data.get("payment_method_specs", []):
            if isinstance(spec, dict) and spec.get("type"):
                element_payment_types.append(spec["type"])
        if element_payment_types:
            ctx["payment_method_types"] = element_payment_types
        return data
    else:
        _log(f"      [elements] 请求失败 [{resp.status_code}], 继续使用本地生成的 ID")
        return {}



def _stripe_link_cookie_headers() -> dict:
    return {
        "accept": "application/json",
        "content-type": "application/json",
        "origin": "https://js.stripe.com",
        "referer": "https://js.stripe.com/",
        "user-agent": USER_AGENT,
    }


def _stripe_get_link_cookie_secret(session: requests.Session) -> str:
    url = "https://merchant-ui-api.stripe.com/link/get-cookie?referrer_host=chatgpt.com"
    try:
        resp = session.get(url, headers=_stripe_link_cookie_headers(), timeout=10)
        _log_response(resp, tag="[2d] link/get-cookie")
        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                data = {}
            token = (data.get("auth_session_client_secret") or "").strip() if isinstance(data, dict) else ""
            if token:
                return token
    except Exception as e:
        _log(f"      [link] get-cookie 异常: {e}")
    try:
        return session.cookies.get("__Host-LinkSession", "")
    except Exception:
        return ""


def _stripe_set_link_cookie_secret(session: requests.Session, auth_session_client_secret: str):
    if not auth_session_client_secret:
        return
    url = "https://merchant-ui-api.stripe.com/link/set-cookie"
    payload = {"auth_session_client_secret": auth_session_client_secret}
    try:
        _log_request("POST", url, data=payload, tag="[2d] link/set-cookie")
        resp = session.post(url, json=payload, headers=_stripe_link_cookie_headers(), timeout=10)
        _log_response(resp, tag="[2d] link/set-cookie")
    except Exception as e:
        _log(f"      [link] set-cookie 异常: {e}")


def lookup_consumer(
    session: requests.Session,
    pk: str,
    email: str,
    checkout_session_id: str,
    stripe_ver: str = STRIPE_VERSION_FULL,
    ctx: dict | None = None,
    init_resp: dict | None = None,
):
    """查询 Stripe Link 消费者会话，优先按 flows 的 cookie-based 链路重放。"""
    url = f"{STRIPE_API}/v1/consumers/sessions/lookup"
    ctx = ctx or {}
    init_resp = init_resp or {}
    results = []

    stripe_js_id = ctx.get("stripe_js_id", "") or checkout_session_id
    currency = str((ctx.get("currency") or init_resp.get("currency") or "usd")).lower()
    expected_amount = None
    total_summary = init_resp.get("total_summary") or {}
    invoice = init_resp.get("invoice") or {}
    if total_summary.get("due") is not None:
        expected_amount = int(total_summary["due"])
    elif invoice.get("amount_due") is not None:
        expected_amount = int(invoice["amount_due"])
    elif ctx.get("checkout_amount") is not None:
        expected_amount = int(ctx["checkout_amount"])

    verification_secret = (
        ctx.get("link_auth_session_client_secret")
        or ctx.get("verification_session_client_secret")
        or _stripe_get_link_cookie_secret(session)
    )

    if verification_secret:
        ctx["link_auth_session_client_secret"] = verification_secret
        _log("      [link] 使用 auth_session_client_secret 按 flows 模式 lookup ...")
        surfaces = [
            (
                "web_elements_controller",
                {
                    "request_surface": "web_elements_controller",
                    "cookies[verification_session_client_secrets][0]": verification_secret,
                    "cookies[lifetime]": "persistent",
                    "session_id": stripe_js_id,
                    "key": pk,
                    "_stripe_version": stripe_ver,
                    "do_not_log_consumer_funnel_event": "true",
                },
            ),
            (
                "web_link_authentication_in_payment_element",
                {
                    "request_surface": "web_link_authentication_in_payment_element",
                    "currency": currency,
                    "transaction_context[link_supported_payment_methods][0]": "CARD",
                    "transaction_context[link_supported_payment_methods][1]": "INSTANT_DEBITS",
                    "transaction_context[is_recurring]": "true",
                    "transaction_context[link_mode]": "LINK_CARD_BRAND",
                    "supported_payment_details_types[0]": "CARD",
                    "supported_payment_details_types[1]": "BANK_ACCOUNT",
                    "cookies[verification_session_client_secrets][0]": verification_secret,
                    "cookies[lifetime]": "persistent",
                    "session_id": checkout_session_id,
                    "key": pk,
                    "_stripe_version": stripe_ver,
                },
            ),
        ]
    else:
        surfaces = [
            (
                "web_elements_controller",
                {
                    "request_surface": "web_elements_controller",
                    "email_address": email,
                    "email_source": "default_value",
                    "session_id": stripe_js_id,
                    "key": pk,
                    "_stripe_version": stripe_ver,
                    "do_not_log_consumer_funnel_event": "true",
                },
            ),
            (
                "web_link_authentication_in_payment_element",
                {
                    "request_surface": "web_link_authentication_in_payment_element",
                    "email_address": email,
                    "email_source": "default_value",
                    "currency": currency,
                    "transaction_context[link_supported_payment_methods][0]": "CARD",
                    "transaction_context[link_supported_payment_methods][1]": "INSTANT_DEBITS",
                    "transaction_context[is_recurring]": "true",
                    "transaction_context[link_mode]": "LINK_CARD_BRAND",
                    "supported_payment_details_types[0]": "CARD",
                    "supported_payment_details_types[1]": "BANK_ACCOUNT",
                    "session_id": checkout_session_id,
                    "key": pk,
                    "_stripe_version": stripe_ver,
                },
            ),
        ]

    if expected_amount is not None and int(expected_amount) > 0:
        surfaces[-1][1]["amount"] = str(int(expected_amount))

    for surface, data in surfaces:
        try:
            _log(f"      [link] lookup ({surface[:30]}...) ...")
            _log_request("POST", url, data=data, tag="[2d] consumer/lookup")
            resp = session.post(url, data=data, headers=_stripe_headers(), timeout=10)
            _log_response(resp, tag="[2d] consumer/lookup")
            if resp.status_code == 200:
                payload = resp.json()
                results.append(payload)
                if isinstance(payload, dict):
                    new_secret = (payload.get("auth_session_client_secret") or "").strip()
                    if new_secret:
                        verification_secret = new_secret
                        ctx["link_auth_session_client_secret"] = new_secret
        except Exception as e:
            _log(f"      [link] lookup 异常: {e}")
        if verification_secret:
            _stripe_set_link_cookie_secret(session, verification_secret)
        time.sleep(random.uniform(0.3, 0.8))

    ctx["link_lookup_results"] = results
    return results


def update_payment_page_address(
    session: requests.Session,
    pk: str,
    session_id: str,
    card: dict,
    ctx: dict,
    stripe_ver: str = STRIPE_VERSION_FULL,
):
    """模拟浏览器逐字段提交地址/税区信息, 共 6 次 POST"""
    url = f"{STRIPE_API}/v1/payment_pages/{session_id}"
    addr = card.get("address", {})
    elements_session_id = ctx.get("elements_session_id", _gen_elements_session_id())
    stripe_js_id = ctx.get("stripe_js_id", str(uuid.uuid4()))
    locale = ctx.get("locale") or _locale_short(LOCALE_PROFILES["US"])

    # 基础字段 — 每次 update 都要带
    base = {
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[session_id]": elements_session_id,
        "elements_session_client[stripe_js_id]": stripe_js_id,
        "elements_session_client[locale]": locale,
        "elements_session_client[is_aggregation_expected]": "false",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
        "key": pk,
        "_stripe_version": stripe_ver,
    }
    base.update(ctx.get("elements_options_client") or _elements_options_client_payload())

    # HAR 中的逐字段提交顺序: country → (重复一次) → line1 → city → state → postal_code
    address_steps = [
        {"tax_region[country]": addr.get("country", "US")},
        {},  # 重复提交 (无新字段, 模拟用户切换焦点)
        {"tax_region[line1]": addr.get("line1", "")},
        {"tax_region[city]": addr.get("city", "")},
        {"tax_region[state]": addr.get("state", "")},
        {"tax_region[postal_code]": addr.get("postal_code", "")},
    ]

    _log("      [address] 逐字段提交税区地址 ...")
    accumulated = {}
    for step_idx, new_fields in enumerate(address_steps):
        accumulated.update(new_fields)
        data = dict(base)
        data.update(accumulated)

        step_name = list(new_fields.keys())[0] if new_fields else "(焦点变更)"
        _log(f"      [address] step {step_idx + 1}/6: {step_name}")
        _log_request("POST", url, data=data, tag=f"[2e] update_address({step_idx + 1}/6)")
        resp = session.post(url, data=data, headers=_stripe_headers())
        _log_response(resp, tag=f"[2e] update_address({step_idx + 1}/6)")

        if resp.status_code != 200:
            _log(f"      [address] step {step_idx + 1} 返回 {resp.status_code}, 继续 ...")

        # 模拟人类输入间隔 (2-5 秒)
        time.sleep(random.uniform(2.0, 4.5))

def send_telemetry(
    session: requests.Session,
    event_type: str,
    session_id: str,
    ctx: dict,
):
    """向 r.stripe.com/b 发送遥测事件, 模拟 stripe.js 行为上报"""
    url = "https://r.stripe.com/b"
    muid = ctx.get("muid", "")
    sid = ctx.get("sid", "")
    guid = ctx.get("guid", "")

    payload = {
        "v2": 1,
        "tag": event_type,
        "src": "js",
        "pid": "checkout_" + session_id[:20],
        "muid": muid,
        "sid": sid,
        "guid": guid,
    }
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
    }
    try:
        body = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        session.post(url, data=body, headers=headers, timeout=5)
    except Exception:
        pass


def send_telemetry_batch(
    session: requests.Session,
    session_id: str,
    ctx: dict,
    phase: str = "init",
):
    """按阶段批量发送遥测事件"""
    events_map = {
        "init": ["checkout.init", "elements.create", "payment_element.mount"],
        "address": ["address.update", "address.focus", "address.blur"],
        "card_input": ["card.focus", "card.input", "card.blur", "cvc.input"],
        "confirm": ["checkout.confirm.start", "payment_method.create", "checkout.confirm.intent"],
        "3ds": ["three_ds2.start", "three_ds2.fingerprint", "three_ds2.authenticate"],
        "poll": ["checkout.poll", "checkout.complete"],
    }
    events = events_map.get(phase, [])
    for evt in events:
        send_telemetry(session, evt, session_id, ctx)
        time.sleep(random.uniform(0.05, 0.2))


def submit_apata_fingerprint(
    session: requests.Session,
    three_ds_server_trans_id: str,
    three_ds_method_url: str,
    notification_url: str,
    locale_profile: dict,
    ctx: dict,
):


    # 1) POST acs-method.apata.io/v1/houston/method — 提交 threeDSMethodData
    _log("      [apata] POST houston/method ...")
    method_data = base64.b64encode(json.dumps({
        "threeDSServerTransID": three_ds_server_trans_id,
        "threeDSMethodNotificationURL": notification_url,
    }, separators=(",", ":")).encode()).decode()

    try:
        method_url = three_ds_method_url or "https://acs-method.apata.io/v1/houston/method"
        resp = session.post(
            method_url,
            data={"threeDSMethodData": method_data},
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://js.stripe.com",
                "Referer": "https://js.stripe.com/",
            },
            timeout=15,
        )
        _log(f"      [apata] houston/method → {resp.status_code}")
    except Exception as e:
        _log(f"      [apata] houston/method 异常: {e}")

    time.sleep(random.uniform(0.5, 1.0))

    # 2) POST acs-method.apata.io/v1/RecordBrowserInfo — 设备指纹上报
    _log("      [apata] POST RecordBrowserInfo ...")
    # 生成 possessionDeviceId (localStorage acsRbaDeviceId 模拟)
    possession_device_id = ctx.get("apata_device_id") or str(uuid.uuid4())
    ctx["apata_device_id"] = possession_device_id

    fp_data = _build_browser_fingerprint(locale_profile)
    record_payload = {
        "threeDSServerTransID": three_ds_server_trans_id,
        "computedValue": hashlib.sha256(os.urandom(32)).hexdigest()[:20],
        "possessionDeviceId": possession_device_id,
    }
    record_payload.update(fp_data)

    try:
        record_url = "https://acs-method.apata.io/v1/RecordBrowserInfo"
        resp = session.post(
            record_url,
            json=record_payload,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Origin": "https://acs-method.apata.io",
                "Referer": "https://acs-method.apata.io/",
            },
            timeout=15,
        )
        _log(f"      [apata] RecordBrowserInfo → {resp.status_code}")
    except Exception as e:
        _log(f"      [apata] RecordBrowserInfo 异常: {e}")

    time.sleep(random.uniform(0.5, 1.0))

    # 3) GET rba.apata.io/xxx.js — 模拟 RBA profile 脚本加载
    _log("      [apata] GET rba profile script ...")
    rba_session_id = ctx.get("rba_session_id") or str(uuid.uuid4())
    ctx["rba_session_id"] = rba_session_id
    try:
        # HAR 中的 URL 格式: rba.apata.io/<random>.js?<random_param>=<org_id>&<random_param>=<session_id>
        rba_script_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16)) + ".js"
        rba_param1 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        rba_param2 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        rba_url = f"https://rba.apata.io/{rba_script_name}?{rba_param1}={APATA_RBA_ORG_ID}&{rba_param2}={rba_session_id}"
        resp = session.get(rba_url, headers={"User-Agent": USER_AGENT}, timeout=10)
        _log(f"      [apata] rba profile → {resp.status_code}")
    except Exception as e:
        _log(f"      [apata] rba profile 异常: {e}")

    # 4) 模拟 aa.online-metrix.net CONNECT (WebRTC beacon 不可模拟, 仅日志标记)
    _log("      [apata] online-metrix beacon (WebRTC, 已跳过 — 无法在 requests 中模拟)")

    # 总等待: 让 Apata 有时间处理指纹结果 (HAR 中这个窗口约 8-12 秒)
    wait = random.uniform(5.0, 8.0)
    _log(f"      [apata] 等待指纹处理完成 ({wait:.1f}s) ...")
    time.sleep(wait)
