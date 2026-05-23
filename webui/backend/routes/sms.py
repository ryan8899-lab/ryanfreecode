"""SMS receiving platform integration for standalone pages.

Supports configurable endpoint templates so pvapins can be wired from their
API docs without changing code. Defaults are placeholders; Ryan can paste the
provider's real paths/params in the standalone panel.
"""
from __future__ import annotations

import json
import re

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import CurrentUser, current_user_optional
from ..db import get_db
from .inventory import _share_token


router = APIRouter(prefix="/api/sms", tags=["sms"])
META_KEY = "sms_provider_config"
SESSION_KEY = "sms_active_number"


class SmsConfig(BaseModel):
    base_url: str = "https://api.pvapins.com"
    api_key: str = ""
    token: str = ""
    service: str = "gojek"
    country: str = "indonesia"
    operator: str = ""
    # endpoint templates, using {api_key},{token},{service},{country},{operator},{activation_id},{phone}
    get_number_path: str = "/user/api/get_number.php"
    get_number_method: str = "GET"
    get_number_params: dict = Field(default_factory=lambda: {"customer": "{api_key}", "app": "{service}", "country": "{country}", "operator": "{operator}"})
    get_sms_path: str = "/user/api/get_sms.php"
    get_sms_method: str = "GET"
    get_sms_params: dict = Field(default_factory=lambda: {"customer": "{api_key}", "number": "{phone}", "country": "{country}", "app": "{service}", "operator": "{operator}"})
    reject_path: str = ""
    reject_method: str = "GET"
    reject_params: dict = Field(default_factory=dict)
    cancel_path: str = "/user/api/get_reject_number.php"
    cancel_method: str = "GET"
    cancel_params: dict = Field(default_factory=lambda: {"customer": "{api_key}", "number": "{phone}", "country": "{country}", "app": "{service}", "operator": "{operator}"})
    continue_path: str = "/user/api/get_number.php"
    continue_method: str = "GET"
    continue_params: dict = Field(default_factory=lambda: {"customer": "{api_key}", "app": "{service}", "country": "{country}", "number": "{phone}", "operator": "{operator}"})
    headers: dict = Field(default_factory=dict)
    extra: dict = Field(default_factory=dict)


class SmsGenericRequest(BaseModel):
    path: str = Field(default="")
    method: str = Field(default="GET", pattern="^(GET|POST)$")
    params: dict = Field(default_factory=dict)
    json_body: dict = Field(default_factory=dict)


class SmsActionRequest(BaseModel):
    activation_id: str = ""
    phone: str = ""


def _default_cfg() -> dict:
    return SmsConfig().model_dump()


def _normalize_cfg(data: dict | None) -> dict:
    base = _default_cfg()
    if isinstance(data, dict):
        base.update(data)
    # Migrate older placeholder defaults to the official PVAPins temporary API.
    if str(base.get("base_url") or "").rstrip("/") == "https://pvapins.com":
        base["base_url"] = "https://api.pvapins.com"
    migrations = {
        "get_number_path": ("/api/get_number", "/user/api/get_number.php"),
        "get_sms_path": ("/api/get_sms", "/user/api/get_sms.php"),
        "cancel_path": ("/api/cancel", "/user/api/get_reject_number.php"),
        "continue_path": ("/api/continue", "/user/api/get_number.php"),
    }
    for key, (old, new) in migrations.items():
        if base.get(key) == old:
            base[key] = new
    if base.get("get_number_params") == {"service": "{service}", "country": "{country}", "operator": "{operator}"}:
        base["get_number_params"] = _default_cfg()["get_number_params"]
    if base.get("get_sms_params") == {"id": "{activation_id}"}:
        base["get_sms_params"] = _default_cfg()["get_sms_params"]
    if base.get("cancel_params") == {"id": "{activation_id}"}:
        base["cancel_params"] = _default_cfg()["cancel_params"]
    if base.get("continue_params") == {"id": "{activation_id}"}:
        base["continue_params"] = _default_cfg()["continue_params"]
    base["service"] = str(base.get("service") or "gojek").strip().lower()
    c = str(base.get("country") or "indonesia").strip().lower()
    if c in {"id", "indo"}:
        c = "indonesia"
    base["country"] = c
    return base


def _load_cfg() -> dict:
    raw = get_db().get_runtime_value(META_KEY, "")
    if not raw:
        return _default_cfg()
    try:
        data = json.loads(raw)
    except Exception:
        data = None
    return _normalize_cfg(data)


def _save_cfg(data: dict):
    get_db().set_runtime_value(META_KEY, json.dumps(_normalize_cfg(data), ensure_ascii=False))




def _standalone_authorized(token: str, user: str | None) -> bool:
    return bool(user) or bool(token and token == _share_token())


def _mask(cfg: dict) -> dict:
    masked = dict(cfg)
    for k in ("api_key", "token"):
        v = str(masked.get(k) or "")
        if v:
            masked[k] = v[:4] + "…" + v[-4:] if len(v) > 10 else "***"
    return masked


def _fmt_obj(obj, ctx):
    if isinstance(obj, str):
        try:
            return obj.format(**ctx)
        except Exception:
            return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            vv = _fmt_obj(v, ctx)
            if vv not in (None, ""):
                out[k] = vv
        return out
    if isinstance(obj, list):
        return [_fmt_obj(x, ctx) for x in obj]
    return obj


def _ctx(cfg: dict, extra: dict | None = None) -> dict:
    service = cfg.get("service", "")
    country = cfg.get("country", "")
    try:
        if str(service).strip().lower() == "gojek" and str(country).strip().lower() in {"indonesia", "id"}:
            service = "Gojek"
            country = "Indonesia"
    except Exception:
        pass
    c = {
        "api_key": cfg.get("api_key", ""),
        "token": cfg.get("token", ""),
        "service": service,
        "country": country,
        "operator": cfg.get("operator", ""),
        "activation_id": "",
        "phone": "",
    }
    if extra:
        c.update(extra)
    return c


def _call_template(cfg: dict, prefix: str, extra: dict | None = None) -> dict:
    ctx = _ctx(cfg, extra)
    path = _fmt_obj(cfg.get(f"{prefix}_path") or "", ctx)
    method = str(cfg.get(f"{prefix}_method") or "GET").upper()
    params = _fmt_obj(cfg.get(f"{prefix}_params") or {}, ctx)
    base_url = str(cfg.get("base_url") or "").rstrip("/")
    provider = str(cfg.get("provider") or (cfg.get("extra") or {}).get("provider") or "").strip().lower()
    is_5sim = provider == "5sim" or "5sim.net" in base_url
    is_hero = provider in {"hero", "hero-sms", "herosms"} or "hero-sms.com" in base_url
    # Generic auth injection; harmless if provider ignores duplicate keys.
    if cfg.get("api_key") and not any(k in params for k in ("api_key", "key", "apikey")):
        params["api_key"] = cfg["api_key"]
    # 5sim requires Authorization: Bearer TOKEN; do not leak the token in query params.
    if cfg.get("token") and "token" not in params and not is_5sim:
        params["token"] = cfg["token"]
    if not path.startswith("/"):
        raise HTTPException(status_code=400, detail=f"{prefix}_path 必须以 / 开头")
    url = base_url + str(path)
    try:
        headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "OpenClaw-WebUI-SMS/1.0"}
        try:
            custom_headers = {}
            h1 = _fmt_obj(cfg.get("headers") or {}, ctx)
            h2 = _fmt_obj((cfg.get("extra") or {}).get("headers") or {}, ctx)
            if isinstance(h1, dict):
                custom_headers.update(h1)
            if isinstance(h2, dict):
                custom_headers.update(h2)
            headers.update({str(k): str(v) for k, v in custom_headers.items() if v not in (None, "")})
        except Exception:
            pass
        if is_5sim and cfg.get("token") and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {cfg['token']}"
            headers["Accept"] = "application/json"
        if method == "POST":
            r = requests.post(url, params=params, headers=headers, timeout=30)
        else:
            r = requests.get(url, params=params, headers=headers, timeout=30)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SMS provider request failed: {type(e).__name__}: {e}")
    try:
        body = r.json()
    except Exception:
        body = r.text[:8000]
    return {"status_code": r.status_code, "ok": r.ok, "body": body, "url": url, "params": params, "provider": provider or ("5sim" if is_5sim else "hero" if is_hero else "")}


def _extract_number(resp: dict) -> dict:
    body = resp.get("body")
    text = json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body or "")

    def find_keys(o):
        if isinstance(o, dict):
            low = {str(k).lower(): v for k, v in o.items()}
            aid = (
                low.get("activation_id") or low.get("activationid") or low.get("activation")
                or low.get("order_id") or low.get("orderid") or low.get("request_id")
                or low.get("requestid") or low.get("id")
            )
            phone = low.get("phone") or low.get("number") or low.get("mobile") or low.get("msisdn") or low.get("phonenumber")
            if aid or phone:
                return aid, phone
            for v in o.values():
                r = find_keys(v)
                if r:
                    return r
        if isinstance(o, list):
            for v in o:
                r = find_keys(v)
                if r:
                    return r
        return None

    r = find_keys(body)
    if r:
        aid, phone = r
        # PVAPins temporary API returns {code:100,data:"PHONE"}; there is no
        # activation id, subsequent actions use the phone number itself.
        if not phone and isinstance(body, dict):
            low = {str(k).lower(): v for k, v in body.items()}
            if str(low.get("code") or "") == "100" and re.fullmatch(r"\+?\d{8,}", str(low.get("data") or "")):
                phone = low.get("data")
                aid = phone
        return {"activation_id": str(aid or phone or ""), "phone": str(phone or "")}
    if isinstance(body, dict):
        low = {str(k).lower(): v for k, v in body.items()}
        data = str(low.get("data") or "")
        if str(low.get("code") or "") == "100" and re.fullmatch(r"\+?\d{8,}", data):
            return {"activation_id": data, "phone": data}
    # fallbacks for ACCESS_NUMBER:id:phone / id|phone / id:phone style APIs
    for pat in (
        r"(?:ACCESS_NUMBER|NUMBER)[^0-9]*(\d+)[^0-9+]*(\+?\d{8,})",
        r"\b(\d{4,})[|:;, ]+(\+?\d{8,})\b",
    ):
        m = re.search(pat, text, re.I)
        if m:
            return {"activation_id": m.group(1), "phone": m.group(2)}
    return {"activation_id": "", "phone": ""}


def _extract_sms(resp: dict) -> dict:
    body = resp.get("body")
    text = json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body or "")

    # 5sim returns {status:"RECEIVED", sms:[{text:"...", code:"123456"}, ...]}.
    # Prefer explicit sms[].code over regexing the whole object; otherwise order ids
    # or timestamps can be mistaken for OTPs.
    if isinstance(body, dict):
        low_top = {str(k).lower(): v for k, v in body.items()}
        sms_list = low_top.get("sms")
        if isinstance(sms_list, list) and sms_list:
            for item in reversed(sms_list):
                if not isinstance(item, dict):
                    continue
                low_item = {str(k).lower(): v for k, v in item.items()}
                explicit_code = str(low_item.get("code") or low_item.get("otp") or "").strip()
                msg = str(low_item.get("text") or low_item.get("message") or low_item.get("sms") or explicit_code or "")
                code = explicit_code if re.fullmatch(r"\d{4,8}", explicit_code) else ""
                if not code:
                    m = re.search(r"(?<!\d)(\d{4,8})(?!\d)", msg)
                    code = m.group(1) if m else ""
                if code or msg:
                    return {"sms_text": msg[:2000], "code": code, "provider_status": str(low_top.get("status") or low_top.get("state") or "")}

    # HeroSMS / SMS-Activate compatible status strings: STATUS_OK:123456,
    # STATUS_WAIT_CODE, ACCESS_CANCEL, etc.
    if isinstance(body, str):
        m = re.search(r"STATUS_OK[:：]\s*(\d{4,8})", body, re.I)
        if m:
            return {"sms_text": body[:2000], "code": m.group(1), "provider_status": "STATUS_OK"}

    def walk(o):
        if isinstance(o, dict):
            low = {str(k).lower(): v for k, v in o.items()}
            msg = low.get("sms") or low.get("message") or low.get("text") or low.get("code") or low.get("otp")
            status = low.get("status") or low.get("state")
            if msg:
                return str(msg), str(status or "")
            for v in o.values():
                r = walk(v)
                if r:
                    return r
        elif isinstance(o, list):
            for v in o:
                r = walk(v)
                if r:
                    return r
        return None

    found = walk(body)
    sms_text = found[0] if found else text
    status = found[1] if found else ""
    code = ""
    m = re.search(r"(?<!\d)(\d{4,8})(?!\d)", sms_text)
    if m:
        code = m.group(1)
    return {"sms_text": sms_text[:2000], "code": code, "provider_status": status}


@router.get("/config")
def get_config(user: str = CurrentUser):
    cfg = _load_cfg()
    return {"config": _mask(cfg), "raw_config": cfg, "has_secret": bool(cfg.get("api_key") or cfg.get("token"))}


@router.post("/config")
def save_config(cfg: SmsConfig, user: str = CurrentUser):
    data = cfg.model_dump()
    _save_cfg(data)
    return {"ok": True, "config": _mask(data)}


@router.get("/standalone/config")
def standalone_config(token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    cfg = _load_cfg()
    return {"config": _mask(cfg), "raw_config": cfg, "has_secret": bool(cfg.get("api_key") or cfg.get("token"))}


@router.post("/standalone/config")
def standalone_save_config(cfg: SmsConfig, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    return save_config(cfg, user=user or "standalone")


@router.post("/generic")
def generic_call(req: SmsGenericRequest, user: str = CurrentUser):
    cfg = _load_cfg()
    base = str(cfg.get("base_url") or "").rstrip("/")
    path = (req.path or "").strip()
    if not path.startswith("/"):
        raise HTTPException(status_code=400, detail="path 必须以 / 开头")
    url = base + path
    params = dict(req.params or {})
    if cfg.get("api_key") and not any(k in params for k in ("api_key", "key", "apikey")):
        params["api_key"] = cfg["api_key"]
    if cfg.get("token") and "token" not in params:
        params["token"] = cfg["token"]
    try:
        r = requests.post(url, params=params, json=req.json_body or None, timeout=30) if req.method == "POST" else requests.get(url, params=params, timeout=30)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SMS provider request failed: {type(e).__name__}: {e}")
    try:
        body = r.json()
    except Exception:
        body = r.text[:8000]
    return {"status_code": r.status_code, "ok": r.ok, "body": body}


@router.post("/standalone/get-number")
def standalone_get_number(token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    cfg = _load_cfg()
    resp = _call_template(cfg, "get_number")
    parsed = _extract_number(resp)
    if parsed.get("activation_id") or parsed.get("phone"):
        get_db().set_runtime_json(SESSION_KEY, {**parsed, "receive_count": 0})
    return {**resp, **parsed}


@router.post("/standalone/get-sms")
def standalone_get_sms(req: SmsActionRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    session = get_db().get_runtime_json(SESSION_KEY, {}) or {}
    aid = req.activation_id or session.get("activation_id", "")
    phone = req.phone or session.get("phone", "")
    resp = _call_template(_load_cfg(), "get_sms", {"activation_id": aid, "phone": phone})
    parsed = _extract_sms(resp)
    if parsed.get("code") or parsed.get("sms_text"):
        try:
            session["last_sms"] = parsed
            get_db().set_runtime_json(SESSION_KEY, session)
        except Exception:
            pass
    return {**resp, **parsed}


@router.post("/standalone/cancel")
def standalone_cancel(req: SmsActionRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    session = get_db().get_runtime_json(SESSION_KEY, {}) or {}
    aid = req.activation_id or session.get("activation_id", "")
    phone = req.phone or session.get("phone", "")
    resp = _call_template(_load_cfg(), "cancel", {"activation_id": aid, "phone": phone})
    get_db().delete_runtime_key(SESSION_KEY)
    return resp


@router.post("/standalone/continue")
def standalone_continue(req: SmsActionRequest, token: str = "", user: str | None = Depends(current_user_optional)):
    if not _standalone_authorized(token, user):
        raise HTTPException(status_code=401, detail="not authenticated")
    session = get_db().get_runtime_json(SESSION_KEY, {}) or {}
    aid = req.activation_id or session.get("activation_id", "")
    phone = req.phone or session.get("phone", "")
    count = int(session.get("receive_count") or 0)
    if count >= 3:
        raise HTTPException(status_code=400, detail="该号码已记录继续接收 3 次；如需强制继续，请先取消/重新取号，或后台清空状态")
    resp = _call_template(_load_cfg(), "continue", {"activation_id": aid, "phone": phone})
    session["activation_id"] = aid
    session["phone"] = phone
    session["receive_count"] = count + 1
    get_db().set_runtime_json(SESSION_KEY, session)
    return {**resp, "receive_count": session["receive_count"]}
