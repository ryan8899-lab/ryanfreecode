import json
import os
import re
import time
import uuid
import random
import string
import secrets
import hashlib
import base64
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Any, Dict, Optional
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests
from curl_cffi.requests import Session

# 配置输出目录和请求UA (对齐用户 curl)
OUT_DIR = Path(__file__).parent.resolve()
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

# ========== 1. Mail.tm 临时邮箱处理模块 ==========

def rstr(n=10): 
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _print_http_error(label, resp):
    if not resp:
        print(f"{label}: 无响应")
        return

    print(f"{label}: HTTP {resp.status_code}")
    try:
        body = resp.json()
        print(f"  [Response] {json.dumps(body, ensure_ascii=False)[:1000]}")
    except Exception:
        text = getattr(resp, "text", "")
        print(f"  [Response] {text[:1000] if text else '<empty>'}")

def mreq(mt, pt, js=None, tk=None, proxies=None):
    hdrs = {
        "content-type": "application/json",
        "accept": "application/json",
        "user-agent": UA,
        "pragma": "no-cache"
    }
    if tk: 
        hdrs["authorization"] = f"Bearer {tk}"
    try:
        with Session(proxies=proxies) as s:
            return s.request(mt, f"https://api.mail.tm{pt}", json=js, headers=hdrs, timeout=20)
    except Exception as e:
        print(f"  [!] mail.tm 请求异常: {type(e).__name__}: {e}")
        return None

def getotp(tk, proxies=None):
    for _ in range(60):
        r = mreq("GET", "/messages", tk=tk, proxies=proxies)
        if r and r.status_code == 200:
            try: 
                dat = r.json()
            except: 
                time.sleep(8); continue
                
            msgs = dat.get("hydra:member", []) if isinstance(dat, dict) else dat
            if not isinstance(msgs, list): msgs = []
                
            for m in msgs:
                if not isinstance(m, dict): continue
                sb = m.get("subject", "")
                intro = m.get("intro", "")
                if "OpenAI" in sb or "ChatGPT" in sb or "code" in intro:
                    rb = mreq("GET", f"/messages/{m.get('id')}", tk=tk, proxies=proxies)
                    if rb and rb.status_code == 200:
                        txt = rb.json().get("text", "")
                        mt = re.search(r"(\d{6})", txt) or re.search(r"(\d{6})", sb)
                        if mt: 
                            return mt.group(1)
        time.sleep(8)
    return None

def setup_mail_tm(proxies=None):
    """动态获取 mail.tm 邮箱并返回所需数据"""
    mail_pw = "at41rvxgptye"
    domain_res = mreq("GET", "/domains", proxies=proxies)
    if not domain_res or domain_res.status_code != 200: return None, None, None
    try:
        js_data = domain_res.json()
        domains_data = js_data if isinstance(js_data, list) else js_data.get("hydra:member", [])
        if not domains_data: return None, None, None
        active_domain = domains_data[0].get("domain")
    except: return None, None, None

    email = f"{rstr(10)}@{active_domain}"
    openai_password = _gen_password()
    r = mreq("POST", "/accounts", {"address": email, "password": mail_pw}, proxies=proxies)
    if not r or r.status_code not in [200, 201]: return None, None, None
    r = mreq("POST", "/token", {"address": email, "password": mail_pw}, proxies=proxies)
    if not r or r.status_code != 200: return None, None, None
    mail_token = r.json().get("token")
    return email, openai_password, (lambda: getotp(mail_token, proxies=proxies))


# ========== 2. OpenAI OAuth2 授权与环境生成模块 ==========

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"

def _gen_password() -> str:
    alphabet = string.ascii_letters + string.digits
    special = "!@#$%^&*.-"
    base = [random.choice(string.ascii_lowercase), random.choice(string.ascii_uppercase), random.choice(string.digits), random.choice(special)]
    base += [random.choice(alphabet + special) for _ in range(12)]
    random.shuffle(base)
    return "".join(base)

def _random_name() -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(5, 9))).capitalize()

def _random_birthdate() -> str:
    start = datetime(1970,1,1)
    end = datetime(1999,12,31)
    d = start + timedelta(days=random.randrange((end - start).days + 1))
    return d.strftime('%Y-%m-%d')

def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())

def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)

def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)

def _parse_callback_url(callback_url: str) -> Dict[str, Any]:
    candidate = callback_url.strip()
    if not candidate: return {"code": "","state": "","error": "","error_description": ""}
    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()
    return {"code": get1("code"),"state": get1("state"),"error": get1("error"),"error_description": get1("error_description")}

def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2: return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try: return json.loads(base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii")).decode("utf-8"))
    except: return {}

def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try: return json.loads(base64.urlsafe_b64decode((raw + pad).encode("ascii")).decode("utf-8"))
    except: return {}

def _to_int(v: Any) -> int:
    try: return int(v)
    except: return 0

def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded","Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e: raise RuntimeError(f"token exchange failed: {e}")

@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str

def generate_oauth_url(*, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)
    params = {
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": redirect_uri,
        "scope": scope, "state": state, "code_challenge": code_challenge,
        "code_challenge_method": "S256", "prompt": "login",
        "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(auth_url=auth_url, state=state, code_verifier=code_verifier, redirect_uri=redirect_uri)

def fetch_sentinel_token(*, flow: str, did: str, sv: str = "20260219f9f6", proxies: Any = None) -> Optional[str]:
    """获取 OpenAI 最新的反爬 Token (Sentinel)"""
    try:
        body = json.dumps({"p": "", "id": did, "flow": flow})
        resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={sv}",
                "content-type": "text/plain;charset=UTF-8",
                "user-agent": UA
            },
            data=body, proxies=proxies, impersonate="chrome120", timeout=15,
        )
        if resp.status_code != 200: return None
        return resp.json().get("token")
    except: return None

def submit_callback_url(*, callback_url: str, expected_state: str, code_verifier: str, redirect_uri: str = DEFAULT_REDIRECT_URI) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]: raise RuntimeError(f"oauth error: {cb['error']}")
    token_resp = _post_form(TOKEN_URL, {"grant_type": "authorization_code", "client_id": CLIENT_ID, "code": cb["code"], "redirect_uri": redirect_uri, "code_verifier": code_verifier})
    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    now = int(time.time())
    expired_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + _to_int(token_resp.get("expires_in"))))
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    config = {"id_token": id_token, "access_token": access_token, "refresh_token": refresh_token, "account_id": str((claims.get("https://api.openai.com/auth") or {}).get("chatgpt_account_id") or ""), "last_refresh": now_rfc3339, "email": email, "type": "codex", "expired": expired_rfc3339}
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ========== 3. 核心注册与提取流程 ==========

def run(proxy: Optional[str]) -> Optional[tuple[str, str, str]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome120")
    s.headers.update({"user-agent": UA})

    email = "ShelbyDavis8132@hotmail.com"
    password = _gen_password()
    print(f"[*] 使用确认邮箱: {email}")
    print(f"[*] 生成验证密码: {password}")

    def code_fetcher():
        print(f"\n{'='*50}\n  [!] 验证码已发送至: {email}\n  [!] 请输入 6 位验证码\n{'='*50}")
        while True:
            code = input(">> 验证码: ").strip()
            if len(code) == 6 and code.isdigit(): return code

    oauth = generate_oauth_url()
    try:
        # 第一步：进入 OAuth 并提取 Sentinel 版本
        resp = s.get(oauth.auth_url, timeout=15)
        sv_match = re.search(r"sentinel/frame\.html\?sv=([a-f0-9]+)", resp.text)
        sv = sv_match.group(1) if sv_match else "20260219f9f6"
        did = s.cookies.get("oai-did")
        if not did: return None

        # 第二步：获取 Sentinel Token (authorize_continue)
        sen_token = fetch_sentinel_token(flow="authorize_continue", did=did, sv=sv, proxies=proxies)
        sentinel_hdr = json.dumps({"p": "", "t": "", "c": sen_token}) if sen_token else None

        # 第三步：获取 Sentinel SO Token (oauth_create_account)
        so_token = fetch_sentinel_token(flow="oauth_create_account", did=did, sv=sv, proxies=proxies)

        # 第四步：提交邮箱授权
        signup_headers = {"referer": "https://auth.openai.com/create-account", "accept": "application/json", "content-type": "application/json", "origin": "https://auth.openai.com"}
        if sentinel_hdr: signup_headers["openai-sentinel-token"] = sentinel_hdr
        signup_resp = s.post("https://auth.openai.com/api/accounts/authorize/continue", headers=signup_headers, data=json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}))
        print(f"[Debug] 提交邮箱响应: {signup_resp.status_code} - {signup_resp.text}")
        if signup_resp.status_code != 200: return None

        # 第五步：设置密码 (修正 flow 为 username_password_create, 且 header 格式对齐 curl)
        reg_sen_token = fetch_sentinel_token(flow="username_password_create", did=did, sv=sv, proxies=proxies)
        reg_sentinel_hdr = json.dumps({"p": "", "t": "", "c": reg_sen_token}) if reg_sen_token else None
        
        register_headers = {
            "referer": "https://auth.openai.com/create-account/password", "accept": "application/json", "content-type": "application/json",
            "x-datadog-origin": "rum", "sec-ch-ua-platform": '"macOS"', "origin": "https://auth.openai.com"
        }
        if reg_sentinel_hdr: register_headers["openai-sentinel-token"] = reg_sentinel_hdr
        
        reg_resp = s.post("https://auth.openai.com/api/accounts/user/register", headers=register_headers, data=json.dumps({"password": password, "username": email}))
        print(f"[Debug] 设置密码响应: {reg_resp.status_code} - {reg_resp.text}")
        if reg_resp.status_code != 200: return None

        # 第六步：触发并提取验证码
        otp_send_token = fetch_sentinel_token(flow="email_otp_send", did=did, sv=sv, proxies=proxies)
        otp_send_hdr = json.dumps({"p": "", "t": "", "c": otp_send_token}) if otp_send_token else None
        otp_headers = register_headers.copy()
        if otp_send_hdr: otp_headers["openai-sentinel-token"] = otp_send_hdr
        s.get("https://auth.openai.com/api/accounts/email-otp/send", headers=otp_headers, timeout=15)
        
        code = code_fetcher()
        
        # 第七步：校验验证码
        otp_val_token = fetch_sentinel_token(flow="email_otp_validate", did=did, sv=sv, proxies=proxies)
        otp_val_hdr = json.dumps({"p": "", "t": "", "c": otp_val_token}) if otp_val_hdr else None
        validate_headers = {"referer": "https://auth.openai.com/email-verification", "accept": "application/json", "content-type": "application/json"}
        if otp_val_hdr: validate_headers["openai-sentinel-token"] = otp_val_hdr
        code_resp = s.post("https://auth.openai.com/api/accounts/email-otp/validate", headers=validate_headers, data=json.dumps({"code": code}))
        if code_resp.status_code != 200: return None

        # 第八步：完成账号注册填写
        create_headers = {"referer": "https://auth.openai.com/about-you", "accept": "application/json", "content-type": "application/json"}
        if so_token: create_headers["openai-sentinel-so-token"] = so_token
        create_resp = s.post("https://auth.openai.com/api/accounts/create_account", headers=create_headers, data=json.dumps({"name": _random_name(), "birthdate": _random_birthdate()}))
        if create_resp.status_code != 200: return None

        # 第九步：选择工作区 Workspace
        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie: return None
        auth_json = _decode_jwt_segment(auth_cookie.split(".")[0])
        workspace_id = str((auth_json.get("workspaces") or [{}])[0].get("id") or "").strip()
        select_resp = s.post("https://auth.openai.com/api/accounts/workspace/select", headers={"referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "content-type": "application/json"}, data=json.dumps({"workspace_id": workspace_id}))
        if select_resp.status_code != 200: return None
        
        # 第十步：拦截重定向，提取终极 Token
        current_url = str(select_resp.json().get("continue_url") or "").strip()
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""
            if final_resp.status_code not in [301, 302, 303, 307, 308] or not location: break
            next_url = urllib.parse.urljoin(current_url, location)
            if "code=" in next_url and "state=" in next_url:
                return submit_callback_url(callback_url=next_url, code_verifier=oauth.code_verifier, redirect_uri=oauth.redirect_uri, expected_state=oauth.state), email, password
            current_url = next_url
        return None
    except Exception as e:
        print(f"[Error] 异常: {e}")
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    while True:
        count += 1
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<")
        run_result = run(args.proxy)
        if run_result:
            token_json, email, password = run_result
            tokens_dir = OUT_DIR / "tokens"
            tokens_dir.mkdir(parents=True, exist_ok=True)
            (tokens_dir / f"token_{email.replace('@', '_')}_{int(time.time())}.json").write_text(token_json, encoding="utf-8")
            with open(tokens_dir / "accounts.txt", "a", encoding="utf-8") as f: f.write(f"{email}----{password}\n")
            print(f"[🎉] 成功获取 Token！")
        else: print("[-] 本次注册流程断开。")
        if args.once: break
        time.sleep(random.randint(5, 15))

if __name__ == "__main__":
    main()
