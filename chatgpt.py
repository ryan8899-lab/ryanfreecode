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
from typing import Any, Dict, Optional, Tuple
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests
from curl_cffi.requests import Session

# 配置输出目录和请求UA (对齐用户 curl)
OUT_DIR = Path(__file__).parent.resolve()
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

# ========== 1. 工具函数模块 ==========

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

# ========== 2. OpenAI OAuth2 授权模块 ==========

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"

@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str

def generate_oauth_url() -> OAuthStart:
    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    params = {
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": DEFAULT_REDIRECT_URI,
        "scope": DEFAULT_SCOPE, "state": state, "code_challenge": code_challenge,
        "code_challenge_method": "S256", "prompt": "login",
        "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(auth_url=auth_url, state=state, code_verifier=code_verifier, redirect_uri=DEFAULT_REDIRECT_URI)

def fetch_sentinel_data(*, flow: str, did: str, sv: str = "20260219f9f6", proxies: Any = None) -> Dict[str, Any]:
    """获取 OpenAI 完整的 Sentinel 响应数据 (包含 token, so 等)"""
    try:
        body = json.dumps({"p": "", "id": did, "flow": flow})
        resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={sv}",
                "content-type": "text/plain;charset=UTF-8", "user-agent": UA
            },
            data=body, proxies=proxies, impersonate="chrome120", timeout=15,
        )
        if resp.status_code != 200: return {}
        return resp.json()
    except: return {}

def submit_callback_url(*, callback_url: str, expected_state: str, code_verifier: str, redirect_uri: str) -> str:
    parsed = urllib.parse.urlparse(callback_url)
    query = urllib.parse.parse_qs(parsed.query)
    code = query.get("code", [""])[0]
    token_resp = requests.post(TOKEN_URL, data={"grant_type": "authorization_code", "client_id": CLIENT_ID, "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier}, headers={"Content-Type": "application/x-www-form-urlencoded","Accept": "application/json"})
    dat = token_resp.json()
    id_token = dat.get("id_token", "")
    payload_b64 = id_token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode("utf-8"))
    now = int(time.time())
    config = {
        "id_token": id_token, "access_token": dat.get("access_token"), "refresh_token": dat.get("refresh_token"),
        "account_id": str((claims.get("https://api.openai.com/auth") or {}).get("chatgpt_account_id") or ""),
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "email": claims.get("email"), "type": "codex",
        "expired": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + int(dat.get("expires_in", 0))))
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ========== 3. 核心注册流程 (双 Header 补全版) ==========

def run(proxy: Optional[str]) -> Optional[tuple[str, str, str]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome120")
    s.headers.update({"user-agent": UA})

    email = "VsxtXagtg6509@outlook.com"
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
        # 1. 初始页面
        resp = s.get(oauth.auth_url, timeout=15)
        sv_match = re.search(r"sentinel/frame\.html\?sv=([a-f0-9]+)", resp.text)
        sv = sv_match.group(1) if sv_match else "20260219f9f6"
        did = s.cookies.get("oai-did")
        if not did: return None

        # 2. 提交邮箱
        sen_dat = fetch_sentinel_data(flow="authorize_continue", did=did, sv=sv, proxies=proxies)
        signup_hdr = json.dumps({"p": "", "t": "", "c": sen_dat.get("token", "")})
        
        signup_headers = {"referer": "https://auth.openai.com/create-account", "accept": "application/json", "content-type": "application/json", "origin": "https://auth.openai.com", "openai-sentinel-token": signup_hdr}
        signup_resp = s.post("https://auth.openai.com/api/accounts/authorize/continue", headers=signup_headers, data=json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}))
        print(f"[Debug] 提交邮箱响应: {signup_resp.status_code}")
        if signup_resp.status_code != 200: return None

        # 3. 设置密码
        reg_sen_dat = fetch_sentinel_data(flow="username_password_create", did=did, sv=sv, proxies=proxies)
        reg_hdr = json.dumps({"p": "", "t": "", "c": reg_sen_dat.get("token", "")})
        
        register_headers = {
            "referer": "https://auth.openai.com/create-account/password", "accept": "application/json", "content-type": "application/json",
            "x-datadog-origin": "rum", "sec-ch-ua-platform": '"macOS"', "origin": "https://auth.openai.com", "openai-sentinel-token": reg_hdr
        }
        reg_resp = s.post("https://auth.openai.com/api/accounts/user/register", headers=register_headers, data=json.dumps({"password": password, "username": email}))
        print(f"[Debug] 设置密码响应: {reg_resp.status_code}")
        if reg_resp.status_code != 200: return None

        # 4. 发送并输入验证码
        otp_send_dat = fetch_sentinel_data(flow="email_otp_send", did=did, sv=sv, proxies=proxies)
        otp_send_hdr = json.dumps({"p": "", "t": "", "c": otp_send_dat.get("token", "")})
        s.get("https://auth.openai.com/api/accounts/email-otp/send", headers={**register_headers, "openai-sentinel-token": otp_send_hdr}, timeout=15)
        
        code = code_fetcher()
        
        # 5. 校验验证码
        otp_val_dat = fetch_sentinel_data(flow="email_otp_validate", did=did, sv=sv, proxies=proxies)
        otp_val_hdr = json.dumps({"p": "", "t": "", "c": otp_val_dat.get("token", "")})
        val_headers = {"referer": "https://auth.openai.com/email-verification", "accept": "application/json", "content-type": "application/json", "origin": "https://auth.openai.com", "openai-sentinel-token": otp_val_hdr}
        code_resp = s.post("https://auth.openai.com/api/accounts/email-otp/validate", headers=val_headers, data=json.dumps({"code": code}))
        print(f"[Debug] 校验验证码响应: {code_resp.status_code}")
        if code_resp.status_code != 200: return None
        
        # --- 核心修复：执行页面跳转 ---
        val_res = code_resp.json()
        cont_url = val_res.get("continue_url", "https://auth.openai.com/about-you")
        print(f"[*] 校验通过，正在跳转至: {cont_url}")
        # 必须先 GET 这个页面，否则直接 POST create_account 会报 invalid_auth_step
        s.get(cont_url, headers={"referer": "https://auth.openai.com/email-verification", "user-agent": UA}, timeout=15)
        # ---------------------------

        # 6. 填写账户信息 (核心对齐步：双 Header 发送)
        # 获取针对 oauth_create_account 的 Sentinel 数据
        so_sen_dat = fetch_sentinel_data(flow="oauth_create_account", did=did, sv=sv, proxies=proxies)
        
        # 构造 Header 1: openai-sentinel-token
        hdr_1 = json.dumps({"p": "", "t": "", "c": so_sen_dat.get("token", "")})
        # 构造 Header 2: openai-sentinel-so-token (对齐用户 curl)
        hdr_2 = json.dumps({
            "so": so_sen_dat.get("so", ""), 
            "c": so_sen_dat.get("token", ""), 
            "id": did, 
            "flow": "oauth_create_account"
        })
        
        create_headers = {
            "referer": "https://auth.openai.com/about-you", 
            "accept": "application/json", 
            "content-type": "application/json", 
            "origin": "https://auth.openai.com",
            "openai-sentinel-token": hdr_1,
            "openai-sentinel-so-token": hdr_2,
            "x-datadog-origin": "rum",
            "priority": "u=1, i",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin"
        }
        create_payload = {"name": "ryan", "birthdate": "2006-05-06"}
        create_resp = s.post("https://auth.openai.com/api/accounts/create_account", headers=create_headers, data=json.dumps(create_payload))
        print(f"[Debug] 账户信息填写响应: {create_resp.status_code} - {create_resp.text}")
        if create_resp.status_code != 200: return None

        # 7. 工作区与 Token 提取 (保持不变)
        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie: return None
        auth_json = json.loads(base64.urlsafe_b64decode(auth_cookie.split(".")[0] + "==").decode("utf-8"))
        workspace_id = str((auth_json.get("workspaces") or [{}])[0].get("id") or "").strip()
        select_resp = s.post("https://auth.openai.com/api/accounts/workspace/select", headers={"referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "content-type": "application/json", "origin": "https://auth.openai.com"}, data=json.dumps({"workspace_id": workspace_id}))
        
        current_url = str(select_resp.json().get("continue_url") or "").strip()
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""
            if not location: break
            next_url = urllib.parse.urljoin(current_url, location)
            if "code=" in next_url:
                return submit_callback_url(callback_url=next_url, expected_state=oauth.state, code_verifier=oauth.code_verifier, redirect_uri=oauth.redirect_uri), email, password
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
