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

# 配置
OUT_DIR = Path(__file__).parent.resolve()
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

# ========== 1. 工具函数 ==========

def _gen_password() -> str:
    alphabet = string.ascii_letters + string.digits
    special = "!@#$%^&*.-"
    base = [random.choice(string.ascii_lowercase), random.choice(string.ascii_uppercase), random.choice(string.digits), random.choice(special)]
    base += [random.choice(alphabet + special) for _ in range(12)]
    random.shuffle(base)
    return "".join(base)

def _generate_p(sv: str) -> str:
    """模拟 OpenAI Sentinel 的 p 参数"""
    now = datetime.now()
    ts_str = now.strftime("%a %b %d %Y %H:%M:%S GMT-0400 (Eastern Daylight Time)")
    ts_ms = int(time.time() * 1000)
    p_arr = [
        30000, ts_str, 4294967296, random.randint(30, 120), UA,
        f"https://sentinel.openai.com/sentinel/{sv}/sdk.js",
        None, "en-US", "en-US,en", random.randint(10, 60),
        "webkitPersistentStorage—[object DeprecatedStorageQuota]", "location", "ongotpointercapture",
        random.uniform(30000, 90000), str(uuid.uuid4()), "", 12, ts_ms,
        0, 0, 0, 0, 0, 0, 0
    ]
    p_json = json.dumps(p_arr, separators=(',', ':'))
    return "gAAAAAB" + base64.b64encode(p_json.encode()).decode() + "~S"

def fetch_sentinel_data(*, flow: str, did: str, sv: str, proxies: Any = None) -> Dict[str, Any]:
    try:
        p_val = _generate_p(sv)
        body = json.dumps({"p": p_val, "id": did, "flow": flow}, separators=(',', ':'))
        resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={"origin": "https://sentinel.openai.com", "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={sv}", "content-type": "text/plain;charset=UTF-8", "user-agent": UA},
            data=body, proxies=proxies, impersonate="chrome120", timeout=15,
        )
        return resp.json() if resp.status_code == 200 else {}
    except: return {}

def submit_callback_url(*, callback_url: str, code_verifier: str) -> str:
    code = callback_url.split("code=")[1].split("&")[0]
    token_resp = requests.post("https://auth.openai.com/oauth/token", data={"grant_type": "authorization_code", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "code": code, "redirect_uri": "http://localhost:1455/auth/callback", "code_verifier": code_verifier}, headers={"Content-Type": "application/x-www-form-urlencoded","Accept": "application/json"})
    return json.dumps(token_resp.json(), ensure_ascii=False)

# ========== 2. 核心注册流程 ==========

def run(proxy: Optional[str]) -> Optional[tuple[str, str, str]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome120")
    s.headers.update({"user-agent": UA})

    email = "PmegtAiycrh7604@outlook.com"
    password = _gen_password()
    print(f"[*] 准备注册邮箱: {email}")

    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")

    try:
        # 1. Init
        auth_url = f"https://auth.openai.com/oauth/authorize?client_id=app_EMoamEEZ73f0CkXaXp7hrann&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&scope=openid+email+profile+offline_access&state=init&code_challenge={code_challenge}&code_challenge_method=S256&prompt=login"
        resp = s.get(auth_url, timeout=15)
        sv = re.search(r"sentinel/frame\.html\?sv=([a-f0-9]+)", resp.text).group(1) if "sv=" in resp.text else "20260219f9f6"
        did = s.cookies.get("oai-did")

        # 2. Email
        sen = fetch_sentinel_data(flow="authorize_continue", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")}, separators=(',', ':'))
        s.post("https://auth.openai.com/api/accounts/authorize/continue", headers={"openai-sentinel-token": hdr, "content-type": "application/json", "referer": "https://auth.openai.com/create-account", "origin": "https://auth.openai.com"}, data=json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}, separators=(',', ':')))

        # 3. Password
        sen = fetch_sentinel_data(flow="username_password_create", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")}, separators=(',', ':'))
        s.post("https://auth.openai.com/api/accounts/user/register", headers={"openai-sentinel-token": hdr, "content-type": "application/json", "referer": "https://auth.openai.com/create-account/password", "origin": "https://auth.openai.com"}, data=json.dumps({"password": password, "username": email}, separators=(',', ':')))

        # 4. OTP Send
        sen = fetch_sentinel_data(flow="email_otp_send", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")}, separators=(',', ':'))
        s.get("https://auth.openai.com/api/accounts/email-otp/send", headers={"openai-sentinel-token": hdr, "referer": "https://auth.openai.com/create-account/password", "accept": "application/json"})
        
        print(f"\n[!] 验证码已发送至: {email}")
        code = input(">> 验证码: ").strip()

        # 5. OTP Validate
        sen = fetch_sentinel_data(flow="email_otp_validate", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")}, separators=(',', ':'))
        val_resp = s.post("https://auth.openai.com/api/accounts/email-otp/validate", headers={"openai-sentinel-token": hdr, "content-type": "application/json", "referer": "https://auth.openai.com/email-verification", "origin": "https://auth.openai.com"}, data=json.dumps({"code": code}, separators=(',', ':')))
        
        # 激活 session
        cont_url = val_resp.json().get("continue_url", "https://auth.openai.com/about-you")
        s.get(cont_url, headers={"referer": "https://auth.openai.com/email-verification"}, timeout=10)

        # 6. Create Account (针对 431 优化：极其紧凑的 Header)
        sen = fetch_sentinel_data(flow="oauth_create_account", did=did, sv=sv, proxies=proxies)
        # 对齐 curl：头 1 只需要 p，头 2 需要 so, c, id, flow
        h1 = json.dumps({"p": _generate_p(sv)}, separators=(',', ':'))
        h2 = json.dumps({"so": sen.get("so", ""), "c": sen.get("token", ""), "id": did, "flow": "oauth_create_account"}, separators=(',', ':'))
        
        create_resp = s.post("https://auth.openai.com/api/accounts/create_account", headers={
            "openai-sentinel-token": h1, "openai-sentinel-so-token": h2, 
            "content-type": "application/json", "referer": "https://auth.openai.com/about-you",
            "origin": "https://auth.openai.com", "priority": "u=1, i"
        }, data=json.dumps({"name": "ryan", "birthdate": "2006-05-06"}, separators=(',', ':')))
        
        print(f"[*] 填写信息结果: {create_resp.status_code}")
        if create_resp.status_code != 200: return None

        # 7. Select Workspace & Redirect
        auth_cookie = s.cookies.get("oai-client-auth-session")
        auth_json = json.loads(base64.urlsafe_b64decode(auth_cookie.split(".")[0] + "==").decode("utf-8"))
        workspace_id = str((auth_json.get("workspaces") or [{}])[0].get("id") or "").strip()
        select_resp = s.post("https://auth.openai.com/api/accounts/workspace/select", headers={"referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "content-type": "application/json", "origin": "https://auth.openai.com"}, data=json.dumps({"workspace_id": workspace_id}, separators=(',', ':')))
        
        current_url = str(select_resp.json().get("continue_url") or "").strip()
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False)
            loc = final_resp.headers.get("Location") or ""
            if not loc: break
            current_url = urllib.parse.urljoin(current_url, loc)
            if "code=" in current_url:
                return submit_callback_url(current_url, code_verifier), email, password
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
    while True:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始流程 <<<")
        run_result = run(args.proxy)
        if run_result:
            token_json, email, password = run_result
            (OUT_DIR / "tokens").mkdir(exist_ok=True)
            (OUT_DIR / "tokens" / f"{email.replace('@', '_')}.json").write_text(token_json, encoding="utf-8")
            with open(OUT_DIR / "tokens" / "accounts.txt", "a") as f: f.write(f"{email}----{password}\n")
            print(f"[🎉] 成功获取 Token！")
        else: print("[-] 断开。")
        if args.once: break
        time.sleep(5)

if __name__ == "__main__":
    main()
