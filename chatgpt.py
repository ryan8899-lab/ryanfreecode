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

# 配置输出目录和请求UA
OUT_DIR = Path(__file__).parent.resolve()
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

# ========== 1. 工具函数模块 ==========

def rstr(n=10): 
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _gen_password() -> str:
    alphabet = string.ascii_letters + string.digits
    special = "!@#$%^&*.-"
    base = [random.choice(string.ascii_lowercase), random.choice(string.ascii_uppercase), random.choice(string.digits), random.choice(special)]
    base += [random.choice(alphabet + special) for _ in range(12)]
    random.shuffle(base)
    return "".join(base)

def _generate_p(sv: str) -> str:
    """模拟 OpenAI Sentinel 的 p 参数 (浏览器环境指纹)"""
    now = datetime.now()
    # 这里的格式必须精准，且前面必须带 gAAAAAB
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
    # 核心修复：添加 gAAAAAB 前缀
    return "gAAAAAB" + base64.b64encode(p_json.encode()).decode() + "~S"

def fetch_sentinel_data(*, flow: str, did: str, sv: str, proxies: Any = None) -> Dict[str, Any]:
    try:
        p_val = _generate_p(sv)
        body = json.dumps({"p": p_val, "id": did, "flow": flow})
        resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={"origin": "https://sentinel.openai.com", "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={sv}", "content-type": "text/plain;charset=UTF-8", "user-agent": UA},
            data=body, proxies=proxies, impersonate="chrome120", timeout=15,
        )
        return resp.json() if resp.status_code == 200 else {}
    except: return {}

# ========== 2. 核心流程 ==========

def run(proxy: Optional[str]) -> Optional[tuple[str, str, str]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome120")
    s.headers.update({"user-agent": UA})

    email = "VspzcpDtqk9300@outlook.com"
    password = _gen_password()
    print(f"[*] 准备注册邮箱: {email}")

    # PKCE 持久化
    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")

    try:
        # 1. 初始化 OAuth
        auth_url = f"https://auth.openai.com/oauth/authorize?client_id=app_EMoamEEZ73f0CkXaXp7hrann&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&scope=openid+email+profile+offline_access&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&prompt=login"
        resp = s.get(auth_url, timeout=15)
        sv_match = re.search(r"sentinel/frame\.html\?sv=([a-f0-9]+)", resp.text)
        sv = sv_match.group(1) if sv_match else "20260219f9f6"
        did = s.cookies.get("oai-did")
        if not did: return None

        # 2. 提交邮箱
        sen = fetch_sentinel_data(flow="authorize_continue", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")})
        signup_resp = s.post("https://auth.openai.com/api/accounts/authorize/continue", headers={"openai-sentinel-token": hdr, "content-type": "application/json", "referer": "https://auth.openai.com/create-account", "origin": "https://auth.openai.com", "accept": "application/json"}, data=json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}))
        print(f"[*] 提交邮箱结果: {signup_resp.status_code}")
        if signup_resp.status_code != 200: return None

        # 3. 设置密码
        sen = fetch_sentinel_data(flow="username_password_create", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")})
        reg_resp = s.post("https://auth.openai.com/api/accounts/user/register", headers={"openai-sentinel-token": hdr, "content-type": "application/json", "referer": "https://auth.openai.com/create-account/password", "origin": "https://auth.openai.com", "accept": "application/json"}, data=json.dumps({"password": password, "username": email}))
        print(f"[*] 设置密码结果: {reg_resp.status_code}")
        if reg_resp.status_code != 200: return None

        # 4. 发送验证码 (重点修复步)
        sen = fetch_sentinel_data(flow="email_otp_send", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")})
        send_resp = s.get("https://auth.openai.com/api/accounts/email-otp/send", headers={"openai-sentinel-token": hdr, "referer": "https://auth.openai.com/create-account/password", "accept": "application/json", "x-datadog-origin": "rum"})
        print(f"[*] 发送验证码结果: {send_resp.status_code} - {send_resp.text}")
        
        print(f"\n{'='*50}\n  [!] 请检查邮箱: {email}\n  [!] 请输入 6 位验证码\n{'='*50}")
        code = input(">> 验证码: ").strip()

        # 5. 校验验证码
        sen = fetch_sentinel_data(flow="email_otp_validate", did=did, sv=sv, proxies=proxies)
        hdr = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")})
        val_resp = s.post("https://auth.openai.com/api/accounts/email-otp/validate", headers={"openai-sentinel-token": hdr, "content-type": "application/json", "referer": "https://auth.openai.com/email-verification", "origin": "https://auth.openai.com", "accept": "application/json"}, data=json.dumps({"code": code}))
        print(f"[*] 校验结果: {val_resp.status_code}")
        if val_resp.status_code != 200: return None

        # 跳转到 About-You 页面激活 session
        s.get("https://auth.openai.com/about-you", headers={"referer": "https://auth.openai.com/email-verification"}, timeout=10)

        # 6. 填写姓名
        sen = fetch_sentinel_data(flow="oauth_create_account", did=did, sv=sv, proxies=proxies)
        hdr1 = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")})
        hdr2 = json.dumps({"so": sen.get("so", ""), "c": sen.get("token", ""), "id": did, "flow": "oauth_create_account"})
        create_resp = s.post("https://auth.openai.com/api/accounts/create_account", headers={"openai-sentinel-token": hdr1, "openai-sentinel-so-token": hdr2, "content-type": "application/json", "referer": "https://auth.openai.com/about-you", "origin": "https://auth.openai.com", "x-datadog-origin": "rum"}, data=json.dumps({"name": "ryan", "birthdate": "2006-05-06"}))
        print(f"[*] 填写信息结果: {create_resp.status_code} - {create_resp.text}")
        if create_resp.status_code != 200: return None

        # 7. 提取最终 Token
        auth_cookie = s.cookies.get("oai-client-auth-session")
        auth_json = json.loads(base64.urlsafe_b64decode(auth_cookie.split(".")[0] + "==").decode("utf-8"))
        workspace_id = str((auth_json.get("workspaces") or [{}])[0].get("id") or "").strip()
        select_resp = s.post("https://auth.openai.com/api/accounts/workspace/select", headers={"referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "content-type": "application/json", "origin": "https://auth.openai.com"}, data=json.dumps({"workspace_id": workspace_id}))
        
        current_url = str(select_resp.json().get("continue_url") or "").strip()
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False)
            loc = final_resp.headers.get("Location") or ""
            if not loc: break
            current_url = urllib.parse.urljoin(current_url, loc)
            if "code=" in current_url:
                # 换取 Token
                token_resp = requests.post("https://auth.openai.com/oauth/token", data={"grant_type": "authorization_code", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "code": current_url.split("code=")[1].split("&")[0], "redirect_uri": "http://localhost:1455/auth/callback", "code_verifier": code_verifier})
                return json.dumps(token_resp.json()), email, password
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
    while True:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始注册流程 <<<")
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
        time.sleep(random.randint(5, 10))

if __name__ == "__main__":
    main()
