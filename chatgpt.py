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

def _random_name() -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(5, 9))).capitalize()

def _random_birthdate() -> str:
    start = datetime(1970,1,1)
    end = datetime(1999,12,31)
    d = start + timedelta(days=random.randrange((end - start).days + 1))
    return d.strftime('%Y-%m-%d')

def _generate_p(sv: str) -> str:
    """模拟 OpenAI Sentinel 的 p 参数 (浏览器环境指纹)"""
    now = datetime.now()
    ts_str = now.strftime("%a %b %d %Y %H:%M:%S GMT-0400 (Eastern Daylight Time)")
    ts_ms = time.time() * 1000
    p_arr = [
        30000, ts_str, 4294967296, random.randint(5, 120), UA,
        f"https://sentinel.openai.com/sentinel/{sv}/sdk.js",
        None, "en-US", "en-US,en", random.randint(10, 60),
        "webkitPersistentStorage—[object DeprecatedStorageQuota]", "location", "ongotpointercapture",
        random.uniform(30000, 90000), str(uuid.uuid4()), "", 12, ts_ms,
        0, 0, 0, 0, 0, 0, 0
    ]
    p_json = json.dumps(p_arr, separators=(',', ':'))
    return base64.b64encode(p_json.encode()).decode() + "~S"

# ========== 2. OpenAI 协议模块 ==========

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

def submit_callback_url(*, callback_url: str, expected_state: str, code_verifier: str, redirect_uri: str) -> str:
    parsed = urllib.parse.urlparse(callback_url)
    query = urllib.parse.parse_qs(parsed.query)
    code = query.get("code", [""])[0]
    token_resp = requests.post("https://auth.openai.com/oauth/token", data={"grant_type": "authorization_code", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier}, headers={"Content-Type": "application/x-www-form-urlencoded","Accept": "application/json"})
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

# ========== 3. 核心流程 ==========

def run(proxy: Optional[str]) -> Optional[tuple[str, str, str]]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(proxies=proxies, impersonate="chrome120")
    s.headers.update({"user-agent": UA})

    email = "PmegtAiycrh7604@outlook.com"
    password = _gen_password()
    print(f"[*] 准备注册邮箱: {email}")

    def code_fetcher():
        print(f"\n{'='*50}\n  [!] 验证码已发送至: {email}\n  [!] 请输入 6 位验证码\n{'='*50}")
        while True:
            code = input(">> 验证码: ").strip()
            if len(code) == 6 and code.isdigit(): return code

    try:
        # 1. 初始化
        resp = s.get("https://auth.openai.com/oauth/authorize?client_id=app_EMoamEEZ73f0CkXaXp7hrann&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&scope=openid+email+profile+offline_access&state=init&code_challenge=S256&code_challenge_method=S256&prompt=login", timeout=15)
        sv = re.search(r"sentinel/frame\.html\?sv=([a-f0-9]+)", resp.text).group(1) if "sv=" in resp.text else "20260219f9f6"
        did = s.cookies.get("oai-did")
        if not did: return None

        # 2. 提交邮箱
        sen = fetch_sentinel_data(flow="authorize_continue", did=did, sv=sv, proxies=proxies)
        s.post("https://auth.openai.com/api/accounts/authorize/continue", headers={"openai-sentinel-token": json.dumps({"p":_generate_p(sv),"t":"","c":sen.get("token","")}), "content-type": "application/json", "referer": "https://auth.openai.com/create-account"}, data=json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"}))
        print("[*] 邮箱已提交")

        # 3. 设置密码
        sen = fetch_sentinel_data(flow="username_password_create", did=did, sv=sv, proxies=proxies)
        s.post("https://auth.openai.com/api/accounts/user/register", headers={"openai-sentinel-token": json.dumps({"p":_generate_p(sv),"t":"","c":sen.get("token","")}), "content-type": "application/json", "referer": "https://auth.openai.com/create-account/password"}, data=json.dumps({"password": password, "username": email}))
        print("[*] 密码已设置")

        # 4. 发送验证码
        sen = fetch_sentinel_data(flow="email_otp_send", did=did, sv=sv, proxies=proxies)
        s.get("https://auth.openai.com/api/accounts/email-otp/send", headers={"openai-sentinel-token": json.dumps({"p":_generate_p(sv),"t":"","c":sen.get("token","")})})
        code = code_fetcher()

        # 5. 校验验证码
        sen = fetch_sentinel_data(flow="email_otp_validate", did=did, sv=sv, proxies=proxies)
        val_resp = s.post("https://auth.openai.com/api/accounts/email-otp/validate", headers={"openai-sentinel-token": json.dumps({"p":_generate_p(sv),"t":"","c":sen.get("token","")}), "content-type": "application/json"}, data=json.dumps({"code": code}))
        
        # 强制纠偏逻辑：无论 continue_url 是什么，都强行引导 session 进入 about-you 状态
        print(f"[*] 校验结果: {val_resp.status_code}")
        s.get("https://auth.openai.com/about-you", headers={"referer": "https://auth.openai.com/email-verification"}, timeout=10)
        time.sleep(1.5)

        # 6. 填写姓名 (终极对齐步)
        sen = fetch_sentinel_data(flow="oauth_create_account", did=did, sv=sv, proxies=proxies)
        hdr1 = json.dumps({"p": _generate_p(sv), "t": "", "c": sen.get("token", "")})
        hdr2 = json.dumps({"so": sen.get("so", ""), "c": sen.get("token", ""), "id": did, "flow": "oauth_create_account"})
        
        create_resp = s.post("https://auth.openai.com/api/accounts/create_account", headers={
            "openai-sentinel-token": hdr1, "openai-sentinel-so-token": hdr2, 
            "content-type": "application/json", "referer": "https://auth.openai.com/about-you",
            "origin": "https://auth.openai.com", "x-datadog-origin": "rum", "priority": "u=1, i"
        }, data=json.dumps({"name": "ryan", "birthdate": "2006-05-06"}))
        
        print(f"[Debug] 账户信息填写响应: {create_resp.status_code} - {create_resp.text}")
        if create_resp.status_code != 200: return None

        # 7. 提取 Token
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
                return submit_callback_url(callback_url=current_url, expected_state="init", code_verifier=secrets.token_urlsafe(64), redirect_uri="http://localhost:1455/auth/callback"), email, password
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
