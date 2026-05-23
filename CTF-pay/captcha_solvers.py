"""Captcha/solver helpers extracted from legacy payment code.

This module owns remote captcha-provider URL building, Arkose FunCaptcha,
PayPal hCaptcha/reCAPTCHA solving, PayPal fn_sync_data generation, and the VLM
hCaptcha browser helper.  It is safe to import without loading ``card.py``.
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests

_REPO_DIR = Path(__file__).resolve().parents[1]
_OUTPUT_DIR = _REPO_DIR / "output"
(_OUTPUT_DIR / "logs").mkdir(parents=True, exist_ok=True)
LOG_FILE = str(_OUTPUT_DIR / "logs" / "captcha_solvers.log")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)

# Remote captcha provider API base URL (createTask/getTaskResult protocol).
_REMOTE_CAPTCHA_BASE_URL = ""


def configure_remote_captcha_base_url(api_url: str = "") -> str:
    """Set module-level remote captcha base URL and mirror it to env for subprocesses."""
    global _REMOTE_CAPTCHA_BASE_URL
    _REMOTE_CAPTCHA_BASE_URL = (api_url or "").rstrip("/")
    if _REMOTE_CAPTCHA_BASE_URL:
        os.environ["CTF_CAPTCHA_API_URL"] = _REMOTE_CAPTCHA_BASE_URL
    return _REMOTE_CAPTCHA_BASE_URL


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _remote_captcha_url(path: str = "") -> str:
    """拼出远端打码平台的完整 URL。path 是 /createTask 或 /getTaskResult 这种。"""
    base = (_REMOTE_CAPTCHA_BASE_URL or os.environ.get("CTF_CAPTCHA_API_URL", "")).rstrip("/")
    if not base:
        base = "https://YOUR_CAPTCHA_PROVIDER"
    if path and not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _solve_arkose_funcaptcha(api_key: str, public_key: str, page_url: str, timeout: int = 120) -> str:
    """调用远端打码平台解 Arkose FunCaptcha"""
    if not api_key:
        _log("      未配置打码平台 API key，无法解 Arkose")
        return ""
    _log(f"      提交 FunCaptcha 到打码平台 (pk={public_key[:20]}...)")
    import requests as _req
    # 创建任务
    create_resp = _req.post(_remote_captcha_url("/createTask"), json={
        "clientKey": api_key,
        "task": {
            "type": "FunCaptchaTaskProxyless",
            "websiteURL": page_url,
            "websitePublicKey": public_key,
        }
    }, timeout=30)
    result = create_resp.json()
    if result.get("errorId"):
        _log(f"      打码平台创建任务失败: {result.get('errorDescription', '')}")
        return ""
    task_id = result.get("taskId")
    _log(f"      打码平台 taskId: {task_id}")

    # 轮询结果
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(5)
        poll_resp = _req.post(_remote_captcha_url("/getTaskResult"), json={
            "clientKey": api_key,
            "taskId": task_id,
        }, timeout=15)
        poll_result = poll_resp.json()
        status = poll_result.get("status", "")
        if status == "ready":
            token = poll_result.get("solution", {}).get("token", "")
            _log(f"      打码平台 FunCaptcha 解题成功")
            return token
        elif poll_result.get("errorId"):
            _log(f"      打码平台解题失败: {poll_result.get('errorDescription', '')}")
            return ""
        _log(f"      打码平台轮询中... status={status}")
    _log("      打码平台 FunCaptcha 超时")
    return ""


def _generate_fn_sync_data(email_text: str = "", password_text: str = "") -> str:
    """生成 PayPal fn_sync_data 设备指纹（键盘时序 + 屏幕信息）"""
    def _keystroke_timing(text: str) -> str:
        if not text:
            return ""
        parts = []
        for _ in text:
            di = random.randint(45, 170)
            ui = random.randint(25, 85)
            dk = random.randint(35, 110)
            uk = random.randint(15, 65)
            parts.append(f"Di{di}Ui{ui}Dk{dk}Uk{uk}")
        return ",".join(parts)

    payload = {
        "ts1": _keystroke_timing(email_text),
        "ts2": _keystroke_timing(password_text),
        "rDT": str(random.randint(30, 200)),
        "bP": "24",
        "wI": "1920",
        "wO": "1080",
    }
    inner = json.dumps(payload, separators=(",", ":"))
    return urllib.parse.quote(inner)


def _solve_remote_hcaptcha_paypal(
    api_key: str,
    site_key: str,
    page_url: str,
    timeout: int = 120,
) -> str:
    """通过远端打码平台解 PayPal 页面上的 hCaptcha（多策略尝试）"""
    if not api_key:
        _log("      [hCaptcha] 未配置 captcha API key")
        return ""

    # 多策略尝试：Enterprise → 普通 → 不同 URL
    strategies = [
        {"type": "HCaptchaTaskProxyless", "websiteURL": page_url,
         "websiteKey": site_key, "isEnterprise": True, "userAgent": USER_AGENT},
        {"type": "HCaptchaTaskProxyless", "websiteURL": page_url,
         "websiteKey": site_key, "userAgent": USER_AGENT},
        {"type": "HCaptchaTaskProxyless", "websiteURL": "https://www.paypal.com",
         "websiteKey": site_key, "isEnterprise": True, "userAgent": USER_AGENT},
    ]
    for idx, task_spec in enumerate(strategies):
        ent = task_spec.get("isEnterprise", False)
        _log(f"      [hCaptcha] 策略 {idx + 1}/{len(strategies)} (enterprise={ent}, url={task_spec['websiteURL'][:40]}...)")
        try:
            create_resp = requests.post(_remote_captcha_url("/createTask"), json={
                "clientKey": api_key, "task": task_spec,
            }, timeout=30)
            result = create_resp.json()
        except Exception as e:
            _log(f"      [hCaptcha] 请求异常: {e}")
            continue
        if result.get("errorId"):
            _log(f"      [hCaptcha] 创建失败: {result.get('errorDescription', '')}")
            continue
        task_id = result.get("taskId")
        _log(f"      [hCaptcha] taskId: {task_id}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(5)
            try:
                poll_resp = requests.post(_remote_captcha_url("/getTaskResult"), json={
                    "clientKey": api_key, "taskId": task_id,
                }, timeout=15)
                poll_result = poll_resp.json()
            except Exception:
                continue
            status = poll_result.get("status", "")
            if status == "ready":
                token = poll_result.get("solution", {}).get("gRecaptchaResponse", "")
                _log(f"      [hCaptcha] 解题成功 (策略 {idx + 1}, token len={len(token)})")
                return token
            elif poll_result.get("errorId"):
                _log(f"      [hCaptcha] 失败: {poll_result.get('errorDescription', '')}")
                break
            _log(f"      [hCaptcha] 轮询中... status={status}")
        else:
            _log(f"      [hCaptcha] 策略 {idx + 1} 超时")
    _log("      [hCaptcha] 所有策略均失败")
    return ""


def _solve_remote_recaptcha_v3(
    api_key: str,
    site_key: str,
    page_url: str,
    action: str = "LOGIN",
    timeout: int = 60,
) -> str:
    """通过远端打码平台解 Google reCAPTCHA Enterprise v3"""
    if not api_key:
        return ""
    _log(f"      [reCAPTCHA v3] 提交到打码平台 ...")
    create_resp = requests.post(_remote_captcha_url("/createTask"), json={
        "clientKey": api_key,
        "task": {
            "type": "RecaptchaV3EnterpriseTaskProxyless",
            "websiteURL": page_url,
            "websiteKey": site_key,
            "pageAction": action,
        }
    }, timeout=30)
    result = create_resp.json()
    if result.get("errorId"):
        _log(f"      [reCAPTCHA v3] 创建失败: {result.get('errorDescription', '')}")
        return ""
    task_id = result.get("taskId")
    _log(f"      [reCAPTCHA v3] taskId: {task_id}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        poll_resp = requests.post(_remote_captcha_url("/getTaskResult"), json={
            "clientKey": api_key, "taskId": task_id,
        }, timeout=15)
        poll_result = poll_resp.json()
        status = poll_result.get("status", "")
        if status == "ready":
            token = poll_result.get("solution", {}).get("gRecaptchaResponse", "")
            _log(f"      [reCAPTCHA v3] 解题成功")
            return token
        elif poll_result.get("errorId"):
            _log(f"      [reCAPTCHA v3] 失败: {poll_result.get('errorDescription', '')}")
            return ""
    _log("      [reCAPTCHA v3] 超时")
    return ""


def _solve_hcaptcha_via_vlm(page, hcaptcha_frame, vlm_base_url, vlm_api_key, vlm_model, max_rounds=5):
    """在 Playwright 中使用 VLM 求解 hCaptcha 视觉挑战"""
    import base64
    for round_idx in range(max_rounds):
        _log(f"      [VLM-hCaptcha] 第 {round_idx + 1}/{max_rounds} 轮 ...")

        # 截图 hCaptcha 区域
        try:
            screenshot_bytes = hcaptcha_frame.locator("body").screenshot(timeout=10000)
        except Exception:
            screenshot_bytes = page.screenshot()
        b64_img = base64.b64encode(screenshot_bytes).decode()

        # 提取 prompt（挑战文字说明）
        prompt_text = ""
        try:
            prompt_el = hcaptcha_frame.query_selector(".prompt-text") or \
                        hcaptcha_frame.query_selector("[class*='prompt']")
            if prompt_el:
                prompt_text = prompt_el.inner_text()
        except Exception:
            pass
        _log(f"      [VLM-hCaptcha] prompt: {prompt_text[:60]}...")

        # 调用 VLM
        vlm_prompt = (
            f"This is a hCaptcha visual challenge screenshot. "
            f"The challenge says: '{prompt_text}'. "
            f"The image shows a 3x3 grid of tiles numbered 1-9 (left to right, top to bottom). "
            f"Which tiles match the challenge? Return ONLY a JSON: {{\"tiles\": [1, 3, 5]}} "
            f"where the numbers are the matching tile positions."
        )
        try:
            vlm_resp = requests.post(
                f"{vlm_base_url}/v1/chat/completions",
                json={
                    "model": vlm_model,
                    "messages": [{"role": "user", "content": [
                        {"type": "text", "text": vlm_prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64_img}"}},
                    ]}],
                    "max_tokens": 200,
                },
                headers={"Authorization": f"Bearer {vlm_api_key}"},
                timeout=45,
            )
            vlm_json = vlm_resp.json()
            if "error" in vlm_json:
                _log(f"      [VLM-hCaptcha] VLM 错误: {str(vlm_json['error'])[:200]}")
                continue
            if "choices" not in vlm_json:
                _log(f"      [VLM-hCaptcha] VLM 异常响应: {str(vlm_json)[:200]}")
                continue
            vlm_text = vlm_json["choices"][0]["message"]["content"]
            _log(f"      [VLM-hCaptcha] VLM 回复: {vlm_text[:100]}")

            # 解析 tiles
            m = re.search(r'\{[^}]*"tiles"\s*:\s*\[([0-9, ]+)\]', vlm_text)
            if m:
                tiles = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            else:
                # 兜底: 提取所有数字
                tiles = [int(x) for x in re.findall(r'\b([1-9])\b', vlm_text)]
            _log(f"      [VLM-hCaptcha] 选择 tiles: {tiles}")

            if not tiles:
                _log("      [VLM-hCaptcha] 无有效 tiles")
                continue

        except Exception as e:
            _log(f"      [VLM-hCaptcha] VLM 调用失败: {e}")
            continue

        # 点击对应的 tiles
        task_images = hcaptcha_frame.query_selector_all(".task-image") or \
                      hcaptcha_frame.query_selector_all("[class*='image']") or \
                      hcaptcha_frame.query_selector_all(".border-focus")
        _log(f"      [VLM-hCaptcha] 找到 {len(task_images)} 个 tile 元素")

        for tile_num in tiles:
            idx = tile_num - 1  # 1-based to 0-based
            if 0 <= idx < len(task_images):
                task_images[idx].click()
                time.sleep(random.uniform(0.3, 0.8))

        # 点击 verify/submit
        time.sleep(0.5)
        verify_btn = hcaptcha_frame.query_selector('button.verify-button') or \
                     hcaptcha_frame.query_selector('div.button-submit') or \
                     hcaptcha_frame.query_selector('[class*="submit"]')
        if verify_btn:
            verify_btn.click()
            _log("      [VLM-hCaptcha] 已点击验证按钮")

        time.sleep(3)

        # 检查是否通过
        still_has_captcha = False
        for frame in page.frames:
            if "hcaptcha" in frame.url:
                # 检查是否还有 challenge
                challenge = frame.query_selector(".challenge-container") or \
                            frame.query_selector("[class*='challenge']")
                if challenge and challenge.is_visible():
                    still_has_captcha = True
                break
        if not still_has_captcha:
            _log("      [VLM-hCaptcha] hCaptcha 已通过!")
            return True
        _log("      [VLM-hCaptcha] 未通过，重试 ...")

    return False
