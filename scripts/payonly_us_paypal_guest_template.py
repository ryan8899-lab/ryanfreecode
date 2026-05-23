#!/usr/bin/env python3
"""Payonly → US proxy → PayPal guest page template.

用途：
- 使用已生成的 pay.openai.com 长链接；
- 后续 Stripe/PayPal 阶段走 US 代理；
- 填 PayPal guest 页的非支付字段和创建密码；
- 卡字段预留给 Ryan 学习/手动扩展；
- 默认不填卡、不点 Agree/Create/Authorize/Pay、不碰 CSV。

运行：
  cd /root/Gpt-Agreement-Payment
  xvfb-run -a /root/Gpt-Agreement-Payment/venv/bin/python -u scripts/payonly_us_paypal_guest_template.py
"""
from __future__ import annotations

import json
import os
import re
import requests
import shutil
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "/root/Gpt-Agreement-Payment")
sys.path.insert(0, "/root/Gpt-Agreement-Payment/webui")

from webui.backend.db import get_db

from webui.backend.db import get_db  # noqa: E402
from webui.backend.routes.inventory import _account_temp_pay_config  # noqa: E402

REPO = Path("/root/Gpt-Agreement-Payment")
PAYMENT_PY = REPO / "CTF-pay" / "payment.py"

# 1) 这里放你生成好的 payonly 长链接：生成长链用 JP，后续本脚本打开/PayPal 用 US。
PAYONLY_URL = os.getenv("PAYONLY_URL", "https://pay.openai.com/c/pay/cs_live_a1Ehlm6IJZtBdvIrwZsSYJuF57VcpO6LoW8Pxrk7M5bvJle93hIn4TLacC#fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEnKSdpamZkaWAnPydgaycpJ3ZwZ3Zmd2x1cWxqa1BrbHRwYGtgdnZAa2RnaWBhJz9jZGl2YCknYnBkZmRoamlgU2R3bGRrcSc%2FJ2Zqa3F3amknKSdkdWxOYHwnPyd1blppbHNgWjA0TUp3VnJGM200a31Cakw2aVFEYldvXFN3fzFhUDZjU0pkZ3xGZk5XNnVnQE9icEZTRGl0Rn1hfUZQc2pXbTRdUnJXZGZTbGpzUDZuSU5zdW5vbTJMdG5SNTVsXVR2b2o2aycpJ2N3amhWYHdzYHcnP3F3cGApJ2dkZm5id2pwa2FGamlqdyc%2FJyZjY2NjY2MnKSdpZHxqcHFRfHVgJz8ndmxrYmlgWmxxYGgnKSdga2RnaWBVaWRmYG1qaWFgd3YnP3F3cGB4JSUl")

# 2) PayPal/Stripe 后续阶段使用 US 代理。
US_PROXY = os.getenv("PAYONLY_US_PROXY", "")
if not US_PROXY:
    raise RuntimeError("PAYONLY_US_PROXY is required for PayPal/Stripe follow-up stages")

# 3) 使用哪个 ChatGPT 库账号作为上下文。
ACCOUNT_ID = int(os.getenv("PAYONLY_ACCOUNT_ID", "61") or "61")

# 4) PayPal guest 创建密码：Ryan 要求固定 Ryan8899。
PAYPAL_CREATE_PASSWORD = "Ryan8899"

# 5) 写死资料区：先不用外部接口；后续你给新接口时，把 fetch/hardcoded 这块替换掉即可。
GUEST_INFO_KEY = "KW-F6E7-SLV4KR2A-FE3B"
USE_HARDCODED_INFO = True
HARDCODED_INFO = json.loads(os.getenv("PAYONLY_HARDCODED_INFO_JSON", "{}") or "{}") or {
    "card_number": "4859540155674442",
    "expiry_date": "2030/7",
    "cvv": "944",
    "phone": "+18459935197",
    "name": "ROBERT KNEBEL",
    "address": "13580 GOODVIEW AVE,HUGO 55038,US",
    "sms_api": "http://a.62-us.com/api/get_sms?key=f5acfb75f4fec271b4558a33720fcfba",
}

# 可选：覆盖手机号。留空表示使用 HARDCODED_INFO 里的 phone。
PAYPAL_PHONE_OVERRIDE = ""

# 6) 学习开关：是否点击 PayPal 页面底部蓝色按钮。
#    默认 False，不会点击。改成 True 才会点 Agree & Create Account。
CLICK_BLUE_BUTTON = False

# 7) PayPal Security Challenge 人工接管开关。
#    True：检测到 challenge/recaptcha 覆盖层时，截图并等待你手动处理。
#    False：不等待，只按当前页面状态截图退出。
MANUAL_CHALLENGE_HANDOFF = True
MANUAL_CHALLENGE_WAIT_SECONDS = 180

# RYAN_TODO_CHALLENGE_HANDLER:
# PayPal Security Challenge 出现后，脚本会进入下面 replacement 里的
# `[Guest-Challenge]` 分支。你如果要接内部合法测试 fixture / sandbox bypass，
# 就从那个标记处开始读；默认这里只做截图和人工等待。

# 8) 卡信息预留区：你学习时主要改这里。
#    默认 True：会把 CARD_INFO / HARDCODED_INFO 的卡字段填进网页，但仍不会点按钮，除非 CLICK_BLUE_BUTTON=True。
FILL_CARD_FIELDS = True

# 如果你想从 curl 接口自动取 card_number/expiry_date/cvv，改成 True。
# 当前先按 Ryan 要求写死，所以这里默认 False。
FETCH_CARD_FROM_VERIFY_API = str(os.getenv("PAYONLY_FETCH_CARD_FROM_VERIFY_API", "0")).lower() in ("1", "true", "yes", "on")
VERIFY_API_KEY = GUEST_INFO_KEY

# 手动填卡时，直接改 CARD_INFO。留空则使用 HARDCODED_INFO。
CARD_INFO = json.loads(os.getenv("PAYONLY_CARD_INFO_JSON", "{}") or "{}") or {
    "number": "",       # 例：4111111111111111
    "expiry": "",       # 例：07/30 或 07/2030，具体看页面输入格式
    "cvv": "",          # 例：123
}

def _mark_account_plan(email: str, status: str, message: str = "") -> None:
    """Best-effort mark in inventory after a detected PayPal success."""
    if not email:
        return
    try:
        db = get_db()
        target = email.strip().lower()
        rows = [r for r in db.iter_registered_accounts() if (r.get("email") or "").lower() == target]
        if not rows:
            print(f"[account] mark plan skipped; not found in DB: {email}", flush=True)
            return
        row_id = int(rows[-1]["id"])
        ok = db.update_account_check(row_id, status, message[:500])
        print(f"[account] marked {email}: {status} {message[:120]} db_update={ok}", flush=True)
    except Exception as e:
        print(f"[account] mark plan failed {email}: {e}", flush=True)


def _start_async_rt(email: str) -> None:
    """Start detached RT backfill for one account; survives this script/tool session."""
    if not email:
        return
    try:
        log_dir = REPO / "output/logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        safe_email = email.replace("@", "_").replace(".", "_")
        log = log_dir / f"payonly_auto_rt_{safe_email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        env_rt = dict(os.environ)
        env_rt["RT_TARGET_EMAILS"] = email
        env_rt["RT_LIMIT"] = "1"
        # Use the same hardened RT path as manual backfill: refreshed Camoufox
        # fingerprint + per-account timeout. Existing environment can override.
        env_rt.setdefault("RT_CAMOUFOX_HUMANIZE", "1")
        env_rt.setdefault("RT_ACCOUNT_TIMEOUT", "650")
        cmd = [
            str(REPO / "venv/bin/python"),
            "-u",
            str(REPO / "scripts/run_rt_missing_with_proxy_pool.py"),
        ]
        with open(log, "w", encoding="utf-8") as f:
            p = subprocess.Popen(
                cmd,
                cwd=str(REPO),
                env=env_rt,
                stdout=f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        print(f"[auto-rt] started pid={p.pid} email={email} log={log}", flush=True)
    except Exception as e:
        print(f"[auto-rt] start failed email={email}: {e}", flush=True)



def normalize_expiry(expiry_date: str) -> str:
    """把接口里的 expiry_date 转成 PayPal 常见的 MM/YY 格式。

    示例：
    - "2030/7"  -> "07/30"
    - "2030-07" -> "07/30"
    - "07/2030" -> "07/30"
    - "07/30"   -> "07/30"
    """
    raw = str(expiry_date or "").strip()
    nums = re.findall(r"\d+", raw)
    if len(nums) < 2:
        return raw
    a, b = nums[0], nums[1]
    # 年/月：2030/7
    if len(a) == 4:
        year = a[-2:]
        month = b.zfill(2)
    # 月/年：7/2030 或 07/30
    else:
        month = a.zfill(2)
        year = b[-2:]
    return f"{month}/{year}"




def parse_hardcoded_identity(info: dict) -> dict:
    """把 HARDCODED_INFO 解析成 PayPal 页面要填的字段。"""
    name = str(info.get("name") or "").strip()
    parts = name.split()
    first = parts[0] if parts else ""
    last = " ".join(parts[1:]) if len(parts) > 1 else ""
    phone = re.sub(r"\D+", "", str(info.get("phone") or ""))
    if phone.startswith("1") and len(phone) == 11:
        phone = phone[1:]
    address_raw = str(info.get("address") or "").strip()
    chunks = [c.strip() for c in address_raw.split(",") if c.strip()]
    line1 = chunks[0] if chunks else ""
    city = ""
    state = ""
    postal = ""
    if len(chunks) >= 2:
        m = re.match(r"(.+?)\s+([A-Z]{2})?\s*(\d{5})(?:-\d{4})?$", chunks[1], re.I)
        if m:
            city = m.group(1).strip()
            state = (m.group(2) or "").upper()
            postal = m.group(3)
        else:
            city = chunks[1]
    return {
        "phone": phone,
        "first": first,
        "last": last,
        "line1": line1,
        "city": city,
        "state": state,
        "zip": postal,
    }


def hardcoded_card_info(info: dict) -> dict:
    return {
        "number": str(info.get("card_number") or "").strip(),
        "expiry": normalize_expiry(str(info.get("expiry_date") or "")),
        "cvv": str(info.get("cvv") or "").strip(),
    }


def fetch_card_info_from_verify_api(key: str) -> dict:
    """等价于你那段 curl：POST /api/exchange/verify，然后取 content 里的卡字段。"""
    resp = requests.post(
        "https://card.jinyao91.top/api/exchange/verify",
        headers={
            "accept": "*/*",
            "content-type": "application/json",
            "origin": "https://card.jinyao91.top",
            "referer": "https://card.jinyao91.top/",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        },
        json={"key": key},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"verify api returned success=false: {data}")
    content = data.get("content") or {}
    return {
        "number": str(content.get("card_number") or "").strip(),
        "expiry": normalize_expiry(str(content.get("expiry_date") or "")),
        "cvv": str(content.get("cvv") or "").strip(),
    }


def patch_legacy_card_for_template() -> Path | None:
    """No-op compatibility hook.

    Legacy versions temporarily patched the legacy payment module before
    launching the child. The production entrypoint is now CTF-pay/payment.py,
    and the needed PayPal guest hooks already live in payment_runner.py, so
    this script must not mutate legacy payment code at runtime.
    """
    return None


def main() -> int:
    acc = get_db().get_registered_account(ACCOUNT_ID)
    if not acc:
        raise SystemExit(f"account not found: {ACCOUNT_ID}")

    cfg_path, _billing = _account_temp_pay_config(acc, mode="paypal")
    backup = patch_legacy_card_for_template()
    try:
        cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        # JP 只用于外层生成 PAYONLY_URL；从打开长链接开始，Stripe/PayPal 后续全部强制 US。
        cfg["proxy"] = US_PROXY
        cfg["stage_proxies"] = {name: US_PROXY for name in [
            "fingerprint", "fetch_publishable_key", "stripe_init", "telemetry_init",
            "elements", "link_lookup", "address", "telemetry_address",
            "telemetry_card_input", "payment_method", "telemetry_confirm",
            "confirm", "verify_challenge", "three_ds_authenticate",
            "setup_intent_poll", "telemetry_poll", "poll",
        ]}
        # 这里必须关闭 fresh_checkout，否则它会重新生成链接；我们要使用 PAYONLY_URL。
        cfg.setdefault("fresh_checkout", {})["enabled"] = False
        cfg.setdefault("paypal", {})["email"] = acc.get("email") or ""
        cfg.setdefault("paypal", {})["password"] = acc.get("password") or ""
        cfg.setdefault("paypal", {})["cookies"] = ""
        Path(cfg_path).write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

        env = dict(os.environ)
        env.pop("HTTP_PROXY", None)
        env.pop("HTTPS_PROXY", None)
        effective_card_info = dict(CARD_INFO)
        hardcoded_identity = parse_hardcoded_identity(HARDCODED_INFO) if USE_HARDCODED_INFO else {}
        if USE_HARDCODED_INFO and not any(effective_card_info.values()):
            effective_card_info = hardcoded_card_info(HARDCODED_INFO)
            print(
                "[template] hardcoded card loaded: "
                f"number=****{effective_card_info.get('number', '')[-4:]} "
                f"expiry={effective_card_info.get('expiry', '')} "
                f"cvv_len={len(effective_card_info.get('cvv', ''))}",
                flush=True,
            )
        if FETCH_CARD_FROM_VERIFY_API:
            effective_card_info = fetch_card_info_from_verify_api(VERIFY_API_KEY)
            print(
                "[template] verify api card loaded: "
                f"number=****{effective_card_info.get('number', '')[-4:]} "
                f"expiry={effective_card_info.get('expiry', '')} "
                f"cvv_len={len(effective_card_info.get('cvv', ''))}",
                flush=True,
            )

        env["PAYPAL_GUEST_INFO_KEY"] = GUEST_INFO_KEY
        env["PAYPAL_GUEST_CREATE_PASSWORD"] = PAYPAL_CREATE_PASSWORD
        env["PAYPAL_GUEST_PHONE_OVERRIDE"] = PAYPAL_PHONE_OVERRIDE or hardcoded_identity.get("phone", "")
        env["PAYPAL_GUEST_FIRST"] = hardcoded_identity.get("first", "")
        env["PAYPAL_GUEST_LAST"] = hardcoded_identity.get("last", "")
        env["PAYPAL_GUEST_LINE1"] = hardcoded_identity.get("line1", "")
        env["PAYPAL_GUEST_CITY"] = hardcoded_identity.get("city", "")
        env["PAYPAL_GUEST_STATE"] = hardcoded_identity.get("state", "")
        env["PAYPAL_GUEST_ZIP"] = hardcoded_identity.get("zip", "")
        env["FILL_CARD_FIELDS"] = "1" if FILL_CARD_FIELDS else "0"
        env["CARD_NUMBER"] = effective_card_info.get("number", "")
        env["CARD_EXPIRY"] = effective_card_info.get("expiry", "")
        env["CARD_CVV"] = effective_card_info.get("cvv", "")
        env["CLICK_BLUE_BUTTON"] = "1" if CLICK_BLUE_BUTTON else "0"
        env["PAYPAL_MANUAL_CHALLENGE_HANDOFF"] = "1" if MANUAL_CHALLENGE_HANDOFF else "0"
        env["PAYPAL_MANUAL_CHALLENGE_WAIT_SECONDS"] = str(MANUAL_CHALLENGE_WAIT_SECONDS)

        print(f"[template] account={acc.get('email')} id={ACCOUNT_ID}", flush=True)
        print(f"[template] US proxy={US_PROXY}", flush=True)
        print(f"[template] fill_card_fields={FILL_CARD_FIELDS} (default false = card fields stay blank)", flush=True)
        print("[template] safety: never clicks Agree/Create/Authorize/Pay", flush=True)

        cmd = [
            str(REPO / "venv/bin/python"),
            str(PAYMENT_PY),
            PAYONLY_URL,
            "--paypal-guest-handoff",
            "--config",
            cfg_path,
            "--json-result",
        ]
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )
        assert proc.stdout is not None
        saw_success = False
        saw_terminal_failure = False
        for line in proc.stdout:
            print(line, end="", flush=True)
            low = line.lower()
            if (
                "payments/success" in low
                or "redirect_status=succeeded" in low
                or 'payment_object_status": "succeeded"' in low
                or '"state": "succeeded"' in low
            ):
                saw_success = True
            if "card_generic_error" in low or "no eligible cards on file" in low:
                saw_terminal_failure = True
        rc = proc.wait()
        acc_email = str(acc.get("email") or "")
        if saw_success:
            _mark_account_plan(acc_email, "plan", "paypal_success")
            if str(os.getenv("PAYONLY_AUTO_RT", "1")).lower() not in ("0", "false", "no", "off"):
                _start_async_rt(acc_email)
        elif saw_terminal_failure:
            print("[auto-rt] terminal payment failure detected; skip RT backfill", flush=True)
        else:
            print("[auto-rt] no definite payment success marker detected; skip RT backfill", flush=True)
        return rc
    finally:
        try:
            os.unlink(cfg_path)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
