#!/usr/bin/env python3
"""Run PayOnly PayPal guest flow for free inventory accounts, sequentially.

Flow:
  inventory free account -> JP PayOnly link -> US PayPal script -> on success script starts async RT.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
try:
    import fcntl
except ImportError:  # pragma: no cover - Linux deployment has fcntl
    fcntl = None

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui.backend.routes import inventory as _inv  # noqa: E402
from webui.backend.routes.inventory import (  # noqa: E402
    _eligible_payonly_inventory_accounts,
    _run_payonly_script_for_account,
)
from webui.backend.plan_checker import check_account_plan_by_id  # noqa: E402


def _notify(key: str, title: str, message: str, cooldown: int = 1800) -> None:
    if str(os.getenv("GPTPAY_NOTIFY", "1")).lower() in ("0", "false", "no", "off"):
        return
    prefix = os.getenv("PAYONLY_NOTIFY_PREFIX", "[PayOnly结果]").strip()
    if prefix and not str(message or "").lstrip().startswith(prefix):
        message = f"{prefix}\n{message}"
    script = ROOT / "scripts" / "notify_easyrelay_ops.py"
    if not script.exists():
        print(f"[notify] missing {script}: {title} {message[:160]}", flush=True)
        return
    notify_start = time.monotonic()
    cmd = [sys.executable, str(script), "--key", key, "--title", title, "--message", message, "--cooldown", str(cooldown)]
    if str(os.getenv("GPTPAY_NOTIFY_ASYNC", "1")).lower() not in ("0", "false", "no", "off"):
        try:
            log_dir = ROOT / "output" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log = log_dir / f"notify_{int(time.time())}_{''.join(c if c.isalnum() else '_' for c in key)[:80]}.log"
            with open(log, "w", encoding="utf-8") as f:
                p = subprocess.Popen(cmd, cwd=str(ROOT), text=True, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
            print(f"[notify] queued pid={p.pid} key={key} log={log}", flush=True)
            print(f"TIMING notify_enqueue_s={time.monotonic() - notify_start:.3f} key={key}", flush=True)
        except Exception as e:
            print(f"[notify] async queue failed: {type(e).__name__}: {e}", flush=True)
        return
    timeout_s = float(os.getenv("GPTPAY_NOTIFY_SUBPROCESS_TIMEOUT", "18") or "18")
    try:
        r = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=timeout_s)
        elapsed = time.monotonic() - notify_start
        print((r.stdout or r.stderr or "").strip() or f"[notify] rc={r.returncode}", flush=True)
        print(f"TIMING notify_s={elapsed:.1f} key={key} rc={r.returncode}", flush=True)
    except Exception as e:
        elapsed = time.monotonic() - notify_start
        print(f"[notify] failed: {type(e).__name__}: {e}", flush=True)
        print(f"TIMING notify_s={elapsed:.1f} key={key} rc=exception", flush=True)


def _short_error(text: str) -> str:
    raw = str(text or "")
    if not raw.strip():
        return ""
    lines = [" ".join(line.strip().split()) for line in raw.splitlines() if line.strip()]
    joined = " ".join(lines)
    low = joined.lower()
    if "datadome" in low or "geo.ddc.paypal.com/captcha" in low or "paypal datadome captcha iframe" in low:
        return "PayPal DataDome captcha，已跳过换下一个"
    if "user is already paid" in low:
        return "User is already paid"
    if "notinstalledgeoipextra" in low:
        return "Camoufox geoip 缺依赖"
    if "card_generic_error" in low:
        return "card_generic_error"
    if "no eligible cards on file" in low:
        return "PayPal no eligible cards"
    if "try a different phone number" in low:
        return "号码被拒"
    if "otp" in low or "sms" in low or "短信" in joined:
        return "OTP/SMS 问题"
    if "manual_challenge_failed" in low or "manual challenge detected" in low or "captcha_iframe" in low or "manual resolution" in low:
        return "PayPal captcha/人工挑战，已置失败并跳过"
    if "targetclosed" in low or "target page, context or browser has been closed" in low:
        return "浏览器/PayPal页面被关闭"
    if "blacklist" in low or "黑名单已回灌db" in low:
        return "手机号黑名单/已回灌DB"
    if "promo coupon" in low and "not eligible" in low:
        return "优惠券不适用，已安全跳过"
    # Prefer the actual response/exception over the preceding raw request body.  The
    # old fallback often started at "--> [5/6] confirm POST ... data=...", so the
    # Telegram alert hid the real Stripe response behind a 220-char truncation.
    preferred = []
    for line in reversed(lines):
        ll = line.lower()
        if "confirm 失败" in line or "confirm failed" in ll:
            preferred.append(line)
        elif "<-- [5/6] confirm" in line or "response [5/6] confirm" in ll:
            preferred.append(line)
        elif any(tok in ll for tok in ["declined", "requires_payment_method", "incorrect", "invalid", "failure_code", "error"]):
            if "--> [5/6] confirm" not in line and " data=" not in line:
                preferred.append(line)
    if preferred:
        return preferred[0][:500]
    for line in reversed(lines):
        if "--> [5/6] confirm" in line or " data=" in line:
            continue
        return line[:500]
    return joined[:500]


def _notify_account_result(result: dict, ok: int, fail: int) -> None:
    email = result.get("email") or "?"
    account_id = result.get("id") or "?"
    status = result.get("status") or "unknown"
    # Default for unattended PayOnly loops is log-only.  Pushing every per-account
    # failure into the ops Telegram group is too noisy while tuning payment flows.
    if str(os.getenv("PAYONLY_NOTIFY_ACCOUNT_RESULTS", "0")).lower() in ("0", "false", "no", "off"):
        return
    if status == "skipped_paid":
        msg = (
            f"ℹ️ AWS PayOnly 跳过已付费账号\n"
            f"账号：{email}\n"
            f"ID：{account_id}\n"
            f"检测：{result.get('plan_type') or '-'} {result.get('message') or ''}\n"
            f"累计：ok={ok} fail={fail}"
        )
        _notify(f"aws_payonly_account_skip_paid_{email}", "Gpt-Pay运维", msg, cooldown=3600)
        return
    session_id = result.get("session_id") or ""
    if status == "ok":
        msg = (
            f"✅ AWS PayOnly 成功\n"
            f"账号：{email}\n"
            f"ID：{account_id}\n"
            f"session：{session_id or '-'}\n"
            f"累计：ok={ok} fail={fail}"
        )
        _notify(f"aws_payonly_account_ok_{email}", "Gpt-Pay运维", msg, cooldown=0)
        return
    err = _short_error(result.get("error") or status)
    if (not err or err == status) and result.get("last_check_message"):
        err = _short_error(result.get("last_check_message"))
    screenshot = result.get("public_screenshot") or result.get("screenshot") or ""
    script_result = result.get("script_result") if isinstance(result.get("script_result"), dict) else {}
    screenshot = screenshot or script_result.get("public_screenshot") or script_result.get("screenshot") or ""
    msg = (
        f"❌ AWS PayOnly 失败\n"
        f"账号：{email}\n"
        f"ID：{account_id}\n"
        f"原因：{err or status}\n"
        + (f"截图：{screenshot}\n" if screenshot else "")
        + f"累计：ok={ok} fail={fail}"
    )
    _notify(f"aws_payonly_account_fail_{email}_{err[:40]}", "Gpt-Pay运维", msg, cooldown=0)


def _classify_payonly_terminal_failure(result: dict) -> tuple[str, str]:
    """Return a durable last_check marker for PayOnly failures that must not be retried by the loop."""
    if not isinstance(result, dict):
        return "", ""
    if result.get("status") in ("ok", "skipped_paid"):
        return "", ""
    parts: list[str] = []
    for key in ("error", "status", "payment_method"):
        if result.get(key):
            parts.append(str(result.get(key)))
    script_result = result.get("script_result")
    if isinstance(script_result, dict):
        parts.append(json.dumps(script_result, ensure_ascii=False, default=str))
    text = "\n".join(parts)
    low = text.lower()
    if "promo coupon" in low and "not_eligible" in low:
        return "payonly_excluded", "payonly:coupon_not_eligible plus-1-month-free"
    if "check_coupon: state=not_eligible" in low or "state=not_eligible" in low:
        return "payonly_excluded", "payonly:coupon_not_eligible plus-1-month-free"
    if "manual_challenge_failed" in low or "manual challenge detected" in low or "captcha_iframe" in low or "datadome" in low or "geo.ddc.paypal.com/captcha" in low:
        return "payonly_excluded", "payonly:paypal_manual_challenge_or_captcha"
    return "", ""


def _mark_payonly_terminal_failure(result: dict) -> bool:
    status, message = _classify_payonly_terminal_failure(result)
    if not status:
        return False
    try:
        account_id = int(result.get("id") or 0)
    except Exception:
        account_id = 0
    if not account_id:
        return False
    try:
        ok = bool(_inv.get_db().update_account_check(account_id, status, message))
        print(f"[payonly-queue] excluded id={account_id} email={result.get('email') or ''} reason={message} db_update={ok}", flush=True)
        return ok
    except Exception as e:
        print(f"[payonly-queue] warn: cannot mark excluded id={account_id}: {type(e).__name__}: {e}", flush=True)
        return False


def _acquire_singleton_lock():
    """Best-effort host-local singleton lock so two loop invocations cannot run the queue concurrently."""
    if str(os.getenv("PAYONLY_DISABLE_SINGLETON_LOCK", "")).lower() in ("1", "true", "yes", "on"):
        return None
    lock_dir = ROOT / "output" / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / "payonly_free_inventory_queue.lock"
    fh = open(lock_path, "a+", encoding="utf-8")
    if fcntl is None:
        return fh
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.seek(0)
        holder = fh.read().strip()
        print(f"[payonly-queue] another queue process is running; lock={lock_path} holder={holder or '?'}", flush=True)
        fh.close()
        return False
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid={os.getpid()} started={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
    fh.flush()
    return fh


def main() -> int:
    lock_fh = _acquire_singleton_lock()
    if lock_fh is False:
        summary = {"total": 0, "ok": 0, "fail": 0, "reason": "already_running", "results": []}
        print("PAYONLY_QUEUE_RESULT_JSON=" + json.dumps(summary, ensure_ascii=False), flush=True)
        return 0
    ap = argparse.ArgumentParser(description="Sequential PayOnly queue from free inventory accounts")
    ap.add_argument("--limit", type=int, default=1, help="max accounts to run; 0 = all eligible")
    default_stop = str(os.getenv("PAYONLY_STOP_ON_FAIL", "1")).lower() not in ("0", "false", "no", "off")
    ap.add_argument("--stop-on-fail", dest="stop_on_fail", action="store_true", default=default_stop, help="stop queue after first failed account; default on")
    ap.add_argument("--no-stop-on-fail", dest="stop_on_fail", action="store_false", help="continue queue after failed account")
    args = ap.parse_args()

    loop_start = time.monotonic()
    pool_start = time.monotonic()
    generate_card_mode = False
    try:
        from webui.backend import settings as _settings
        _cfg = json.loads(_settings.PAY_CONFIG_PATH.read_text(encoding="utf-8"))
        generate_card_mode = bool((_cfg.get("payonly") or {}).get("generate_card"))
    except Exception as e:
        print(f"[payonly-queue] warn: cannot read PayOnly config: {e}", flush=True)
    if generate_card_mode:
        pool_count = -1
        print("[payonly-queue] PayOnly generate_card=true; skip DB key/card pool precheck", flush=True)
    else:
        try:
            from webui.backend.routes import inventory as _inv
            pool_count = int(_inv._payonly_available_key_count())
        except Exception as e:
            print(f"[payonly-queue] warn: cannot read PayOnly DB key pool: {e}", flush=True)
    print(f"TIMING key_pool_s={time.monotonic() - pool_start:.1f}", flush=True)

    eligible_start = time.monotonic()
    accounts = _eligible_payonly_inventory_accounts(int(args.limit or 0))
    print(f"TIMING eligible_query_s={time.monotonic() - eligible_start:.1f}", flush=True)
    print(f"[payonly-queue] eligible={len(accounts)} limit={args.limit} key_pool={pool_count}", flush=True)
    print(f"TIMING queue_prepare_s={time.monotonic() - loop_start:.1f}", flush=True)
    if accounts and not generate_card_mode and pool_count <= 0:
        _notify("aws_payonly_key_pool_empty", "Gpt-Pay运维", f"⚠️ AWS PayOnly key/card 库存为空\nfree待支付账号：{len(accounts)}\n本轮已停止。", cooldown=900)
        summary = {"total": 0, "ok": 0, "fail": 0, "reason": "key_pool_empty", "eligible": len(accounts), "key_pool": pool_count, "results": []}
        print("PAYONLY_QUEUE_RESULT_JSON=" + json.dumps(summary, ensure_ascii=False), flush=True)
        return 0
    results = []
    ok = 0
    fail = 0

    for idx, acc in enumerate(accounts, 1):
        account_start = time.monotonic()
        email = acc.get("email") or ""
        print(f"\n[payonly-queue] {idx}/{len(accounts)} start id={acc.get('id')} email={email}", flush=True)
        print(f"TIMING account_start idx={idx} email={email}", flush=True)
        try:
            precheck_start = time.monotonic()
            if str(os.getenv("PAYONLY_PRECHECK_PLAN", "1")).lower() not in ("0", "false", "no", "off"):
                print(f"[payonly-queue] precheck plan id={acc.get('id')} email={email}", flush=True)
                pre = check_account_plan_by_id(int(acc.get("id") or 0), timeout_s=float(os.getenv("PAYONLY_PRECHECK_TIMEOUT", "12") or "12"), use_proxy=True)
                print(f"[payonly-queue] precheck result email={email} status={pre.get('status')} plan={pre.get('plan_type')} msg={pre.get('message')}", flush=True)
                print(f"TIMING precheck_plan_s={time.monotonic() - precheck_start:.1f} email={email}", flush=True)
                if pre.get("status") == "paid":
                    r = {"id": acc.get("id"), "email": email, "status": "skipped_paid", "plan_type": pre.get("plan_type") or "", "message": pre.get("message") or ""}
                else:
                    r = _run_payonly_script_for_account(acc, log_cb=lambda line: print(line, flush=True))
            else:
                r = _run_payonly_script_for_account(acc, log_cb=lambda line: print(line, flush=True))
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            r = {"id": acc.get("id"), "email": email, "status": "error", "error": err}
            print(f"[payonly-queue] exception: {r['error']}", flush=True)
            low = err.lower()
            if "payonly curl 请求体池子为空" in err or "pool" in low or "key" in low:
                _notify("aws_payonly_key_pool_empty", "Gpt-Pay运维", f"⚠️ PayOnly key/card 库存不足\n账号：{email}\n错误：{err[:500]}", cooldown=900)
            elif "phone" in low or "号码" in err or "sms" in low:
                _notify("aws_payonly_phone_pool_issue", "Gpt-Pay运维", f"⚠️ 手机号/短信库存或验证异常\n账号：{email}\n错误：{err[:500]}", cooldown=900)
            else:
                # Do not push generic per-account exceptions from here: the normal
                # result notifier below will send the success/failure summary once.
                # This avoids duplicate/noisy ops-channel messages for expected
                # PayOnly safety gates such as coupon_not_eligible.
                pass
        results.append(r)
        if r.get("status") == "ok":
            ok += 1
        elif r.get("status") == "skipped_paid":
            ok += 1
        else:
            fail += 1
        account_elapsed = time.monotonic() - account_start
        if r.get("status") not in ("ok", "skipped_paid"):
            _mark_payonly_terminal_failure(r)
        print(f"[payonly-queue] result email={email} status={r.get('status')} ok={ok} fail={fail}", flush=True)
        print(f"TIMING account_total_s={account_elapsed:.1f} email={email} status={r.get('status')}", flush=True)
        _notify_account_result(r, ok, fail)
        if args.stop_on_fail and r.get("status") not in ("ok", "skipped_paid"):
            print(f"[payonly-queue] stop_on_fail enabled; stopping after failed account email={email}", flush=True)
            break

    summary = {"total": len(results), "ok": ok, "fail": fail, "key_pool": pool_count, "elapsed_s": round(time.monotonic() - loop_start, 1), "results": results}
    print("PAYONLY_QUEUE_RESULT_JSON=" + json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
