#!/usr/bin/env python3
"""Run PayOnly payments by oldest eligible registered account first.

External side effects: generates free Plus checkout and completes PayPal/Stripe flow.
Stops on the first failure by default to avoid burning accounts/resources.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

ROOT = "/root/Gpt-Agreement-Payment"
os.chdir(ROOT)
sys.path.insert(0, ROOT)
os.environ.setdefault("PYTHONPATH", ROOT)
os.environ.setdefault("PAYONLY_AUTO_RT", "0")
os.environ.setdefault("PAYONLY_PRECHECK_PLAN", "1")
os.environ.setdefault("PAYONLY_STOP_ON_FAIL", "1")
os.environ.setdefault("GPTPAY_NOTIFY_ASYNC", "1")

from webui.backend.routes.inventory import _eligible_payonly_inventory_accounts, _run_payonly_script_for_account  # noqa:E402


def _ts(row: dict) -> str:
    return str(row.get("ts") or row.get("created_at") or "")


def _pick_oldest() -> dict | None:
    rows = _eligible_payonly_inventory_accounts(0)
    rows = sorted(rows, key=lambda r: (_ts(r), int(r.get("id") or 0)))
    return rows[0] if rows else None


def log(line: str) -> None:
    print(line, flush=True)


def main() -> int:
    limit = int(os.getenv("PAYONLY_OLDEST_LIMIT", "0") or "0")
    interval = int(os.getenv("PAYONLY_OLDEST_INTERVAL", "20") or "20")
    stop_on_fail = os.getenv("PAYONLY_STOP_ON_FAIL", "1") != "0"
    done = 0
    ok = 0
    fail = 0
    log("PAYONLY_OLDEST_LOOP_START=" + json.dumps({
        "started_at": datetime.now(timezone.utc).isoformat(),
        "limit": limit,
        "interval": interval,
        "stop_on_fail": stop_on_fail,
        "auto_rt": os.getenv("PAYONLY_AUTO_RT"),
        "precheck_plan": os.getenv("PAYONLY_PRECHECK_PLAN"),
    }, ensure_ascii=False))
    while True:
        if limit and done >= limit:
            log(f"PAYONLY_OLDEST_LOOP_DONE limit={limit} ok={ok} fail={fail}")
            return 0 if fail == 0 else 1
        acc = _pick_oldest()
        if not acc:
            log(f"PAYONLY_OLDEST_NO_ELIGIBLE ok={ok} fail={fail}; sleeping {interval}s")
            if limit:
                return 0 if fail == 0 else 1
            time.sleep(interval)
            continue
        target = {"id": acc.get("id"), "email": acc.get("email"), "ts": acc.get("ts")}
        log("TARGET_JSON=" + json.dumps(target, ensure_ascii=False))
        start = time.time()
        res = _run_payonly_script_for_account(acc, log_cb=log)
        elapsed = round(time.time() - start, 3)
        done += 1
        if res.get("status") == "ok":
            ok += 1
        else:
            fail += 1
        log("PAYONLY_OLDEST_RESULT_JSON=" + json.dumps({
            "target": target,
            "elapsed_s": elapsed,
            "status": res.get("status"),
            "live_plus_verified": (res.get("script_result") or {}).get("live_plus_verified"),
            "session_id": res.get("session_id"),
            "screenshot": res.get("public_screenshot") or res.get("screenshot"),
            "summary": {"done": done, "ok": ok, "fail": fail},
        }, ensure_ascii=False))
        if res.get("status") != "ok" and stop_on_fail:
            log("PAYONLY_OLDEST_STOP_ON_FAIL")
            return 1
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
