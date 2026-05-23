#!/usr/bin/env bash
set -euo pipefail
ROOT=/root/Gpt-Agreement-Payment
INTERVAL="${AWS_PAYONLY_INTERVAL:-180}"
LIMIT="${AWS_PAYONLY_LIMIT:-0}"
LOCK="$ROOT/output/aws_payonly_free_loop.lock"
LOG_DIR="$ROOT/output/logs"
mkdir -p "$LOG_DIR"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "[$(date -Is)] another aws_payonly_free_loop is running; exit"
  exit 0
fi
summarize_notify() {
  local rc="$1"
  "$ROOT/venv/bin/python" - "$rc" <<'PY'
import json, re, sys
rc = sys.argv[1]
out = sys.stdin.read()
summary = None
for line in out.splitlines()[::-1]:
    if line.startswith('PAYONLY_QUEUE_RESULT_JSON='):
        try:
            summary = json.loads(line.split('=', 1)[1])
        except Exception:
            summary = None
        break
errs = []
low = out.lower()
if 'notinstalledgeoipextra' in low:
    errs.append('AWS 缺 Camoufox geoip 依赖（已知会导致 PayPal guest 打不开）')
if 'card_generic_error' in low:
    errs.append('卡被 Stripe/PayPal 返回 card_generic_error')
if 'payment_method_provider_decline' in low or 'generic_decline' in low or 'do_not_honor' in low or 'card_declined' in low:
    errs.append('Stripe confirm 阶段卡/支付方式被拒')
if 'requires_payment_method' in low:
    errs.append('Stripe confirm 返回 requires_payment_method')
if 'no eligible cards on file' in low:
    errs.append('PayPal 没有可用卡')
if 'try a different phone number' in low or '号码池已用尽' in out or 'phone pool' in low:
    errs.append('号码池/手机号被拒')
if 'key_pool_empty' in low or 'payonly curl 请求体池子为空' in out:
    errs.append('PayOnly key 池为空')
if ('traceback' in low or 'exception' in low or 'error' in low) and not errs:
    # Keep only the last meaningful exception/error line, not the whole traceback.
    for line in reversed(out.splitlines()):
        s=line.strip()
        if not s or len(s) > 240:
            continue
        if any(x in s.lower() for x in ['exception', 'error', 'traceback']):
            errs.append(s)
            break
lines = []
if summary:
    lines.append(f"AWS PayOnly 本轮结束：total={summary.get('total', 0)} ok={summary.get('ok', 0)} fail={summary.get('fail', 0)} key_pool={summary.get('key_pool', '-')}")
    if summary.get('reason'):
        lines.append(f"原因：{summary.get('reason')}")
    samples=[]
    for r in (summary.get('results') or []):
        if r.get('status') != 'ok':
            e = (r.get('error') or '').lower()
            cause = '失败'
            if 'notinstalledgeoipextra' in e: cause='Camoufox geoip 缺依赖'
            elif 'card_generic_error' in e: cause='card_generic_error'
            elif any(x in e for x in ['payment_method_provider_decline', 'generic_decline', 'do_not_honor', 'card_declined', 'requires_payment_method']): cause='confirm卡/支付方式被拒'
            elif 'try a different phone number' in e or 'phone' in e: cause='号码/短信问题'
            elif 'key_pool_empty' in e: cause='key池为空'
            samples.append(f"#{r.get('id')} {r.get('email','')}：{cause}")
            if len(samples) >= 3: break
    if samples:
        lines.append('样例：' + '；'.join(samples))
else:
    lines.append(f"AWS PayOnly 循环异常 rc={rc}")
if errs:
    # Deduplicate while preserving order.
    seen=set(); uniq=[]
    for e in errs:
        if e not in seen:
            seen.add(e); uniq.append(e)
    lines.append('判断：' + '；'.join(uniq[:3]))
# Add a short tail marker without stack traces.
for line in reversed(out.splitlines()):
    s=line.strip()
    if s.startswith('[20') and ('loop done' in s or 'loop start' in s):
        lines.append('日志：' + s)
        break
print('\n'.join(lines)[:1800])
PY
}
while true; do
  echo "[$(date -Is)] loop start limit=$LIMIT interval=$INTERVAL"
  set +e
  OUT_FILE=$(mktemp "$LOG_DIR/aws_payonly_round.XXXXXX.log")
  timeout 2h "$ROOT/scripts/aws_payonly_free_from_hk.sh" "$LIMIT" 2>&1 | tee "$OUT_FILE"
  rc=${PIPESTATUS[0]}
  OUT=$(cat "$OUT_FILE" 2>/dev/null)
  rm -f "$OUT_FILE"
  set -e
  if [ "${GPTPAY_NOTIFY_LOOP_ERRORS:-0}" != "0" ] && [ "$rc" -ne 0 ]; then
    summarize_notify "$rc" <<<"$OUT" | "$ROOT/venv/bin/python" "$ROOT/scripts/notify_easyrelay_ops.py" --stdin --key "aws_payonly_loop_rc_${rc}" --title "Gpt-Pay运维" --cooldown 900 || true
  fi
  if [ "${GPTPAY_NOTIFY_LOOP_ERRORS:-0}" != "0" ] && printf '%s\n' "$OUT" | grep -Eiq 'no eligible cards on file|card_generic_error|try a different phone number|号码池已用尽|phone pool|sms|PayOnly curl 请求体池子为空|key_pool_empty|traceback|exception|error'; then
    summarize_notify "$rc" <<<"$OUT" | "$ROOT/venv/bin/python" "$ROOT/scripts/notify_easyrelay_ops.py" --stdin --key "aws_payonly_loop_detected_error" --title "Gpt-Pay运维" --cooldown 900 || true
  fi
  echo "[$(date -Is)] loop done rc=$rc; sleep ${INTERVAL}s"
  sleep "$INTERVAL"
done
