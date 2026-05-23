#!/usr/bin/env bash
set -euo pipefail

cd /root/Gpt-Agreement-Payment
source ops/payonly.env

mkdir -p output/logs
LOG="output/logs/aws_payonly_once_${LIMIT}_$(date +%Y%m%d_%H%M%S).log"

if pgrep -af 'aws_payonly_free_from_hk|run_payonly_free_inventory_queue|payment_runner|payonly_us_paypal_guest' >/dev/null 2>&1; then
  echo "[payonly] 检测到已有 PayOnly/支付进程，先退出，避免重复跑："
  pgrep -af 'aws_payonly_free_from_hk|run_payonly_free_inventory_queue|payment_runner|payonly_us_paypal_guest' || true
  exit 1
fi

echo "LIMIT=$LIMIT"
echo "PAYONLY_STOP_ON_FAIL=$PAYONLY_STOP_ON_FAIL"
echo "GPTPAY_NOTIFY_ASYNC=$GPTPAY_NOTIFY_ASYNC"
echo "LOG=$LOG"

PAYONLY_STOP_ON_FAIL="$PAYONLY_STOP_ON_FAIL" \
GPTPAY_NOTIFY_ASYNC="$GPTPAY_NOTIFY_ASYNC" \
nohup ./scripts/aws_payonly_free_from_hk.sh "$LIMIT" \
  > "$LOG" 2>&1 &

PID=$!
echo "$PID" > output/aws_payonly_once.pid
echo "PID=$PID"
echo "LOG=$LOG"
echo "tail -f $LOG"
