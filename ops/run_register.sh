#!/usr/bin/env bash
set -euo pipefail

cd /root/Gpt-Agreement-Payment
source ops/register.env

mkdir -p output/logs
LOG="output/logs/register_hk_${COUNT}_$(date +%Y%m%d_%H%M%S).log"

if pgrep -af 'pipeline.py.*register-only|browser_register.py' >/dev/null 2>&1; then
  echo "[register] 检测到已有注册进程，先退出，避免重复跑："
  pgrep -af 'pipeline.py.*register-only|browser_register.py' || true
  exit 1
fi

echo "COUNT=$COUNT"
echo "DELAY=$DELAY"
echo "WORKERS=$WORKERS"
echo "REG_FP_COUNTRY=${REG_FP_COUNTRY:-}"
echo "CARDW_CONFIG=$CARDW_CONFIG"
echo "LOG=$LOG"

WEBUI_REG_MODE="$WEBUI_REG_MODE" \
REG_CAMOUFOX_HEADLESS="$REG_CAMOUFOX_HEADLESS" \
REG_FP_COUNTRY="${REG_FP_COUNTRY:-}" \
nohup xvfb-run -a /root/Gpt-Agreement-Payment/venv/bin/python -u pipeline.py \
  --register-only \
  --cardw-config "$CARDW_CONFIG" \
  --batch "$COUNT" \
  --workers "$WORKERS" \
  --delay "$DELAY" \
  > "$LOG" 2>&1 &

PID=$!
echo "$PID" > output/register_hk.pid
echo "PID=$PID"
echo "LOG=$LOG"
echo "tail -f $LOG"
