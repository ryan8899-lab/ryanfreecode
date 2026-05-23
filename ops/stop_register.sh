#!/usr/bin/env bash
set -euo pipefail

cd /root/Gpt-Agreement-Payment

pkill -f 'pipeline.py.*register-only' || true
pkill -f 'browser_register|camoufox|chrome' || true

echo "[register] stop sent. remaining:"
ps -eo pid,ppid,stat,etime,cmd | grep -E 'pipeline.py.*register-only|browser_register|camoufox|chrome' | grep -v grep || true
