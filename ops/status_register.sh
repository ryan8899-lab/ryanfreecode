#!/usr/bin/env bash
set -euo pipefail

cd /root/Gpt-Agreement-Payment

echo "== register processes =="
ps -eo pid,ppid,stat,etime,cmd | grep -E 'pipeline.py.*register-only|browser_register|camoufox|chrome' | grep -v grep || true

echo
echo "== latest register logs =="
find output/logs -maxdepth 1 -type f -iname '*register*' -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort | tail -20
