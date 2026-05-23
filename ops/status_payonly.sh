#!/usr/bin/env bash
set -euo pipefail

cd /root/Gpt-Agreement-Payment

echo "== payonly/payment processes =="
ps -eo pid,ppid,stat,etime,cmd | grep -E 'aws_payonly_free_loop|aws_payonly_free_from_hk|run_payonly_free_inventory_queue|payment_runner|payonly|paypal|camoufox|chrome' | grep -v grep || true

echo
echo "== latest payonly/payment logs =="
find output/logs -maxdepth 1 -type f \( -iname '*payonly*' -o -iname '*payment*' -o -iname '*aws*' \) -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort | tail -30
