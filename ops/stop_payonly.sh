#!/usr/bin/env bash
set -euo pipefail

cd /root/Gpt-Agreement-Payment

pkill -f 'aws_payonly_free_loop|aws_payonly_free_from_hk|run_payonly_free_inventory_queue|payment_runner|payonly_us_paypal_guest' || true
pkill -f 'camoufox|chrome|xvfb' || true

echo "[payonly] stop sent. remaining:"
ps -eo pid,ppid,stat,etime,cmd | grep -E 'aws_payonly_free_loop|aws_payonly_free_from_hk|run_payonly_free_inventory_queue|payment_runner|payonly|paypal|camoufox|chrome' | grep -v grep || true
