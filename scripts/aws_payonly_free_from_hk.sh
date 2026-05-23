#!/usr/bin/env bash
set -euo pipefail
ROOT=/root/Gpt-Agreement-Payment
HK=root@8.210.227.183
KEY=/home/ubuntu/.ssh/hk_gptpay_db
LIMIT="${1:-0}"
mkdir -p "$ROOT/output" "$ROOT/output/logs"
if [ -n "${DATABASE_URL:-}" ]; then
  # Respect an explicit caller-provided DATABASE_URL.
  echo "[aws-payonly] using shared Postgres database from environment"
elif [ -f "$ROOT/.secrets/postgres-public.env" ] && hostname | grep -q '^ip-'; then
  # AWS worker: prefer direct public Postgres when HK pg_hba/firewall whitelist is configured.
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.secrets/postgres-public.env"
  set +a
  echo "[aws-payonly] using shared Postgres database (public)"
elif [ -f "$ROOT/.secrets/postgres-tunnel.env" ] && hostname | grep -q '^ip-'; then
  # Fallback only if public env is absent/unavailable.
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.secrets/postgres-tunnel.env"
  set +a
  echo "[aws-payonly] using shared Postgres database (ssh tunnel)"
elif [ -f "$ROOT/.secrets/postgres.env" ]; then
  # Network DB mode: HK and AWS use the same Postgres database, no webui.db copy.
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.secrets/postgres.env"
  set +a
  echo "[aws-payonly] using shared Postgres database"
else
  echo "[aws-payonly] ERROR: missing Postgres env; refusing SQLite/webui.db fallback" >&2
  exit 2
fi
echo "[aws-payonly] scanning free inventory and running PayOnly queue limit=$LIMIT (0=all eligible)"
cd "$ROOT"
exec xvfb-run -a "$ROOT/venv/bin/python" -u "$ROOT/scripts/run_payonly_free_inventory_queue.py" --limit "$LIMIT" --no-stop-on-fail
