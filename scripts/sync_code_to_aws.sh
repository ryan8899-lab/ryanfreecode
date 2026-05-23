#!/usr/bin/env bash
set -euo pipefail
ROOT=/root/Gpt-Agreement-Payment
AWS=${AWS_HOST:-ubuntu@18.145.125.121}
KEY=${AWS_KEY:-/root/.ssh/aws_uploads/aws_20260518_202330.pem}
cd "$ROOT"
echo "[sync-code] HK -> AWS $AWS"
rsync -az --delete \
  --exclude '.git/' \
  --exclude '.secrets/' \
  --exclude 'venv/' \
  --exclude 'webui/frontend/node_modules/' \
  --exclude 'webui/frontend/dist/' \
  --exclude 'output/' \
  --exclude '__pycache__/' \
  --exclude '*/__pycache__/' \
  --exclude '*.pyc' \
  -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  "$ROOT/" "$AWS:/root/Gpt-Agreement-Payment/"
# output/ is excluded above; explicitly ship the small runtime pool files AWS needs.
rsync -az \
  -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  "$ROOT/output/payonly_us_proxy_pool.txt" \
  "$ROOT/output/payonly_us_proxy_pool.state" \
  "$ROOT/output/rt_proxy_pool_1024_jp.txt" \
  "$ROOT/output/rt_proxy_pool_1024_us.txt" \
  "$AWS:/root/Gpt-Agreement-Payment/output/" 2>/dev/null || true
ssh -i "$KEY" -o StrictHostKeyChecking=accept-new "$AWS" 'set -e
cd /root/Gpt-Agreement-Payment
mkdir -p output/logs output/debug
if [ -d webui/frontend ]; then
  cd webui/frontend
  if [ -f package.json ]; then
    npm install >/tmp/gptpay_npm_install.log
    npm run build >/tmp/gptpay_npm_build.log
    sudo rsync -a --delete dist/ /var/www/gptpay-aws/
    sudo chown -R www-data:www-data /var/www/gptpay-aws
  fi
fi
sudo systemctl restart gptpay-worker 2>/dev/null || true
sudo nginx -t >/dev/null && sudo systemctl reload nginx
'
echo "[sync-code] done"
