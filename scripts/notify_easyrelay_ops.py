#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, shlex, ssl, subprocess, sys, time, urllib.request
from pathlib import Path

STATE_DIR = Path(os.getenv('GPTPAY_NOTIFY_STATE_DIR', '/root/Gpt-Agreement-Payment/output/notify_state'))
CHANNEL = os.getenv('GPTPAY_NOTIFY_CHANNEL', 'telegram')
ACCOUNT = os.getenv('GPTPAY_NOTIFY_ACCOUNT', 'default')
TARGET = os.getenv('GPTPAY_NOTIFY_TARGET', '-1003776908920')
BOT_API_FALLBACK = os.getenv('GPTPAY_NOTIFY_BOT_API_FALLBACK', '1').lower() not in ('0','false','no','off')
OPENCLAW_CONFIG = Path(os.getenv('OPENCLAW_CONFIG', '/root/.openclaw/openclaw.json'))


def should_send(key: str, cooldown: int) -> bool:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    safe = ''.join(c if c.isalnum() or c in '._-' else '_' for c in key)[:160]
    p = STATE_DIR / (safe + '.ts')
    now = time.time()
    try:
        last = float(p.read_text().strip())
    except Exception:
        last = 0
    if cooldown > 0 and now - last < cooldown:
        return False
    p.write_text(str(now))
    return True


def _openclaw_send(text: str) -> subprocess.CompletedProcess:
    cmd = ['openclaw', 'message', 'send', '--channel', CHANNEL, '--account', ACCOUNT, '--target', TARGET, '--message', text, '--json']
    return subprocess.run(cmd, text=True, capture_output=True, timeout=60)


def _read_bot_token() -> str:
    cfg = json.loads(OPENCLAW_CONFIG.read_text())
    tg = cfg.get('channels', {}).get('telegram', {})
    acct = (tg.get('accounts') or {}).get(ACCOUNT) or {}
    token = acct.get('botToken') or tg.get('botToken') or ''
    if not token:
        raise RuntimeError(f'no Telegram botToken for account={ACCOUNT}')
    return token


def _bot_api_send(text: str) -> subprocess.CompletedProcess:
    token = _read_bot_token()
    # Never print token. curl stdout contains only Telegram API response.
    cmd = ['curl', '-sS', f'https://api.telegram.org/bot{token}/sendMessage', '-d', f'chat_id={TARGET}', '--data-urlencode', f'text={text}']
    return subprocess.run(cmd, text=True, capture_output=True, timeout=60)


def _webhook_notify(key: str, title: str, body: str, cooldown: int) -> subprocess.CompletedProcess | None:
    url = os.getenv('GPTPAY_NOTIFY_WEBHOOK_URL', '').strip()
    if not url:
        return None
    token = os.getenv('GPTPAY_NOTIFY_WEBHOOK_TOKEN', '').strip()
    payload = json.dumps({
        'key': key,
        'title': title,
        'message': body,
        'cooldown': cooldown,
    }, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=payload, method='POST', headers={'Content-Type': 'application/json'})
    host = os.getenv('GPTPAY_NOTIFY_WEBHOOK_HOST', '').strip()
    if host:
        req.add_header('Host', host)
    if token:
        req.add_header('X-Gptpay-Ops-Token', token)
    timeout = float(os.getenv('GPTPAY_NOTIFY_WEBHOOK_TIMEOUT', '8') or '8')
    context = None
    if os.getenv('GPTPAY_NOTIFY_WEBHOOK_INSECURE_TLS', '').lower() in ('1', 'true', 'yes', 'on'):
        context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
        out = resp.read().decode('utf-8', errors='replace')
    return subprocess.CompletedProcess(['webhook'], 0, out, '')


def _remote_hk_notify(key: str, title: str, body: str, cooldown: int) -> subprocess.CompletedProcess | None:
    if os.getenv('GPTPAY_NOTIFY_DISABLE_REMOTE', '1').lower() not in ('0', 'false', 'no', 'off'):
        return None
    hk = os.getenv('GPTPAY_NOTIFY_HK_HOST', 'root@8.210.227.183')
    keyfile = os.getenv('GPTPAY_NOTIFY_HK_KEY', '/home/ubuntu/.ssh/hk_gptpay_db')
    remote_py = os.getenv('GPTPAY_NOTIFY_HK_PY', '/root/Gpt-Agreement-Payment/venv/bin/python')
    remote_script = os.getenv('GPTPAY_NOTIFY_HK_SCRIPT', '/root/Gpt-Agreement-Payment/scripts/notify_easyrelay_ops.py')
    timeout = int(os.getenv('GPTPAY_NOTIFY_REMOTE_TIMEOUT', '8') or '8')
    if not Path(keyfile).exists():
        return None
    remote_cmd = shlex.join([
        remote_py, remote_script,
        '--key', key, '--title', title, '--cooldown', str(cooldown), '--stdin',
    ])
    cmd = [
        'ssh', '-i', keyfile,
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=5',
        '-o', 'BatchMode=yes',
        hk, remote_cmd,
    ]
    return subprocess.run(cmd, input=body, text=True, capture_output=True, timeout=timeout)


def _print_and_return(r: subprocess.CompletedProcess | None, fallback: str = 'sent') -> int:
    if r is None:
        print(fallback)
        return 0
    out = (r.stdout or '').strip()
    err = (r.stderr or '').strip()
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return int(r.returncode or 0)


def send_message(text: str) -> subprocess.CompletedProcess:
    try:
        r = _openclaw_send(text)
    except FileNotFoundError:
        r = None
    if r is not None and r.returncode == 0:
        return r
    if BOT_API_FALLBACK and (r is None or 'chat not found' in (r.stderr + r.stdout).lower() or 'unknown target' in (r.stderr + r.stdout).lower()):
        return _bot_api_send(text)
    return r


def main() -> int:
    start_ts = time.monotonic()
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', required=True)
    ap.add_argument('--title', default='GPTPay AWS')
    ap.add_argument('--message', default='')
    ap.add_argument('--cooldown', type=int, default=1800)
    ap.add_argument('--stdin', action='store_true')
    args = ap.parse_args()
    body = sys.stdin.read() if args.stdin else args.message
    body = (body or '').strip()
    text = f"【{args.title}】\n{body}" if body else f"【{args.title}】"
    # If running on AWS, OpenClaw config/token may not exist locally. In that case
    # forward the notification to the HK source host, where OpenClaw is installed.
    if not OPENCLAW_CONFIG.exists():
        # Prefer a short HTTP webhook to HK/WebUI. It must never block payment.
        try:
            r_hook = _webhook_notify(args.key, args.title, body, args.cooldown)
            if r_hook is not None:
                
                rc = _print_and_return(r_hook, 'sent-via-webhook')
                print(f'TIMING notify_webhook_s={time.monotonic() - start_ts:.1f}', file=sys.stderr)
                return rc
        except Exception as e:
            print(f'webhook notify failed nonfatal: {type(e).__name__}: {e}', file=sys.stderr)
            print(f'TIMING notify_webhook_s={time.monotonic() - start_ts:.1f}', file=sys.stderr)
            return 0
        # AWS should never let notification delivery block payment workers.  By
        # default remote HK forwarding is disabled; when explicitly enabled it
        # has a short timeout and any failure is logged but treated as non-fatal.
        try:
            r_remote = _remote_hk_notify(args.key, args.title, body, args.cooldown)
        except Exception as e:
            print(f'remote notify skipped/failed nonfatal: {type(e).__name__}: {e}', file=sys.stderr)
            return 0
        if r_remote is not None:
            rc = _print_and_return(r_remote, 'sent-via-hk')
            return 0 if rc != 0 else 0
        print('notify skipped: no local OpenClaw config; remote disabled')
        return 0

    if not should_send(args.key, args.cooldown):
        print(f'skipped cooldown key={args.key}')
        return 0
    r = send_message(text[:3900])
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        return r.returncode
    print(r.stdout.strip() or 'sent')
    print(f'TIMING notify_local_s={time.monotonic() - start_ts:.1f}', file=sys.stderr)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
