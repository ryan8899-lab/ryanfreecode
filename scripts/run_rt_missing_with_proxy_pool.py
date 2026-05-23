#!/usr/bin/env python3
import json, os, re, subprocess, sys, tempfile, time, socket, atexit, fcntl
from pathlib import Path

ROOT = Path('/root/Gpt-Agreement-Payment')
sys.path.insert(0, str(ROOT))
from webui.backend.db import get_db  # noqa: E402

BASE_CONFIG = ROOT / 'CTF-pay/config.paypal.json'
PROXY_FILE = Path(os.environ.get('RT_PROXY_FILE') or str(ROOT / 'output/rt_proxy_pool_1024_jp.txt'))
RT_PROXY_DB_KEY = os.environ.get('RT_PROXY_DB_KEY') or 'proxy_pool_jp_v1'
PYTHON = ROOT / 'venv/bin/python'
PIPELINE = ROOT / 'pipeline.py'
_RELAYS = []
_LOCK_FDS = []


def _proxy_key(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', (value or '')).strip('_')[:96] or 'proxy'


def _acquire_relay_lock(upstream: str):
    lock_dir = Path('/tmp/rt-gost-locks')
    lock_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_dir / f'{_proxy_key(upstream)}.lock'), os.O_CREAT | os.O_RDWR, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX)
    _LOCK_FDS.append(fd)
    return fd


def _release_relay_lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        os.close(fd)
    except Exception:
        pass
    try:
        _LOCK_FDS.remove(fd)
    except ValueError:
        pass


def _release_all_locks():
    for fd in list(_LOCK_FDS):
        _release_relay_lock(fd)


def _probe_socks_proxy(proxy_url: str, timeout_s: int = 6) -> bool:
    """Probe the local relay through curl. TCP listen alone is not enough for gost; dead upstreams accept but fail later."""
    try:
        r = subprocess.run(
            [
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--max-time', str(timeout_s),
                '-x', proxy_url.replace('socks5://', 'socks5h://', 1),
                'https://api.ipify.org',
            ],
            capture_output=True, text=True, timeout=timeout_s + 2,
        )
        return r.stdout.strip() == '200'
    except Exception:
        return False


def _proxy_public_ip(proxy_url: str, timeout_s: int = 8) -> str:
    """Return public IP through local socks relay for logging/debugging."""
    try:
        r = subprocess.run(
            [
                'curl', '-sS', '--max-time', str(timeout_s),
                '-x', proxy_url.replace('socks5://', 'socks5h://', 1),
                'https://api.ipify.org',
            ],
            capture_output=True, text=True, timeout=timeout_s + 2,
        )
        out = (r.stdout or '').strip()
        if r.returncode == 0 and out:
            return out[:80]
        err = (r.stderr or '').strip().replace('\n', ' ')
        return f'ERR rc={r.returncode} {err[:120]}'
    except Exception as e:
        return f'ERR {type(e).__name__}: {str(e)[:120]}'


def _redact_proxy(proxy_url: str) -> str:
    return re.sub(r':[^:@/]+@', ':***@', str(proxy_url or ''))


def _terminate_relay(p: subprocess.Popen | None):
    if not p:
        return
    try:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
    except Exception:
        pass


def _runtime_proxy_lines() -> list[str]:
    try:
        raw = get_db().get_runtime_json(RT_PROXY_DB_KEY, None)
        lines = []
        if isinstance(raw, list):
            for x in raw:
                if isinstance(x, str):
                    line = x.strip()
                elif isinstance(x, dict):
                    line = str(x.get('proxy') or x.get('url') or x.get('line') or '').strip()
                else:
                    line = str(x or '').strip()
                if line and not line.startswith('#'):
                    lines.append(line)
        elif isinstance(raw, str):
            lines = [x.strip() for x in raw.splitlines() if x.strip() and not x.strip().startswith('#')]
        if lines:
            return lines
    except Exception as e:
        print(f'[rt-proxy] DB proxy pool read failed key={RT_PROXY_DB_KEY}: {e}', flush=True)
    return []


def convert_proxy(line: str) -> str:
    line = (line or '').strip()
    if not line:
        return ''
    if '://' in line:
        return line
    parts = line.split(':')
    if len(parts) >= 4:
        host, port, user = parts[0], parts[1], parts[2]
        pwd = ':'.join(parts[3:])
        return f'socks5://{user}:{pwd}@{host}:{port}'
    raise ValueError(f'bad proxy line: {line!r}')



def _free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_gost_relay(upstream: str) -> tuple[str, subprocess.Popen]:
    lock_fd = _acquire_relay_lock(upstream)
    p = None
    try:
        port = _free_port()
        local = f'socks5://127.0.0.1:{port}'
        cmd = ['gost', f'-L={local}', f'-F={upstream}']
        log_path = f'/tmp/rt-gost-{port}.log'
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            p = subprocess.Popen(cmd, stdout=log_fd, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        finally:
            os.close(log_fd)
        deadline = time.time() + int(os.environ.get('RT_GOST_START_TIMEOUT', '15'))
        last = None
        while time.time() < deadline:
            if p.poll() is not None:
                raise RuntimeError(f'gost relay exited early for {upstream}, see {log_path}')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    pass
                if _probe_socks_proxy(local, timeout_s=4):
                    _RELAYS.append(p)
                    p._rt_lock_fd = lock_fd  # type: ignore[attr-defined]
                    return local, p
                last = RuntimeError('upstream probe failed')
            except Exception as e:
                last = e
            time.sleep(0.35)
        _terminate_relay(p)
        raise RuntimeError(f'gost relay failed/probe-dead for {upstream}: {last} (see {log_path})')
    except Exception:
        _terminate_relay(p)
        _release_relay_lock(lock_fd)
        raise


def cleanup_relays():
    for p in list(_RELAYS):
        _terminate_relay(p)
        fd = getattr(p, '_rt_lock_fd', None)
        if fd is not None:
            _release_relay_lock(fd)

atexit.register(cleanup_relays)
atexit.register(_release_all_locks)

def load_proxies():
    proxies = []
    raw_lines = _runtime_proxy_lines()
    if raw_lines:
        print(f'[rt-proxy] loaded {len(raw_lines)} proxies from DB key={RT_PROXY_DB_KEY}', flush=True)
    else:
        raw_lines = PROXY_FILE.read_text().splitlines()
        print(f'[rt-proxy] loaded proxies from file {PROXY_FILE}', flush=True)
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        proxies.append(convert_proxy(line))
    if not proxies:
        raise SystemExit('proxy pool empty')
    return proxies


def target_emails(limit=0):
    env_targets = os.environ.get('RT_TARGET_EMAILS', '').strip()
    accounts = get_db().iter_registered_accounts()
    by_email = {}
    for r in accounts:
        em = (r.get('email') or '').strip().lower()
        if em:
            by_email[em] = r
    if env_targets:
        out = []
        seen = set()
        for raw in re.split(r'[,\n\s]+', env_targets):
            email = raw.strip().lower()
            if not email or email in seen:
                continue
            seen.add(email)
            row = by_email.get(email)
            out.append((int(row.get('id') or 0) if row else 0, row.get('email') if row else email))
        return out[:limit] if limit else out
    rows = [r for r in accounts if not (r.get('refresh_token') or '') and (r.get('session_token') or '') and (r.get('access_token') or '')]
    rows.sort(key=lambda r: int(r.get('id') or 0), reverse=True)
    if os.environ.get('RT_PREFER_PAYONLY_SUCCESS', '').strip().lower() not in ('0', 'false', 'no', 'off'):
        paid = [r for r in rows if str(r.get('last_check_status') or '') == 'plan' and 'paypal_success' in str(r.get('last_check_message') or '')]
        unpaid = [r for r in rows if r not in paid]
        rows = paid + unpaid
    out = [(int(r['id']), r['email']) for r in rows]
    return out[:limit] if limit else out


def has_rt(email: str) -> bool:
    target = (email or '').strip().lower()
    rows = [r for r in get_db().iter_registered_accounts() if (r.get('email') or '').strip().lower() == target]
    return bool(rows and (rows[-1].get('refresh_token') or ''))


def _sms_active_snapshot() -> tuple[str, int]:
    try:
        active = get_db().get_runtime_json('sms_active_number', {}) or {}
        return str(active.get('phone') or active.get('activation_id') or ''), int(active.get('receive_count') or 0)
    except Exception:
        return '', 0


def _sleep_between_accounts(prev_phone: str, prev_count: int, cur_phone: str, cur_count: int, default_sleep: float):
    reuse_sleep = float(os.environ.get('RT_REUSE_COOLDOWN_SECONDS') or '25')
    sleep_s = default_sleep
    if cur_phone and cur_phone == prev_phone and cur_count > prev_count and cur_count < 3:
        sleep_s = max(sleep_s, reuse_sleep)
        print(f'[runner] reuse cooldown {sleep_s:.0f}s phone=***{cur_phone[-4:]} receive_count={cur_count}', flush=True)
    else:
        print(f'[runner] breath {sleep_s:.0f}s', flush=True)
    time.sleep(sleep_s)


def make_config(proxy: str) -> str:
    cfg = json.load(open(BASE_CONFIG))
    cfg['proxy'] = proxy
    # Ryan 要求：RT 获取时如果命中 add-phone，先不要走手机号验证。
    # 只允许授权页自身有 Skip/Not now 时跳过；没有 Skip 就放弃该账号本轮 RT，避免消耗号码/触发手机风控。
    rt = cfg.setdefault('rt_phone_verify', {})
    rt['enabled'] = False
    fd, path = tempfile.mkstemp(prefix='rt_proxy_cfg_', suffix='.json', dir=str(ROOT / 'CTF-pay'))
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return path


def main():
    limit = int(os.environ.get('RT_LIMIT') or '0')
    start_index = int(os.environ.get('RT_PROXY_OFFSET') or '0')
    dry = os.environ.get('RT_DRY_RUN') == '1'
    proxies = load_proxies()
    targets = target_emails(limit)
    print(f'[runner] targets={len(targets)} proxies={len(proxies)} limit={limit or "all"}', flush=True)
    ok = fail = skip = 0
    results = []
    for idx, (row_id, email) in enumerate(targets):
        if has_rt(email):
            print(f'[runner] skip already has rt: #{row_id} {email}', flush=True)
            skip += 1
            continue
        upstream_proxy = proxies[(start_index + idx) % len(proxies)]
        print(f'\n[runner] {idx+1}/{len(targets)} id={row_id} email={email} proxy_index={(start_index+idx)%len(proxies)}', flush=True)
        if dry:
            print(f'[runner] DRY proxy={upstream_proxy}', flush=True)
            continue
        relay_proc = None
        try:
            if upstream_proxy.startswith('socks5://') and '@' in upstream_proxy:
                proxy, relay_proc = start_gost_relay(upstream_proxy)
                proxy_ip = _proxy_public_ip(proxy, timeout_s=8)
                print(
                    f'[runner] gost relay {proxy} -> upstream proxy_index={(start_index+idx)%len(proxies)} '
                    f'upstream={_redact_proxy(upstream_proxy)} public_ip={proxy_ip}',
                    flush=True,
                )
            else:
                proxy = upstream_proxy
        except Exception as e:
            print(f'[runner] proxy relay failed: {e}', flush=True)
            fail += 1
            continue
        pre_phone, pre_count = _sms_active_snapshot()
        cfg_path = make_config(proxy)
        cmd = [
            'xvfb-run', '-a', str(PYTHON), '-u', str(PIPELINE),
            '--config', cfg_path,
            '--rt-only', '--target-emails', email,
        ]
        rc = 999
        child = None
        try:
            child = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                env={**os.environ, 'PYTHONUNBUFFERED': '1'},
            )
            deadline = time.time() + int(os.environ.get('RT_ACCOUNT_TIMEOUT', '900'))
            while True:
                if child.stdout is None:
                    break
                line = child.stdout.readline()
                if line:
                    print(line, end='', flush=True)
                if child.poll() is not None:
                    # Drain any remaining buffered lines.
                    rest = child.stdout.read() if child.stdout else ''
                    if rest:
                        print(rest, end='', flush=True)
                    break
                if time.time() > deadline:
                    print(f'[runner] TIMEOUT {email}', flush=True)
                    try:
                        child.kill()
                    except Exception:
                        pass
                    break
            rc = child.wait(timeout=10) if child else 999
        except Exception as e:
            print(f'[runner] child error {email}: {type(e).__name__}: {e}', flush=True)
        finally:
            try: os.unlink(cfg_path)
            except Exception: pass
            try:
                if relay_proc and relay_proc.poll() is None:
                    relay_proc.terminate()
                    try:
                        relay_proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        relay_proc.kill()
                fd = getattr(relay_proc, '_rt_lock_fd', None) if relay_proc else None
                if fd is not None:
                    _release_relay_lock(fd)
            except Exception:
                pass
        post_phone, post_count = _sms_active_snapshot()
        if has_rt(email):
            ok += 1
            st = 'ok'
        else:
            fail += 1
            st = f'fail(rc={rc})'
        results.append({'id': row_id, 'email': email, 'status': st})
        print(f'[runner] result {email}: {st} | ok={ok} fail={fail} skip={skip}', flush=True)
        # Small breath between browser sessions; when the same SMS number was
        # successfully consumed but is still reusable, wait 20-30s before the
        # next account so OpenAI/PVAPins stop returning the previous code.
        _sleep_between_accounts(pre_phone, pre_count, post_phone, post_count, 3)
    print('\n[runner] DONE')
    print(json.dumps({'ok': ok, 'fail': fail, 'skip': skip, 'results': results}, ensure_ascii=False, indent=2), flush=True)

if __name__ == '__main__':
    main()
