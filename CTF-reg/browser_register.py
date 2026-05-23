"""
基于 Camoufox 真浏览器的 ChatGPT 注册流程。
目的：让 Turnstile/反欺诈指纹通过真实浏览器执行，避免账号被内部风控标记
（导致注册 OK 但后续 Team 邀请功能被禁用）。

流程：
  1. Camoufox 启动 → goto https://chatgpt.com/
  2. 点击 Sign up → 跳转到 auth.openai.com
  3. 填邮箱 → Continue
  4. 填密码 → Continue（可能触发 Turnstile，Camoufox 指纹可通过）
  5. IMAP 取 OTP → 填入 → Continue
  6. 填姓名/生日 → Continue
  7. 回到 chatgpt.com → 从 /api/auth/session 拿 access_token
  8. 从 Cookie 拿 session_token / oai-did

返回：{email, password, session_token, access_token, device_id, cookie_header}
"""
import os
import subprocess
import random
import string
import time
import logging
import tempfile
import shutil
import json
import re
import hashlib
import base64
import secrets
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs

logger = logging.getLogger(__name__)


def _gen_name() -> tuple[str, str]:
    first_names = ["James", "John", "Emily", "Sophia", "Michael", "Oliver", "Emma",
                   "William", "Amelia", "Lucas", "Mia", "Ethan"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
                  "Miller", "Davis", "Rodriguez", "Martinez"]
    return random.choice(first_names), random.choice(last_names)


def _gen_birthday() -> tuple[str, str, str]:
    # 成年，1980-2000 随机
    year = random.randint(1980, 2000)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return str(month).zfill(2), str(day).zfill(2), str(year)


def _gen_openai_password(length: int = 14) -> str:
    """Generate a random password that satisfies OpenAI's current signup rules."""
    alphabet = string.ascii_letters + string.digits
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    rest = [secrets.choice(alphabet) for _ in range(max(length, 12) - len(required))]
    chars = required + rest
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def _register_fingerprint_profile() -> tuple[str, str, tuple[int, int], bool]:
    """Return a mildly varied desktop browser profile for each registration."""
    fp_country = os.environ.get("REG_FP_COUNTRY", "").strip().upper()
    if fp_country == "JP":
        locales = [("ja-JP", "Asia/Tokyo")]
    else:
        locales = [
            ("en-US", "America/Los_Angeles"),
            ("en-US", "America/Chicago"),
            ("en-US", "America/New_York"),
            ("en-CA", "America/Toronto"),
            ("en-GB", "Europe/London"),
        ]
    screens = [
        (1366, 768),
        (1440, 900),
        (1536, 864),
        (1600, 900),
        (1680, 1050),
        (1920, 1080),
    ]
    loc, tz = random.choice(locales)
    width, height = random.choice(screens)
    width = max(1280, width + random.randint(-24, 24))
    height = max(720, height + random.randint(-20, 20))
    humanize = str(os.environ.get("REG_CAMOUFOX_HUMANIZE", "1")).lower() not in ("0", "false", "no", "off")
    return loc, tz, (width, height), humanize


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _build_pkce_pair(raw_bytes: int = 64) -> tuple[str, str]:
    verifier = _b64url_no_pad(secrets.token_bytes(raw_bytes))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _test_proxy_public_ip(proxy_url: str, timeout: int = 15) -> str:
    # Use curl for the same simple public-IP check Camoufox geoip performs.
    # socks5h avoids local DNS edge cases; HTTP proxies are left as-is.
    test_proxy = proxy_url
    if test_proxy.startswith("socks5://"):
        test_proxy = "socks5h://" + test_proxy[len("socks5://"):]
    try:
        out = subprocess.check_output(
            ["curl", "-sS", "--max-time", str(timeout), "--proxy", test_proxy, "https://api.ipify.org"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 3,
        ).strip()
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", out):
            return out
    except Exception as e:
        logger.warning(f"[browser-reg] 代理自检失败: {proxy_url} ({type(e).__name__}: {str(e)[:160]})")
    return ""


def _pick_proxy_round_robin(pool_spec: str) -> tuple[str, str]:
    path_s = pool_spec.split(":", 1)[1].strip()
    path = Path(path_s)
    if not path.exists():
        raise RuntimeError(f"复用代理池不存在: {path}")
    lines = [x.strip() for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip() and not x.strip().startswith("#")]
    if not lines:
        raise RuntimeError(f"复用代理池已空: {path}")
    state_path = Path(os.getenv("REG_PROXY_RR_STATE", str(path) + ".state"))
    lock_path = Path(str(state_path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_f:
        try:
            import fcntl
            fcntl.flock(lock_f, fcntl.LOCK_EX)
        except Exception:
            pass
        try:
            raw_idx = state_path.read_text(encoding="utf-8", errors="replace").strip() if state_path.exists() else "0"
            idx = int(raw_idx or "0")
        except Exception:
            idx = 0
        start = idx % len(lines)
        bad_path = path.with_suffix(path.suffix + ".bad")
        for offset in range(len(lines)):
            pos = (start + offset) % len(lines)
            proxy = lines[pos]
            ip = _test_proxy_public_ip(proxy, timeout=int(os.getenv("REG_PROXY_TEST_TIMEOUT", "12")))
            next_idx = (pos + 1) % len(lines)
            state_path.write_text(str(next_idx), encoding="utf-8")
            if ip:
                logger.info(f"[browser-reg] 从复用代理池取出 1 条代理，出口 {ip}，位置 {pos + 1}/{len(lines)}，不消耗: {path}")
                return proxy, str(path)
            with bad_path.open("a", encoding="utf-8") as f:
                f.write(proxy + "\n")
            logger.warning(f"[browser-reg] 复用代理不可用，已记录 bad 但不从池删除: {proxy}")
        raise RuntimeError(f"复用代理池没有可用代理: {path}")


def _pop_proxy_from_pool(pool_spec: str) -> str:
    path_s = pool_spec[len("pool:"):].strip()
    path = Path(path_s)
    if not path.exists():
        raise RuntimeError(f"代理池不存在: {path}")
    lines = [x.strip() for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip() and not x.strip().startswith("#")]
    if not lines:
        raise RuntimeError(f"代理池已空: {path}")
    bak = path.with_suffix(path.suffix + f".bak.before-pop-{int(time.time())}")
    try:
        shutil.copy2(path, bak)
    except Exception:
        pass
    bad_path = path.with_suffix(path.suffix + ".bad")
    bad_count = 0
    while lines:
        proxy = lines.pop(0)
        ip = _test_proxy_public_ip(proxy, timeout=int(os.getenv("REG_PROXY_TEST_TIMEOUT", "12")))
        if ip:
            path.write_text(("\n".join(lines) + ("\n" if lines else "")), encoding="utf-8")
            # Registration proxies are one-shot: once a proxy is assigned to an
            # account attempt, never put it back into the pool. This avoids
            # reusing an IP/session that OpenAI may already have associated
            # with a failed/partial signup state.
            _commit_proxy_to_used(str(path), proxy)
            logger.info(f"[browser-reg] 从代理池取出 1 条代理，出口 {ip}，已消耗，剩余 {len(lines)}: {path}")
            return proxy
        bad_count += 1
        with bad_path.open("a", encoding="utf-8") as f:
            f.write(proxy + "\n")
        logger.warning(f"[browser-reg] 代理不可用，已移入 bad: {proxy}")
    path.write_text("", encoding="utf-8")
    raise RuntimeError(f"代理池没有可用代理，bad={bad_count}: {path}")


def _commit_proxy_to_used(pool_path: str, proxy_url: str) -> None:
    if not pool_path or not proxy_url:
        return
    try:
        used = Path(pool_path).with_suffix(Path(pool_path).suffix + ".used")
        existing = {x.strip() for x in used.read_text(encoding="utf-8", errors="replace").splitlines()} if used.exists() else set()
        if proxy_url not in existing:
            with used.open("a", encoding="utf-8") as f:
                f.write(proxy_url + "\n")
        logger.info(f"[browser-reg] 代理已提交到 used: {used}")
    except Exception as e:
        logger.warning(f"[browser-reg] 写入代理 used 失败: {e}")


def _mark_proxy_bad(pool_path: str, proxy_url: str, reason: str = "") -> None:
    if not pool_path or not proxy_url:
        return
    try:
        bad = Path(pool_path).with_suffix(Path(pool_path).suffix + ".bad")
        existing = {x.split("\t", 1)[0].strip() for x in bad.read_text(encoding="utf-8", errors="replace").splitlines()} if bad.exists() else set()
        if proxy_url not in existing:
            with bad.open("a", encoding="utf-8") as f:
                suffix = f"\t# {reason[:180]}" if reason else ""
                f.write(proxy_url + suffix + "\n")
        logger.warning(f"[browser-reg] 代理已标记 bad: {proxy_url} ({reason[:160]})")
    except Exception as e:
        logger.warning(f"[browser-reg] 写入代理 bad 失败: {e}")


def _is_proxy_failure(exc: Exception) -> bool:
    msg = f"{type(exc).__name__}: {exc}".lower()
    return any(x in msg for x in (
        "invalidip",
        "failed to get ip address",
        "proxy",
        "gost",
        "take a break",
        "try again soon",
        "your session has ended",
        "session has ended",
        "邮箱输入框未出现",
        "login_with 未渲染",
        "cf-mitigated",
        "cloudflare challenge",
        "auth 风控",
        "net::err_tunnel",
        "err_proxy",
        "remotedisconnected",
        "remote end closed connection",
        "connection without response",
        "connection reset",
        "connection aborted",
    ))


def _rollback_proxy_to_pool(pool_path: str, proxy_url: str) -> None:
    if not pool_path or not proxy_url:
        return
    try:
        path = Path(pool_path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
        if proxy_url not in [x.strip() for x in lines]:
            path.write_text(proxy_url + "\n" + ("\n".join(lines).rstrip() + ("\n" if lines else "")), encoding="utf-8")
            logger.info(f"[browser-reg] 注册失败，代理已回滚到池: {proxy_url}")
    except Exception as e:
        logger.warning(f"[browser-reg] 代理回滚失败: {e}")


def _resolve_proxy_api(proxy_url: str) -> str:
    """Resolve a dynamic proxy API URL to a concrete proxy URL.

    1024 white-list API may return JSON or plain text. Accept common shapes:
    - {"data": ["1.2.3.4:8080"]}
    - {"data": {"proxy": "1.2.3.4:8080"}}
    - ["1.2.3.4:8080"]
    - plain "1.2.3.4:8080"

    If no scheme is present, use http:// because whitelist APIs usually return
    IP-auth HTTP proxies.
    """
    if not proxy_url or not proxy_url.startswith(("http://", "https://")):
        return proxy_url
    if "1024proxy" not in proxy_url and "white" not in proxy_url and "proxy" not in proxy_url:
        return proxy_url
    try:
        import requests as _requests
        r = _requests.get(proxy_url, timeout=25, headers={"Accept": "application/json, text/plain, */*", "User-Agent": "OpenClaw-RegProxy/1.0"})
        text = (r.text or "").strip()
    except Exception as e:
        raise RuntimeError(f"动态代理 API 请求失败: {type(e).__name__}: {e}")
    if not r.ok:
        raise RuntimeError(f"动态代理 API HTTP {r.status_code}: {text[:300]}")
    if "not added to whitelist" in text.lower() or "whitelist" in text.lower() and "not" in text.lower():
        raise RuntimeError(f"动态代理 API 拒绝: {text[:300]}。请先把服务器 IP 加入 1024 白名单。")

    candidate = ""
    try:
        obj = r.json()
    except Exception:
        obj = None

    def pick(o):
        if isinstance(o, str):
            return o.strip()
        if isinstance(o, list):
            for x in o:
                v = pick(x)
                if v:
                    return v
        if isinstance(o, dict):
            port = o.get("port")
            for k in ("proxy", "host", "ip", "addr", "address", "server", "url"):
                v = o.get(k)
                if isinstance(v, str) and v.strip():
                    if k in ("host", "ip", "addr", "address", "server") and port and ":" not in v:
                        return f"{v.strip()}:{port}"
                    return v.strip()
            for k in ("data", "result", "list", "proxies"):
                v = pick(o.get(k))
                if v:
                    return v
        return ""

    candidate = pick(obj) if obj is not None else ""
    if not candidate:
        for line in text.splitlines():
            line = line.strip().strip('"').strip("'")
            if re.search(r"[A-Za-z0-9_.-]+:\d{2,5}", line):
                candidate = line
                break
    if not candidate:
        raise RuntimeError(f"动态代理 API 未返回可解析代理: {text[:500]}")
    # Remove JSON-ish punctuation around simple values.
    candidate = candidate.strip().strip(',;')
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "http://" + candidate
    logger.info(f"[browser-reg] 动态代理 API 返回: {candidate}")
    return candidate


def _camoufox_public_ip_check(proxy_url: str) -> str:
    """Run the same public_ip check Camoufox geoip=True will run.

    Curl succeeding is not enough for Camoufox because Camoufox uses requests /
    urllib3 and several public IP URLs. This catches RemoteDisconnected and
    similar proxy issues before launching the browser.
    """
    try:
        from camoufox.ip import public_ip as _cf_public_ip
        return str(_cf_public_ip(proxy_url) or "").strip()
    except Exception as e:
        raise RuntimeError(f"Camoufox geoip 预检失败: {type(e).__name__}: {e}") from e


def _parse_proxy(proxy_url: str):
    """Return a Camoufox proxy config.

    Camoufox/geoip uses urllib3 internally; authenticated proxies can fail or
    behave inconsistently there. Route authenticated proxies through a local
    no-auth SOCKS5 gost relay so both browser traffic and geoip use the same
    intended upstream.

    Important: when the upstream proxy changes, an old gost process on the
    fixed relay port must not be reused. We verify the process command line and
    restart the relay if it points at another upstream.
    """
    if not proxy_url:
        return None
    proxy_url = proxy_url.strip()
    pool_path_for_return = ""
    reusable_pool = False
    if proxy_url.startswith("rrpool:"):
        proxy_url, pool_path_for_return = _pick_proxy_round_robin(proxy_url)
        reusable_pool = True
    elif proxy_url.startswith("pool:"):
        pool_path_for_return = proxy_url[len("pool:"):].strip()
        proxy_url = _pop_proxy_from_pool(proxy_url)
    pp = urlparse(proxy_url)
    # Authenticated proxy URLs from static/reusable pools are already concrete
    # upstreams. Do not feed them into the dynamic 1024/white-list API resolver;
    # that would send a normal HTTP request through the proxy host and get
    # "407 Proxy Authentication needed".
    if pp.username:
        resolved_proxy_url = proxy_url
    else:
        resolved_proxy_url = _resolve_proxy_api(proxy_url)
        pp = urlparse(resolved_proxy_url)
    proxy_url = resolved_proxy_url
    if pp.username:
        import socket as _sock
        if pool_path_for_return:
            # Each registration process gets its own local relay port. This
            # avoids workers fighting over 18899 and prevents Camoufox geoip
            # from seeing a relay that was just switched by another worker.
            relay_port = int(os.environ.get("REG_GOST_PORT", str(18000 + (os.getpid() % 10000))))
        else:
            relay_port = int(os.environ.get("REG_GOST_PORT", "18899"))
        relay = f"socks5://127.0.0.1:{relay_port}"

        def _relay_running_for_upstream() -> bool:
            try:
                out = subprocess.check_output(
                    ["bash", "-lc", f"ps -eo pid=,args= | grep 'gost .*127.0.0.1:{relay_port}' | grep -v grep || true"],
                    text=True,
                    timeout=3,
                )
            except Exception:
                out = ""
            if not out.strip():
                return False
            if proxy_url in out:
                try:
                    with _sock.create_connection(("127.0.0.1", relay_port), timeout=2):
                        return True
                except Exception:
                    return False
            # geoip=True and browser traffic both use this relay. If upstream
            # changed, the current browser context must use a fresh gost relay;
            # otherwise Camoufox geoip can still detect the previous proxy.
            logger.warning(f"[browser-reg] 发现旧 gost 中继不是当前代理，重启 {relay}")
            try:
                pids = [line.split(None, 1)[0] for line in out.splitlines() if line.strip()]
                for pid in pids:
                    subprocess.run(["kill", pid], timeout=3)
                time.sleep(0.8)
                for pid in pids:
                    subprocess.run(["kill", "-9", pid], timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            return False

        if _relay_running_for_upstream():
            result = {"server": relay}
            if pool_path_for_return:
                ip = _camoufox_public_ip_check(relay)
                logger.info(f"[browser-reg] Camoufox geoip 预检通过: {ip}")
                result["_pool_path"] = pool_path_for_return
                result["_upstream"] = proxy_url
                result["_reusable_pool"] = "1" if reusable_pool else ""
            return result

        cmd = [
            "gost",
            f"-L={relay}",
            f"-F={proxy_url}",
        ]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # gost can take >0.8s to bind under load; wait briefly before judging failure.
            deadline = time.time() + 5.0
            last_exc = None
            while True:
                try:
                    conn = _sock.create_connection(("127.0.0.1", relay_port), timeout=1)
                    conn.close()
                    break
                except Exception as e:
                    last_exc = e
                    if time.time() >= deadline:
                        raise last_exc
                    time.sleep(0.25)
            with _sock.create_connection(("127.0.0.1", relay_port), timeout=3):
                logger.info(f"[browser-reg] 已启动本地 gost 代理中继: {relay}")
                result = {"server": relay}
                if pool_path_for_return:
                    ip = _camoufox_public_ip_check(relay)
                    logger.info(f"[browser-reg] Camoufox geoip 预检通过: {ip}")
                    result["_pool_path"] = pool_path_for_return
                    result["_upstream"] = proxy_url
                    result["_reusable_pool"] = "1" if reusable_pool else ""
                return result
        except Exception as e:
            raise RuntimeError(
                f"需要 gost 中继但启动/连接失败: gost -L={relay} -F=<proxy> ({type(e).__name__}: {e})"
            )
    return {
        "server": f"{pp.scheme}://{pp.hostname}:{pp.port}",
        "username": pp.username or "",
        "password": pp.password or "",
    }



def _goto_with_retry(page, url: str, *, wait_until: str = "domcontentloaded", timeout: int = 60000, attempts: int = 3, label: str = "page"):
    last_exc = None
    for i in range(attempts):
        try:
            return page.goto(url, wait_until=wait_until, timeout=timeout)
        except Exception as e:
            last_exc = e
            msg = str(e)
            transient = any(x in msg for x in (
                "NS_ERROR_NET_INTERRUPT",
                "NS_ERROR_NET_RESET",
                "NS_ERROR_NET_TIMEOUT",
                "net::ERR_CONNECTION",
                "net::ERR_TUNNEL",
                "Timeout",
            ))
            if not transient or i >= attempts - 1:
                raise
            logger.warning(f"[browser-reg] {label} goto 瞬断/超时，重试 {i+1}/{attempts-1}: {type(e).__name__}: {msg[:120]}")
            time.sleep(2 + i * 3)
    raise last_exc


def _page_text(page) -> str:
    try:
        return page.inner_text("body", timeout=3000)
    except Exception:
        return ""


def _blocking_challenge_reason(page) -> str:
    title = ""
    try:
        title = page.title() or ""
    except Exception:
        pass
    url = getattr(page, "url", "") or ""
    text = _page_text(page)
    haystack = "\n".join([title, url, text]).lower()

    if "just a moment" in haystack and ("cloudflare" in haystack or "verifying" in haystack):
        return "Cloudflare challenge"
    if "cf-turnstile" in haystack or "turnstile" in haystack:
        return "Turnstile challenge"
    if "verify you are human" in haystack or "verifying you are human" in haystack:
        return "human verification challenge"
    return ""


def _raise_if_blocking_challenge(page, *, stage: str, screenshot_path) -> None:
    reason = _blocking_challenge_reason(page)
    if not reason:
        return
    try:
        page.screenshot(path=str(screenshot_path))
    except Exception:
        pass
    raise RuntimeError(
        f"{reason} detected during {stage}; saved diagnostic screenshot to {screenshot_path}. "
        "This is a target-site verification page, not a missing form selector. "
        "Retry later, change network conditions, or complete verification manually if supported."
    )


def browser_register(cfg, mail_provider) -> dict:
    """
    用真实浏览器走注册流程。
    cfg: Config 实例（需要 proxy 字段）
    mail_provider: MailProvider 实例（调 create_mailbox + wait_for_otp）
    返回 dict：与 AuthResult.to_dict() 格式兼容
    """
    from camoufox.sync_api import Camoufox
    from browserforge.fingerprints import Screen

    email = mail_provider.create_mailbox()
    # ChatGPT/OpenAI password: use a fresh random >=12-char password.
    # Do not derive the account password from the mailbox address or mailbox password.
    password = _gen_openai_password(int(os.environ.get("REG_PASSWORD_LENGTH", "14") or "14"))
    persona = getattr(mail_provider, "last_persona", None)
    if persona is not None:
        first_name = persona.first
        last_name = persona.last
        logger.info("[browser-reg] 使用 mail_provider 同源 persona 姓名 + 随机 OpenAI 密码")
    else:
        first_name, last_name = _gen_name()
    bmonth, bday, byear = _gen_birthday()
    logger.info(f"[browser-reg] 创建账号: {email}")
    logger.info(f"[browser-reg] 密码: {password}  姓名: {first_name} {last_name}")

    cf_proxy = _parse_proxy(cfg.proxy)
    proxy_pool_path = ""
    proxy_upstream = ""
    proxy_reusable_pool = False
    if isinstance(cf_proxy, dict):
        proxy_pool_path = str(cf_proxy.pop("_pool_path", "") or "")
        proxy_upstream = str(cf_proxy.pop("_upstream", "") or "")
        proxy_reusable_pool = bool(cf_proxy.pop("_reusable_pool", False))
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    _reg_locale, _reg_tz, (_reg_w, _reg_h), _reg_humanize = _register_fingerprint_profile()
    _force_headless = os.environ.get("REG_CAMOUFOX_HEADLESS", "").strip().lower()
    if _force_headless in ("1", "true", "yes", "on"):
        _headless = True
    elif _force_headless in ("0", "false", "no", "off"):
        _headless = False
    else:
        _headless = not has_display

    tmp_profile = tempfile.mkdtemp(prefix="chatgpt_reg_")
    logger.info(f"[browser-reg] 临时 profile: {tmp_profile}")
    logger.info(f"[browser-reg] Camoufox fp locale={_reg_locale} tz={_reg_tz} screen={_reg_w}x{_reg_h} headless={_headless} humanize={_reg_humanize}")

    result = {
        "email": email,
        "password": password,
        "session_token": "",
        "access_token": "",
        "device_id": "",
        "csrf_token": "",
        "id_token": "",
        "refresh_token": "",
        "cookie_header": "",
    }

    try:
        with Camoufox(
            headless=_headless,
            humanize=_reg_humanize,
            persistent_context=True,
            user_data_dir=tmp_profile,
            os="windows",
            screen=Screen(max_width=_reg_w, max_height=_reg_h),
            proxy=cf_proxy,
            geoip=True,
            locale=_reg_locale,
        ) as ctx:
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            # [1] 打开 ChatGPT 首页，点 "Sign up for free"
            logger.info("[browser-reg] 打开 ChatGPT 首页 ...")
            _goto_with_retry(page, "https://chatgpt.com/", wait_until="domcontentloaded", timeout=60000, attempts=3, label="ChatGPT home")
            _raise_if_blocking_challenge(
                page,
                stage="opening ChatGPT home",
                screenshot_path="/tmp/browser_reg_cloudflare_challenge.png",
            )
            # 等 React 渲染完成 + Sign up 按钮可交互
            try:
                page.wait_for_selector('button[data-testid="signup-button"], a[data-testid="signup-button"]',
                                       state='visible', timeout=20000)
            except Exception:
                _raise_if_blocking_challenge(
                    page,
                    stage="waiting for signup button",
                    screenshot_path="/tmp/browser_reg_cloudflare_challenge.png",
                )
                pass
            time.sleep(3)

            # 点击 Sign up 按钮 — 找右上角的 "Sign up for free"
            clicked_signup = False
            for sel in ['a[data-testid="signup-button"]',
                        'button[data-testid="signup-button"]',
                        'button:has-text("Sign up for free")',
                        'a:has-text("Sign up for free")',
                        'button:has-text("Sign up")',
                        'a:has-text("Sign up")']:
                try:
                    btns = page.query_selector_all(sel)
                except Exception:
                    continue
                for btn in btns:
                    try:
                        if not btn.is_visible():
                            continue
                        text = btn.inner_text().lower()
                        if "sign up" not in text:
                            continue
                        # 用 5s 超时的 click，防止卡 30s
                        try:
                            btn.click(timeout=5000)
                        except Exception:
                            # click 卡住就用 JS 触发
                            btn.evaluate("el => el.click()")
                        clicked_signup = True
                        logger.info(f"[browser-reg] 点击 Sign up ({sel}): {text[:40]}")
                        break
                    except Exception as e_click:
                        if "attached to the DOM" in str(e_click) or "detached" in str(e_click).lower():
                            continue
                        logger.warning(f"[browser-reg] click 异常: {e_click}")
                if clicked_signup:
                    break
            if not clicked_signup:
                page.screenshot(path="/tmp/browser_reg_no_signup.png")
                raise RuntimeError(f"未找到 Sign up 按钮, URL={page.url[:120]}")

            # 等待跳转到 auth.openai.com 或 modal 加载（含重试点击）
            pre_url = page.url
            for i in range(20):
                time.sleep(1)
                if "auth.openai.com" in page.url or page.query_selector('input[type="email"]'):
                    break
                # 如果 5s 后还没变化，重试点击 Sign up
                if i == 5 and page.url == pre_url:
                    logger.info("[browser-reg] Sign up 点击未生效，重试")
                    try:
                        btn = page.query_selector('button[data-testid="signup-button"], a[data-testid="signup-button"]')
                        if btn:
                            btn.click(timeout=3000)
                    except Exception:
                        try:
                            btn.evaluate("el => el.click()")
                        except Exception:
                            pass
            # 如果 Sign up 被首页 SPA 吃掉/未弹出 modal，就不要继续傻等邮箱框。
            # 近期 chatgpt.com 首页有时会直接落到 New chat / Ask anything 页面，
            # OCR 表现像已进入聊天主页，但没有 auth 邮箱输入；此时直接走 auth signup 入口更稳。
            if not ("auth.openai.com" in page.url or page.query_selector('input[type="email"], input[name="email"]')):
                body_now = (_page_text(page) or "").lower()
                if "ask anything" in body_now or "new chat" in body_now or "where should we begin" in body_now:
                    logger.warning("[browser-reg] Sign up 后仍停在 ChatGPT 首页/聊天页，改用 auth signup 直达入口")
                else:
                    logger.warning(f"[browser-reg] Sign up 后未出现邮箱框/跳转，当前 URL={page.url[:120]}，改用 auth signup 直达入口")
                for signup_url in [
                    "https://auth.openai.com/authorize?client_id=chatgpt-web&response_type=code&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fauth%2Fcallback&scope=openid%20email%20profile&screen_hint=signup",
                    "https://auth.openai.com/create-account",
                    "https://auth.openai.com/sign-up",
                ]:
                    try:
                        _goto_with_retry(page, signup_url, wait_until="domcontentloaded", timeout=45000, attempts=2, label="OpenAI signup direct")
                        time.sleep(3)
                        body_after = (_page_text(page) or "").lower()
                        if "your session has ended" in body_after:
                            logger.warning("[browser-reg] auth signup 直达遇到 session ended，尝试继续登录/注册入口")
                            for cont_sel in [
                                'button:has-text("Continue by logging in")',
                                'a:has-text("Continue by logging in")',
                                'button:has-text("Log in")',
                                'a:has-text("Log in")',
                            ]:
                                try:
                                    b = page.query_selector(cont_sel)
                                    if b and b.is_visible():
                                        b.click(timeout=5000)
                                        logger.info(f"[browser-reg] session ended 后点击: {cont_sel}")
                                        time.sleep(3)
                                        break
                                except Exception:
                                    continue
                        # 只有真的出现邮箱框才算 signup 入口成功；auth.openai.com 的
                        # session-ended/错误壳不能算成功，否则后面会卡 wait_for_selector。
                        if page.query_selector('input[type="email"], input[name="email"]'):
                            logger.info(f"[browser-reg] auth signup 直达成功并出现邮箱框: {page.url[:120]}")
                            break
                    except Exception as e:
                        logger.warning(f"[browser-reg] auth signup 直达失败: {signup_url} {type(e).__name__}: {str(e)[:100]}")


            def _recover_from_login_with_blank(stage: str) -> bool:
                try:
                    if "chatgpt.com/auth/login_with" not in (page.url or ""):
                        return False
                    has_visible_email = False
                    try:
                        ei = page.query_selector('input[type="email"], input[name="email"]')
                        has_visible_email = bool(ei and ei.is_visible())
                    except Exception:
                        has_visible_email = False
                    if has_visible_email:
                        return False
                    body = (_page_text(page) or "").strip()
                    logger.warning(f"[browser-reg] {stage}: login_with 未渲染邮箱框(body_len={len(body)})，跳回 auth signup")
                    page.screenshot(path="/tmp/browser_reg_login_with_blank.png")
                    signup_url = "https://auth.openai.com/authorize?client_id=chatgpt-web&response_type=code&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fauth%2Fcallback&scope=openid%20email%20profile&screen_hint=signup"
                    _goto_with_retry(page, signup_url, wait_until="domcontentloaded", timeout=45000, attempts=2, label="recover login_with blank")
                    time.sleep(4)
                    return True
                except Exception as e:
                    logger.warning(f"[browser-reg] login_with 恢复失败: {type(e).__name__}: {str(e)[:160]}")
                    return False

            logger.info(f"[browser-reg] 当前 URL: {page.url[:120]}")
            page.screenshot(path="/tmp/browser_reg_before_email.png")
            _raise_if_blocking_challenge(
                page,
                stage="before email form",
                screenshot_path="/tmp/browser_reg_cloudflare_challenge.png",
            )
            _recover_from_login_with_blank("before email form")

            # [2a] 新版 OpenAI（2026-05 起）: 点 Sign up 后不跳 auth.openai.com，
            # 而是在 chatgpt.com 上弹「Log in or sign up」modal，里面是
            # Continue with Google / Apple / Phone + OR + Continue with email。
            # 旧脚本直接等 input[type=email] 会 30s 超时，所以先识别 modal、
            # 关掉 Google One-Tap、再点「Continue with email」。
            try:
                # Google One-Tap iframe（标题含 "Sign in with Google"）会盖在 modal 上面，
                # 先关掉以免拦截点击。
                for ot_sel in [
                    'iframe[src*="accounts.google.com/gsi"]',
                    'div#credential_picker_container button[aria-label*="Close"]',
                    '[aria-label="Close"][role="button"]',
                ]:
                    try:
                        f = page.query_selector(ot_sel)
                        if f and f.is_visible():
                            if "iframe" in ot_sel:
                                # iframe 自己点不到，直接 JS 删掉容器
                                page.evaluate(
                                    "() => document.querySelectorAll("
                                    "'iframe[src*=\"accounts.google.com/gsi\"]')"
                                    ".forEach(el => el.remove())"
                                )
                            else:
                                try:
                                    f.click(timeout=2000)
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                pass

            if not page.query_selector('input[type="email"], input[name="email"]'):
                # 如果当前没看到 email 输入框，找 modal 里的 email 入口按钮再点一次。
                # 顺序：先精确匹配 "Continue with email"，再宽松到包含 email 的按钮。
                modal_email_clicked = False
                for sel in [
                    'button:has-text("Continue with email")',
                    'button:has-text("Sign up with email")',
                    'a:has-text("Continue with email")',
                    'a:has-text("Sign up with email")',
                    'button:has-text("Email")',
                    'button[data-testid*="email"]',
                ]:
                    try:
                        btns = page.query_selector_all(sel)
                    except Exception:
                        continue
                    for b in btns:
                        try:
                            if not b.is_visible():
                                continue
                            label = (b.inner_text() or "").lower().strip()
                            # 排除 Google/Apple/Phone 这些社交按钮里碰巧含 "email" 的字样
                            if any(skip in label for skip in ("google", "apple", "phone")):
                                continue
                            try:
                                b.scroll_into_view_if_needed(timeout=2000)
                            except Exception:
                                pass
                            try:
                                b.click(timeout=5000)
                            except Exception:
                                b.evaluate("el => el.click()")
                            modal_email_clicked = True
                            logger.info(f"[browser-reg] 点击 modal email 入口 ({sel}): {label[:40]}")
                            break
                        except Exception:
                            continue
                    if modal_email_clicked:
                        break

            # [2] 填邮箱（click + fill 分步，React 重渲染可能让 handle 失效 → 每步重新 query）
            logger.info("[browser-reg] 填邮箱 ...")
            _recover_from_login_with_blank("email wait")
            try:
                page.wait_for_selector('input[type="email"], input[name="email"]', timeout=30000)
            except Exception as e:
                page.screenshot(path="/tmp/browser_reg_email_wait_fail.png")
                body = (_page_text(page) or "").strip()
                low_body = body.lower()
                if "take a break" in low_body or "try again soon" in low_body or "ran into an issue while signing you in" in low_body:
                    raise RuntimeError(
                        f"OpenAI auth 风控/限流: {body[:300]}；当前代理/会话需要更换或等待冷却，URL={page.url[:160]}"
                    ) from e
                try:
                    diag = page.evaluate("() => {\n                        const scripts = Array.from(document.scripts).slice(0, 20).map(s => s.src || '[inline]');\n                        const links = Array.from(document.querySelectorAll('link[href]')).slice(0, 20).map(l => l.href);\n                        return {\n                            href: location.href,\n                            title: document.title,\n                            readyState: document.readyState,\n                            bodyText: document.body ? document.body.innerText.slice(0, 2000) : '',\n                            bodyHtml: document.body ? document.body.innerHTML.slice(0, 4000) : '',\n                            scripts,\n                            links,\n                        };\n                    }")
                except Exception as de:
                    diag = {"diag_error": f"{type(de).__name__}: {de}"}
                try:
                    Path("/tmp/browser_reg_email_wait_fail_diag.json").write_text(json.dumps(diag, ensure_ascii=False, indent=2), encoding="utf-8")
                    Path("/tmp/browser_reg_email_wait_fail_body.txt").write_text(body, encoding="utf-8")
                except Exception:
                    pass
                raise RuntimeError(
                    f"邮箱输入框未出现，URL={page.url[:160]}，title={diag.get('title','') if isinstance(diag, dict) else ''}，"
                    f"readyState={diag.get('readyState','') if isinstance(diag, dict) else ''}，页面文本={body[:500]}，"
                    "诊断: /tmp/browser_reg_email_wait_fail_diag.json"
                ) from e
            for _try in range(4):
                try:
                    ei = page.query_selector('input[type="email"]') or \
                         page.query_selector('input[name="email"]')
                    if not ei: time.sleep(0.5); continue
                    try:
                        ei.click(timeout=5000)
                        time.sleep(0.3)
                    except Exception as e_click:
                        logger.warning(f"[browser-reg] email input 点击超时/失败，改用 JS fill: {str(e_click)[:160]}")
                    ei2 = page.query_selector('input[type="email"]') or \
                          page.query_selector('input[name="email"]')
                    target = ei2 or ei
                    try:
                        target.fill(email, timeout=10000)
                    except Exception:
                        page.evaluate("(el, v) => { el.value = v; el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); }", target, email)
                    break
                except Exception as e:
                    msg = str(e).lower()
                    if any(x in msg for x in ("not attached", "detached", "timeout")):
                        logger.info(f"[browser-reg] email input 脱链 重试 {_try+1}/4")
                        time.sleep(0.5)
                        continue
                    raise
            time.sleep(random.uniform(0.5, 1.2))
            # Continue
            for sel in ['button[type="submit"]', 'button:has-text("Continue")',
                        'button:has-text("Next")']:
                b = page.query_selector(sel)
                if b and b.is_visible():
                    b.click()
                    logger.info(f"[browser-reg] 点击 email 继续: {sel}")
                    break
            time.sleep(3)

            def _click_signup_from_login_password() -> bool:
                try:
                    body = (_page_text(page) or "").lower()
                    if not ("enter your password" in body and "don't have an account" in body and "sign up" in body):
                        return False
                    logger.warning("[browser-reg] 邮箱后进入登录密码页，切换到 Sign up 注册流程")
                    page.screenshot(path="/tmp/browser_reg_login_password_wrong_flow.png")
                    for sel in [
                        'a:has-text("Sign up")',
                        'button:has-text("Sign up")',
                        'text="Sign up"',
                    ]:
                        try:
                            b = page.query_selector(sel)
                            if b and b.is_visible():
                                b.click(timeout=5000)
                                logger.info(f"[browser-reg] 登录页点击 Sign up: {sel}")
                                time.sleep(3)
                                return True
                        except Exception:
                            continue
                except Exception:
                    return False
                return False

            if _click_signup_from_login_password():
                # Sign up 后通常回到 email/password/OTP 注册链路。若还是邮箱框，重填；
                # 若直接出现 OTP，则后续 OTP 分支会处理。
                try:
                    if page.query_selector('input[type="email"], input[name="email"]'):
                        ei = page.query_selector('input[type="email"]') or page.query_selector('input[name="email"]')
                        ei.click(timeout=3000)
                        ei.fill(email)
                        for sel in ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Next")']:
                            b = page.query_selector(sel)
                            if b and b.is_visible():
                                b.click(timeout=5000)
                                logger.info(f"[browser-reg] Sign up 后重新点击 email 继续: {sel}")
                                time.sleep(3)
                                break
                except Exception as e:
                    logger.warning(f"[browser-reg] Sign up 切换后重填邮箱异常: {e}")

            # [3] 填密码（新账号会看到密码框）
            logger.info("[browser-reg] 等待密码框 ...")
            try:
                page.wait_for_selector(
                    'input[type="password"], input[name="password"]',
                    state="visible", timeout=30000,
                )
                pwd_input = page.query_selector('input[type="password"]:visible') or \
                            page.query_selector('input[name="password"]:visible')
                pwd_input.click()
                time.sleep(0.3)
                pwd_input.fill(password)
                time.sleep(random.uniform(0.5, 1.2))
                for sel in ['button[type="submit"]', 'button:has-text("Continue")',
                            'button:has-text("Create")', 'button:has-text("Next")']:
                    b = page.query_selector(sel)
                    if b and b.is_visible():
                        b.click()
                        logger.info(f"[browser-reg] 点击 password 继续: {sel}")
                        break
            except Exception as e:
                logger.warning(f"[browser-reg] 密码框异常: {e}，可能走无密码 OTP 路径")

            time.sleep(3)
            logger.info(f"[browser-reg] 密码后 URL: {page.url[:120]}")

            # [4] Turnstile / hCaptcha 等待（Camoufox 指纹通常可自动通过）
            logger.info("[browser-reg] 等待反欺诈检查 ...")
            for wait_i in range(30):
                time.sleep(1)
                cur = page.url
                # 到达 OTP 输入或继续步骤 → 通过
                if page.query_selector('input[autocomplete="one-time-code"]') or \
                   page.query_selector('input[name="code"]') or \
                   page.query_selector('input[inputmode="numeric"]'):
                    logger.info(f"[browser-reg] 已到达 OTP 页面")
                    break
                if "chatgpt.com" in cur and "auth.openai.com" not in cur:
                    logger.info(f"[browser-reg] 已直接登录到 chatgpt.com")
                    break
                if wait_i == 15:
                    page.screenshot(path="/tmp/browser_reg_wait15.png")
                    logger.info(f"[browser-reg] 15s 等待中: {cur[:80]}")

            # [5] OTP 步骤
            if page.query_selector('input[autocomplete="one-time-code"]') or \
               page.query_selector('input[inputmode="numeric"]'):
                logger.info("[browser-reg] 等待 IMAP OTP ...")
                otp_sent_at = time.time()
                try:
                    otp_timeout = max(30, int(os.getenv("OTP_TIMEOUT", "180")))
                except Exception:
                    otp_timeout = 180
                otp_code = mail_provider.wait_for_otp(email, timeout=otp_timeout, issued_after=otp_sent_at)
                logger.info(f"[browser-reg] 收到 OTP: {otp_code}")
                # 填 OTP
                otp_filled = False
                # 可能是单框 / 多框两种
                single = page.query_selector('input[autocomplete="one-time-code"]') or \
                         page.query_selector('input[name="code"]') or \
                         page.query_selector('input[inputmode="numeric"]:not([maxlength="1"])')
                if single:
                    single.click()
                    time.sleep(0.3)
                    single.fill(otp_code)
                    otp_filled = True
                else:
                    digits = page.query_selector_all('input[maxlength="1"][inputmode="numeric"]') or \
                             page.query_selector_all('input[maxlength="1"]')
                    if len(digits) >= 6:
                        for i, ch in enumerate(otp_code[:6]):
                            digits[i].click()
                            time.sleep(0.1)
                            digits[i].fill(ch)
                        otp_filled = True
                if not otp_filled:
                    page.screenshot(path="/tmp/browser_reg_otp_fail.png")
                    raise RuntimeError("OTP 输入框未找到")
                time.sleep(0.8)
                # Continue
                for sel in ['button[type="submit"]', 'button:has-text("Continue")',
                            'button:has-text("Verify")', 'button:has-text("Next")']:
                    b = page.query_selector(sel)
                    if b and b.is_visible():
                        b.click()
                        logger.info(f"[browser-reg] 点击 OTP 继续: {sel}")
                        break
                time.sleep(4)

                # OpenAI 在 OTP 错误时会显示 "Incorrect code" 红字，反复点
                # Continue 会触发 max_check_attempts 风控（永久卡死）。早退。
                try:
                    err = page.query_selector(
                        'text=/incorrect code|invalid code|wrong code|验证码不正确|验证码错误/i'
                    )
                    if err and err.is_visible():
                        page.screenshot(path="/tmp/browser_reg_otp_rejected.png")
                        raise RuntimeError(
                            f"OpenAI 拒绝 OTP {otp_code}（OTP 抽取错误，可能是 hex 颜色/tracking id 假阳性）"
                        )
                except RuntimeError:
                    raise
                except Exception:
                    pass

            # [6] /about-you：Full name + Age（单框）
            logger.info(f"[browser-reg] OTP 后 URL: {page.url[:120]}")
            time.sleep(5)  # 等重定向到 /about-you
            logger.info(f"[browser-reg] 稳定后 URL: {page.url[:120]}")

            # 等 /about-you 表单加载完成。先等 URL 稳定
            for _ in range(20):
                time.sleep(1)
                if "about-you" in page.url or "chatgpt.com" in page.url:
                    break

            # OpenAI about-you 变种：
            #   老版：Full name + Age（数字框）
            #   新版（2026-04 起）：Full name + Birthday（日期框，预填今日）
            # 用 JS 一次性把所有 input 的元数据导出，避免 visibility 检测不一致
            def _enum_inputs():
                try:
                    return page.evaluate('''() => {
                        return Array.from(document.querySelectorAll('input')).map((el, idx) => {
                            const r = el.getBoundingClientRect();
                            const cs = getComputedStyle(el);
                            return {
                                idx,
                                type: (el.type || '').toLowerCase(),
                                name: el.name || '',
                                placeholder: el.placeholder || '',
                                ariaLabel: el.getAttribute('aria-label') || '',
                                label: (el.labels && el.labels[0] && el.labels[0].innerText) || '',
                                value: el.value || '',
                                visible: (r.width > 0 && r.height > 0 &&
                                          cs.visibility !== 'hidden' && cs.display !== 'none'),
                            };
                        });
                    }''') or []
                except Exception:
                    return []

            def _is_birthday(meta: dict) -> bool:
                blob = " ".join([meta.get("type",""), meta.get("name",""),
                                  meta.get("placeholder",""), meta.get("ariaLabel",""),
                                  meta.get("label","")]).lower()
                if meta.get("type") == "date":
                    return True
                return any(kw in blob for kw in ("birth", "birthday", "dob",
                                                  "mm/dd/yyyy", "mm / dd / yyyy"))

            def _is_age_input(meta: dict) -> bool:
                blob = " ".join([meta.get("type",""), meta.get("name",""),
                                  meta.get("placeholder",""), meta.get("ariaLabel",""),
                                  meta.get("label","")]).lower()
                # 只有明确出现 age 才按年龄填；number 类型不等价于 age，
                # 新版 about-you 可能把 birthday 拆成日期/数字组件。
                return "age" in blob

            def _is_name_input(meta: dict) -> bool:
                blob = " ".join([meta.get("name",""), meta.get("placeholder",""),
                                  meta.get("ariaLabel",""), meta.get("label","")]).lower()
                # 不把 age 当 name，避免 legacy 兼容分支误判。
                return any(kw in blob for kw in ("name", "first", "last", "full",
                                                  "given", "family"))

            def _looks_like_chat_ui() -> bool:
                """chatgpt.com 主页的特征：右下角 chat 输入框 + sidebar 上的「New chat」。
                这种页面不是 about-you 表单，看到 2 个 input 也不能瞎填。"""
                try:
                    return bool(page.evaluate('''() => {
                        const url = location.href;
                        if (url.includes("/about-you")) return false;
                        // chat 输入框：textarea 或 contenteditable，placeholder 含 "Ask"
                        const ta = document.querySelector(
                            'textarea[placeholder*="Ask"], div[contenteditable="true"]'
                        );
                        // 左侧 New chat 链接
                        const nc = Array.from(document.querySelectorAll("a, button"))
                            .some(el => /new chat/i.test(el.textContent || ""));
                        return !!(ta || nc);
                    }'''))
                except Exception:
                    return False

            full_name_input = None
            birthday_input = None
            birthday_meta = None
            for attempt in range(30):
                metas = _enum_inputs()
                visible_metas = [m for m in metas if m["visible"]
                                  and m["type"] not in ("hidden","submit","button",
                                                         "checkbox","radio","password")]
                # 先挑 Birthday + 关键字命中的 name input — 双方关键字都要命中才认。
                bd = next((m for m in visible_metas if _is_birthday(m)), None)
                name_m = next((m for m in visible_metas
                                if m is not bd
                                and _is_name_input(m)
                                and not _is_birthday(m)), None)
                if bd and name_m:
                    all_inputs_el = page.query_selector_all('input')
                    full_name_input = all_inputs_el[name_m["idx"]]
                    birthday_input = all_inputs_el[bd["idx"]]
                    birthday_meta = bd
                    logger.info(f"[browser-reg] 表单: name.idx={name_m['idx']} "
                                f"birthday.idx={bd['idx']} type={bd['type']} "
                                f"placeholder={bd['placeholder'][:30]!r}")
                    break
                # 兼容 2-input about-you：通常是 Full name + Birthday/age。
                # 只有第二框明确是 Age 才填年龄；否则优先按生日填，避免新版
                # about-you 把生日控件识别成普通 input 后误填 30 导致 Finish 不跳转。
                if (
                    not bd
                    and len(visible_metas) >= 2
                    and any(_is_name_input(m) for m in visible_metas)
                    and not _looks_like_chat_ui()
                ):
                    all_inputs_el = page.query_selector_all('input')
                    name_meta = next((m for m in visible_metas if _is_name_input(m)), visible_metas[0])
                    other_meta = next((m for m in visible_metas if m is not name_meta), visible_metas[1])
                    full_name_input = all_inputs_el[name_meta["idx"]]
                    birthday_input = all_inputs_el[other_meta["idx"]]
                    birthday_meta = other_meta
                    logger.info(
                        f"[browser-reg] 表单 (2-input fallback): name.idx={name_meta['idx']} "
                        f"other.idx={other_meta['idx']} type={other_meta['type']} "
                        f"age={_is_age_input(other_meta)} placeholder={other_meta['placeholder'][:30]!r}"
                    )
                    break
                # 纯 Age 页面：只有一个 age 输入框，没有 full name。
                if (
                    not bd
                    and len(visible_metas) == 1
                    and _is_age_input(visible_metas[0])
                    and not _looks_like_chat_ui()
                ):
                    all_inputs_el = page.query_selector_all('input')
                    full_name_input = None
                    birthday_input = all_inputs_el[visible_metas[0]["idx"]]
                    birthday_meta = visible_metas[0]
                    logger.info(
                        f"[browser-reg] 表单 (age only): idx={visible_metas[0]['idx']} "
                        f"type={visible_metas[0]['type']} placeholder={visible_metas[0]['placeholder'][:30]!r}"
                    )
                    break
                # 已经在 chatgpt.com 主页（非 about-you 子路径），且看不到 about-you 表单
                # —— 注册可能已直接完成，跳出循环让外层去判断 accessToken。
                if (
                    "chatgpt.com" in page.url
                    and "auth" not in page.url
                    and "/about-you" not in page.url
                    and _looks_like_chat_ui()
                ):
                    logger.info("[browser-reg] URL 在 chatgpt.com 主页，无 about-you 表单 → 跳过表单填写")
                    break
                if attempt == 5:
                    page.screenshot(path="/tmp/browser_reg_about_you_wait.png")
                    logger.info(f"[browser-reg] 等待 about-you 输入框 5s, URL={page.url[:100]} "
                                f"inputs visible={len(visible_metas)}")
                time.sleep(1)

            if birthday_input:
                page.screenshot(path="/tmp/browser_reg_about_you.png")
                full_name = f"{first_name} {last_name}"
                # Birthday：26-40 岁之间的 1 月 15 日（足够>18，固定日期便于一致指纹）
                import datetime as _dt
                year = _dt.datetime.now().year - random.randint(26, 40)
                mm, dd = "01", "15"
                # native date input 用 YYYY-MM-DD，文本框大多是 MM/DD/YYYY
                bd_type = (birthday_meta or {}).get("type", "")
                if bd_type == "date":
                    birthday_str = f"{year}-{mm}-{dd}"
                else:
                    birthday_str = f"{mm}/{dd}/{year}"
                legacy_age = str(random.randint(26, 40))
                logger.info(f"[browser-reg] 填 Full name={full_name}  "
                            f"Birthday={birthday_str} (legacy_age={legacy_age})")
                try:
                    if full_name_input:
                        full_name_input.focus(); time.sleep(0.3)
                        page.keyboard.type(full_name, delay=random.randint(30, 80))
                        time.sleep(random.uniform(0.4, 0.9))
                    birthday_input.focus(); time.sleep(0.3)
                    # 先清空（预填可能有今日日期）
                    try:
                        page.keyboard.press("Control+A")
                        page.keyboard.press("Delete")
                    except Exception:
                        pass
                    # 对 native date input 用 fill 直接写 ISO；文本框用 keyboard.type
                    if bd_type == "date":
                        try:
                            birthday_input.fill(birthday_str)
                        except Exception:
                            page.keyboard.type(birthday_str, delay=random.randint(30, 70))
                    else:
                        # MM/DD/YYYY：只有明确是 age 字段才填年龄；否则按生日填。
                        if _is_age_input(birthday_meta or {}):
                            page.keyboard.type(legacy_age, delay=random.randint(40, 100))
                        else:
                            page.keyboard.type(birthday_str, delay=random.randint(30, 70))
                    time.sleep(random.uniform(0.4, 0.9))
                    clicked = False
                    for sel in ['button:has-text("Finish")', 'button:has-text("Create")',
                                'button:has-text("Agree")', 'button[type="submit"]',
                                'button:has-text("Continue")']:
                        b = page.query_selector(sel)
                        if b and b.is_visible():
                            b.click()
                            clicked = True
                            logger.info(f"[browser-reg] 点击 about-you 继续: {sel}")
                            break
                    if not clicked:
                        page.screenshot(path="/tmp/browser_reg_no_finish_btn.png")
                except Exception as e:
                    logger.warning(f"[browser-reg] about-you 填写异常: {e}")
                    page.screenshot(path="/tmp/browser_reg_name_fail.png")
            else:
                page.screenshot(path="/tmp/browser_reg_no_name_form.png")
                logger.warning(f"[browser-reg] 未找到 about-you 表单，URL={page.url[:120]}")

            # [7] 等待回到 chatgpt.com (可能有中间页如 email-verification / success-page)
            logger.info("[browser-reg] 等待跳转回 chatgpt.com ...")

            def _retry_about_you_network_error() -> bool:
                """OpenAI about-you 提交后偶发前端 fetch 网络错误。

                页面会停在 auth.openai.com/about-you，正文类似：
                "Oops, an error occurred / NetworkError when attempting to fetch / Try again"。
                这通常是代理链路瞬断，不是表单选择器问题；自动点 Try again/Finish 重试。
                """
                try:
                    body = (_page_text(page) or "").lower()
                    if not (
                        "networkerror when attempting to fetch" in body
                        or ("oops" in body and "try again" in body)
                    ):
                        return False
                    page.screenshot(path="/tmp/browser_reg_about_you_network_error.png")
                    logger.warning("[browser-reg] about-you 提交遇到 NetworkError，尝试自动重试")
                    for sel in [
                        'button:has-text("Try again")',
                        'button:has-text("Retry")',
                        'button:has-text("Finish creating account")',
                        'button:has-text("Finish")',
                        'button[type="submit"]',
                    ]:
                        try:
                            b = page.query_selector(sel)
                            if b and b.is_visible():
                                try:
                                    b.click(timeout=5000)
                                except Exception:
                                    b.evaluate("el => el.click()")
                                logger.info(f"[browser-reg] NetworkError 后重试点击: {sel}")
                                return True
                        except Exception:
                            continue
                except Exception:
                    return False
                return False

            arrived = False
            cached_session_info = {}
            last_url = ""
            network_retry_count = 0
            for i in range(120):
                time.sleep(1)
                cur = page.url
                if cur != last_url:
                    logger.info(f"[browser-reg] URL@{i}s: {cur[:120]}")
                    last_url = cur
                if "auth.openai.com" in cur and "about-you" in cur and i % 5 == 2 and network_retry_count < 5:
                    if _retry_about_you_network_error():
                        network_retry_count += 1
                        time.sleep(3)
                        continue
                # 到 chatgpt.com 且已加载 React 主界面
                if "chatgpt.com" in cur and "auth.openai.com" not in cur:
                    # 等 /api/auth/session 能正常返回 accessToken 才算完成
                    try:
                        info = page.evaluate('''async () => {
                            try {
                                const r = await fetch("/api/auth/session", {credentials: "include"});
                                const txt = await r.text();
                                let d;
                                try { d = JSON.parse(txt); } catch(e) { return {len: -2, text: txt.slice(0, 200)}; }
                                return {len: d.accessToken ? d.accessToken.length : 0, session: d};
                            } catch(e){ return {len: -1, error: String(e)}; }
                        }''')
                        token_len = info.get("len", 0) if isinstance(info, dict) else int(info or 0)
                        if token_len and token_len > 100:
                            cached_session_info = info.get("session") or {}
                            arrived = True
                            logger.info(f"[browser-reg] 到达 + session accessToken 长度={token_len}")
                            break
                    except Exception:
                        pass
                # 如果仍在 auth.openai.com，可能还有 /email-verification 或其他中转，继续点 continue
                if "auth.openai.com" in cur and i % 10 == 5:
                    for sel in ['button:has-text("Continue")', 'button:has-text("Next")',
                                'button[type="submit"]']:
                        try:
                            b = page.query_selector(sel)
                            if b and b.is_visible():
                                b.click()
                                logger.info(f"[browser-reg] 中转点击: {sel}")
                                break
                        except Exception:
                            # 页面导航时 context destroyed，忽略
                            pass
            if not arrived:
                page.screenshot(path="/tmp/browser_reg_no_chatgpt.png")
                raise RuntimeError(f"未跳转回 chatgpt.com，当前: {page.url[:120]}")

            # [8] 等 JS 初始化完成，取 access_token
            time.sleep(5)
            logger.info("[browser-reg] 拉取 /api/auth/session ...")
            try:
                session_info = page.evaluate('''async () => {
                    const r = await fetch("/api/auth/session", {credentials: "include"});
                    const txt = await r.text();
                    try { return JSON.parse(txt); }
                    catch(e) { return {__parse_error: String(e), __text: txt.slice(0, 500)}; }
                }''')
            except Exception as e:
                logger.warning(f"[browser-reg] 二次拉取 /api/auth/session 异常，尝试使用已缓存 session: {type(e).__name__}: {str(e)[:160]}")
                session_info = cached_session_info or {}
            if isinstance(session_info, dict) and session_info.get("__parse_error"):
                logger.warning(f"[browser-reg] 二次 /api/auth/session 返回非 JSON，尝试使用已缓存 session: {session_info.get('__text','')[:160]}")
                session_info = cached_session_info or {}
            result["access_token"] = session_info.get("accessToken", "") if isinstance(session_info, dict) else ""
            result["id_token"] = session_info.get("idToken", "") if isinstance(session_info, dict) else ""
            logger.info(f"[browser-reg] access_token 长度: {len(result['access_token'])}")

            # [9] 提取 cookies
            all_cookies = ctx.cookies()
            chatgpt_cookies = [c for c in all_cookies if "chatgpt.com" in c.get("domain", "")]
            for c in chatgpt_cookies:
                n = c["name"]
                if n == "__Secure-next-auth.session-token":
                    result["session_token"] = c["value"]
                if n in ("oai-did", "oai-device-id"):
                    result["device_id"] = c["value"]
                if n == "__Host-next-auth.csrf-token":
                    result["csrf_token"] = c["value"].split("|")[0] if "|" in c["value"] else c["value"]
            result["cookie_header"] = "; ".join(
                f"{c['name']}={c['value']}" for c in chatgpt_cookies
            )
            logger.info(
                f"[browser-reg] session_token={'yes' if result['session_token'] else 'no'} "
                f"device_id={result['device_id'][:16]}..."
            )

            # [10] Codex OAuth 获取 refresh_token
            # 已知限制: signup 完成后 auth.openai.com 的 hydra session 无法给 Codex 换 token
            # (login_session 只是 signup 挑战态，不是完整用户会话)
            # 当前 refresh_token 会为空；如需 refresh_token，需要登录账号重走 Codex OAuth
            #
            # 经实证（2026-04 近期 daemon + self-dealer 全量日志），signup-state Codex OAuth
            # 100% 返回 token_exchange_user_error，每次浪费 ~30s。默认跳过；如需保留旧路径
            # 作为逆向参考，设 SKIP_SIGNUP_CODEX_RT=0。后续 _exchange_refresh_token_with_session
            # (card.py) 或 self-dealer 的 member 重登会正常拿 RT。
            if str(os.environ.get("SKIP_SIGNUP_CODEX_RT", "1")).lower() in ("1", "true", "yes", "on"):
                logger.info("[browser-reg] 跳过 signup 态 Codex OAuth（SKIP_SIGNUP_CODEX_RT=1，已知 100% 失败）")
                result["refresh_token"] = result.get("refresh_token", "") or ""
            else:
                try:
                    codex_client_id = (os.getenv("OAUTH_CODEX_CLIENT_ID", "") or "").strip() or "app_EMoamEEZ73f0CkXaXp7hrann"
                    codex_redirect = "http://localhost:1455/auth/callback"
                    codex_scope = "openid email profile offline_access"
                    codex_state = _b64url_no_pad(secrets.token_bytes(24))
                    verifier, challenge = _build_pkce_pair()
                    auth_params = {
                        "client_id": codex_client_id,
                        "response_type": "code",
                        "redirect_uri": codex_redirect,
                        "scope": codex_scope,
                        "state": codex_state,
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "id_token_add_organizations": "true",
                        "codex_cli_simplified_flow": "true",
                        # 不加 prompt=none: session 已经通过浏览器注册建立，
                        # 让服务器自动识别 session，有 consent 页面时自动 auto-approve
                    }
                    auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(auth_params)}"
                    logger.info("[browser-reg] Codex OAuth 获取 refresh_token ...")
                    # 真浏览器 goto + route 拦截 localhost
                    cb_url = ""
                    callback_holder = {"url": ""}

                    def _codex_intercept(route):
                        url = route.request.url
                        if "localhost:1455" in url and "code=" in url:
                            callback_holder["url"] = url
                            logger.info(f"[browser-reg] 拦截到 Codex callback: {url[:150]}")
                        try:
                            route.fulfill(status=200, content_type="text/html", body="<html>OK</html>")
                        except Exception:
                            try: route.abort()
                            except: pass

                    page.route("**/localhost:1455/**", _codex_intercept)
                    page.route("http://localhost:1455/**", _codex_intercept)
                    page.route("**localhost:1455**", _codex_intercept)

                    try:
                        page.goto(auth_url, wait_until="commit", timeout=30000)
                    except Exception as e_nav:
                        logger.info(f"[browser-reg] Codex goto: {str(e_nav)[:120]}")

                    for _ in range(30):
                        if callback_holder["url"]:
                            break
                        if "localhost:1455" in page.url and "code=" in page.url:
                            callback_holder["url"] = page.url
                            break
                        time.sleep(0.5)

                    try:
                        page.unroute("**/localhost:1455/**")
                        page.unroute("http://localhost:1455/**")
                        page.unroute("**localhost:1455**")
                    except Exception:
                        pass

                    cb_url = callback_holder["url"]
                    logger.info(f"[browser-reg] Codex callback URL: {cb_url[:150] if cb_url else '<空>'}")
                    if not cb_url:
                        logger.info(f"[browser-reg] 当前 page.url: {page.url[:200]}")
                    if cb_url:
                        qs = parse_qs(urlparse(cb_url).query)
                        code = (qs.get("code") or [""])[0]
                        if code:
                            logger.info(f"[browser-reg] 获得 auth code, 换 refresh_token ...")
                            import curl_cffi.requests as cr
                            http_token = cr.Session(impersonate="chrome136")
                            if cf_proxy and cf_proxy.get("server"):
                                pu = cf_proxy["server"]
                                http_token.proxies = {"http": pu, "https": pu}
                            resp_token = http_token.post(
                                "https://auth.openai.com/oauth/token",
                                data={
                                    "grant_type": "authorization_code",
                                    "client_id": codex_client_id,
                                    "code": code,
                                    "redirect_uri": codex_redirect,
                                    "code_verifier": verifier,
                                },
                                headers={
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    "Accept": "application/json",
                                },
                                timeout=30,
                            )
                            logger.info(f"[browser-reg] /oauth/token: {resp_token.status_code}")
                            if resp_token.status_code == 200:
                                try:
                                    tj = resp_token.json()
                                    result["refresh_token"] = tj.get("refresh_token", "") or ""
                                    if tj.get("access_token"):
                                        result["codex_access_token"] = tj["access_token"]
                                    logger.info(f"[browser-reg] refresh_token 长度: {len(result['refresh_token'])}")
                                except Exception as e_tok:
                                    logger.warning(f"[browser-reg] 解析 token 响应失败: {e_tok}")
                            else:
                                logger.warning(f"[browser-reg] token 交换失败: {resp_token.status_code} {resp_token.text[:200]}")
                        else:
                            logger.warning(f"[browser-reg] callback 无 code: {cb_url[:120]}")
                    else:
                        logger.warning("[browser-reg] 未捕获到 callback URL")
                except Exception as e_codex:
                    logger.warning(f"[browser-reg] Codex OAuth 异常: {e_codex}")

            # 新版 OpenAI passwordless signup 有时只在 /api/auth/session 返回
            # accessToken，不再落 __Secure-next-auth.session-token cookie。
            # access_token 已足够后续生成 checkout/验证账号；不要因为缺
            # session_token 把已注册成功的邮箱错误回滚。
            if not result["access_token"]:
                page.screenshot(path="/tmp/browser_reg_missing_token.png")
                raise RuntimeError(
                    f"缺少凭证: access_token={bool(result['access_token'])} "
                    f"session_token={bool(result['session_token'])}"
                )
            if not result["session_token"]:
                logger.warning("[browser-reg] 未拿到 session_token cookie，但 access_token 存在，按注册成功处理")
            if proxy_pool_path and proxy_upstream and not proxy_reusable_pool:
                _commit_proxy_to_used(proxy_pool_path, proxy_upstream)
    except Exception as e:
        if proxy_pool_path and proxy_upstream and not proxy_reusable_pool:
            if _is_proxy_failure(e):
                _mark_proxy_bad(proxy_pool_path, proxy_upstream, f"{type(e).__name__}: {e}")
            else:
                logger.info(f"[browser-reg] 注册失败，代理已按一次性规则保留 consumed，不回池: {proxy_upstream}")
        raise
    finally:
        try:
            shutil.rmtree(tmp_profile, ignore_errors=True)
        except Exception:
            pass

    return result
