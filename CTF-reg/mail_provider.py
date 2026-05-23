"""邮箱服务（CF Email Routing 路径）。

历史上这个模块走 IMAP 拉 QQ 邮箱接 OTP（5s 轮询 + 转发链路 30–90s 延迟）。
现在彻底切到 Cloudflare Email Worker → KV 路径：

    寄件人 → CF MX (catch-all) → otp-relay Worker → KV
                                                       ↓
                                            cf_kv_otp_provider 读

OTP 提取由 Worker 端做（见 scripts/otp_email_worker.js），
本模块只剩两件事：
  1. 用 catch-all 域名生成随机收件地址 (`create_mailbox`)
  2. 委托 `CloudflareKVOtpProvider` 阻塞拿 OTP (`wait_for_otp`)

KV 凭证读取顺序：环境变量 `CF_API_TOKEN/CF_ACCOUNT_ID/CF_OTP_KV_NAMESPACE_ID`
→ SQLite runtime_meta[secrets] 的 cloudflare 段。详见 cf_kv_otp_provider.py。
"""
from __future__ import annotations

import logging
import random
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
import json
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)


# —— 真人风邮箱前缀生成 ——
# 与 browser_register._gen_name 保持同款英美常见名池；OpenAI 反欺诈系统对
# "随机字符串前缀"评分较低，用 first/last 组合更接近真实新用户分布。
_FIRST_NAMES = [
    "james", "john", "emily", "sophia", "michael", "oliver", "emma",
    "william", "amelia", "lucas", "mia", "ethan", "noah", "ava", "liam",
    "isabella", "mason", "charlotte", "logan", "harper", "elijah", "evelyn",
    "benjamin", "abigail", "jacob", "ella", "alexander", "scarlett", "henry",
    "grace", "daniel", "chloe", "matthew", "lily", "samuel", "zoe",
    "david", "hannah", "joseph", "aria", "ryan", "nora",
]
_LAST_NAMES = [
    "smith", "johnson", "williams", "brown", "jones", "garcia",
    "miller", "davis", "rodriguez", "martinez", "wilson", "anderson",
    "taylor", "thomas", "moore", "jackson", "martin", "lee", "walker",
    "hall", "allen", "young", "king", "wright", "scott", "green",
    "baker", "adams", "nelson", "carter",
]


def _humanlike_local_part(rng: random.Random | None = None) -> str:
    """生成像真人的邮箱前缀，例如 emma.davis、jsmith92、liam_wilson03。

    采样模式（权重）：
      - first.last                       (常见专业邮箱)
      - firstlast                        (无分隔)
      - first_last                       (下划线)
      - first.last + 1-2 位数字
      - firstlast + 2-4 位数字（含年份）
      - first 首字母 + last + 数字 (jsmith92)
      - first + last 首字母 + 数字 (emmas01)
      - first + 出生年（1985-2003）

    所有结果只含 [a-z0-9._]，长度 5-22，符合 RFC + 多数邮件服务的本地部要求。
    """
    r = rng or random
    first = r.choice(_FIRST_NAMES)
    last = r.choice(_LAST_NAMES)

    pattern = r.choices(
        population=[
            "first.last", "firstlast", "first_last",
            "first.last+num", "firstlast+num",
            "f.last+num", "first.l+num", "first+year",
        ],
        weights=[14, 10, 6, 18, 16, 14, 10, 12],
        k=1,
    )[0]

    if pattern == "first.last":
        local = f"{first}.{last}"
    elif pattern == "firstlast":
        local = f"{first}{last}"
    elif pattern == "first_last":
        local = f"{first}_{last}"
    elif pattern == "first.last+num":
        n = r.randint(1, 99)
        local = f"{first}.{last}{n:02d}"
    elif pattern == "firstlast+num":
        # 偏向 4 位年份样式（更像真人）
        if r.random() < 0.55:
            n = r.randint(1985, 2003)
            local = f"{first}{last}{n}"
        else:
            n = r.randint(1, 999)
            local = f"{first}{last}{n}"
    elif pattern == "f.last+num":
        n = r.randint(1, 99)
        local = f"{first[0]}{last}{n:02d}"
    elif pattern == "first.l+num":
        n = r.randint(1, 99)
        local = f"{first}{last[0]}{n:02d}"
    else:  # first+year
        n = r.randint(1985, 2003)
        local = f"{first}{n}"

    # 兜底长度（极个别长姓如 rodriguez+full year 会到 22）
    if len(local) > 22:
        local = local[:22]
    return local


class MailProvider:
    """生成 catch-all 子域随机邮箱 + 委托 CF KV provider 取 OTP。

    `last_persona` 暴露最近一次 `create_mailbox()` 产生的完整 persona
    （邮箱 / first / last / 密码），供 `browser_register` 复用，
    确保「邮箱 first-name 与注册显示姓名一致」——OpenAI 反欺诈系统
    会对二者不一致打负分。
    """

    def __init__(self, catch_all_domain: str = ""):
        self.catch_all_domain = catch_all_domain
        self._reuse_email: Optional[str] = None  # 兼容 register-only resume
        self._custom_email_password: str = ""
        self._custom_otp_url: str = ""
        self._custom_pool_current_raw: str = ""
        # 临时自定义邮箱池：支持：
        #   email----password
        #   email----password----fetch_url
        #   email----password----fetch_url----client_id----refresh_token
        # 开启：export CUSTOM_MAIL_POOL=/root/Gpt-Agreement-Payment/CTF-reg/custom_mail_pool.txt
        # 未显式设置时，默认使用同目录 custom_mail_pool.txt，避免 WebUI/批量注册
        # 回退到 CF catch-all 随机邮箱。
        default_pool = Path(__file__).with_name("custom_mail_pool.txt")
        self._custom_pool_path = os.environ.get("CUSTOM_MAIL_POOL", "").strip()
        if not self._custom_pool_path and default_pool.exists() and default_pool.stat().st_size > 0:
            self._custom_pool_path = str(default_pool)
        self._custom_otp_url_template = os.environ.get(
            "CUSTOM_MAIL_OTP_URL_TEMPLATE",
            "https://ms.lqqq.cc/web/{email}----{password}",
        ).strip()
        # 算法化 persona 生成器（音节合成法，详见 persona.py）
        from persona import PersonaGenerator, Persona
        self._persona_gen = PersonaGenerator(catch_all_domain)
        self.last_persona: Optional[Persona] = None

    def _pop_custom_mailbox(self) -> Optional[tuple[str, str, str, str]]:
        if not self._custom_pool_path:
            return None
        path = Path(self._custom_pool_path)
        if not path.exists():
            raise RuntimeError(f"CUSTOM_MAIL_POOL 不存在: {path}")
        lines = path.read_text(encoding="utf-8").splitlines()
        picked = None
        rest = []
        for line in lines:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                rest.append(line)
                continue
            if picked is None:
                parts = raw.split("----")
                if len(parts) < 2:
                    raise RuntimeError(f"邮箱池行格式错误，应至少为 email----password: {raw}")
                # 支持 Ryan 新格式：email----邮箱密码----取件地址----client_id----refresh_token
                email, password = parts[0].strip(), parts[1].strip()
                otp_url = parts[2].strip() if len(parts) >= 3 else ""
                picked = (email, password, otp_url, raw)
            else:
                rest.append(line)
        if picked is None:
            raise RuntimeError(f"CUSTOM_MAIL_POOL 已空: {path}")
        used = path.with_suffix(path.suffix + ".used")
        used.write_text(
            (used.read_text(encoding="utf-8") if used.exists() else "")
            + picked[3] + "\n",
            encoding="utf-8",
        )
        path.write_text("\n".join(rest).rstrip() + ("\n" if rest else ""), encoding="utf-8")
        return picked


    def rollback_custom_mailbox(self) -> bool:
        """Move the current custom-pool mailbox back from .used to the front of the pool.

        Registration pops a mailbox before the browser starts. If the browser/proxy/OTP
        flow fails, the outer register wrapper calls this so transient failures do not
        burn mailbox inventory. Returns True when something was restored.
        """
        raw = (self._custom_pool_current_raw or "").strip()
        if not raw or not self._custom_pool_path:
            return False
        path = Path(self._custom_pool_path)
        used = path.with_suffix(path.suffix + ".used")
        pool_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        if raw in pool_lines:
            return False
        used_lines = used.read_text(encoding="utf-8").splitlines() if used.exists() else []
        removed = False
        kept = []
        for line in used_lines:
            if not removed and line.strip() == raw:
                removed = True
                continue
            kept.append(line)
        if not removed:
            # Best-effort fallback: if .used was externally edited, still avoid losing it.
            removed = True
        path.write_text(raw + "\n" + "\n".join(pool_lines).rstrip() + ("\n" if pool_lines else ""), encoding="utf-8")
        if used.exists():
            used.write_text("\n".join(kept).rstrip() + ("\n" if kept else ""), encoding="utf-8")
        logger.info(f"[mail] 注册失败，邮箱已回滚到 custom pool: {raw.split('----', 1)[0]}")
        self._custom_pool_current_raw = ""
        self._custom_email_password = ""
        self._custom_otp_url = ""
        return True

    def commit_custom_mailbox(self) -> bool:
        """Mark current custom-pool mailbox as consumed after successful registration."""
        if not self._custom_pool_current_raw:
            return False
        logger.info(f"[mail] 注册成功，确认消耗 custom pool 邮箱: {self._custom_pool_current_raw.split('----', 1)[0]}")
        self._custom_pool_current_raw = ""
        return True

    def _custom_otp_fetch_url(self, email_addr: str) -> str:
        if self._custom_otp_url:
            return self._custom_otp_url.format(
                email=urllib.parse.quote(email_addr, safe=""),
                password=urllib.parse.quote(self._custom_email_password, safe=""),
            )
        tpl = self._custom_otp_url_template
        return tpl.format(
            email=urllib.parse.quote(email_addr, safe=""),
            password=urllib.parse.quote(self._custom_email_password, safe=""),
        )

    def _fetch_url(self, opener, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=15) as r:
            return r.read().decode("utf-8", errors="replace")

    def _iter_texts(self, obj: Any):
        if obj is None:
            return
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from self._iter_texts(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from self._iter_texts(v)

    def _extract_otp_from_html(self, html: str) -> Optional[str]:
        # 先抓语义上下文，再兜底 6 位数字；排除 CSS 颜色值。
        patterns = [
            r"(?:OpenAI|ChatGPT|code(?:\s*is)?|verification|one[-\s]*time|verify|验证码)[^0-9]{0,180}(\d{6})\b",
            r"\b(\d{6})\b",
        ]
        for pat in patterns:
            for m in re.finditer(pat, html, re.I | re.S):
                otp = m.group(1)
                before = html[max(0, m.start(1) - 30):m.start(1)]
                if "#" in before[-2:] or re.search(r"(?:color|background|bgcolor|fill|stroke)\s*[:=]\s*[\"']?#?\s*$", before, re.I):
                    continue
                return otp
        return None

    def _extract_otp_from_payload(self, payload: str) -> Optional[str]:
        try:
            obj = json.loads(payload)
        except Exception:
            return self._extract_otp_from_html(payload)
        joined = "\n".join(self._iter_texts(obj) or [])
        return self._extract_otp_from_html(joined)

    def _custom_api_get_payload(self, opener, url: str) -> Optional[dict]:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc != "api.nineemail.com" or "/token=" not in parsed.path:
            return None
        token = parsed.path.split("/token=", 1)[1].split("/", 1)[0].strip()
        if not token:
            return None
        api_url = f"{parsed.scheme or 'https'}://{parsed.netloc}/api/get?token={urllib.parse.quote(token)}"
        payload = self._fetch_url(opener, api_url)
        obj = json.loads(payload)
        if not obj.get("success") or not isinstance(obj.get("data"), dict):
            raise RuntimeError(f"nineemail /api/get failed: {payload[:200]}")
        return obj["data"]

    def _fetch_nineemail_mailbox(self, opener, base: str, data: dict, mailbox: str) -> str:
        params = urllib.parse.urlencode({
            "endpoint": "mail-new",
            "refresh_token": data.get("refresh_token", ""),
            "client_id": data.get("client_id", ""),
            "email": data.get("email", ""),
            "mailbox": mailbox,
            "response_type": "json",
        })
        return self._fetch_url(opener, f"{base}/api/proxy?{params}")

    def _wait_custom_otp(self, email_addr: str, timeout: int = 120) -> str:
        if not self._custom_email_password:
            raise RuntimeError("自定义邮箱 OTP 缺少邮箱密码")
        url = self._custom_otp_fetch_url(email_addr)
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else "https://ms.lqqq.cc"
        deadline = time.time() + timeout
        last_log = 0.0
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        logger.info(f"[mail] 走自定义邮箱 API/页面取 OTP -> {email_addr} timeout={timeout}s")

        api_data = None
        try:
            api_data = self._custom_api_get_payload(opener, url)
            logger.info(f"[mail] nineemail API 已载入: {api_data.get('email') or email_addr}")
        except Exception as e:
            logger.info(f"[mail] nineemail API 初始化失败，降级页面轮询: {type(e).__name__}: {e}")

        while time.time() < deadline:
            try:
                if api_data:
                    for mailbox in ("INBOX", "Junk"):
                        payload = self._fetch_nineemail_mailbox(opener, base, api_data, mailbox)
                        otp = self._extract_otp_from_payload(payload)
                        if otp:
                            logger.info(f"[mail] nineemail {mailbox} 收到 OTP={otp} -> {email_addr}")
                            return otp
                        try:
                            obj = json.loads(payload)
                            new_rt = obj.get("new_refresh_token")
                            if new_rt and new_rt != api_data.get("refresh_token"):
                                api_data["refresh_token"] = new_rt
                        except Exception:
                            pass
                else:
                    html = self._fetch_url(opener, url)
                    otp = self._extract_otp_from_payload(html)
                    if otp:
                        logger.info(f"[mail] 自定义邮箱收到 OTP={otp} -> {email_addr}")
                        return otp

                    # 列表页通常没有正文验证码；打开最新 ChatGPT 邮件详情页。
                    links = re.findall(r'href=["\']([^"\']*show_email/[^"\']+)["\']', html, re.I)
                    for href in links[:5]:
                        detail_url = urllib.parse.urljoin(base, href)
                        detail = self._fetch_url(opener, detail_url)
                        if "ChatGPT" not in detail and "OpenAI" not in detail:
                            continue
                        otp = self._extract_otp_from_payload(detail)
                        if otp:
                            logger.info(f"[mail] 自定义邮箱详情页收到 OTP={otp} -> {email_addr}")
                            return otp
            except Exception as e:
                if time.time() - last_log > 10:
                    logger.info(f"[mail] 自定义邮箱 OTP 轮询中: {type(e).__name__}: {e}")
                    last_log = time.time()
            time.sleep(2)
        raise TimeoutError(f"自定义邮箱 OTP timeout after {timeout}s: {email_addr}")

    @staticmethod
    def _random_name() -> str:
        # 保留旧 API 兼容；新流程走 persona generator
        return _humanlike_local_part()

    def create_mailbox(self) -> str:
        """生成 random@catch_all 邮箱地址（也可复用 _reuse_email）。

        同时将算法生成的完整 persona 缓存到 `self.last_persona`，
        `browser_register` 通过该字段读取与邮箱同源的姓名 / 密码。
        """
        if self._reuse_email:
            addr = self._reuse_email
            self._reuse_email = None
            logger.info(f"复用邮箱: {addr}")
            self.last_persona = None  # resume 路径无法回推 first/last
            return addr
        custom = self._pop_custom_mailbox()
        if custom:
            addr, password, otp_url, raw = custom
            self._custom_email_password = password
            self._custom_otp_url = otp_url
            self._custom_pool_current_raw = raw
            self.last_persona = None
            logger.info(f"邮箱已创建: {addr} (路径: custom mail pool{' + fetch_url' if otp_url else ''})")
            return addr
        if not self.catch_all_domain:
            raise RuntimeError(
                "MailProvider.create_mailbox: catch_all_domain 未配置；"
                "CF Email Worker 路径需要 catch-all 子域（在 zone 内）"
            )
        persona = self._persona_gen.next()
        self.last_persona = persona
        logger.info(
            f"邮箱已创建: {persona.email} | persona={persona.first} {persona.last} "
            f"(路径: CF Email Worker → KV)"
        )
        return persona.email

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        """阻塞等 OTP。直接走 CF KV，不再有 IMAP fallback。

        失败抛 TimeoutError 或 RuntimeError。原 IMAP 路径已删除——
        QQ 邮箱 / auth_code 这些参数全部废弃。
        """
        if self._custom_pool_path:
            return self._wait_custom_otp(email_addr, timeout=timeout)

        from cf_kv_otp_provider import CloudflareKVOtpProvider

        logger.info(
            f"[mail] 走 CF KV 取 OTP -> {email_addr} (timeout={timeout}s)"
        )
        provider = CloudflareKVOtpProvider.from_env_or_secrets()
        return provider.wait_for_otp(
            email_addr, timeout=timeout, issued_after=issued_after
        )
