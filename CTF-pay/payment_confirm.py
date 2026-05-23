"""Stripe payment confirmation and outcome helpers extracted from legacy code.

This module owns card confirm, 3DS handling, Stripe hCaptcha solving used by 3DS,
result polling, and offline terminal-result helpers.  It imports no legacy
``card.py`` code.
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import string
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from fresh_checkout import (
    FreshCheckoutAuthError,
    _build_fresh_checkout_body,
    _extract_checkout_identifiers,
    _load_fresh_checkout_bootstrap,
)
from rt_login import _build_proxy_url_from_cfg
from stripe_checkout import (
    DEFAULT_STRIPE_RUNTIME_VERSION,
    DEFAULT_STRIPE_HCAPTCHA_ASSET_VERSION,
    STRIPE_API,
    STRIPE_VERSION_BASE,
    STRIPE_VERSION_FULL,
    _accept_language_for_locale,
    _browser_tz_offset,
    _build_stripe_hcaptcha_url,
    _elements_options_client_payload,
    _gen_elements_session_id,
    _gen_fingerprint,
    _locale_short,
    _stripe_headers,
)

_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output"
(_OUTPUT_DIR / "logs").mkdir(parents=True, exist_ok=True)
LOG_FILE = str(_OUTPUT_DIR / "logs" / "payment_confirm.log")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
DEFAULT_FRONTEND_EXECUTION = base64.b64encode(
    json.dumps({"fingerprintOutcome": "not_supported"}, separators=(",", ":")).encode()
).decode()


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _log_raw(msg: str):
    print(msg, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(str(msg) + "\n")
    except Exception:
        pass


def _log_request(label: str, method: str, url: str = "", headers=None, data=None, json_body=None, tag: str = ""):
    if tag and not url:
        url = method
        method = label
        label = tag
    _log(f"--> {label} {method} {url}")
    if data is not None:
        preview = data if isinstance(data, str) else urllib.parse.urlencode(data)
        _log(f"    data={preview[:500]}")
    if json_body is not None:
        try:
            preview = json.dumps(json_body, ensure_ascii=False)
        except Exception:
            preview = str(json_body)
        _log(f"    json={preview[:500]}")


def _log_response(label_or_resp, resp=None, tag: str = ""):
    if resp is None:
        resp = label_or_resp
        label = tag or "response"
    else:
        label = label_or_resp
    try:
        text = resp.text or ""
    except Exception:
        text = ""
    _log(f"<-- {label} HTTP {getattr(resp, 'status_code', '?')} body={text[:800]}")


def _describe_challenge_artifact(kind: str, value: str | None) -> str:
    if not value:
        return ""
    value = str(value)
    if len(value) <= 20:
        return value
    return f"{value[:10]}...{value[-8:]}"


def _describe_proxy_cfg(proxy_cfg) -> str:
    proxy_url = _build_proxy_url_from_cfg(proxy_cfg)
    if not proxy_url:
        return "direct"
    return re.sub(r"//([^:/@]+):([^@]+)@", r"//\1:***@", proxy_url)


def _resolve_stage_proxy_cfg(stage_proxy_cfg: dict | None, stage_name: str):
    if not isinstance(stage_proxy_cfg, dict):
        return None
    return stage_proxy_cfg.get(stage_name) or stage_proxy_cfg.get("default")


class _NullProxyContext:
    def __enter__(self):
        return None
    def __exit__(self, exc_type, exc, tb):
        return False


def _http_session_stage_proxy(session_obj, stage_proxy_cfg: dict | None, stage_name: str):
    proxy_cfg = _resolve_stage_proxy_cfg(stage_proxy_cfg, stage_name)
    if not proxy_cfg or not hasattr(session_obj, "proxies"):
        return _NullProxyContext()
    proxy_url = _build_proxy_url_from_cfg(proxy_cfg)
    class _ProxyCtx:
        def __enter__(self_inner):
            self_inner.old = dict(getattr(session_obj, "proxies", {}) or {})
            session_obj.proxies.update({"http": proxy_url, "https": proxy_url})
            return proxy_url
        def __exit__(self_inner, exc_type, exc, tb):
            session_obj.proxies.clear(); session_obj.proxies.update(self_inner.old)
            return False
    return _ProxyCtx()


def solve_hcaptcha(
    captcha_cfg: dict,
    hcaptcha_config: dict,
    max_retries: int = 3,
    session: requests.Session | None = None,
) -> tuple[str, str]:
    """返回 (token, ekey) 元组"""
    api_url = (captcha_cfg.get("api_url") or "").rstrip("/") or "https://YOUR_CAPTCHA_PROVIDER"
    client_key = captcha_cfg["api_key"]
    site_key = hcaptcha_config["site_key"]
    rqdata = hcaptcha_config.get("rqdata", "")
    is_invisible = hcaptcha_config.get("is_invisible", True)
    website_url = hcaptcha_config.get("website_url") or _build_stripe_hcaptcha_url(invisible=is_invisible)

    for retry in range(max_retries):
        if retry > 0:
            _log(f"      --- 重试第 {retry + 1}/{max_retries} 次 ---")

        _log(f"      解 hCaptcha (siteKey: {site_key[:20]}...)")

        # 创建 1 个任务
        task_body = {
            "type": "HCaptchaTaskProxyless",
            "websiteURL": website_url,
            "websiteKey": site_key,
            "isEnterprise": True,
            "userAgent": USER_AGENT,
        }
        if is_invisible:
            task_body["isInvisible"] = True
        if rqdata:
            task_body["rqdata"] = rqdata

        create_payload = {"clientKey": client_key, "task": task_body}
        try:
            create_url = f"{api_url}/createTask"
            _log_request("POST", create_url, data=create_payload, tag="[captcha] createTask")
            create_resp = requests.post(create_url, json=create_payload, timeout=15)
            _log_response(create_resp, tag="[captcha] createTask")
            data = create_resp.json()
            if data.get("errorId", 1) != 0:
                _log(f"      任务创建失败: {data.get('errorDescription', '?')}")
                time.sleep(3)
                continue
            task_id = data["taskId"]
        except Exception as e:
            _log(f"      任务创建异常: {e}")
            time.sleep(3)
            continue

        _log(f"      任务: {task_id}  等待解题 ...")

     
        for attempt in range(60):
            time.sleep(3)
            try:
                result_url = f"{api_url}/getTaskResult"
                result_payload = {"clientKey": client_key, "taskId": task_id}
                result_resp = requests.post(result_url, json=result_payload, timeout=10)
                result_data = result_resp.json()
            except Exception:
                continue

            if result_data.get("errorId", 0) != 0:
                error_code = result_data.get("errorCode", "")
                if error_code == "ERROR_TASK_TIMEOUT":
                    _log("      任务超时, 重新发起 ...")
                    break
                continue

            if result_data.get("status") == "ready":
                solution = result_data["solution"]
                _log_raw(f"      solution keys: {list(solution.keys())}")
                _log_raw(f"      solution full: {json.dumps(solution, ensure_ascii=False)[:500]}")
                token = solution["gRecaptchaResponse"]
                # eKey 可能在不同字段名下
                ekey = solution.get("eKey", "") or solution.get("respKey", "") or solution.get("ekey", "")
                solved_user_agent = solution.get("userAgent", "")
                if solved_user_agent and solved_user_agent != USER_AGENT:
                    _log(f"      打码平台返回不同 UA，后续请求改用该 UA")
                    if session is not None:
                        session.headers["User-Agent"] = solved_user_agent
                _log(f"      已解决 (token: {len(token)} chars, ekey: {len(ekey)} chars)")
                _log_raw(f"      captcha_token(前100): {token[:100]}...")
                if ekey:
                    _log_raw(f"      captcha_ekey(前100): {ekey[:100]}...")
                return token, ekey

            if attempt % 5 == 4:
                _log(f"      等待中 ... ({attempt + 1}/60)")

    raise RuntimeError(f"打码平台解题失败 (已重试 {max_retries} 轮)")


def _build_stripe_hcaptcha_parent_html(
    frame_id: str,
    wrapper_url: str,
    site_key: str,
    rqdata: str,
    merchant_id: str,
    locale: str,
    invisible: bool = False,
) -> str:
    visible_payload = {
        "sitekey": site_key,
        "rqdata": rqdata,
        "merchantId": merchant_id,
        "locale": locale,
        "headerText": "Verification required",
        "instructionText": "Complete captcha to continue",
        "showCloseButton": False,
    }
    invisible_init_payload = {
        "tag": "INITIALIZE_HCAPTCHA_INVISIBLE",
        "message": {
            "sitekey": site_key,
        },
    }
    invisible_execute_payload = {
        "tag": "EXECUTE_HCAPTCHA_INVISIBLE",
        "message": {
            "sitekey": site_key,
            "rqdata": rqdata,
            "data": {
                "merchant_id": merchant_id or "",
                "locale": locale or "",
                "flow": "passive_captcha",
                "captcha_vendor": "hcaptcha",
            },
        },
    }
    invisible_signal_payloads = [
        {
            "tag": "SEND_FRAUD_SIGNALS_HCAPTCHA_INVISIBLE",
            "message": {
                "type": "mouse",
                "eventName": "mousemove",
                "coordinates": {"x": 168, "y": 132},
            },
        },
        {
            "tag": "SEND_FRAUD_SIGNALS_HCAPTCHA_INVISIBLE",
            "message": {
                "type": "pointer",
                "eventName": "pointermove",
                "coordinates": {"x": 214, "y": 176},
            },
        },
        {
            "tag": "SEND_FRAUD_SIGNALS_HCAPTCHA_INVISIBLE",
            "message": {
                "type": "keyboard",
                "eventName": "keydown",
            },
        },
    ]
    payload_js = json.dumps(visible_payload, ensure_ascii=False)
    invisible_init_payload_js = json.dumps(invisible_init_payload, ensure_ascii=False)
    invisible_execute_payload_js = json.dumps(invisible_execute_payload, ensure_ascii=False)
    invisible_signal_payloads_js = json.dumps(invisible_signal_payloads, ensure_ascii=False)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Stripe hCaptcha Bridge</title>
    <style>
      body {{
        margin: 0;
        font-family: Arial, sans-serif;
        background: #f7f7f7;
      }}
      .shell {{
        padding: 16px;
      }}
      #status {{
        font-size: 14px;
        margin-bottom: 12px;
        color: #333;
      }}
      iframe {{
        width: 420px;
        height: 720px;
        border: 0;
        background: white;
      }}
      pre {{
        white-space: pre-wrap;
        word-break: break-word;
        font-size: 12px;
      }}
    </style>
  </head>
  <body>
    <div class="shell">
      <div id="status">Waiting for Stripe captcha frame…</div>
      <iframe id="stripeCaptchaFrame" src="{wrapper_url}"></iframe>
      <pre id="result"></pre>
    </div>
    <script>
      window.__stripeChallengeEvents = [];
      window.__stripeChallengeResult = null;
      window.__stripeChallengeCancelled = false;
      window.__stripeChallengeError = null;
      const frameID = {json.dumps(frame_id)};
      const invisibleMode = {json.dumps(bool(invisible))};
      const childPayload = {payload_js};
      const invisibleInitPayload = {invisible_init_payload_js};
      const invisibleExecutePayload = {invisible_execute_payload_js};
      const invisibleSignalPayloads = {invisible_signal_payloads_js};
      let invisibleInitialized = false;
      let invisibleExecuted = false;

      function setStatus(text) {{
        document.getElementById("status").textContent = text;
      }}

      function postToBridge(path, payload) {{
        fetch(path, {{
          method: "POST",
          headers: {{
            "Content-Type": "application/json",
          }},
          body: JSON.stringify(payload || {{}}),
          keepalive: true,
        }}).catch(() => {{}});
      }}

      function postToChild(source, origin, payload) {{
        source.postMessage({{
          type: "stripe-third-party-parent-to-child",
          frameID,
          payload,
        }}, origin);
      }}

      function postInvisibleInitialize(source, origin) {{
        if (invisibleInitialized) {{
          return;
        }}
        invisibleInitialized = true;
        setStatus("Initializing invisible hCaptcha…");
        postToBridge("/event", {{
          type: "invisible_initialize",
          payload: invisibleInitPayload,
        }});
        postToChild(source, origin, invisibleInitPayload);
      }}

      function postInvisibleExecute(source, origin) {{
        if (invisibleExecuted) {{
          return;
        }}
        invisibleExecuted = true;
        setStatus("Executing invisible hCaptcha…");
        invisibleSignalPayloads.forEach((signalPayload, idx) => {{
          setTimeout(() => postToChild(source, origin, signalPayload), 50 * idx);
        }});
        setTimeout(() => {{
          postToBridge("/event", {{
            type: "invisible_execute",
            payload: invisibleExecutePayload,
          }});
          postToChild(source, origin, invisibleExecutePayload);
        }}, 180);
      }}

      window.addEventListener("message", (event) => {{
        window.__stripeChallengeEvents.push({{
          origin: event.origin,
          data: event.data,
        }});

        const data = event.data || {{}};
        if (data.type === "stripe-third-party-frame-ready" && data.frameID === frameID) {{
          setStatus("Stripe captcha frame ready. Loading challenge…");
          postToBridge("/event", {{
            type: "frame_ready",
            origin: event.origin,
            frameID,
          }});
          if (invisibleMode) {{
            postInvisibleInitialize(event.source, event.origin);
          }} else {{
            postToChild(event.source, event.origin, childPayload);
          }}
          return;
        }}

        if (data.type !== "stripe-third-party-child-to-parent" || data.frameID !== frameID) {{
          return;
        }}

        const payload = data.payload || {{}};
        document.getElementById("result").textContent = JSON.stringify(payload, null, 2);

        postToBridge("/event", {{
          type: "child_payload",
          origin: event.origin,
          requestID: data.requestID || null,
          payload,
        }});

        if (invisibleMode) {{
          const tag = payload.tag || "";
          const value = payload.value || {{}};

          if (tag === "LOAD_HCAPTCHA_INVISIBLE") {{
            setStatus("Invisible hCaptcha loaded. Executing…");
            postInvisibleExecute(event.source, event.origin);
            return;
          }}

          if (tag === "SEND_COMPLETE_HCAPTCHA_INVISIBLE") {{
            setStatus("Invisible hCaptcha fraud signals delivered.");
            return;
          }}

          if (tag === "RESPONSE_HCAPTCHA_INVISIBLE") {{
            const solved = {{
              response: value.response || "",
              ekey: value.key || "",
              duration: value.duration || 0,
              raw: payload,
            }};
            setStatus("Invisible hCaptcha solved. You can close this window.");
            window.__stripeChallengeResult = solved;
            postToBridge("/result", solved);
            return;
          }}

          if (tag === "ERROR_HCAPTCHA_INVISIBLE") {{
            const err = {{
              error: value.error || "unknown_error",
              raw: payload,
            }};
            setStatus("Invisible hCaptcha failed: " + err.error);
            window.__stripeChallengeError = err;
            postToBridge("/error", err);
            return;
          }}

          return;
        }}

        if (payload.type === "event") {{
          setStatus("Stripe captcha event: " + payload.name);
          postToBridge("/event", payload);
        }} else if (payload.type === "response") {{
          setStatus("Challenge solved. You can close this window.");
          window.__stripeChallengeResult = payload;
          postToBridge("/result", payload);
        }} else if (payload.type === "cancel") {{
          setStatus("Challenge cancelled.");
          window.__stripeChallengeCancelled = true;
          postToBridge("/cancel", payload);
        }}
      }});
    </script>
  </body>
</html>
"""


def solve_stripe_hcaptcha_in_browser(
    hcaptcha_config: dict,
    merchant_id: str,
    locale: str,
    browser_cfg: dict | None = None,
    verify_url: str = "",
    verify_form_base: dict | None = None,
) -> tuple[str, str, dict | None]:
    """通过 Stripe 自带 HCaptcha 包装页获取 token。

    - `is_invisible=true` 时优先用于 passive captcha，通常希望浏览器自动执行后直接回传 token
    - `is_invisible=false` 时用于 challenge captcha，必要时可人工处理
    """
    browser_cfg = browser_cfg or {}
    timeout_ms = int(browser_cfg.get("timeout_ms", 5 * 60 * 1000))
    headless = bool(browser_cfg.get("headless", False))
    auto_click_checkbox = bool(browser_cfg.get("auto_click_checkbox", True))
    invisible = bool(hcaptcha_config.get("is_invisible", False))
    external_solver_cfg = dict(browser_cfg.get("external_solver") or {})
    if not invisible and verify_url and not bool(external_solver_cfg.get("enabled")):
        bundled_solver = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "hcaptcha_auto_solver.py",
        )
        python_candidates = [
            str(os.environ.get("CTFML_PYTHON") or "").strip(),
            "~/.venvs/ctfml/bin/python",
            sys.executable,
        ]
        solver_python = next((p for p in python_candidates if p and os.path.exists(p)), sys.executable)
        auto_vlm_cfg = dict(external_solver_cfg.get("vlm") or {})
        auto_vlm_cfg.setdefault("enabled", True)
        auto_vlm_cfg.setdefault("model", "gpt-5.4")
        auto_vlm_cfg.setdefault("base_url", "https://YOUR_VLM_ENDPOINT/api")
        auto_vlm_cfg.setdefault("api_key", "")
        auto_vlm_cfg.setdefault("timeout_s", 45)
        external_solver_cfg = {
            **external_solver_cfg,
            "enabled": True,
            "python": external_solver_cfg.get("python") or solver_python,
            "script": external_solver_cfg.get("script") or bundled_solver,
            "out_dir": external_solver_cfg.get("out_dir") or "/tmp/hcaptcha_auto_solver_live",
            "timeout_s": int(
                external_solver_cfg.get("timeout_s")
                or max(180, int(timeout_ms / 1000))
            ),
            "headed": bool(external_solver_cfg.get("headed", False)),
            "vlm": auto_vlm_cfg,
        }
        browser_cfg["external_solver"] = external_solver_cfg
        _log("      challenge 分支未携带 external_solver，已在 solve_stripe_hcaptcha_in_browser 内补齐内置 solver")
    external_solver_enabled = bool(external_solver_cfg.get("enabled")) and not invisible
    if external_solver_enabled:
        solver_timeout_s = int(external_solver_cfg.get("timeout_s") or max(180, int(timeout_ms / 1000)))
        min_timeout_ms = max(timeout_ms, solver_timeout_s * 1000 + 15_000)
        if min_timeout_ms != timeout_ms:
            _log(
                "      browser_challenge.timeout_ms 对 external_solver 过短，"
                f"自动从 {timeout_ms}ms 提升到 {min_timeout_ms}ms"
            )
            timeout_ms = min_timeout_ms
    auto_launch_browser_requested = bool(browser_cfg.get("auto_launch_browser", True))
    auto_launch_browser = auto_launch_browser_requested and not external_solver_enabled
    viewport = browser_cfg.get("viewport") or {"width": 1280, "height": 960}
    site_key = hcaptcha_config["site_key"]
    rqdata = hcaptcha_config.get("rqdata", "")
    proxy_url = str(browser_cfg.get("proxy_url") or "").strip()
    verify_url = (verify_url or "").strip()
    verify_form_base = dict(verify_form_base or {})
    browser_timezone = str(
        browser_cfg.get("browser_timezone")
        or browser_cfg.get("timezone")
        or DEFAULT_TIMEZONE
    )
    browser_accept_language = str(
        browser_cfg.get("accept_language")
        or _accept_language_for_locale(locale)
    )
    playwright_proxy = None
    _log(
        "      浏览器 hCaptcha 运行参数: "
        f"invisible={invisible} auto_launch={auto_launch_browser_requested} "
        f"external_solver={external_solver_enabled} headless={headless}"
    )
    if proxy_url:
        try:
            parsed_proxy = urllib.parse.urlsplit(proxy_url)
            proxy_host = parsed_proxy.hostname or ""
            proxy_scheme = parsed_proxy.scheme or "http"
            proxy_port = parsed_proxy.port
            if proxy_host:
                server = f"{proxy_scheme}://{proxy_host}"
                if proxy_port:
                    server += f":{proxy_port}"
                playwright_proxy = {
                    "server": server,
                    "bypass": "127.0.0.1,localhost",
                }
                proxy_user = urllib.parse.unquote(parsed_proxy.username or "")
                proxy_pass = urllib.parse.unquote(parsed_proxy.password or "")
                if proxy_user:
                    playwright_proxy["username"] = proxy_user
                if proxy_pass:
                    playwright_proxy["password"] = proxy_pass
        except Exception:
            playwright_proxy = None

    bridge_meta_path = browser_cfg.get("bridge_meta_path") or "/tmp/stripe_hcaptcha_bridge_latest.json"

    def _display_looks_usable(env: dict) -> bool:
        display = str(env.get("DISPLAY") or "").strip()
        if not display:
            return False
        probe_env = dict(env)
        for probe_cmd in (["xdpyinfo"], ["xset", "q"]):
            try:
                proc = subprocess.run(
                    probe_cmd,
                    env=probe_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
            except FileNotFoundError:
                continue
            except Exception:
                return False
            return proc.returncode == 0
        display_suffix = display.split(":", 1)[-1].split(".", 1)[0]
        if display_suffix.isdigit() and os.path.exists(f"/tmp/.X11-unix/X{display_suffix}"):
            return True
        return False

    with tempfile.TemporaryDirectory(prefix="stripe-hcaptcha-bridge-") as tmpdir:
        frame_id = str(uuid.uuid4())
        bridge_state = {
            "events": [],
            "result": None,
            "cancelled": False,
            "error": None,
        }
        result_event = threading.Event()
        cancel_event = threading.Event()
        error_event = threading.Event()

        def _persist_bridge_meta():
            try:
                bridge_meta = {
                    "bridge_url": f"{origin}/index.html",
                    "site_key": site_key,
                    "rqdata": rqdata,
                    "merchant_id": merchant_id,
                    "locale": locale,
                    "frame_id": frame_id,
                    "wrapper_url": wrapper_url,
                    "invisible": invisible,
                    "created_at": bridge_state.get("created_at") or int(time.time()),
                    "updated_at": int(time.time()),
                    "state": bridge_state,
                }
                with open(bridge_meta_path, "w", encoding="utf-8") as f:
                    json.dump(bridge_meta, f, ensure_ascii=False, indent=2)
                bridge_state["created_at"] = bridge_meta["created_at"]
            except Exception:
                pass

        class _QuietHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=tmpdir, **kwargs)

            def log_message(self, fmt, *args):
                return

            def _write_json(self, status: int, payload: dict):
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    payload = json.loads(raw_body.decode("utf-8") or "{}")
                except Exception:
                    payload = {}

                if self.path == "/event":
                    bridge_state["events"].append(payload)
                    _persist_bridge_meta()
                    self._write_json(200, {"ok": True})
                    return

                if self.path == "/result":
                    bridge_state["result"] = payload
                    _persist_bridge_meta()
                    result_event.set()
                    self._write_json(200, {"ok": True})
                    return

                if self.path == "/cancel":
                    bridge_state["cancelled"] = True
                    bridge_state["cancel_payload"] = payload
                    _persist_bridge_meta()
                    cancel_event.set()
                    self._write_json(200, {"ok": True})
                    return

                if self.path == "/error":
                    bridge_state["error"] = payload
                    _persist_bridge_meta()
                    error_event.set()
                    self._write_json(200, {"ok": True})
                    return

                self._write_json(404, {"error": "not found"})

        class _BridgeTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        httpd = _BridgeTCPServer(("127.0.0.1", 0), _QuietHandler)
        port = httpd.server_address[1]
        origin = f"http://127.0.0.1:{port}"
        wrapper_url = _build_stripe_hcaptcha_url(
            invisible=invisible,
            frame_id=frame_id,
            origin=origin,
        )
        html = _build_stripe_hcaptcha_parent_html(
            frame_id=frame_id,
            wrapper_url=wrapper_url,
            site_key=site_key,
            rqdata=rqdata,
            merchant_id=merchant_id,
            locale=locale,
            invisible=invisible,
        )
        with open(os.path.join(tmpdir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)

        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        try:
            _log(
                "      启用浏览器 "
                + ("passive captcha" if invisible else "challenge")
                + " 方案 ..."
            )
            _log(f"      本地桥接页: {origin}/index.html")
            _log("      如未自动拉起浏览器，请手动复制上面的本地桥接页地址到可用浏览器中打开。")
            try:
                _persist_bridge_meta()
                _log(f"      bridge 元数据已写入: {bridge_meta_path}")
            except Exception as e:
                _log(f"      bridge 元数据写入失败，忽略: {e}")

            browser = None
            page = None
            external_solver_proc = None
            external_solver_reader = None
            external_solver_exit_logged = False
            if external_solver_enabled:
                solver_headed = bool(external_solver_cfg.get("headed", False))
                solver_python = str(external_solver_cfg.get("python") or sys.executable)
                solver_script = str(
                    external_solver_cfg.get("script")
                    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "hcaptcha_auto_solver.py")
                )
                if not os.path.isabs(solver_script):
                    solver_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), solver_script)
                solver_timeout_s = int(
                    external_solver_cfg.get("timeout_s")
                    or max(90, int(timeout_ms / 1000))
                )
                solver_out_dir = str(
                    external_solver_cfg.get("out_dir")
                    or "/tmp/hcaptcha_auto_solver_live"
                )
                os.makedirs(solver_out_dir, exist_ok=True)
                solver_log_path = os.path.join(
                    solver_out_dir,
                    f"solver_stdout_{int(time.time() * 1000)}.log",
                )
                solver_vlm_cfg = dict(external_solver_cfg.get("vlm") or {})
                solver_cmd = [
                    solver_python,
                    "-u",
                    solver_script,
                    f"{origin}/index.html",
                    "--timeout",
                    str(solver_timeout_s),
                    "--out-dir",
                    solver_out_dir,
                ]
                if proxy_url:
                    solver_cmd.extend(["--proxy-url", proxy_url])
                if bool(solver_vlm_cfg.get("enabled", True)):
                    solver_cmd.extend(
                        [
                            "--vlm-base-url",
                            str(solver_vlm_cfg.get("base_url") or "https://YOUR_VLM_ENDPOINT/api"),
                            "--vlm-model",
                            str(solver_vlm_cfg.get("model") or "gpt-5.4"),
                            "--vlm-timeout",
                            str(int(solver_vlm_cfg.get("timeout_s") or 45)),
                        ]
                    )
                else:
                    solver_cmd.append("--no-vlm")
                extra_args = external_solver_cfg.get("extra_args") or []
                if isinstance(extra_args, (list, tuple)):
                    solver_cmd.extend(str(x) for x in extra_args if x not in (None, ""))

                solver_env = os.environ.copy()
                solver_tmpdir = str(external_solver_cfg.get("tmpdir") or "").strip()
                if solver_tmpdir:
                    solver_env["TMPDIR"] = solver_tmpdir
                solver_cmd_prefix = []
                if solver_headed and not _display_looks_usable(solver_env):
                    xvfb_run = shutil.which("xvfb-run")
                    if xvfb_run:
                        solver_cmd_prefix = [
                            xvfb_run,
                            "-a",
                            "--server-args=-screen 0 1280x960x24",
                        ]
                        _log("      external_solver headed 模式无可用 DISPLAY，自动改用 xvfb-run 启动虚拟显示。")
                    else:
                        solver_headed = False
                        _log("      external_solver headed 模式不可用，且系统无 xvfb-run，自动回退为 headless。")
                solver_vlm_api_key = str(solver_vlm_cfg.get("api_key") or "").strip()
                if solver_vlm_api_key:
                    solver_env["CTF_VLM_API_KEY"] = solver_vlm_api_key
                if solver_headed:
                    solver_cmd.append("--headed")
                if verify_url and verify_form_base:
                    solver_cmd.extend(["--verify-url", verify_url])
                    if verify_form_base.get("client_secret"):
                        solver_cmd.extend(["--verify-client-secret", str(verify_form_base["client_secret"])])
                    if verify_form_base.get("key"):
                        solver_cmd.extend(["--verify-key", str(verify_form_base["key"])])
                    if verify_form_base.get("_stripe_version"):
                        solver_cmd.extend(["--verify-stripe-version", str(verify_form_base["_stripe_version"])])
                    if verify_form_base.get("captcha_vendor_name"):
                        solver_cmd.extend(["--verify-captcha-vendor", str(verify_form_base["captcha_vendor_name"])])
                solver_cmd.extend(["--browser-locale", str(locale or "en-US")])
                solver_cmd.extend(["--browser-timezone", browser_timezone])
                solver_cmd.extend(["--accept-language", browser_accept_language])

                final_solver_cmd = [*solver_cmd_prefix, *solver_cmd]
                _log(
                    "      启动 external_solver: "
                    + " ".join(final_solver_cmd)
                )
                _log(f"      external_solver stdout 日志: {solver_log_path}")
                try:
                    external_solver_proc = subprocess.Popen(
                        final_solver_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        cwd=os.path.dirname(solver_script) or None,
                        env=solver_env,
                    )

                    def _forward_external_solver_output():
                        try:
                            if external_solver_proc is None or external_solver_proc.stdout is None:
                                return
                            with open(solver_log_path, "a", encoding="utf-8") as solver_log_f:
                                for line in external_solver_proc.stdout:
                                    solver_log_f.write(line)
                                    solver_log_f.flush()
                                    line = line.rstrip()
                                    if line:
                                        _log(f"      [solver] {line}")
                        except Exception as e:
                            _log(f"      [solver] 输出转发失败，忽略: {e}")

                    external_solver_reader = threading.Thread(
                        target=_forward_external_solver_output,
                        daemon=True,
                    )
                    external_solver_reader.start()
                except Exception as e:
                    raise RuntimeError(f"启动 external_solver 失败: {e}") from e

            if external_solver_enabled and auto_launch_browser_requested:
                _log("      challenge 已启用 external_solver，内置 Playwright 自动拉起将跳过。")
            if auto_launch_browser:
                try:
                    from playwright.sync_api import sync_playwright

                    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
                    effective_headless = headless or not has_display
                    if not has_display and not headless:
                        _log("      当前环境没有可用 DISPLAY，自动回退为 headless Playwright。")
                    if effective_headless or has_display:
                        playwright_ctx = sync_playwright().start()
                        launch_kwargs = {"headless": effective_headless}
                        if playwright_proxy:
                            launch_kwargs["proxy"] = playwright_proxy
                            _log(f"      浏览器桥接代理: {_describe_proxy_cfg(proxy_url)}")
                        browser = playwright_ctx.chromium.launch(**launch_kwargs)
                        browser_context = browser.new_context(
                            viewport=viewport,
                            user_agent=USER_AGENT,
                            locale=str(locale or "en-US"),
                            timezone_id=browser_timezone,
                            extra_http_headers={
                                "Accept-Language": browser_accept_language,
                                "Sec-CH-UA": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
                                "Sec-CH-UA-Mobile": "?0",
                                "Sec-CH-UA-Platform": '"Windows"',
                                "Priority": "u=1, i",
                            },
                        )
                        page = browser_context.new_page()
                        page.goto(f"{origin}/index.html", wait_until="domcontentloaded", timeout=60_000)
                        _log(
                            "      已自动拉起本地浏览器桥接页。"
                            f" (headless={'true' if effective_headless else 'false'})"
                        )
                    else:
                        _log("      当前环境没有可用 DISPLAY，跳过 Playwright 拉起；请手动在有图形界面的浏览器中打开桥接页。")
                        playwright_ctx = None
                except Exception as e:
                    playwright_ctx = None
                    _log(f"      自动拉起浏览器失败，改为手动打开桥接页: {e}")
            else:
                playwright_ctx = None

            try:
                if page is not None and auto_click_checkbox and not invisible:
                    try:
                        checkbox_deadline = time.time() + 20
                        checkbox_frame = None
                        while time.time() < checkbox_deadline:
                            checkbox_frame = next(
                                (frame for frame in page.frames if "frame=checkbox" in frame.url),
                                None,
                            )
                            if checkbox_frame:
                                break
                            page.wait_for_timeout(500)
                        if checkbox_frame:
                            for selector in ["#checkbox", '[role="checkbox"]', 'div[aria-checked]']:
                                try:
                                    checkbox_frame.locator(selector).first.click(timeout=2_000)
                                    _log("      已自动点击 hCaptcha checkbox，等待后续 challenge ...")
                                    break
                                except Exception:
                                    continue
                    except Exception as e:
                        _log(f"      自动点击 checkbox 失败，继续等待人工处理: {e}")

                deadline = time.time() + (timeout_ms / 1000)
                logged_event_count = 0
                while time.time() < deadline:
                    events = bridge_state["events"]
                    while logged_event_count < len(events):
                        event_payload = events[logged_event_count]
                        logged_event_count += 1
                        event_type = event_payload.get("type", "event")
                        event_name = event_payload.get("name", "")
                        if event_type == "child_payload" and invisible:
                            tag = (
                                (event_payload.get("payload") or {}).get("tag")
                                or "unknown"
                            )
                            _log(f"      Stripe invisible payload: {tag}")
                            continue
                        if event_type == "frame_ready":
                            _log("      Stripe captcha bridge 已就绪，等待 challenge 加载 ...")
                        elif event_type == "invisible_initialize":
                            _log("      Stripe invisible captcha 初始化 ...")
                        elif event_type == "invisible_execute":
                            _log("      Stripe invisible captcha 开始执行 ...")
                        elif event_name:
                            _log(f"      Stripe captcha 事件: {event_name}")

                    if result_event.wait(timeout=1):
                        result = bridge_state.get("result") or {}
                        raw = result.get("raw") or {}
                        source = raw.get("source") or "bridge_postmessage"
                        if source != "network_checkcaptcha":
                            wait_deadline = time.time() + 1.5
                            while time.time() < wait_deadline:
                                time.sleep(0.1)
                                newer_result = bridge_state.get("result") or {}
                                newer_raw = newer_result.get("raw") or {}
                                newer_source = newer_raw.get("source") or "bridge_postmessage"
                                if newer_source == "network_checkcaptcha":
                                    _log("      bridge result 已出现，但随后拿到真实 checkcaptcha(pass=true) 结果，优先使用网络侧结果")
                                    result = newer_result
                                    raw = newer_raw
                                    source = newer_source
                                    break
                        browser_verify = raw.get("browser_verify") if isinstance(raw, dict) else None
                        if source == "network_checkcaptcha" and not browser_verify and verify_url:
                            wait_deadline = time.time() + 4.0
                            while time.time() < wait_deadline:
                                time.sleep(0.1)
                                newer_result = bridge_state.get("result") or {}
                                newer_raw = newer_result.get("raw") or {}
                                newer_browser_verify = newer_raw.get("browser_verify") if isinstance(newer_raw, dict) else None
                                if newer_browser_verify:
                                    result = newer_result
                                    raw = newer_raw
                                    browser_verify = newer_browser_verify
                                    _log("      已拿到同浏览器上下文内的 verify_challenge 响应")
                                    break
                        token = result.get("response", "")
                        ekey = result.get("ekey", "")
                        _log(
                            "      浏览器 challenge 已完成 "
                            f"(source={source}, token: {len(token)} chars, ekey: {len(ekey)} chars)"
                        )
                        _log(f"      {_describe_challenge_artifact('challenge_token', token)}")
                        _log(f"      {_describe_challenge_artifact('challenge_ekey', ekey)}")
                        if source == "network_checkcaptcha":
                            _log("      challenge 凭证来源: 真实 checkcaptcha(pass=true) 网络结果")
                        if browser_verify:
                            bv_status = browser_verify.get("status")
                            bv_text = str(browser_verify.get("text") or "")
                            _log(
                                "      浏览器内 verify_challenge: "
                                f"status={bv_status} body_len={len(bv_text)}"
                            )
                        return token, ekey, browser_verify

                    if external_solver_proc is not None:
                        rc = external_solver_proc.poll()
                        if rc is not None and not external_solver_exit_logged:
                            external_solver_exit_logged = True
                            _log(f"      external_solver 已退出 rc={rc}")
                            if rc != 0 and not bridge_state.get("result"):
                                raise RuntimeError(f"external_solver 失败 (rc={rc})")

                    if error_event.is_set() or bridge_state.get("error"):
                        err = bridge_state.get("error") or {}
                        raise RuntimeError(
                            "浏览器 challenge 返回错误: "
                            + json.dumps(err, ensure_ascii=False)[:500]
                        )

                    if cancel_event.is_set() or bridge_state.get("cancelled"):
                        raise RuntimeError("浏览器 challenge 被取消")

                raise TimeoutError(f"浏览器 challenge 超时 ({timeout_ms / 1000:.0f}s)")
            finally:
                if page is not None:
                    try:
                        page.close()
                    except Exception:
                        pass
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:
                        pass
                if playwright_ctx is not None:
                    try:
                        playwright_ctx.stop()
                    except Exception:
                        pass
                if external_solver_proc is not None:
                    try:
                        if external_solver_proc.poll() is None:
                            external_solver_proc.terminate()
                            try:
                                external_solver_proc.wait(timeout=5)
                            except Exception:
                                external_solver_proc.kill()
                    except Exception:
                        pass
        finally:
            httpd.shutdown()
            httpd.server_close()


def _build_inline_payment_method_fields(
    card: dict,
    session_id: str,
    ctx: dict,
    runtime_version: str,
) -> dict:
    addr = card.get("address", {})
    payment_method_checkout_config_id = (
        ctx.get("payment_method_checkout_config_id")
        or ctx.get("config_id")
        or ""
    )
    elements_session_config_id = (
        ctx.get("elements_session_config_id")
        or str(uuid.uuid4())
    )
    return {
        "payment_method_data[type]": "card",
        "payment_method_data[allow_redisplay]": "unspecified",
        "payment_method_data[billing_details][name]": card["name"],
        "payment_method_data[billing_details][email]": card["email"],
        "payment_method_data[billing_details][address][country]": addr.get("country", "US"),
        "payment_method_data[billing_details][address][line1]": addr.get("line1", ""),
        "payment_method_data[billing_details][address][city]": addr.get("city", ""),
        "payment_method_data[billing_details][address][postal_code]": addr.get("postal_code", ""),
        "payment_method_data[billing_details][address][state]": addr.get("state", ""),
        "payment_method_data[card][number]": card["number"],
        "payment_method_data[card][cvc]": card["cvc"],
        "payment_method_data[card][exp_month]": str(card["exp_month"]).zfill(2),
        "payment_method_data[card][exp_year]": str(card["exp_year"])[-2:],
        "payment_method_data[pasted_fields]": ctx.get("pasted_fields", "number"),
        "payment_method_data[payment_user_agent]": (
            f"stripe.js/{runtime_version}; stripe-js-v3/{runtime_version}; "
            "payment-element; deferred-intent"
        ),
        "payment_method_data[referrer]": "https://chatgpt.com",
        "payment_method_data[time_on_page]": str(
            ctx.get("time_on_page", random.randint(25000, 55000))
        ),
        "payment_method_data[client_attribution_metadata][client_session_id]": ctx.get("stripe_js_id", str(uuid.uuid4())),
        "payment_method_data[client_attribution_metadata][checkout_session_id]": session_id,
        "payment_method_data[client_attribution_metadata][checkout_config_id]": payment_method_checkout_config_id,
        "payment_method_data[client_attribution_metadata][elements_session_id]": ctx.get("elements_session_id", _gen_elements_session_id()),
        "payment_method_data[client_attribution_metadata][elements_session_config_id]": elements_session_config_id,
        "payment_method_data[client_attribution_metadata][merchant_integration_source]": "elements",
        "payment_method_data[client_attribution_metadata][merchant_integration_subtype]": "payment-element",
        "payment_method_data[client_attribution_metadata][merchant_integration_version]": "2021",
        "payment_method_data[client_attribution_metadata][payment_intent_creation_flow]": "deferred",
        "payment_method_data[client_attribution_metadata][payment_method_selection_flow]": "automatic",
        "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]": "payment",
        "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][1]": "address",
    }


def confirm_payment(
    session: requests.Session,
    pk: str,
    session_id: str,
    pm_id: str,
    card: dict | None,
    captcha_token: str,
    init_resp: dict,
    stripe_ver: str = STRIPE_VERSION_BASE,
    captcha_cfg: dict = None,
    captcha_ekey: str = "",
    ctx: dict = None,
    locale_profile: dict = None,
) -> dict:
    ctx = ctx or {}
    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    guid = ctx.get("guid") or _gen_fingerprint()[0]
    muid = ctx.get("muid") or _gen_fingerprint()[0]
    sid  = ctx.get("sid")  or _gen_fingerprint()[0]
    runtime_version = ctx.get("runtime_version") or DEFAULT_STRIPE_RUNTIME_VERSION
    locale_short = ctx.get("locale") or _locale_short(locale_profile)
    top_checkout_config_id = ctx.get("top_checkout_config_id") or ctx.get("config_id", "")
    elements_session_config_id = (
        ctx.get("elements_session_config_id")
        or str(uuid.uuid4())
    )
    confirm_mode = ctx.get("confirm_mode", "inline_payment_method_data")

    # 优先从 total_summary.due 获取金额（最准确）
    expected_amount = "0"
    total_summary = init_resp.get("total_summary", {})
    if total_summary.get("due") is not None:
        expected_amount = str(total_summary["due"])
    elif init_resp.get("invoice", {}).get("amount_due") is not None:
        expected_amount = str(init_resp["invoice"]["amount_due"])
    else:
        line_items = init_resp.get("line_items", [])
        if line_items:
            total = sum(item.get("amount", 0) for item in line_items)
            expected_amount = str(total)


    init_checksum = init_resp.get("init_checksum", "")
    stripe_js_id = ctx.get("stripe_js_id", str(uuid.uuid4()))
    elements_session_id = ctx.get("elements_session_id", _gen_elements_session_id())
    stripe_hosted_url = (
        ctx.get("stripe_hosted_url")
        or init_resp.get("stripe_hosted_url")
        or ""
    )
    success_return_url = (
        ctx.get("return_url")
        or init_resp.get("return_url")
        or init_resp.get("url")
        or ""
    )
    checkout_url = stripe_hosted_url or success_return_url
    if stripe_hosted_url and success_return_url:
        parsed_hosted = urllib.parse.urlsplit(stripe_hosted_url)
        hosted_query = urllib.parse.urlencode(
            [
                ("returned_from_redirect", "true"),
                ("ui_mode", "custom"),
                ("return_url", success_return_url),
            ]
        )
        checkout_url = urllib.parse.urlunsplit(
            (
                parsed_hosted.scheme,
                parsed_hosted.netloc,
                parsed_hosted.path,
                hosted_query,
                parsed_hosted.fragment,
            )
        )


    ver = STRIPE_VERSION_FULL

    data = {
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "expected_amount": expected_amount,
        "expected_payment_method_type": ctx.get("payment_method_type", "card"),
        "key": pk,
        "_stripe_version": ver,
  
        "init_checksum": init_checksum,
     
        "version": runtime_version,
      
        "return_url": checkout_url,
    
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": stripe_js_id,
        "elements_session_client[locale]": locale_short,
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_session_client[session_id]": elements_session_id,
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
  
        "client_attribution_metadata[client_session_id]": stripe_js_id,
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[checkout_config_id]": top_checkout_config_id,
        "client_attribution_metadata[elements_session_id]": elements_session_id,
        "client_attribution_metadata[elements_session_config_id]": elements_session_config_id,
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[merchant_integration_version]": "custom",
        "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
        "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
    }
    consent_behavior = ctx.get("include_terms_of_service_consent")
    if consent_behavior is None:
        consent_collection = init_resp.get("consent_collection", {}) or {}
        consent_behavior = consent_collection.get("terms_of_service") not in (None, "", "none")
    if consent_behavior:
        data["consent[terms_of_service]"] = "accepted"

    data.update(ctx.get("elements_options_client") or _elements_options_client_payload())

    if ctx.get("js_checksum"):
        data["js_checksum"] = ctx["js_checksum"]
    if ctx.get("rv_timestamp"):
        data["rv_timestamp"] = ctx["rv_timestamp"]

  
    if captcha_token:
        data["passive_captcha_token"] = captcha_token
    if captcha_ekey:
        data["passive_captcha_ekey"] = captcha_ekey

    if confirm_mode == "inline_payment_method_data":
        if not card:
            raise RuntimeError("inline confirm 模式缺少 card 数据")
        if not data.get("js_checksum") or not data.get("rv_timestamp"):
            raise RuntimeError("inline confirm 需要 runtime.js_checksum 与 runtime.rv_timestamp")
        data.update(_build_inline_payment_method_fields(card, session_id, ctx, runtime_version))
    else:
        if not pm_id:
            raise RuntimeError("shared_payment_method 模式缺少 payment_method")
        data["payment_method"] = pm_id
  

    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/confirm"
    _log("[5/6] 确认支付 (confirm) ...")
    _log_request("POST", url, data=data, tag="[5/6] confirm")
    resp = session.post(url, data=data, headers=_stripe_headers())
    _log_response(resp, tag="[5/6] confirm")
    if (
        resp.status_code == 400
        and "consent[terms_of_service]" not in data
        and "terms of service" in (resp.text or "").lower()
    ):
        _log("      confirm 提示需要接受 merchant terms of service，自动补 consent 后重试一次 ...")
        data["consent[terms_of_service]"] = "accepted"
        ctx["include_terms_of_service_consent"] = True
        _log_request("POST", url, data=data, tag="[5/6] confirm(retry_tos)")
        resp = session.post(url, data=data, headers=_stripe_headers())
        _log_response(resp, tag="[5/6] confirm(retry_tos)")
    if resp.status_code != 200:
        raise RuntimeError(f"confirm 失败 [{resp.status_code}]: {resp.text[:500]}")

    confirm_data = resp.json()

    # 从顶层、payment_intent 或 setup_intent 提取 next_action
    next_action = confirm_data.get("next_action")
    if not next_action:
        pi_obj = confirm_data.get("payment_intent")
        if pi_obj and isinstance(pi_obj, dict):
            next_action = pi_obj.get("next_action")
    if not next_action:
        seti = _find_setup_intent(confirm_data)
        if seti and isinstance(seti, dict):
            next_action = seti.get("next_action")

    if next_action and next_action.get("type") == "use_stripe_sdk":
        _log("      触发 3DS/challenge 验证，正在处理 ...")
        _handle_3ds(session, pk, confirm_data, captcha_token, stripe_ver, captcha_cfg,
                    locale_profile=locale_profile, ctx=ctx)

    return confirm_data


def _extract_terminal_payment_failure(intent_obj: dict, source_kind: str = "setup_intent") -> dict | None:
    """把 Stripe 已经明确给出的终态失败对象标准化，避免继续误判成“要重试/继续轮询”."""
    if not isinstance(intent_obj, dict):
        return None

    status = intent_obj.get("status", "")
    error = intent_obj.get("last_setup_error") or intent_obj.get("last_payment_error") or {}
    if status != "requires_payment_method" or not error:
        return None

    err_code = (error.get("code") or "").lower()
    err_msg = (error.get("message") or "").lower()
    if "captcha" in err_msg or "authentication_failure" in err_code:
        return None

    return {
        "state": "failed",
        "payment_object_status": status,
        "source_kind": source_kind,
        "error": error,
        source_kind: intent_obj,
    }


def _find_setup_intent(data: dict) -> dict | None:
    si = data.get("setup_intent")
    if si:
        return si
    pm_obj = data.get("payment_method_object")
    if pm_obj and isinstance(pm_obj, dict):
        return pm_obj.get("setup_intent")
    raw = json.dumps(data)
    m = re.search(r"seti_[A-Za-z0-9]+", raw)
    if m:
        return {"id": m.group(0)}
    return None


def _build_3ds_browser_payload(locale_profile: dict, ctx: dict) -> dict:
    return {
        "fingerprintAttempted": False,
        "fingerprintData": None,
        "challengeWindowSize": None,
        "threeDSCompInd": "Y",
        "browserJavaEnabled": False,
        "browserJavascriptEnabled": True,
        "browserLanguage": locale_profile.get("browser_language", "en-US"),
        "browserColorDepth": str(locale_profile.get("color_depth", 24)),
        "browserScreenHeight": str(locale_profile.get("screen_h", 1080)),
        "browserScreenWidth": str(locale_profile.get("screen_w", 1920)),
        "browserTZ": str(_browser_tz_offset(locale_profile)),
        "browserUserAgent": USER_AGENT,
    }


def _handle_3ds(
    session: requests.Session,
    pk: str,
    confirm_data: dict,
    captcha_token: str,
    stripe_ver: str = STRIPE_VERSION_BASE,
    captcha_cfg: dict = None,
    locale_profile: dict = None,
    ctx: dict = None,
):
    """处理 3DS2 认证流程 (模拟浏览器: captcha → verify_challenge → Apata指纹 → 3ds2/authenticate)"""
    locale_profile = locale_profile or LOCALE_PROFILES["US"]
    ctx = ctx or {}
    browser_challenge_cfg = ctx.get("browser_challenge") or {}
    stage_proxy_cfg = ctx.get("stage_proxies") or {}
    raw = json.dumps(confirm_data)

    # 查找 setatt_ (直接在 confirm 响应中)
    source_match = re.search(r"(setatt_[A-Za-z0-9]+)", raw)
    source = source_match.group(1) if source_match else None
    _log(f"      3DS: setatt_ = {source}")

    # 查找 seti_ 和 client_secret
    seti_match = re.search(r"(seti_[A-Za-z0-9]+)", raw)
    seti_id = seti_match.group(1) if seti_match else None
    _log(f"      3DS: seti_id = {seti_id}")

    client_secret = None
    if seti_id:
        cs_match = re.search(rf"({re.escape(seti_id)}_secret_[A-Za-z0-9]+)", raw)
        if cs_match:
            client_secret = cs_match.group(1)
    _log(f"      3DS: client_secret = {client_secret[:40] + '...' if client_secret else None}")


    challenge_site_key = None
    challenge_rqdata = ""
    challenge_verify_url = None
    intent_id = None
    intent_client_secret = None

    # 优先从 payment_intent 提取 challenge 信息
    pi_obj = confirm_data.get("payment_intent")
    if pi_obj and isinstance(pi_obj, dict):
        intent_id = pi_obj.get("id")
        intent_client_secret = pi_obj.get("client_secret")
        na = pi_obj.get("next_action", {})
        sdk_info = na.get("use_stripe_sdk", {})
        stripe_js = sdk_info.get("stripe_js", {})
        if stripe_js.get("site_key"):
            challenge_site_key = stripe_js["site_key"]
            challenge_rqdata = stripe_js.get("rqdata", "")
            challenge_verify_url = stripe_js.get("verification_url", "")
            _log(f"      检测到 payment_intent confirmation challenge (site_key: {challenge_site_key[:20]}...)")

    # 如果 payment_intent 没有，再从 setup_intent 提取
    if not challenge_site_key:
        seti_obj = _find_setup_intent(confirm_data)
        if seti_obj and isinstance(seti_obj, dict):
            na = seti_obj.get("next_action", {})
            sdk_info = na.get("use_stripe_sdk", {})
            stripe_js = sdk_info.get("stripe_js", {})
            if stripe_js.get("site_key"):
                challenge_site_key = stripe_js["site_key"]
                challenge_rqdata = stripe_js.get("rqdata", "")
                challenge_verify_url = stripe_js.get("verification_url", "")
                _log(f"      检测到 setup_intent confirmation challenge (site_key: {challenge_site_key[:20]}...)")

    # 用于 verify_challenge 的 intent 标识（兼容 pi_ 和 seti_）
    if not intent_id:
        intent_id = seti_id
    if not intent_client_secret:
        intent_client_secret = client_secret

    merchant_id = (
        confirm_data.get("account_settings", {}).get("account_id")
        or ctx.get("merchant_account_id")
        or ""
    )
    effective_browser_challenge_cfg = dict(browser_challenge_cfg or {})
    verify_browser_proxy = _resolve_stage_proxy_cfg(stage_proxy_cfg, "verify_challenge_browser")
    if verify_browser_proxy is not _PROXY_OVERRIDE_SENTINEL:
        effective_browser_challenge_cfg["proxy_url"] = _build_proxy_url_from_cfg(verify_browser_proxy)

    if challenge_site_key and intent_id and intent_client_secret and (captcha_cfg or browser_challenge_cfg.get("enabled")):
        # 构建 verify_challenge URL
        if challenge_verify_url and challenge_verify_url.startswith("/"):
            actual_verify_url = f"{STRIPE_API}{challenge_verify_url}"
        elif intent_id.startswith("pi_"):
            actual_verify_url = f"{STRIPE_API}/v1/payment_intents/{intent_id}/verify_challenge"
        else:
            actual_verify_url = f"{STRIPE_API}/v1/setup_intents/{intent_id}/verify_challenge"

        challenge_hcaptcha_cfg = {
            "site_key": challenge_site_key,
            "rqdata": challenge_rqdata,
            "is_invisible": False,
            "website_url": _build_stripe_hcaptcha_url(invisible=False),
        }

        _log("      解 challenge captcha ...")
        browser_verify_result = None
        verify_form_base = {
            "client_secret": intent_client_secret,
            "captcha_vendor_name": "hcaptcha",
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        if browser_challenge_cfg.get("enabled"):
            effective_browser_challenge_cfg = dict(effective_browser_challenge_cfg or {})
            if not effective_browser_challenge_cfg.get("external_solver"):
                bundled_solver = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "hcaptcha_auto_solver.py",
                )
                python_candidates = [
                    str(os.environ.get("CTFML_PYTHON") or "").strip(),
                    "~/.venvs/ctfml/bin/python",
                    sys.executable,
                ]
                solver_python = next((p for p in python_candidates if p and os.path.exists(p)), sys.executable)
                auto_vlm_cfg = {
                    "enabled": True,
                    "model": "gpt-5.4",
                    "base_url": "https://YOUR_VLM_ENDPOINT/api",
                    "api_key": "",
                    "timeout_s": 45,
                }
                effective_browser_challenge_cfg["external_solver"] = {
                    "enabled": True,
                    "python": solver_python,
                    "script": bundled_solver,
                    "out_dir": "/tmp/hcaptcha_auto_solver_live",
                    "timeout_s": max(180, int(effective_browser_challenge_cfg.get("timeout_ms", 300000) / 1000)),
                    "headed": not bool(effective_browser_challenge_cfg.get("headless", False)),
                    "vlm": auto_vlm_cfg,
                }
            challenge_token, challenge_ekey, browser_verify_result = solve_stripe_hcaptcha_in_browser(
                challenge_hcaptcha_cfg,
                merchant_id=merchant_id,
                locale=locale_profile.get("browser_locale", "en-US"),
                browser_cfg=effective_browser_challenge_cfg,
                verify_url=actual_verify_url,
                verify_form_base=verify_form_base,
            )
        else:
            challenge_token, challenge_ekey = solve_hcaptcha(
                captcha_cfg,
                challenge_hcaptcha_cfg,
                max_retries=3,
                session=session,
            )

        _log(f"      {_describe_challenge_artifact('challenge_response_token', challenge_token)}")
        if challenge_ekey:
            _log(f"      {_describe_challenge_artifact('challenge_response_ekey', challenge_ekey)}")
        else:
            _log("      challenge_response_ekey: <empty>")
        _log(f"      verify_challenge ({intent_id[:30]}...) ...")
        verify_data = {
            **verify_form_base,
            "challenge_response_token": challenge_token,
        }
        if challenge_ekey:
            verify_data["challenge_response_ekey"] = challenge_ekey

        verify_status_code = 0
        verify_text = ""
        if browser_verify_result and int(browser_verify_result.get("status") or 0):
            verify_status_code = int(browser_verify_result.get("status") or 0)
            verify_text = str(browser_verify_result.get("text") or "")
            _log_request("POST", actual_verify_url, data=verify_data, tag="[5/6] verify_challenge(browser)")
            _log(f"      使用浏览器内 verify_challenge 响应，跳过 Python requests verify")
        else:
            _log_request("POST", actual_verify_url, data=verify_data, tag="[5/6] verify_challenge")
            with _http_session_stage_proxy(session, stage_proxy_cfg, "verify_challenge"):
                resp = session.post(actual_verify_url, data=verify_data, headers=_stripe_headers())
            _log_response(resp, tag="[5/6] verify_challenge")
            verify_status_code = resp.status_code
            verify_text = resp.text

        if verify_status_code != 200:
            err_text = verify_text[:300]
            _log(f"      verify_challenge 返回 {verify_status_code}: {err_text}")
            if "no valid challenge" in err_text.lower():
                raise ChallengeReconfirmRequired(
                    f"challenge 已失效 (Stripe 返回 {verify_status_code}), 需要重新 confirm 获取新的 challenge"
                )
            raise RuntimeError(f"verify_challenge 失败 [{verify_status_code}]: {err_text}")

        verify_result = (
            browser_verify_result.get("json")
            if browser_verify_result and isinstance(browser_verify_result.get("json"), dict)
            else json.loads(verify_text)
        )
        verify_status = verify_result.get("status", "unknown")
        _log(f"      verify_challenge 状态: {verify_status}")

        # 检测 captcha challenge 失败（payment_intent 用 last_payment_error，setup_intent 用 last_setup_error）
        payment_error = verify_result.get("last_payment_error", {})
        setup_error = verify_result.get("last_setup_error", {})
        error_to_check = payment_error if payment_error else setup_error
        if error_to_check:
            err_code = error_to_check.get("code", "")
            err_msg = error_to_check.get("message", "")
            err_decline = error_to_check.get("decline_code", "")
            _log(
                "      verify_challenge error: "
                f"code={err_code or '-'} decline_code={err_decline or '-'} msg={err_msg or '-'}"
            )
            if "captcha" in err_msg.lower() or "authentication_failure" in err_code:
                raise ChallengeReconfirmRequired(
                    f"challenge captcha 被 Stripe 拒绝: [{err_code}] {err_msg}"
                )

        source_kind = "payment_intent" if intent_id.startswith("pi_") else "setup_intent"
        terminal_failure = _extract_terminal_payment_failure(verify_result, source_kind=source_kind)
        if terminal_failure:
            ctx["terminal_result"] = terminal_failure
            err = terminal_failure.get("error", {})
            _log(
                "      verify_challenge 已落到终态失败: "
                f"[{err.get('code', '?')}] {err.get('decline_code', '')} {err.get('message', '')}".strip()
            )
            return

        if verify_status == "requires_payment_method":
            raise ChallengeReconfirmRequired(
                "verify_challenge 后 setup_intent 进入 requires_payment_method，需要重新 confirm 获取新的 challenge"
            )

        # verify 成功, 从响应中提取 setatt_
        verify_raw = json.dumps(verify_result)
        new_source = re.search(r"(setatt_[A-Za-z0-9]+)", verify_raw)
        if new_source:
            source = new_source.group(1)
            _log(f"      从 verify 响应中获取 setatt_: {source[:30]}...")

    elif seti_id and client_secret and not source:
        # 没有 challenge 但也没有 setatt_, 尝试原始 verify_challenge
        verify_url = f"{STRIPE_API}/v1/setup_intents/{seti_id}/verify_challenge"
        _log(f"      verify_challenge (seti: {seti_id[:30]}...) ...")
        verify_data = {
            "client_secret": client_secret,
            "challenge_response_token": captcha_token,
            "captcha_vendor_name": "hcaptcha",
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        if browser_challenge_cfg.get("enabled"):
            fallback_hcaptcha_cfg = {
                "site_key": challenge_site_key or HCAPTCHA_SITE_KEY_FALLBACK,
                "rqdata": challenge_rqdata,
                "is_invisible": False,
                "website_url": _build_stripe_hcaptcha_url(invisible=False),
            }
            challenge_token, challenge_ekey, _ = solve_stripe_hcaptcha_in_browser(
                fallback_hcaptcha_cfg,
                merchant_id=merchant_id,
                locale=locale_profile.get("browser_locale", "en-US"),
                browser_cfg=browser_challenge_cfg,
            )
            verify_data["challenge_response_token"] = challenge_token
            if challenge_ekey:
                verify_data["challenge_response_ekey"] = challenge_ekey
        elif captcha_cfg:
            fallback_hcaptcha_cfg = {
                "site_key": challenge_site_key or HCAPTCHA_SITE_KEY_FALLBACK,
                "rqdata": challenge_rqdata,
                "is_invisible": False,
                "website_url": _build_stripe_hcaptcha_url(invisible=False),
            }
            challenge_token, challenge_ekey = solve_hcaptcha(
                captcha_cfg,
                fallback_hcaptcha_cfg,
                max_retries=3,
                session=session,
            )
            verify_data["challenge_response_token"] = challenge_token
            if challenge_ekey:
                verify_data["challenge_response_ekey"] = challenge_ekey
        _log(f"      {_describe_challenge_artifact('challenge_response_token', verify_data.get('challenge_response_token', ''))}")
        if verify_data.get("challenge_response_ekey"):
            _log(f"      {_describe_challenge_artifact('challenge_response_ekey', verify_data['challenge_response_ekey'])}")
        else:
            _log("      challenge_response_ekey: <empty>")
        _log_request("POST", verify_url, data=verify_data, tag="[5/6] verify_challenge(fallback)")
        with _http_session_stage_proxy(session, stage_proxy_cfg, "verify_challenge"):
            resp = session.post(verify_url, data=verify_data, headers=_stripe_headers())
        _log_response(resp, tag="[5/6] verify_challenge(fallback)")
        if resp.status_code == 200:
            si_result = resp.json()
            _log(f"      verify_challenge 状态: {si_result.get('status', 'unknown')}")
            # 检测 captcha challenge 失败
            setup_error = si_result.get("last_setup_error", {})
            if setup_error:
                err_code = setup_error.get("code", "")
                err_msg = setup_error.get("message", "")
                err_decline = setup_error.get("decline_code", "")
                _log(
                    "      verify_challenge error: "
                    f"code={err_code or '-'} decline_code={err_decline or '-'} msg={err_msg or '-'}"
                )
                if "captcha" in err_msg.lower() or "authentication_failure" in err_code:
                    raise ChallengeReconfirmRequired(f"challenge captcha 被 Stripe 拒绝: [{err_code}] {err_msg}")
            verify_raw = json.dumps(si_result)
            new_source = re.search(r"(setatt_[A-Za-z0-9]+)", verify_raw)
            if new_source:
                source = new_source.group(1)
        else:
            _log(f"      verify_challenge 返回 {resp.status_code}: {resp.text[:300]}")
            if "no valid challenge" in resp.text.lower():
                raise ChallengeReconfirmRequired(
                    f"challenge 已失效 (Stripe 返回 {resp.status_code}), 需要重新 confirm 获取新的 challenge"
                )

    if source:
        auth_url = f"{STRIPE_API}/v1/3ds2/authenticate"
        _log(f"      3DS2 authenticate (source: {source[:30]}...) ...")
        auth_data = {
            "source": source,
            "browser": json.dumps(_build_3ds_browser_payload(locale_profile, ctx)),
            "one_click_authn_device_support[hosted]": "false",
            "one_click_authn_device_support[same_origin_frame]": "false",
            "one_click_authn_device_support[spc_eligible]": "true",
            "one_click_authn_device_support[webauthn_eligible]": "true",
            "one_click_authn_device_support[publickey_credentials_get_allowed]": "true",
            "frontend_execution": ctx.get("frontend_execution", DEFAULT_FRONTEND_EXECUTION),
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        _log_request("POST", auth_url, data=auth_data, tag="[5/6] 3ds2/authenticate")
        with _http_session_stage_proxy(session, stage_proxy_cfg, "three_ds_authenticate"):
            resp = session.post(auth_url, data=auth_data, headers=_stripe_headers())
        _log_response(resp, tag="[5/6] 3ds2/authenticate")
        if resp.status_code == 200:
            result = resp.json()
            state = result.get("state", "unknown")
            trans_status = result.get("ares", {}).get("transStatus", "?")
            _log(f"      3DS2 结果: state={state}, transStatus={trans_status}")
            ctx["three_ds_result"] = {
                "state": state,
                "trans_status": trans_status,
                "source": result.get("source") or source,
                "acs_url": result.get("ares", {}).get("acsURL"),
                "creq": result.get("creq"),
                "three_ds_server_trans_id": result.get("ares", {}).get("threeDSServerTransID"),
            }
            if state == "challenge_required":
                _log("      3DS2 进入 challenge_required；这不是废卡，后续需要浏览器侧完成 challenge。")
                return
        else:
            _log(f"      3DS2 authenticate 返回 {resp.status_code}: {resp.text[:200]}")
    else:
        _log("      ⚠ 没有 setatt_ source, 跳过 3DS2 authenticate")
        raise RuntimeError("3DS 验证失败: 未获取到 setatt_ source, 无法完成认证")

  
    if seti_id and client_secret:
        time.sleep(3)
        poll_url = f"{STRIPE_API}/v1/setup_intents/{seti_id}"
        poll_params = {
            "client_secret": client_secret,
            "is_stripe_sdk": "false",
            "key": pk,
            "_stripe_version": STRIPE_VERSION_FULL,
        }
        _log(f"      查询 setup_intent 最终状态 ...")
        _log_request("GET", poll_url, params=poll_params, tag="[5/6] setup_intent状态")
        with _http_session_stage_proxy(session, stage_proxy_cfg, "setup_intent_poll"):
            poll_resp = session.get(poll_url, params=poll_params, headers=_stripe_headers())
        _log_response(poll_resp, tag="[5/6] setup_intent状态")
        if poll_resp.status_code == 200:
            si_data = poll_resp.json()
            si_status = si_data.get("status", "unknown")
            _log(f"      setup_intent 状态: {si_status}")
            terminal_failure = _extract_terminal_payment_failure(si_data, source_kind="setup_intent")
            if terminal_failure:
                ctx["terminal_result"] = terminal_failure
                err = terminal_failure.get("error", {})
                _log(
                    "      setup_intent 已落到终态失败: "
                    f"[{err.get('code', '?')}] {err.get('decline_code', '')} {err.get('message', '')}".strip()
                )
        else:
            _log("      ⚠ 无 seti_id / client_secret, 跳过 setup_intent 查询")


def poll_result(session: requests.Session, pk: str, session_id: str, stripe_ver: str = STRIPE_VERSION_BASE) -> dict:
    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/poll"
    params = {
        "key": pk,
        "_stripe_version": stripe_ver,
    }

    _log("[6/6] 轮询支付结果 ...")
    for attempt in range(30):
        time.sleep(2)
        _log_request("GET", url, params=params, tag=f"[6/6] poll({attempt+1}/30)")
        resp = session.get(url, params=params, headers=_stripe_headers())
        _log_response(resp, tag=f"[6/6] poll({attempt+1}/30)")
        if resp.status_code != 200:
            _log(f"      poll 返回 {resp.status_code}, 重试 ...")
            continue

        data = resp.json()
        state = data.get("state", "unknown")
        payment_status = data.get("payment_object_status", "unknown")

        if state == "succeeded":
            return_url = data.get("return_url", "")
            _log(f"\n{'='*60}")
            _log(f"  支付成功!")
            _log(f"  state:          {state}")
            _log(f"  payment_status: {payment_status}")
            _log(f"  mode:           {data.get('mode', '?')}")
            _log(f"  return_url:     {return_url}")
            _log(f"{'='*60}\n")
            return data

        if state in ("failed", "expired", "canceled"):
            _log(f"\n  支付失败: state={state}")
            _log_raw(f"  完整 poll 响应: {json.dumps(data, ensure_ascii=False, indent=4)}")
            return data

        _log(f"      state={state}, payment_status={payment_status} ({attempt + 1}/30)")

    raise TimeoutError("轮询超时 (60s)")
def _resolve_config_relative_path(cfg: dict, path_value: str, default_value: str = "") -> str:
    candidate = str(path_value or default_value or "").strip()
    if not candidate:
        return ""
    if os.path.isabs(candidate):
        return candidate

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dirs = []
    loaded_from = str(cfg.get("_loaded_from") or "").strip()
    if loaded_from:
        base_dirs.append(os.path.dirname(os.path.abspath(loaded_from)))
    base_dirs.append(script_dir)
    base_dirs.append(os.path.dirname(script_dir))

    seen = set()
    for base_dir in base_dirs:
        if not base_dir or base_dir in seen:
            continue
        seen.add(base_dir)
        resolved = os.path.abspath(os.path.join(base_dir, candidate))
        if os.path.exists(resolved):
            return resolved

    first_base = base_dirs[0] if base_dirs else script_dir
    return os.path.abspath(os.path.join(first_base, candidate))


def _normalize_terminal_result(payload: dict | None) -> dict:
    data = json.loads(json.dumps(payload or {}))
    data.setdefault("source_kind", "setup_intent")
    data.setdefault("payment_object_status", "requires_payment_method")
    err = data.setdefault("error", {})
    err.setdefault("code", "card_declined")
    err.setdefault("decline_code", "generic_decline")
    err.setdefault("message", "Your card was declined.")
    return data


def _build_offline_terminal_result(offline_cfg: dict) -> dict:
    explicit = offline_cfg.get("terminal_result")
    if explicit:
        return _normalize_terminal_result(explicit)

    scenario = str(offline_cfg.get("scenario") or "3ds_succeeded_card_declined").strip().lower()
    if scenario == "challenge_failed":
        return _normalize_terminal_result(
            {
                "source_kind": "setup_intent",
                "payment_object_status": "requires_payment_method",
                "error": {
                    "code": "setup_intent_authentication_failure",
                    "decline_code": "",
                    "message": "Captcha challenge failed. Try again with a different payment method.",
                },
            }
        )
    if scenario in {"no_3ds_card_declined", "direct_decline"}:
        return _normalize_terminal_result(
            {
                "source_kind": "payment_intent",
                "payment_object_status": "requires_payment_method",
                "error": {
                    "code": "card_declined",
                    "decline_code": "generic_decline",
                    "message": "Your card was declined.",
                },
            }
        )

    return _normalize_terminal_result(
        {
            "source_kind": "setup_intent",
            "payment_object_status": "requires_payment_method",
            "error": {
                "code": "card_declined",
                "decline_code": "generic_decline",
                "message": "Your card was declined.",
            },
        }
    )


def _build_offline_fresh_checkout_info(cfg: dict) -> dict:
    fresh_cfg = cfg.get("fresh_checkout") or {}
    offline_cfg = cfg.get("offline_replay") or {}
    flows_path = _resolve_config_relative_path(
        cfg,
        offline_cfg.get("flows_path") or fresh_cfg.get("flows_path"),
        "../flows",
    )
    bootstrap = _load_fresh_checkout_bootstrap(flows_path)
    body = _build_fresh_checkout_body(fresh_cfg, bootstrap)
    checkout_resp = bootstrap.get("checkout_response") or {}
    checkout_session_id, processor_entity, checkout_url = _extract_checkout_identifiers(checkout_resp)
    if not checkout_url and checkout_session_id and processor_entity:
        checkout_url = f"https://chatgpt.com/checkout/{processor_entity}/{checkout_session_id}"
    if not checkout_url:
        raise FreshCheckoutAuthError("离线回放未能从 flows 还原 checkout_url")

    return {
        "url": checkout_url,
        "session_id": checkout_session_id,
        "processor_entity": processor_entity,
        "body": body,
        "bootstrap": bootstrap,
    }
