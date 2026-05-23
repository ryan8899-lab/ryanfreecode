"""Upload/download/run small debug scripts from the WebUI.

This is intentionally separate from the main pipeline runner: Ryan often tweaks a
one-off script while diagnosing browser/payment flows and needs a quick way to
upload it, run it, then see logs and screenshots without SSHing into the box.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from ..auth import CurrentUser
from .. import settings as s

router = APIRouter(prefix="/api/debug-scripts", tags=["debug-scripts"])

ROOT = s.get_data_dir() / "debug_scripts"
SCRIPTS_DIR = ROOT / "scripts"
RUNS_DIR = ROOT / "runs"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_SUFFIXES = {".py", ".sh", ".txt"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
PATH_RE = re.compile(r"(?P<path>(?:/tmp|/root/Gpt-Agreement-Payment|output|\./output)[^\s'\"<>]+\.(?:png|jpg|jpeg|webp|gif))", re.I)

_lock = threading.Lock()
_proc: Optional[subprocess.Popen] = None
_current_run_id: str = ""
_started_at: Optional[float] = None
_ended_at: Optional[float] = None
_exit_code: Optional[int] = None
_cmd: list[str] = []
_log_lines: list[dict] = []
_seq = 0
_artifacts: list[dict] = []


class RunRequest(BaseModel):
    filename: str
    args: list[str] = Field(default_factory=list)
    interpreter: str = Field(default="auto", pattern="^(auto|python|bash)$")
    paypal_guest_prefill: bool = False


def _ensure_dirs() -> None:
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)


def _safe_name(name: str) -> str:
    base = Path(name or "").name.strip()
    if not base or base in {".", ".."}:
        raise HTTPException(status_code=400, detail="文件名无效")
    suffix = Path(base).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"只允许上传：{', '.join(sorted(ALLOWED_SUFFIXES))}")
    return base


def _script_path(filename: str) -> Path:
    _ensure_dirs()
    name = _safe_name(filename)
    p = (SCRIPTS_DIR / name).resolve()
    if SCRIPTS_DIR.resolve() not in p.parents:
        raise HTTPException(status_code=400, detail="路径越界")
    return p


def _run_dir(run_id: str | None = None) -> Path:
    rid = run_id or _current_run_id
    if not rid:
        raise HTTPException(status_code=404, detail="还没有运行记录")
    p = (RUNS_DIR / rid).resolve()
    if RUNS_DIR.resolve() not in p.parents:
        raise HTTPException(status_code=400, detail="路径越界")
    return p


def _append(line: str) -> None:
    global _seq, _log_lines
    with _lock:
        _seq += 1
        _log_lines.append({"seq": _seq, "ts": time.time(), "line": line})
        if len(_log_lines) > 3000:
            _log_lines = _log_lines[-2000:]


def _artifact_url(run_id: str, rel: str) -> str:
    return f"/api/debug-scripts/runs/{run_id}/files/{rel}"


def _add_artifact(path: Path, *, source: str = "run") -> None:
    global _artifacts
    if not path.exists() or not path.is_file():
        return
    if path.suffix.lower() not in IMAGE_SUFFIXES:
        return
    run_dir = _run_dir()
    try:
        resolved = path.resolve()
    except Exception:
        return
    try:
        rel = resolved.relative_to(run_dir.resolve()).as_posix()
    except ValueError:
        # Copy screenshots from /tmp or project paths into the current run dir
        # so the browser can fetch them through authenticated WebUI routes.
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", resolved.name)[:120] or "screenshot.png"
        dst = run_dir / safe
        if dst.exists():
            dst = run_dir / f"{int(time.time())}_{safe}"
        try:
            shutil.copy2(resolved, dst)
            resolved = dst.resolve()
            rel = resolved.relative_to(run_dir.resolve()).as_posix()
        except Exception:
            return
    url = _artifact_url(_current_run_id, rel)
    with _lock:
        if any(a.get("url") == url for a in _artifacts):
            return
        _artifacts.append({
            "name": resolved.name,
            "rel": rel,
            "url": url,
            "source": source,
            "size": resolved.stat().st_size,
            "mtime": resolved.stat().st_mtime,
        })


def _scan_line_for_artifacts(line: str) -> None:
    for m in PATH_RE.finditer(line):
        raw = m.group("path").rstrip(".,);]")
        p = Path(raw)
        if not p.is_absolute():
            p = s.ROOT / raw.lstrip("./")
        _add_artifact(p, source="log")


def _scan_run_dir() -> None:
    try:
        rd = _run_dir()
    except HTTPException:
        return
    for p in rd.rglob("*"):
        _add_artifact(p, source="run")


def _drain(proc: subprocess.Popen) -> None:
    global _ended_at, _exit_code
    try:
        if proc.stdout is not None:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                if not line:
                    continue
                _append(line)
                _scan_line_for_artifacts(line)
    finally:
        proc.wait()
        _scan_run_dir()
        with _lock:
            _ended_at = time.time()
            _exit_code = proc.returncode
        _append(f"[debug-run] exited code={proc.returncode}")


def _build_cmd(script: Path, interpreter: str, args: list[str]) -> list[str]:
    suffix = script.suffix.lower()
    if interpreter == "python" or (interpreter == "auto" and suffix == ".py"):
        py = os.getenv("GPT_PAYMENT_PYTHON", "/root/Gpt-Agreement-Payment/venv/bin/python")
        return [py, "-u", str(script), *[str(a) for a in args]]
    if interpreter == "bash" or (interpreter == "auto" and suffix == ".sh"):
        return ["bash", str(script), *[str(a) for a in args]]
    raise HTTPException(status_code=400, detail="请选择 python 或 bash 运行；.txt 仅用于保存/下载")


def _paypal_guest_prefill_env(run_dir: Path) -> dict[str, str]:
    """Fetch PayPal guest non-payment identity and expose it to debug scripts.

    The helper in CTF-pay/payment.py intentionally ignores upstream card-number /
    expiry / CVV fields.  We only pass safe guest form fields for Ryan's PayPal
    handoff debugging.
    """
    try:
        import sys
        ctf_pay = str(s.CTF_PAY_DIR)
        if ctf_pay not in sys.path:
            sys.path.insert(0, ctf_pay)
        import card  # type: ignore
        info = card._fetch_paypal_guest_nonpayment_info()  # noqa: SLF001 - project-local debug hook
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"PayPal 资料接口请求失败: {type(e).__name__}: {e}") from e
    if not isinstance(info, dict):
        raise HTTPException(status_code=502, detail="PayPal 资料接口返回异常")
    safe = {
        "phone": str(info.get("phone") or ""),
        "first": str(info.get("first") or ""),
        "last": str(info.get("last") or ""),
        "line1": str(info.get("line1") or ""),
        "city": str(info.get("city") or ""),
        "state": str(info.get("state") or ""),
        "zip": str(info.get("zip") or ""),
    }
    safe["name"] = " ".join(x for x in [safe["first"], safe["last"]] if x).strip()
    path = run_dir / "paypal_guest_prefill.json"
    path.write_text(__import__("json").dumps(safe, ensure_ascii=False, indent=2), encoding="utf-8")
    _append(
        "[debug-run] PayPal guest prefill: "
        f"name={safe['name'] or '-'} phone={safe['phone'] or '-'} "
        f"city={safe['city'] or '-'} state={safe['state'] or '-'} zip={safe['zip'] or '-'}"
    )
    return {
        "PAYPAL_GUEST_PREFILL_JSON": str(path),
        "PAYPAL_GUEST_PHONE": safe["phone"],
        "PAYPAL_GUEST_FIRST": safe["first"],
        "PAYPAL_GUEST_LAST": safe["last"],
        "PAYPAL_GUEST_NAME": safe["name"],
        "PAYPAL_GUEST_ADDRESS1": safe["line1"],
        "PAYPAL_GUEST_CITY": safe["city"],
        "PAYPAL_GUEST_STATE": safe["state"],
        "PAYPAL_GUEST_ZIP": safe["zip"],
    }


def _status() -> dict:
    running = _proc is not None and _proc.poll() is None
    return {
        "running": running,
        "run_id": _current_run_id,
        "started_at": _started_at,
        "ended_at": _ended_at,
        "exit_code": None if running else _exit_code,
        "pid": _proc.pid if running and _proc else None,
        "cmd": _cmd,
        "log_count": _seq,
        "artifacts": list(_artifacts),
    }


@router.get("/scripts")
def list_scripts(user: str = CurrentUser):
    _ensure_dirs()
    items = []
    for p in sorted(SCRIPTS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            items.append({"filename": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime})
    return {"items": items}


@router.post("/upload")
async def upload_script(file: UploadFile = File(...), user: str = CurrentUser):
    path = _script_path(file.filename or "")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="脚本太大，最多 2MB")
    path.write_bytes(data)
    if path.suffix.lower() == ".sh":
        path.chmod(path.stat().st_mode | 0o111)
    return {"filename": path.name, "size": path.stat().st_size, "mtime": path.stat().st_mtime}


@router.get("/scripts/{filename}/download")
def download_script(filename: str, user: str = CurrentUser):
    path = _script_path(filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="脚本不存在")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@router.post("/start")
def start(req: RunRequest, user: str = CurrentUser):
    global _proc, _current_run_id, _started_at, _ended_at, _exit_code, _cmd, _log_lines, _seq, _artifacts
    script = _script_path(req.filename)
    if not script.exists():
        raise HTTPException(status_code=404, detail="脚本不存在")
    with _lock:
        if _proc is not None and _proc.poll() is None:
            raise HTTPException(status_code=409, detail="已有调试脚本在运行")
        _current_run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        rd = _run_dir(_current_run_id)
        rd.mkdir(parents=True, exist_ok=True)
        _started_at = time.time()
        _ended_at = None
        _exit_code = None
        _log_lines = []
        _seq = 0
        _artifacts = []
        _cmd = _build_cmd(script, req.interpreter, req.args)
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "WEBUI_DEBUG_RUN_DIR": str(_run_dir(_current_run_id))}
    _append(f"[debug-run] run_id={_current_run_id}")
    _append("[debug-run] " + " ".join(_cmd))
    rd_for_env = _run_dir(_current_run_id)
    if req.paypal_guest_prefill:
        env.update(_paypal_guest_prefill_env(rd_for_env))
    try:
        proc = subprocess.Popen(
            _cmd,
            cwd=str(s.ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError as e:
        with _lock:
            _ended_at = time.time()
            _exit_code = -1
        raise HTTPException(status_code=500, detail=f"启动失败：{e}") from e
    with _lock:
        _proc = proc
    threading.Thread(target=_drain, args=(proc,), daemon=True).start()
    return _status()


@router.post("/stop")
def stop(user: str = CurrentUser):
    proc = _proc
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            proc.terminate()
    return _status()


@router.get("/status")
def status(user: str = CurrentUser):
    _scan_run_dir()
    return _status()


@router.get("/logs")
def logs(tail: int = 500, user: str = CurrentUser):
    with _lock:
        return {"lines": _log_lines[-tail:]}


@router.get("/stream")
async def stream(user: str = CurrentUser):
    last_seq = 0

    async def gen():
        nonlocal last_seq
        while True:
            with _lock:
                new_lines = [e for e in _log_lines if e["seq"] > last_seq][:500]
                st = _status()
            for entry in new_lines:
                last_seq = entry["seq"]
                yield {"event": "line", "data": __import__("json").dumps(entry)}
            yield {"event": "status", "data": __import__("json").dumps(st)}
            if not st["running"]:
                break
            import asyncio
            await asyncio.sleep(0.5)

    return EventSourceResponse(gen())


@router.get("/runs/{run_id}/files/{rel:path}")
def run_file(run_id: str, rel: str, user: str = CurrentUser):
    rd = _run_dir(run_id)
    p = (rd / rel).resolve()
    try:
        p.relative_to(rd.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="路径越界")
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    media = "image/png" if p.suffix.lower() == ".png" else "application/octet-stream"
    return FileResponse(p, filename=p.name, media_type=media)
