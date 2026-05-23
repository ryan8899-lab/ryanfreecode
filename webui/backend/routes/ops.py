from __future__ import annotations

import os
import subprocess

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/ops", tags=["ops"])


class NotifyRequest(BaseModel):
    key: str = Field(default="webhook")
    title: str = Field(default="Gpt-Pay运维")
    message: str = Field(default="")
    cooldown: int = Field(default=0, ge=0, le=86400)


def _ops_token() -> str:
    return os.getenv("GPTPAY_OPS_TOKEN", "").strip()


@router.post("/notify")
def notify(req: NotifyRequest, x_gptpay_ops_token: str = Header(default="")):
    token = _ops_token()
    if token and x_gptpay_ops_token != token:
        raise HTTPException(status_code=403, detail="bad ops token")
    root = "/root/Gpt-Agreement-Payment"
    script = os.path.join(root, "scripts", "notify_easyrelay_ops.py")
    py = os.path.join(root, "venv", "bin", "python")
    msg = (req.message or "")[:3500]
    try:
        r = subprocess.run(
            [py, script, "--key", req.key, "--title", req.title, "--cooldown", str(req.cooldown), "--stdin"],
            input=msg,
            text=True,
            capture_output=True,
            timeout=15,
            cwd=root,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="notify timeout")
    return {"ok": r.returncode == 0, "rc": r.returncode, "stdout": (r.stdout or "")[-1000:], "stderr": (r.stderr or "")[-1000:]}
