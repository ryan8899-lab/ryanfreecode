from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from ..db import DBIntegrityError, get_db

router = APIRouter(prefix="/api/setup", tags=["setup"])


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


@router.get("/status")
def status():
    return {"initialized": get_db().user_count() > 0}


@router.post("")
def setup(req: SetupRequest):
    db = get_db()
    if db.user_count() > 0:
        raise HTTPException(status_code=409, detail="already initialized")
    try:
        db.create_user(req.username, req.password)
    except DBIntegrityError:
        raise HTTPException(status_code=409, detail="already initialized") from None
    return {"ok": True}
