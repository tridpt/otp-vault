"""FastAPI backend: quản lý & sinh mã 2FA (TOTP) có mật khẩu chủ.

- Mật khẩu chủ: khóa mã hóa sinh từ mật khẩu (scrypt), không lưu ra đĩa.
- Tự khóa sau thời gian không thao tác; có nút khóa thủ công.
- "Sinh mã nhanh" từ secret tùy ý KHÔNG cần mở khóa (không đụng kho).
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import totp
from config import AUTO_LOCK_SECONDS
from store import VaultLocked, WrongPassword, is_initialized, session

app = FastAPI(title="OTP Vault", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------- Schemas -----------------------
class GenerateRequest(BaseModel):
    secret: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


class PasswordRequest(BaseModel):
    password: str


class AddAccountRequest(BaseModel):
    name: str = ""
    secret: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


class ImportUriRequest(BaseModel):
    uri: str


# ----------------------- Helpers -----------------------
def _ensure_unlocked() -> None:
    if not session.is_unlocked():
        raise HTTPException(status_code=401, detail="Kho đang khóa")


def _code_payload(account: dict) -> dict:
    digits = account.get("digits", 6)
    period = account.get("period", 30)
    algorithm = account.get("algorithm", "SHA1")
    try:
        code = totp.generate_code(
            account["secret"], digits=digits, period=period, algorithm=algorithm
        )
        return {
            "id": account.get("id"),
            "name": account.get("name"),
            "code": code,
            "remaining": totp.seconds_remaining(period),
            "period": period,
            "error": None,
        }
    except totp.TOTPError as exc:
        return {
            "id": account.get("id"),
            "name": account.get("name"),
            "code": None,
            "remaining": 0,
            "period": period,
            "error": str(exc),
        }


# ----------------------- Trạng thái / khóa -----------------------
@app.get("/api/status")
def status() -> dict:
    """Trạng thái kho: đã thiết lập chưa, đang khóa hay mở."""
    return {
        "initialized": is_initialized(),
        "locked": not session.is_unlocked(),
        "auto_lock_seconds": AUTO_LOCK_SECONDS,
        "idle_remaining": session.remaining_idle(),
    }


@app.post("/api/setup")
def setup(req: PasswordRequest) -> dict:
    """Thiết lập mật khẩu chủ lần đầu."""
    if is_initialized():
        raise HTTPException(status_code=400, detail="Đã thiết lập mật khẩu rồi")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Mật khẩu tối thiểu 6 ký tự")
    session.setup(req.password)
    return {"ok": True}


@app.post("/api/unlock")
def unlock(req: PasswordRequest) -> dict:
    """Mở khóa kho bằng mật khẩu chủ."""
    if not is_initialized():
        raise HTTPException(status_code=400, detail="Chưa thiết lập mật khẩu")
    try:
        session.unlock(req.password)
    except WrongPassword as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return {"ok": True}


@app.post("/api/lock")
def lock() -> dict:
    """Khóa kho thủ công (xóa khóa khỏi bộ nhớ)."""
    session.lock()
    return {"ok": True}


# ----------------------- Sinh mã nhanh (không cần mở khóa) -----------------------
@app.post("/api/generate")
def generate(req: GenerateRequest) -> dict:
    try:
        code = totp.generate_code(
            req.secret, digits=req.digits, period=req.period, algorithm=req.algorithm
        )
    except totp.TOTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"code": code, "remaining": totp.seconds_remaining(req.period), "period": req.period}


# ----------------------- Tài khoản (cần mở khóa) -----------------------
@app.get("/api/accounts")
def list_accounts() -> dict:
    _ensure_unlocked()
    accounts = session.load_accounts()
    return {
        "accounts": [_code_payload(a) for a in accounts],
        "idle_remaining": session.remaining_idle(),
    }


@app.post("/api/accounts")
def add_account(req: AddAccountRequest) -> dict:
    _ensure_unlocked()
    try:
        totp.normalize_secret(req.secret)
    except totp.TOTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    account = session.add_account(
        req.name,
        req.secret,
        digits=req.digits,
        period=req.period,
        algorithm=req.algorithm,
    )
    return _code_payload(account)


@app.post("/api/accounts/import-uri")
def import_uri(req: ImportUriRequest) -> dict:
    _ensure_unlocked()
    try:
        parsed = totp.parse_otpauth(req.uri)
    except totp.TOTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    account = session.add_account(
        parsed["name"],
        parsed["secret"],
        digits=parsed["digits"],
        period=parsed["period"],
        algorithm=parsed["algorithm"],
    )
    return _code_payload(account)


@app.delete("/api/accounts/{account_id}")
def remove_account(account_id: str) -> dict:
    _ensure_unlocked()
    if not session.delete_account(account_id):
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản")
    return {"deleted": account_id}


# Phục vụ frontend tĩnh (đặt cuối để không che các route /api).
BASE_DIR = Path(__file__).resolve().parent.parent
frontend_dir = BASE_DIR / "frontend"
app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
