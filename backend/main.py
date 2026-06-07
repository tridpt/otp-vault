"""FastAPI backend: quản lý & sinh mã 2FA (TOTP).

- Nhập secret -> trả mã 6 số (kèm thời gian còn lại).
- Lưu nhiều tài khoản, hiển thị mã cho tất cả cùng lúc.
- Dữ liệu lưu mã hóa cục bộ trong storage/.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import store
import totp

app = FastAPI(title="TOTP Manager", version="1.0.0")

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


class AddAccountRequest(BaseModel):
    name: str = ""
    secret: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


class ImportUriRequest(BaseModel):
    uri: str


# ----------------------- Helpers -----------------------
def _code_payload(account: dict) -> dict:
    """Sinh mã hiện tại cho 1 tài khoản, kèm trạng thái lỗi nếu secret sai."""
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


# ----------------------- Routes -----------------------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/generate")
def generate(req: GenerateRequest) -> dict:
    """Sinh mã nhanh từ một secret mà KHÔNG lưu lại."""
    try:
        code = totp.generate_code(
            req.secret, digits=req.digits, period=req.period, algorithm=req.algorithm
        )
    except totp.TOTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"code": code, "remaining": totp.seconds_remaining(req.period), "period": req.period}


@app.get("/api/accounts")
def list_accounts() -> dict:
    """Danh sách tài khoản đã lưu kèm mã hiện tại."""
    accounts = store.load_accounts()
    return {"accounts": [_code_payload(a) for a in accounts]}


@app.post("/api/accounts")
def add_account(req: AddAccountRequest) -> dict:
    """Thêm tài khoản mới (kiểm tra secret hợp lệ trước khi lưu)."""
    try:
        totp.normalize_secret(req.secret)
    except totp.TOTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    account = store.add_account(
        req.name,
        req.secret,
        digits=req.digits,
        period=req.period,
        algorithm=req.algorithm,
    )
    return _code_payload(account)


@app.post("/api/accounts/import-uri")
def import_uri(req: ImportUriRequest) -> dict:
    """Thêm tài khoản từ chuỗi otpauth:// (nội dung QR code)."""
    try:
        parsed = totp.parse_otpauth(req.uri)
    except totp.TOTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    account = store.add_account(
        parsed["name"],
        parsed["secret"],
        digits=parsed["digits"],
        period=parsed["period"],
        algorithm=parsed["algorithm"],
    )
    return _code_payload(account)


@app.delete("/api/accounts/{account_id}")
def remove_account(account_id: str) -> dict:
    if not store.delete_account(account_id):
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản")
    return {"deleted": account_id}


# Phục vụ frontend tĩnh (đặt cuối để không che các route /api).
BASE_DIR = Path(__file__).resolve().parent.parent
frontend_dir = BASE_DIR / "frontend"
app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
