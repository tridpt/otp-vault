"""FastAPI backend: quản lý & sinh mã 2FA (TOTP) có mật khẩu chủ.

- Mật khẩu chủ: khóa mã hóa sinh từ mật khẩu (scrypt), không lưu ra đĩa.
- Tự khóa sau thời gian không thao tác; có nút khóa thủ công.
- "Sinh mã nhanh" từ secret tùy ý KHÔNG cần mở khóa (không đụng kho).
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import totp
from config import AUTO_LOCK_SECONDS
from store import VaultLocked, WrongPassword, is_initialized, session

try:
    import segno  # sinh QR code (thuần Python)
except ImportError:  # cho phép chạy nếu chưa cài; chỉ tính năng QR bị tắt
    segno = None

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


class ImportBackupRequest(BaseModel):
    password: str
    backup: dict


class RenameRequest(BaseModel):
    name: str


class ReorderRequest(BaseModel):
    ids: list[str]


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


@app.patch("/api/accounts/{account_id}")
def rename_account(account_id: str, req: RenameRequest) -> dict:
    """Đổi tên tài khoản."""
    _ensure_unlocked()
    acc = session.rename_account(account_id, req.name)
    if acc is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản")
    return _code_payload(acc)


@app.post("/api/accounts/reorder")
def reorder_accounts(req: ReorderRequest) -> dict:
    """Sắp xếp lại thứ tự tài khoản theo danh sách id."""
    _ensure_unlocked()
    ordered = session.reorder_accounts(req.ids)
    return {"accounts": [_code_payload(a) for a in ordered]}


@app.get("/api/accounts/{account_id}/reveal")
def reveal_account(account_id: str) -> dict:
    """Trả secret + chuỗi otpauth + QR (SVG) để thêm tài khoản sang app khác."""
    _ensure_unlocked()
    acc = session.get_account(account_id)
    if acc is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản")
    uri = totp.build_otpauth(
        acc["name"],
        acc["secret"],
        digits=acc.get("digits", 6),
        period=acc.get("period", 30),
        algorithm=acc.get("algorithm", "SHA1"),
    )
    qr_svg = None
    if segno is not None:
        qr = segno.make(uri, error="m")
        # omitsize=True -> SVG có viewBox vuông, không có width/height cố định,
        # nhờ đó CSS co giãn đúng tỉ lệ (không bị méo/cắt xén).
        qr_svg = qr.svg_inline(scale=5, omitsize=True, dark="#0f1117", light="#ffffff")
    return {
        "name": acc["name"],
        "secret": totp.normalize_secret(acc["secret"]).rstrip("="),
        "otpauth": uri,
        "qr_svg": qr_svg,
    }


# ----------------------- Sao lưu / khôi phục (cần mở khóa) -----------------------
@app.post("/api/export")
def export_backup(req: PasswordRequest) -> dict:
    """Xuất gói sao lưu mã hóa bằng mật khẩu do người dùng đặt."""
    _ensure_unlocked()
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Mật khẩu sao lưu tối thiểu 6 ký tự")
    return session.export_backup(req.password)


@app.post("/api/import")
def import_backup(req: ImportBackupRequest) -> dict:
    """Khôi phục từ gói sao lưu; gộp vào kho hiện tại."""
    _ensure_unlocked()
    try:
        added = session.import_backup(req.password, req.backup)
    except WrongPassword as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"added": added}


@app.get("/api/export-csv", response_class=PlainTextResponse)
def export_csv() -> PlainTextResponse:
    """Xuất danh sách tài khoản ra CSV ĐỌC ĐƯỢC (tên/mail + secret).

    CẢNH BÁO: file chứa secret ở dạng văn bản rõ, KHÔNG mã hóa. Chỉ dùng khi cần
    và giữ file an toàn / xóa sau khi dùng xong.
    """
    _ensure_unlocked()
    accounts = session.load_accounts()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "secret", "digits", "period", "algorithm", "otpauth"])
    for a in accounts:
        digits = a.get("digits", 6)
        period = a.get("period", 30)
        algorithm = a.get("algorithm", "SHA1")
        try:
            secret = totp.normalize_secret(a["secret"]).rstrip("=")
            uri = totp.build_otpauth(
                a["name"], a["secret"], digits=digits, period=period, algorithm=algorithm
            )
        except totp.TOTPError:
            secret = a.get("secret", "")
            uri = ""
        writer.writerow([a.get("name", ""), secret, digits, period, algorithm, uri])
    # BOM giúp Excel mở đúng tiếng Việt (UTF-8).
    return PlainTextResponse("\ufeff" + buf.getvalue(), media_type="text/csv")


# Phục vụ frontend tĩnh (đặt cuối để không che các route /api).
BASE_DIR = Path(__file__).resolve().parent.parent
frontend_dir = BASE_DIR / "frontend"
app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
