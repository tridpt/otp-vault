"""Lưu trữ danh sách tài khoản TOTP, mã hóa trên đĩa bằng Fernet.

Mỗi tài khoản: {id, name, secret, digits, period, algorithm}.
File accounts.bin được mã hóa bằng khóa trong vault.key (sinh tự động).
"""
from __future__ import annotations

import json
import os
import uuid
from typing import Any

from cryptography.fernet import Fernet

from config import ACCOUNTS_PATH, ENCRYPTION_KEY_PATH


def _get_fernet() -> Fernet:
    """Lấy (hoặc tạo mới) khóa mã hóa cục bộ."""
    if ENCRYPTION_KEY_PATH.exists():
        key = ENCRYPTION_KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        ENCRYPTION_KEY_PATH.write_bytes(key)
        # Hạn chế quyền đọc file khóa (chỉ chủ sở hữu) khi OS hỗ trợ.
        try:
            os.chmod(ENCRYPTION_KEY_PATH, 0o600)
        except OSError:
            pass
    return Fernet(key)


def load_accounts() -> list[dict[str, Any]]:
    """Đọc danh sách tài khoản đã giải mã. Trả về [] nếu chưa có."""
    if not ACCOUNTS_PATH.exists():
        return []
    try:
        raw = _get_fernet().decrypt(ACCOUNTS_PATH.read_bytes())
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, list) else []
    except Exception:  # noqa: BLE001 - file hỏng/khóa sai -> coi như rỗng
        return []


def save_accounts(accounts: list[dict[str, Any]]) -> None:
    """Mã hóa và ghi danh sách tài khoản xuống đĩa."""
    payload = json.dumps(accounts, ensure_ascii=False).encode("utf-8")
    ACCOUNTS_PATH.write_bytes(_get_fernet().encrypt(payload))


def add_account(
    name: str,
    secret: str,
    *,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> dict[str, Any]:
    """Thêm tài khoản mới và lưu lại."""
    accounts = load_accounts()
    account = {
        "id": uuid.uuid4().hex[:12],
        "name": name.strip() or "Tài khoản",
        "secret": secret.strip(),
        "digits": digits,
        "period": period,
        "algorithm": algorithm.upper(),
    }
    accounts.append(account)
    save_accounts(accounts)
    return account


def delete_account(account_id: str) -> bool:
    """Xóa tài khoản theo id. Trả về True nếu có xóa."""
    accounts = load_accounts()
    remaining = [a for a in accounts if a.get("id") != account_id]
    if len(remaining) == len(accounts):
        return False
    save_accounts(remaining)
    return True
