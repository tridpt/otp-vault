"""Cấu hình cho ứng dụng quản lý mã 2FA (TOTP).

Bảo mật bằng MẬT KHẨU CHỦ (master password): khóa mã hóa được sinh trực tiếp
từ mật khẩu (scrypt), KHÔNG lưu khóa ra đĩa. Không có mật khẩu thì không
giải mã được dữ liệu, kể cả khi có file.
"""
from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Kho dữ liệu: chứa salt + danh sách tài khoản (đã mã hóa bằng khóa từ mật khẩu).
VAULT_PATH = STORAGE_DIR / "vault.bin"

# Tham số scrypt (đủ mạnh cho dùng cục bộ).
SCRYPT_N = 2 ** 15  # 32768
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32  # 32 byte -> khóa Fernet

# Tự khóa sau khoảng thời gian không thao tác (giây).
AUTO_LOCK_SECONDS = 300  # 5 phút
