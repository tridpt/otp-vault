"""Cấu hình cho ứng dụng quản lý mã 2FA (TOTP).

Lưu danh sách tài khoản (tên + secret) dưới dạng MÃ HÓA trên đĩa,
giống cách outlook-mail-reader mã hóa token cache.
"""
from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Nơi lưu danh sách tài khoản (đã mã hóa) và khóa mã hóa.
ACCOUNTS_PATH = STORAGE_DIR / "accounts.bin"
ENCRYPTION_KEY_PATH = STORAGE_DIR / "vault.key"
