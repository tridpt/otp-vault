"""Cấu hình chung cho pytest: thêm backend vào sys.path + cô lập storage.

Mọi test chạy trên vault TẠM (thư mục tạm), không bao giờ đụng tới dữ liệu
storage thật của người dùng. Tham số scrypt được giảm để test chạy nhanh.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Cho phép import các module trong backend/ (totp, store, main, config).
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture(autouse=True)
def isolated_vault(tmp_path, monkeypatch):
    """Chuyển hướng vault sang thư mục tạm + reset phiên về trạng thái khóa.

    autouse=True nên áp dụng cho TẤT CẢ test, đảm bảo không có test nào ghi
    vào VAULT_PATH thật.
    """
    import store

    temp_vault = tmp_path / "vault.bin"
    # Đổi đường dẫn vault trong module store (functions dùng global này).
    monkeypatch.setattr(store, "VAULT_PATH", temp_vault, raising=True)
    # Giảm chi phí scrypt để test nhanh (vẫn nhất quán trong từng test).
    monkeypatch.setattr(store, "SCRYPT_N", 2 ** 10, raising=True)

    # Reset phiên dùng chung về trạng thái khóa trước mỗi test.
    store.session.lock()

    yield

    # Dọn dẹp: khóa phiên, xóa vault tạm (tmp_path tự được pytest dọn).
    store.session.lock()
    if temp_vault.exists():
        temp_vault.unlink()
