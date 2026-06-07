"""Kho dữ liệu TOTP, mã hóa bằng khóa sinh từ MẬT KHẨU CHỦ.

- Khóa được suy ra từ mật khẩu qua scrypt -> KHÔNG lưu khóa ra đĩa.
- File vault.bin = JSON { "salt": ..., "data": <Fernet token> }.
- Phiên mở khóa (unlocked) giữ khóa trong BỘ NHỚ server; tự khóa khi quá hạn.
"""
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config import (
    AUTO_LOCK_SECONDS,
    SCRYPT_DKLEN,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    VAULT_PATH,
)


class VaultLocked(Exception):
    """Kho đang khóa (chưa nhập mật khẩu hoặc đã hết hạn phiên)."""


class WrongPassword(Exception):
    """Mật khẩu chủ không đúng."""


def _derive_fernet(password: str, salt: bytes) -> Fernet:
    """Sinh khóa Fernet từ mật khẩu + salt qua scrypt."""
    kdf = Scrypt(salt=salt, length=SCRYPT_DKLEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    raw = kdf.derive(password.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(raw))


def is_initialized() -> bool:
    """Đã thiết lập mật khẩu chủ (vault tồn tại) hay chưa."""
    return VAULT_PATH.exists()


def _read_vault_file() -> dict[str, Any]:
    return json.loads(VAULT_PATH.read_text(encoding="utf-8"))


def _write_vault_file(salt: bytes, fernet: Fernet, accounts: list[dict]) -> None:
    payload = json.dumps(accounts, ensure_ascii=False).encode("utf-8")
    token = fernet.encrypt(payload)
    body = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": token.decode("ascii"),
    }
    VAULT_PATH.write_text(json.dumps(body), encoding="utf-8")
    try:
        os.chmod(VAULT_PATH, 0o600)
    except OSError:
        pass


@dataclass
class Session:
    """Phiên làm việc: giữ khóa trong bộ nhớ khi đã mở khóa."""

    fernet: Fernet | None = None
    salt: bytes | None = None
    last_activity: float = field(default_factory=time.time)

    # ----- Trạng thái -----
    def is_unlocked(self) -> bool:
        if self.fernet is None:
            return False
        if time.time() - self.last_activity > AUTO_LOCK_SECONDS:
            self.lock()
            return False
        return True

    def touch(self) -> None:
        self.last_activity = time.time()

    def lock(self) -> None:
        self.fernet = None
        self.salt = None

    def remaining_idle(self) -> int:
        if self.fernet is None:
            return 0
        return max(0, int(AUTO_LOCK_SECONDS - (time.time() - self.last_activity)))

    # ----- Thiết lập / mở khóa -----
    def setup(self, password: str) -> None:
        """Tạo kho mới với mật khẩu chủ (chỉ khi chưa khởi tạo)."""
        salt = os.urandom(16)
        fernet = _derive_fernet(password, salt)
        _write_vault_file(salt, fernet, [])
        self.fernet = fernet
        self.salt = salt
        self.touch()

    def unlock(self, password: str) -> None:
        """Mở khóa kho hiện có bằng mật khẩu chủ."""
        body = _read_vault_file()
        salt = base64.b64decode(body["salt"])
        fernet = _derive_fernet(password, salt)
        try:
            fernet.decrypt(body["data"].encode("ascii"))
        except InvalidToken as exc:
            raise WrongPassword("Mật khẩu chủ không đúng") from exc
        self.fernet = fernet
        self.salt = salt
        self.touch()

    # ----- Đọc / ghi tài khoản -----
    def _require(self) -> Fernet:
        if not self.is_unlocked():
            raise VaultLocked()
        self.touch()
        return self.fernet  # type: ignore[return-value]

    def load_accounts(self) -> list[dict[str, Any]]:
        fernet = self._require()
        body = _read_vault_file()
        raw = fernet.decrypt(body["data"].encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, list) else []

    def _save_accounts(self, accounts: list[dict]) -> None:
        assert self.salt is not None and self.fernet is not None
        _write_vault_file(self.salt, self.fernet, accounts)

    def add_account(
        self,
        name: str,
        secret: str,
        *,
        digits: int = 6,
        period: int = 30,
        algorithm: str = "SHA1",
    ) -> dict[str, Any]:
        accounts = self.load_accounts()
        account = {
            "id": uuid.uuid4().hex[:12],
            "name": name.strip() or "Tài khoản",
            "secret": secret.strip(),
            "digits": digits,
            "period": period,
            "algorithm": algorithm.upper(),
        }
        accounts.append(account)
        self._save_accounts(accounts)
        return account

    def delete_account(self, account_id: str) -> bool:
        accounts = self.load_accounts()
        remaining = [a for a in accounts if a.get("id") != account_id]
        if len(remaining) == len(accounts):
            return False
        self._save_accounts(remaining)
        return True


# Phiên dùng chung cho toàn bộ ứng dụng (chạy cục bộ, một người dùng).
session = Session()
