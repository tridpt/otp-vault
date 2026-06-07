"""Sinh mã TOTP (RFC 6238) - cùng chuẩn Google Authenticator / Authy.

Không cần thư viện ngoài: chỉ dùng hmac, hashlib, base64 của Python.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse


class TOTPError(ValueError):
    """Lỗi khi secret hoặc tham số TOTP không hợp lệ."""


def normalize_secret(secret: str) -> str:
    """Chuẩn hóa secret base32: bỏ khoảng trắng, viết hoa, thêm padding.

    Người dùng hay copy secret có dấu cách (vd "JBSW Y3DP EHPK 3PXP")
    nên cần dọn sạch trước khi decode.
    """
    if not secret:
        raise TOTPError("Secret rỗng")
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    # Base32 yêu cầu độ dài bội số của 8 -> thêm '=' padding nếu thiếu.
    pad = (-len(cleaned)) % 8
    cleaned += "=" * pad
    try:
        base64.b32decode(cleaned, casefold=True)
    except Exception as exc:  # noqa: BLE001
        raise TOTPError("Secret không phải base32 hợp lệ") from exc
    return cleaned


_ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def generate_code(
    secret: str,
    *,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    at: float | None = None,
) -> str:
    """Trả về mã TOTP hiện tại (mặc định 6 số, đổi mỗi 30 giây)."""
    key_b32 = normalize_secret(secret)
    key = base64.b32decode(key_b32, casefold=True)

    algo = _ALGOS.get(algorithm.upper())
    if algo is None:
        raise TOTPError(f"Thuật toán không hỗ trợ: {algorithm}")

    now = time.time() if at is None else at
    counter = int(now // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, algo).digest()

    # Dynamic truncation theo RFC 4226.
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


def seconds_remaining(period: int = 30, at: float | None = None) -> int:
    """Số giây còn lại trước khi mã hiện tại đổi."""
    now = time.time() if at is None else at
    # Kết quả nằm trong khoảng 1..period (không bao giờ là 0).
    return period - int(now % period)


def parse_otpauth(uri: str) -> dict:
    """Phân tích chuỗi otpauth:// (lấy từ QR code) thành tham số TOTP.

    Ví dụ: otpauth://totp/Shop:user@x.com?secret=ABC&issuer=Shop&digits=6
    """
    if not uri.lower().startswith("otpauth://"):
        raise TOTPError("Không phải chuỗi otpauth://")
    parsed = urlparse(uri)
    if parsed.netloc.lower() != "totp":
        raise TOTPError("Chỉ hỗ trợ loại 'totp'")

    qs = parse_qs(parsed.query)
    secret = qs.get("secret", [""])[0]
    if not secret:
        raise TOTPError("Thiếu 'secret' trong chuỗi otpauth")

    label = unquote(parsed.path.lstrip("/"))
    issuer = qs.get("issuer", [""])[0]
    # Label dạng "Issuer:account" -> ưu tiên issuer trong query string.
    if ":" in label:
        label_issuer, account = label.split(":", 1)
        issuer = issuer or label_issuer
        name = f"{issuer} ({account})" if issuer else account
    else:
        name = f"{issuer} ({label})" if issuer else label

    return {
        "name": name.strip() or "Tài khoản",
        "secret": secret,
        "digits": int(qs.get("digits", ["6"])[0]),
        "period": int(qs.get("period", ["30"])[0]),
        "algorithm": qs.get("algorithm", ["SHA1"])[0].upper(),
    }


def build_otpauth(
    name: str,
    secret: str,
    *,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """Dựng chuỗi otpauth:// để tạo lại QR code (thêm vào app khác)."""
    from urllib.parse import quote

    label = quote(name.strip() or "Tài khoản")
    sec = normalize_secret(secret).rstrip("=")
    params = (
        f"secret={sec}"
        f"&digits={digits}"
        f"&period={period}"
        f"&algorithm={algorithm.upper()}"
    )
    return f"otpauth://totp/{label}?{params}"
