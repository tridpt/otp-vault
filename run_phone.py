"""Chạy OTP Vault cho truy cập từ điện thoại trong cùng mạng Wi-Fi (LAN).

Lắng nghe trên 0.0.0.0 và in ra địa chỉ để mở trên điện thoại.

CẢNH BÁO: khi chạy bằng script này, app mở cho MỌI thiết bị trong cùng mạng
LAN. Hãy đặt mật khẩu chủ đủ mạnh và chỉ dùng trên mạng tin cậy (Wi-Fi nhà
riêng). KHÔNG dùng trên Wi-Fi công cộng.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

PORT = 8200
BACKEND = Path(__file__).resolve().parent / "backend"
sys.path.insert(0, str(BACKEND))


def lan_ip() -> str:
    """Đoán IP LAN của máy này (IP dùng để ra Internet/mạng nội bộ)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == "__main__":
    import uvicorn

    ip = lan_ip()
    print("=" * 56)
    print("  OTP Vault — mở trên điện thoại (cùng Wi-Fi):")
    print(f"    http://{ip}:{PORT}")
    print("  Trên máy này:")
    print(f"    http://127.0.0.1:{PORT}")
    print("=" * 56)
    print("  Lưu ý: camera quét QR và 'cài app (PWA)' cần HTTPS,")
    print("  nên trên điện thoại qua http:// sẽ KHÔNG quét camera được.")
    print("  Xem/copy mã, thêm bằng dán secret, sao lưu... vẫn chạy bình thường.")
    print("=" * 56)

    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
