# TOTP Manager — Quản lý mã 2FA

Web app nhập secret key và nhận mã 6 số (TOTP), đổi mỗi 30 giây — cùng chuẩn
Google Authenticator / Authy (RFC 6238). Lưu được nhiều tài khoản, hiển thị mã
cho tất cả cùng lúc, dữ liệu lưu **mã hóa** cục bộ.

> ⚠️ Dùng cho các tài khoản **của bạn** hoặc bạn được phép quản lý. Đây không
> phải công cụ tạo/nuôi tài khoản ảo hàng loạt.

## Tính năng
- **Sinh mã nhanh**: dán secret key → ra mã ngay, không cần lưu.
- **Lưu tài khoản**: nhập tên + secret, hoặc dán chuỗi `otpauth://` (nội dung QR).
- Hiển thị mã + đếm ngược thời gian còn lại cho mọi tài khoản.
- Tìm kiếm theo tên, bấm vào mã để copy.
- Dữ liệu lưu mã hóa (Fernet) trong `storage/accounts.bin`.

## Cài đặt & chạy

```bat
cd /d d:\AI_App\totp-manager
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Chạy server (từ thư mục `backend`):

```bat
cd /d d:\AI_App\totp-manager\backend
uvicorn main:app --reload --port 8200
```

Mở trình duyệt: http://127.0.0.1:8200

## API
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| POST | `/api/generate` | Sinh mã từ secret, không lưu |
| GET | `/api/accounts` | Danh sách tài khoản + mã hiện tại |
| POST | `/api/accounts` | Thêm tài khoản (name, secret) |
| POST | `/api/accounts/import-uri` | Thêm từ chuỗi `otpauth://` |
| DELETE | `/api/accounts/{id}` | Xóa tài khoản |

## Lưu ý bảo mật
- Secret 2FA tương đương "chìa khóa" tài khoản — `storage/` đã được `.gitignore`.
- App chạy local, không có xác thực người dùng. Đừng expose cổng ra Internet
  công khai; nếu cần truy cập từ xa hãy đặt sau lớp đăng nhập/VPN.
```
