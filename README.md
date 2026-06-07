# OTP Vault — Quản lý mã 2FA

Web app nhập secret key và nhận mã 6 số (TOTP), đổi mỗi 30 giây — cùng chuẩn
Google Authenticator / Authy (RFC 6238). Lưu được nhiều tài khoản, hiển thị mã
cho tất cả cùng lúc, bảo vệ bằng **mật khẩu chủ** và mã hóa cục bộ.

> ⚠️ Dùng cho các tài khoản **của bạn** hoặc bạn được phép quản lý. Đây không
> phải công cụ tạo/nuôi tài khoản ảo hàng loạt.

## Tính năng
- **Mật khẩu chủ**: khóa mã hóa được sinh từ mật khẩu qua `scrypt`, **không lưu
  khóa ra đĩa**. Không có mật khẩu thì không giải mã được dữ liệu, kể cả khi có file.
- **Tự khóa** sau 5 phút không thao tác + nút khóa thủ công; **ẩn/hiện mã**.
- **Sinh mã nhanh**: dán secret key → ra mã ngay (không cần mở khóa, không lưu).
- **Lưu tài khoản**: nhập tên + secret, dán chuỗi `otpauth://`, hoặc **quét QR**
  (camera hoặc tải ảnh lên — giải mã ngay trong trình duyệt bằng jsQR).
- **Hiện lại QR / secret** của từng tài khoản để thêm sang điện thoại/app khác.
- **Sao lưu & khôi phục**: xuất ra 1 file mã hóa (mật khẩu riêng), nhập lại trên
  máy khác; tự bỏ qua mục trùng khi khôi phục.
- Hiển thị mã + đếm ngược thời gian còn lại; tìm kiếm theo tên; bấm vào mã để copy.

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

Mở trình duyệt: http://127.0.0.1:8200 — lần đầu sẽ yêu cầu tạo mật khẩu chủ.

## Kiểm thử (test)

Bộ test tự động (pytest) kiểm chứng TOTP, kho mã hóa và API. Test chạy **cô lập**
trên vault tạm, không đụng dữ liệu thật.

```bat
cd /d d:\AI_App\totp-manager
.venv\Scripts\activate
pip install -r requirements-dev.txt
pytest
```

- `tests/test_totp.py` — sinh mã theo test vector RFC 6238 (SHA1/256/512), chuẩn
  hóa secret, round-trip otpauth, biên `seconds_remaining` (property-based bằng hypothesis).
- `tests/test_store.py` — setup/unlock/lock, auto-lock, CRUD, mã hóa-tại-chỗ, export/import.
- `tests/test_api.py` — quy tắc khóa (401), lỗi 400/404, luồng đầu-cuối qua TestClient.

## API
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | `/api/status` | Trạng thái kho (đã thiết lập / đang khóa) |
| POST | `/api/setup` | Tạo mật khẩu chủ lần đầu |
| POST | `/api/unlock` | Mở khóa kho |
| POST | `/api/lock` | Khóa kho |
| POST | `/api/generate` | Sinh mã từ secret, không lưu (không cần mở khóa) |
| GET | `/api/accounts` | Danh sách tài khoản + mã hiện tại (cần mở khóa) |
| POST | `/api/accounts` | Thêm tài khoản (name, secret) |
| POST | `/api/accounts/import-uri` | Thêm từ chuỗi `otpauth://` |
| GET | `/api/accounts/{id}/reveal` | Lấy secret + otpauth + QR (SVG) của 1 tài khoản |
| DELETE | `/api/accounts/{id}` | Xóa tài khoản |
| POST | `/api/export` | Xuất gói sao lưu mã hóa (mật khẩu riêng) |
| POST | `/api/import` | Khôi phục từ gói sao lưu |

## Bảo mật
- Dữ liệu lưu trong `storage/vault.bin` = `{ salt, data }`, `data` được mã hóa
  bằng khóa suy ra từ mật khẩu chủ (scrypt + Fernet). `storage/` đã `.gitignore`.
- Quên mật khẩu chủ = **không khôi phục được** dữ liệu (đúng theo thiết kế).
- App chạy local, không có hệ thống đa người dùng. Đừng expose cổng ra Internet
  công khai; nếu cần truy cập từ xa hãy đặt sau lớp đăng nhập/VPN.
