# Requirements Document

## Introduction

Dự án OTP Vault (trình quản lý mã 2FA/TOTP) hiện chưa có bộ kiểm thử tự động nào. Tính năng này xây dựng một bộ test tự động dựa trên `pytest` để kiểm chứng tính đúng đắn của ba lớp backend: sinh mã TOTP (`backend/totp.py`), kho lưu trữ mã hóa (`backend/store.py`), và các route FastAPI (`backend/main.py`). Bộ test khuyến khích dùng property-based testing (`hypothesis`) cho các bất biến của TOTP/secret, và phải chạy hoàn toàn cô lập — không đụng tới dữ liệu storage thật của người dùng, mọi trạng thái lưu trữ dùng thư mục tạm.

Mục tiêu là tạo lưới an toàn (safety net) cho phép refactor và phát triển tiếp mà vẫn bảo toàn các đảm bảo chính: mã TOTP đúng chuẩn RFC 6238, dữ liệu được mã hóa và chỉ mở được bằng đúng mật khẩu, và các endpoint API tuân thủ đúng quy tắc khóa/mở khóa.

## Glossary

- **Test_Suite**: Bộ kiểm thử tự động dựa trên `pytest` được xây dựng bởi tính năng này.
- **TOTP_Module**: Module `backend/totp.py` cần kiểm thử (gồm `normalize_secret`, `generate_code`, `seconds_remaining`, `parse_otpauth`, `build_otpauth`).
- **Store_Module**: Module `backend/store.py` cần kiểm thử (class `Session`, hàm `is_initialized`).
- **API_Layer**: Ứng dụng FastAPI trong `backend/main.py` được kiểm thử qua `fastapi.testclient.TestClient`.
- **RFC_6238_Vector**: Test vector chuẩn công bố trong RFC 6238 dùng seed ASCII `"12345678901234567890"` (base32 = `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`) với mã 8 chữ số.
- **Property_Test**: Test dựa trên `hypothesis`, sinh nhiều input ngẫu nhiên để kiểm chứng một bất biến.
- **Temp_Vault**: File vault dùng cho test, đặt trong thư mục tạm và được dọn sạch sau mỗi test, tách biệt khỏi `VAULT_PATH` thật.
- **Round_Trip**: Tính chất một phép biến đổi kết hợp với phép nghịch đảo của nó trả về giá trị tương đương ban đầu.
- **Auto_Lock**: Cơ chế tự khóa phiên sau `AUTO_LOCK_SECONDS` giây không thao tác.

## Requirements

### Requirement 1: Cô lập môi trường kiểm thử

**User Story:** Là một lập trình viên, tôi muốn bộ test chạy trên dữ liệu tạm, để các bài test không làm hỏng hay đụng tới kho mã 2FA thật của người dùng.

#### Acceptance Criteria

1. THE Test_Suite SHALL chuyển hướng đường dẫn vault sang Temp_Vault trong một thư mục tạm trước khi chạy bất kỳ bài test nào của Store_Module hoặc API_Layer.
2. WHEN một bài test kết thúc, THE Test_Suite SHALL xóa Temp_Vault và mọi tệp tạm được tạo trong bài test đó.
3. THE Test_Suite SHALL đặt lại trạng thái phiên dùng chung (`session`) về trạng thái khóa trước mỗi bài test của Store_Module và API_Layer.
4. IF đường dẫn vault thật (`VAULT_PATH` mặc định trong storage của người dùng) được truy cập trong khi chạy test, THEN THE Test_Suite SHALL không tạo, sửa hoặc xóa tệp tại đường dẫn đó.
5. THE Test_Suite SHALL chạy thành công khi gọi bằng lệnh `pytest` từ thư mục gốc dự án mà không cần thiết lập thủ công thêm.

### Requirement 2: Kiểm chứng sinh mã TOTP theo RFC 6238

**User Story:** Là một lập trình viên, tôi muốn xác nhận mã TOTP khớp chuẩn RFC 6238, để người dùng nhận được mã giống Google Authenticator/Authy.

#### Acceptance Criteria

1. WHEN `generate_code` được gọi với RFC_6238_Vector tại thời điểm `at=59` với `digits=8` và `algorithm="SHA1"`, THE Test_Suite SHALL xác nhận kết quả bằng `"94287082"`.
2. WHEN `generate_code` được gọi với RFC_6238_Vector tại các thời điểm chuẩn `at=1111111109`, `at=1234567890` và `at=2000000000` với `digits=8` và `algorithm="SHA1"`, THE Test_Suite SHALL xác nhận từng thời điểm tạo ra đúng mã tương ứng của nó, lần lượt bằng `"07081804"`, `"89005924"` và `"69279037"` (bắt buộc đúng cặp thời điểm–mã, không chấp nhận khớp bất kỳ).
3. WHEN `generate_code` được gọi với `algorithm="SHA256"` và `algorithm="SHA512"` cùng các test vector tương ứng của RFC 6238, THE Test_Suite SHALL xác nhận kết quả khớp giá trị chuẩn được công bố.
4. THE Test_Suite SHALL xác nhận `generate_code` trả về chuỗi có độ dài đúng bằng tham số `digits` cho các giá trị `digits` trong tập {6, 7, 8}.
5. WHEN `generate_code` được gọi hai lần với cùng secret và cùng `at` nằm trong cùng một chu kỳ `period`, THE Test_Suite SHALL xác nhận hai kết quả bằng nhau.
6. IF `generate_code` được gọi với `algorithm` không thuộc {SHA1, SHA256, SHA512}, THEN THE Test_Suite SHALL xác nhận `TOTPError` được nâng lên.

### Requirement 3: Kiểm chứng chuẩn hóa secret

**User Story:** Là một lập trình viên, tôi muốn xác nhận `normalize_secret` xử lý đúng input người dùng, để secret dán từ nhiều nguồn vẫn dùng được.

#### Acceptance Criteria

1. WHEN `normalize_secret` nhận secret có dấu cách, dấu gạch ngang hoặc chữ thường (ví dụ `"jbsw y3dp ehpk-3pxp"`), THE Test_Suite SHALL xác nhận kết quả là chuỗi base32 viết hoa, không khoảng trắng, có độ dài là bội số của 8.
2. THE Test_Suite SHALL xác nhận kết quả của `normalize_secret` giải mã được bằng `base64.b32decode` với `casefold=True` mà không nâng lỗi.
3. IF `normalize_secret` nhận chuỗi rỗng, THEN THE Test_Suite SHALL xác nhận `TOTPError` được nâng lên.
4. IF `normalize_secret` nhận chuỗi không phải base32 hợp lệ (ví dụ chứa ký tự `"1"` hoặc `"0"`), THEN THE Test_Suite SHALL xác nhận `TOTPError` được nâng lên.
5. THE Test_Suite SHALL xác nhận `normalize_secret` là idempotent: áp dụng lần thứ hai lên kết quả lần thứ nhất trả về chuỗi bằng kết quả lần thứ nhất.

### Requirement 4: Kiểm chứng phân tích và dựng chuỗi otpauth

**User Story:** Là một lập trình viên, tôi muốn xác nhận việc phân tích và dựng chuỗi otpauth là nhất quán, để việc import từ QR và export sang app khác không mất dữ liệu.

#### Acceptance Criteria

1. WHEN `parse_otpauth` nhận một chuỗi otpauth totp hợp lệ có `secret`, `issuer`, `digits`, `period`, `algorithm`, THE Test_Suite SHALL xác nhận các trường `secret`, `digits`, `period`, `algorithm` trong kết quả khớp giá trị trong chuỗi đầu vào.
2. WHEN nhãn (label) ở dạng `"Issuer:account"`, THE Test_Suite SHALL xác nhận trường `name` trong kết quả chứa cả issuer và account.
3. IF `parse_otpauth` nhận chuỗi không bắt đầu bằng `otpauth://`, THEN THE Test_Suite SHALL xác nhận `TOTPError` được nâng lên.
4. IF `parse_otpauth` nhận chuỗi otpauth thiếu tham số `secret`, THEN THE Test_Suite SHALL xác nhận `TOTPError` được nâng lên.
5. IF `parse_otpauth` nhận chuỗi otpauth có loại khác `totp` (ví dụ `hotp`), THEN THE Test_Suite SHALL xác nhận `TOTPError` được nâng lên.
6. FOR ALL bộ tham số hợp lệ (name, secret base32, digits, period, algorithm), THE Test_Suite SHALL xác nhận Round_Trip `parse_otpauth(build_otpauth(...))` trả về `secret` (sau chuẩn hóa, bỏ padding), `digits`, `period`, `algorithm` tương đương giá trị ban đầu.

### Requirement 5: Kiểm chứng số giây còn lại

**User Story:** Là một lập trình viên, tôi muốn xác nhận `seconds_remaining` luôn nằm trong khoảng hợp lệ, để bộ đếm thời gian hiển thị không bao giờ sai.

#### Acceptance Criteria

1. FOR ALL thời điểm `at` không âm và `period` trong tập {15, 30, 60}, THE Test_Suite SHALL xác nhận `seconds_remaining(period, at)` trả về giá trị nằm trong khoảng đóng từ 1 đến `period`.
2. WHEN `seconds_remaining` được gọi với `at` là bội số đúng của `period`, THE Test_Suite SHALL xác nhận kết quả bằng `period`.
3. THE Test_Suite SHALL xác nhận `seconds_remaining` không bao giờ trả về 0 cho bất kỳ `at` không âm nào trong tập kiểm thử.

### Requirement 6: Kiểm chứng thiết lập, mở khóa và khóa kho

**User Story:** Là một lập trình viên, tôi muốn xác nhận luồng thiết lập/mở khóa/khóa hoạt động đúng, để chỉ người có mật khẩu chủ mới truy cập được dữ liệu.

#### Acceptance Criteria

1. WHEN `Session.setup` được gọi với một mật khẩu trên Temp_Vault chưa khởi tạo, THE Test_Suite SHALL xác nhận `is_initialized()` trả về `True` và phiên ở trạng thái mở khóa sau đó.
2. WHEN một phiên mới gọi `Session.unlock` với đúng mật khẩu đã thiết lập, THE Test_Suite SHALL xác nhận phiên chuyển sang trạng thái mở khóa.
3. IF `Session.unlock` được gọi với mật khẩu sai, THEN THE Test_Suite SHALL xác nhận `WrongPassword` được nâng lên và phiên vẫn ở trạng thái khóa.
4. WHEN `Session.lock` được gọi trên một phiên đang mở khóa, THE Test_Suite SHALL xác nhận `is_unlocked()` trả về `False` sau đó.
5. THE Test_Suite SHALL xác nhận `is_initialized()` trả về `False` khi Temp_Vault chưa tồn tại.

### Requirement 7: Kiểm chứng tự khóa theo thời gian không thao tác

**User Story:** Là một lập trình viên, tôi muốn xác nhận cơ chế Auto_Lock, để phiên tự khóa sau thời gian rảnh nhằm bảo vệ dữ liệu.

#### Acceptance Criteria

1. WHILE một phiên đang mở khóa và thời gian kể từ `last_activity` vượt quá `AUTO_LOCK_SECONDS`, THE Test_Suite SHALL xác nhận `is_unlocked()` trả về `False`.
2. WHEN một thao tác đọc/ghi tài khoản được thực hiện trên phiên mở khóa, THE Test_Suite SHALL xác nhận `last_activity` được cập nhật để dời mốc tự khóa.
3. THE Test_Suite SHALL xác nhận `remaining_idle()` trả về 0 khi phiên đang khóa.

### Requirement 8: Kiểm chứng thêm, đọc và xóa tài khoản

**User Story:** Là một lập trình viên, tôi muốn xác nhận các thao tác CRUD tài khoản, để dữ liệu tài khoản được lưu và truy xuất chính xác.

#### Acceptance Criteria

1. WHEN `add_account` được gọi trên phiên mở khóa, THE Test_Suite SHALL xác nhận tài khoản trả về có trường `id` không rỗng và xuất hiện trong kết quả `load_accounts()`.
2. WHEN `get_account` được gọi với một `id` đã tồn tại, THE Test_Suite SHALL xác nhận kết quả khớp tài khoản đã thêm; và với `id` không tồn tại SHALL trả về `None`.
3. WHEN `delete_account` được gọi với một `id` đã tồn tại, THE Test_Suite SHALL xác nhận kết quả là `True` và tài khoản không còn trong `load_accounts()`.
4. IF `delete_account` được gọi với một `id` không tồn tại, THEN THE Test_Suite SHALL xác nhận kết quả là `False` và số lượng tài khoản không đổi.
5. IF một thao tác `load_accounts`, `add_account` hoặc `delete_account` được gọi trên phiên đang khóa, THEN THE Test_Suite SHALL xác nhận `VaultLocked` được nâng lên.
6. THE Test_Suite SHALL xác nhận dữ liệu tài khoản được ghi xuống Temp_Vault ở dạng đã mã hóa: nội dung tệp thô không chứa chuỗi `secret` ở dạng văn bản rõ.
7. IF thao tác mã hóa khi ghi tài khoản thất bại, THEN THE Test_Suite SHALL xác nhận thao tác ghi không hoàn tất và trạng thái tài khoản trong Temp_Vault không thay đổi.

### Requirement 9: Kiểm chứng sao lưu và khôi phục

**User Story:** Là một lập trình viên, tôi muốn xác nhận export/import bảo toàn dữ liệu và xử lý lỗi đúng, để người dùng khôi phục an toàn trên máy khác.

#### Acceptance Criteria

1. WHEN `export_backup` rồi `import_backup` được thực hiện với cùng mật khẩu vào một kho rỗng, THE Test_Suite SHALL xác nhận các tài khoản khôi phục có cùng `name`, `secret`, `digits`, `period`, `algorithm` với tài khoản gốc (Round_Trip).
2. IF `import_backup` được gọi với mật khẩu sai so với mật khẩu lúc export, THEN THE Test_Suite SHALL xác nhận `WrongPassword` được nâng lên.
3. IF `import_backup` được gọi với gói có trường `type` khác `"otp-vault-backup"`, THEN THE Test_Suite SHALL xác nhận `ValueError` được nâng lên.
4. WHEN `import_backup` nhập một gói chứa các mục trùng (cùng `name` và `secret`) với kho hiện tại, THE Test_Suite SHALL xác nhận các mục trùng bị bỏ qua và số trả về chỉ đếm các mục mới được thêm.
5. WHEN `import_backup` thêm các mục mới, THE Test_Suite SHALL xác nhận mỗi mục được cấp một `id` mới khác với `id` trong gói sao lưu.

### Requirement 10: Kiểm chứng API trạng thái và quy tắc khóa

**User Story:** Là một lập trình viên, tôi muốn xác nhận các endpoint API tuân thủ quy tắc khóa/mở khóa, để dữ liệu nhạy cảm không lộ khi kho đang khóa.

#### Acceptance Criteria

1. WHEN `GET /api/status` được gọi trên kho chưa khởi tạo, THE API_Layer SHALL trả về mã 200 với `initialized=False` và `locked=True`.
2. IF `GET /api/accounts` được gọi khi kho đang khóa, THEN THE API_Layer SHALL trả về mã trạng thái 401.
3. IF một thao tác cần mở khóa (`POST /api/accounts`, `POST /api/accounts/import-uri`, `DELETE /api/accounts/{id}`, `GET /api/accounts/{id}/reveal`, `POST /api/export`, `POST /api/import`) được gọi khi kho đang khóa, THEN THE API_Layer SHALL trả về mã trạng thái 401.
4. IF `POST /api/setup` được gọi với mật khẩu ngắn hơn 6 ký tự, THEN THE API_Layer SHALL trả về mã trạng thái 400.
5. IF `POST /api/unlock` được gọi với mật khẩu sai, THEN THE API_Layer SHALL trả về mã trạng thái 401.

### Requirement 11: Kiểm chứng luồng API đầu-cuối

**User Story:** Là một lập trình viên, tôi muốn xác nhận luồng nghiệp vụ chính qua API, để các bước thiết lập đến quản lý tài khoản hoạt động liền mạch.

#### Acceptance Criteria

1. WHEN thực hiện tuần tự `POST /api/setup` → `POST /api/accounts` → `GET /api/accounts` trên TestClient, THE API_Layer SHALL trả về danh sách chứa tài khoản vừa thêm với trường `code` là chuỗi không rỗng.
2. WHEN thực hiện tuần tự `POST /api/lock` rồi `POST /api/unlock` với đúng mật khẩu sau khi đã thêm tài khoản, THE API_Layer SHALL cho phép `GET /api/accounts` trả về mã 200 với đầy đủ tài khoản đã thêm.
3. WHEN `POST /api/generate` được gọi với secret hợp lệ, THE API_Layer SHALL trả về mã 200 với trường `code` đúng độ dài `digits`, kể cả khi kho đang khóa hoặc chưa khởi tạo.
4. IF `POST /api/generate` được gọi với secret không hợp lệ, THEN THE API_Layer SHALL trả về mã trạng thái 400.
5. WHEN `DELETE /api/accounts/{id}` được gọi với `id` không tồn tại trên kho đã mở khóa, THE API_Layer SHALL trả về mã trạng thái 404.
