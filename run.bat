@echo off
REM Chay OTP Vault tren may nay (chi localhost - khong mo ra mang).
cd /d "%~dp0backend"
"..\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8200
