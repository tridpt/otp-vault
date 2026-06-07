@echo off
REM Chay OTP Vault tren may nay (chi localhost - khong mo ra mang).
REM Bam dup file nay la chay server + tu mo trinh duyet.
title OTP Vault

cd /d "%~dp0backend"

if not exist "..\.venv\Scripts\python.exe" (
  echo [LOI] Khong tim thay moi truong .venv.
  echo Hay tao truoc bang: python -m venv .venv ^&^& pip install -r requirements.txt
  pause
  exit /b 1
)

REM Mo trinh duyet sau 2 giay (doi server san sang).
start "" /min cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8200"

echo Dang chay OTP Vault tai http://127.0.0.1:8200
echo (Dong cua so nay de tat server.)
"..\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8200
