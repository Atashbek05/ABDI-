@echo off
title CyberShield AI Backend
echo.
echo  ========================================
echo   CyberShield AI - Security Backend v2.0
echo  ========================================
echo.

cd /d "%~dp0"

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

:: Install dependencies if needed
if not exist ".deps_installed" (
    echo [*] Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    echo. > .deps_installed
)

:: Train ML model if not exists
if not exist "ml\model.pkl" (
    echo [*] Training ML model (first run)...
    python -m ml.train_model
    echo [+] ML model trained successfully
)

echo.
echo [+] Starting CyberShield AI backend...
echo [+] API: http://127.0.0.1:8000
echo [+] Docs: http://127.0.0.1:8000/docs
echo.
echo  Press Ctrl+C to stop
echo.

python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
