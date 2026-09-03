@echo off
setlocal
echo =======================================================
echo   NetSec IT Support Toolkit - New Computer Setup
echo =======================================================
echo.

cd /d "%~dp0"

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Python is not found in your system PATH.
    echo     Please install Python 3.11 or higher from https://python.org
    echo     (Make sure to check "Add Python to PATH" during installation)
    pause
    exit /b 1
)

echo [*] Python detected on this system.

:: Create virtual environment if missing
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if %ERRORLEVEL% NEQ 0 (
        echo [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Install dependencies
echo [*] Installing required packages from requirements.txt...
.\.venv\Scripts\pip.exe install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [!] Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo =======================================================
echo   Setup Complete! Launching NetSec Toolkit...
echo =======================================================
echo.

start "" .\.venv\Scripts\python.exe app.py
