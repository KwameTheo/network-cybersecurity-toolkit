@echo off
title Network & Cybersecurity IT Support Toolkit
echo Starting Network & Cybersecurity IT Support Toolkit...
cd /d "%~dp0"
.\.venv\Scripts\python.exe app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo An error occurred while running the application.
    pause
)
