@echo off
echo =======================================================
echo   Pushing NetSec Toolkit v1.5.0 to GitHub
echo   Repository: https://github.com/KwameTheo/network-cybersecurity-toolkit
echo =======================================================
echo.

cd /d "%~dp0"

echo [*] Checking remote configuration...
git remote -v

echo.
echo [*] Pushing main branch to GitHub (a browser sign-in may appear)...
git push -u origin main

echo.
if %ERRORLEVEL% equ 0 (
    echo =======================================================
    echo   SUCCESS! Code pushed to GitHub successfully!
    echo =======================================================
) else (
    echo [!] Push encountered an issue. Please verify your GitHub credentials.
)

echo.
pause
