@echo off
echo =======================================================
echo   Building Standalone Executable for NetSec Toolkit
echo =======================================================
echo.

cd /d "%~dp0"

echo [*] Compiling hardened standalone Windows binary (Author: Kwame_Theo)...
.\.venv\Scripts\pyinstaller.exe --noconfirm NetSec_Toolkit.spec

echo.
echo =======================================================
echo   BUILD COMPLETED!
echo =======================================================
echo.
echo Standalone folder created at: dist\NetSec_Toolkit\
echo Standalone launcher: dist\NetSec_Toolkit\NetSec_Toolkit.exe
echo.
pause
