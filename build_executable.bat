@echo off
echo =======================================================
echo   Building Standalone Executable for NetSec Toolkit
echo =======================================================
echo.

cd /d "%~dp0"

echo [*] Compiling standalone Windows application with PyInstaller...
.\.venv\Scripts\pyinstaller.exe --noconfirm --onedir --windowed --name "NetSec_Toolkit" --collect-all customtkinter --collect-all reportlab app.py

echo.
echo =======================================================
echo   BUILD COMPLETED!
echo =======================================================
echo.
echo Standalone folder created at: dist\NetSec_Toolkit\
echo Standalone launcher: dist\NetSec_Toolkit\NetSec_Toolkit.exe
echo.
pause
