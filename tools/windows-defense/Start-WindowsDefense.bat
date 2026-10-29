@echo off
setlocal
title Windows Defense - Safe Audit
cd /d "%~dp0"
echo.
echo ==========================================
echo   Windows Defense - Safe Audit (v0.1)
echo   Read-only checks; no automatic changes.
echo ==========================================
echo.
where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: Windows PowerShell was not found.
  pause
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense.ps1"
echo.
echo Scan finished. Press any key to close.
pause >nul
endlocal
