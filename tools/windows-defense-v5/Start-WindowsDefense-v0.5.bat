@echo off
setlocal
cd /d "%~dp0"
title Windows Defense v0.5
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense-v0.5.ps1"
echo.
echo Windows Defense stopped. Review the logs and response ledger.
pause
