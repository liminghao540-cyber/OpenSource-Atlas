@echo off
setlocal
cd /d "%~dp0"
title Windows Defense v0.4 - Independent Monitor
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense-v0.4.ps1"
echo.
echo Monitor stopped. Review logs and data folders.
pause
