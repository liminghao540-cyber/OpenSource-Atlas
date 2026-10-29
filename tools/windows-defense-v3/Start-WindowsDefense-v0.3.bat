@echo off
setlocal
cd /d "%~dp0"
title Windows Defense v0.3 - Continuous Monitor
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense-Monitor-v0.3.ps1"
echo.
echo Monitor stopped. Check the logs folder.
pause
