@echo off
title Windows Defense v0.6
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense-v0.6.ps1"
echo.
echo Windows Defense stopped. Press any key to close.
pause >nul
