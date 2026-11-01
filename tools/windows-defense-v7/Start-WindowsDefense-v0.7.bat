@echo off
cd /d "%~dp0"
title Windows Defense v0.7
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense-v0.7.ps1"
echo.
echo Stopped. Review logs and data folders.
pause
