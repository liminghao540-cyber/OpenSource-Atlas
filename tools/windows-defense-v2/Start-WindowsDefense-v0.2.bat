@echo off
setlocal
cd /d "%~dp0"
title Windows Defense - Safe Audit v0.2
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsDefense-v0.2.ps1"
echo.
echo Audit finished. Reports are in the reports folder.
echo This tool does not change settings or block connections.
pause
