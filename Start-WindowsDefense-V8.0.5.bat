@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title OpenSource Atlas - Windows Defense V8.0.5
:MENU
cls
echo ============================================================
echo   OpenSource Atlas - Windows Defense V8.0.5
echo   Native PowerShell ^| Read-only ^| No auto-blocking
echo ============================================================
echo.
echo   1. Collect one host snapshot
echo   2. Start bounded monitoring (5 minutes)
echo   3. Exit
echo.
choice /C 123 /N /M "Select an option [1-3]: "
if errorlevel 3 goto END
if errorlevel 2 goto MONITOR
if errorlevel 1 goto SNAPSHOT
:SNAPSHOT
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0WindowsDefense-V8.0.5.ps1" -Mode Snapshot
echo.
echo Snapshot finished. Review any warnings above.
pause
goto MENU
:MONITOR
echo.
echo Press Ctrl+C to stop monitoring early.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0WindowsDefense-V8.0.5.ps1" -Mode Monitor -PollSeconds 8 -DurationMinutes 5
echo.
echo Monitor finished.
pause
goto MENU
:END
echo No firewall settings were changed.
exit /b 0
