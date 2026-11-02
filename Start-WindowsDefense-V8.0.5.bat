@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title OpenSource Atlas - Windows Defense V8.0.5

echo ============================================================
echo   OpenSource Atlas - Windows Defense V8.0.5
echo   Foreground only ^| Read-only monitoring by default
echo ============================================================
echo.

set "PYTHON_CMD="
where py >nul 2>nul
if not errorlevel 1 (
  py -3.11 --version >nul 2>nul
  if not errorlevel 1 set "PYTHON_CMD=py -3.11"
  if not defined PYTHON_CMD (
    py -3.12 --version >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=py -3.12"
  )
  if not defined PYTHON_CMD (
    py -3.13 --version >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=py -3.13"
  )
)
if not defined PYTHON_CMD (
  where python >nul 2>nul
  if not errorlevel 1 (
    python --version 2>&1 | findstr /R "Python 3\.1[1-9]" >nul
    if not errorlevel 1 set "PYTHON_CMD=python"
  )
)

if not defined PYTHON_CMD (
  echo [ERROR] Python 3.11 or newer was not found.
  echo Install Python from https://www.python.org/downloads/windows/
  echo During setup, enable "Add python.exe to PATH".
  echo No firewall or system settings have been changed.
  echo.
  pause
  exit /b 1
)

set "PYTHONPATH=%CD%\src;%PYTHONPATH%"
echo [INFO] Using:
%PYTHON_CMD% --version
echo [INFO] Starting the Windows Defense desktop interface...
echo [INFO] This launcher does not request administrator privileges.
echo [INFO] Monitoring starts only when you click a monitoring button.
echo [INFO] Press Ctrl+C here if you need to stop the launcher.
echo.

%PYTHON_CMD% "%CD%\packaging\windows\defense_launcher.py"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
  echo [ERROR] Windows Defense exited with code %EXIT_CODE%.
) else (
  echo [INFO] Windows Defense closed.
)
echo Review the error details above before retrying.
pause
exit /b %EXIT_CODE%
