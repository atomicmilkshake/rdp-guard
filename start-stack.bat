@echo off
setlocal EnableDelayedExpansion
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Elevating to Administrator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)
title RDP-Guard - Startup Manager
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-stack.ps1"
echo.
echo Launching Security Dashboard (http://127.0.0.1:8099/)...
start http://127.0.0.1:8099/
echo.
echo All requested services are active.
timeout /t 10 /nobreak >nul