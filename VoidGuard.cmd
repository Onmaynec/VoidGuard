@echo off
setlocal
chcp 65001 >nul 2>&1
set "VG_ROOT=%~dp0"
title VOIDGUARD Security Console

where pwsh.exe >nul 2>&1
if %errorlevel% equ 0 (
    pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VG_ROOT%VoidGuard.ps1" %*
) else (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VG_ROOT%VoidGuard.ps1" %*
)

set "VG_EXIT=%errorlevel%"
endlocal & exit /b %VG_EXIT%
