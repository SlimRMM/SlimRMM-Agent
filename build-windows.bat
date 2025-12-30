@echo off
REM SlimRMM Agent - Windows Build Script
REM Copyright (c) 2025 Kiefer Networks
REM
REM Usage: build-windows.bat [version]
REM

setlocal enabledelayedexpansion

set VERSION=%1
if "%VERSION%"=="" set VERSION=1.0.0

echo ================================================
echo   SlimRMM Agent - Windows Builder
echo   Version: %VERSION%
echo ================================================
echo.

REM Check for PowerShell
where powershell >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: PowerShell is required but not found
    exit /b 1
)

REM Run the PowerShell build script
powershell -ExecutionPolicy Bypass -File "%~dp0build-windows-msi.ps1" -Version %VERSION%

if %ERRORLEVEL% neq 0 (
    echo.
    echo Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo.
echo Build completed successfully!
