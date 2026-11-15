@echo off
cd /d "%~dp0"
title BDAdmin Build

where gcc >/dev/null 2>nul
if errorlevel 1 (
    echo [ERROR] gcc not found. Please install MinGW-w64 and add it to PATH.
    goto :fail
)

echo [BUILD] BDAdmin.exe ...
gcc -O2 -Wall -municode -mwindows BDAdmin.c -o BDAdmin.exe ^
    -luser32 -lshell32 -lgdi32 -lcomctl32 -lcomdlg32 -lws2_32 -lole32 -lbcrypt
if errorlevel 1 goto :fail
echo [OK] BDAdmin.exe

pause
exit /b 0

:fail
echo [FAILED] Build interrupted.
pause
exit /b 1
