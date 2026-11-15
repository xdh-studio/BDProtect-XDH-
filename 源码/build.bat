@echo off
setlocal enabledelayedexpansion
title BDProtect Build Script

echo ============================================================
echo                    BDProtect Build
echo ============================================================
echo.

where gcc >/dev/null 2>nul
if errorlevel 1 (
    echo [ERROR] gcc not found. Please install MinGW-w64 and add it to PATH.
    goto :fail
)

echo [BUILD 1/3] BDProtect.exe (background protection)...
gcc -O2 -Wall -municode -mwindows ^
    bd_privilege.c bd_util.c bd_paths.c bd_ui.c bd_file.c bd_reg.c bd_mbr.c bd_net.c ^
    bd_protect.c bd_inject.c bd_scan.c main.c ^
    -o BDProtect.exe ^
    -ladvapi32 -lntdll -luser32 -lshell32 -lole32 -loleaut32 -liphlpapi -lcomctl32 -lws2_32
if errorlevel 1 goto :fail
echo [OK] BDProtect.exe

echo [BUILD 2/3] BDMain.exe (control center)...
gcc -O2 -Wall -municode -mwindows BDMain.c bd_paths.c -o BDMain.exe ^
    -luser32 -lshell32 -lpdh -liphlpapi -lgdi32 -lcomctl32 -lws2_32 -lole32 -lbcrypt -ladvapi32
if errorlevel 1 goto :fail
echo [OK] BDMain.exe

echo [BUILD 3/3] Uninstall.exe...
gcc -O2 -Wall -municode -mwindows Uninstall.c -o Uninstall.exe -ladvapi32 -lshell32 -luser32 -lole32
if errorlevel 1 goto :fail
echo [OK] Uninstall.exe

echo.
echo ============================================================
echo   All programs built successfully.
echo   Copy the exe files to ..\源文件 before building setup.exe.
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [FAILED] Build interrupted. See the error messages above.
pause
exit /b 1
