@echo off
setlocal
title BDApp Setup Builder

echo ============================================
echo           BDApp Installer Build Script
echo ============================================
echo.

echo [1/4] Checking compiler environment...
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] GCC not found! Please check MinGW environment variables.
    goto :error
)
where windres >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] windres not found! Please check MinGW environment variables.
    goto :error
)
echo        Environment OK.
echo.

echo [2/4] Checking source files...
if not exist "installer.c" (
    echo [ERROR] Missing file: installer.c
    goto :error
)
if not exist "installer.rc" (
    echo [ERROR] Missing file: installer.rc
    goto :error
)
echo        File check OK.
echo.

echo [3/4] Cleaning old build files...
if exist "installer.res" del /f /q "installer.res"
if exist "setup.exe" del /f /q "setup.exe"
echo        Cleanup OK.
echo.

echo [4/4] Compiling...
echo        - Packing resources...
windres installer.rc -O coff -o installer.res
if %errorlevel% neq 0 (
    echo [ERROR] Resource compilation failed!
    goto :error
)

echo        - Compiling and linking setup.exe...
gcc installer.c installer.res -o setup.exe -mwindows -municode -lole32 -lshlwapi -ladvapi32 -lcomctl32 -luuid -static
if %errorlevel% neq 0 (
    echo [ERROR] C code compilation failed! 
    goto :error
)

echo.
echo ============================================
echo [SUCCESS] Build completed! setup.exe generated.
echo ============================================
echo.
explorer .
pause
exit /b 0

:error
echo.
echo ============================================
echo [FAILED] Build interrupted. See error messages above.
echo ============================================
echo.
pause
exit /b 1