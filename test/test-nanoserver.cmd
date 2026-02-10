@echo off
echo ========================================
echo  certz Nanoserver Smoke Tests
echo ========================================
echo.

set CERTZ=C:\app\certz.exe
set WORK=C:\app\testwork

mkdir %WORK% 2>nul
cd /d %WORK%

:: ---- BASIC COMMANDS ----

echo [1/20] --version
%CERTZ% --version
if %errorlevel% neq 0 goto :fail

echo.
echo [2/20] --help
%CERTZ% --help >nul
if %errorlevel% neq 0 goto :fail

echo.
echo [3/20] examples
%CERTZ% examples >nul
if %errorlevel% neq 0 goto :fail

:: ---- CREATE COMMANDS ----

echo.
echo [4/20] create dev
%CERTZ% create dev test.local --file dev.pfx --cert dev.pem --key dev.key --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [5/20] create ca
%CERTZ% create ca --name "Test CA" --file ca.pfx --cert ca.pem --key ca.key --password CaPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [6/20] create dev --ephemeral
%CERTZ% create dev ephemeral.local --ephemeral
if %errorlevel% neq 0 goto :fail

:: ---- INSPECT COMMANDS ----

echo.
echo [7/20] inspect pem
%CERTZ% inspect dev.pem
if %errorlevel% neq 0 goto :fail

echo.
echo [8/20] inspect pfx
%CERTZ% inspect dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [9/20] inspect --format json
%CERTZ% inspect dev.pem --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- LINT COMMANDS ----

echo.
echo [10/20] lint
%CERTZ% lint dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [11/20] lint --format json
%CERTZ% lint dev.pfx --password TestPass123 --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- CONVERT COMMANDS ----

echo.
echo [12/20] convert pem to der
%CERTZ% convert dev.pem --to der
if %errorlevel% neq 0 goto :fail

echo.
echo [13/20] convert der to pem
%CERTZ% convert dev.der --to pem --output roundtrip.pem
if %errorlevel% neq 0 goto :fail

echo.
echo [14/20] convert pem to pfx
%CERTZ% convert dev.pem --to pfx --key dev.key --password ConvertPass123 --output converted.pfx
if %errorlevel% neq 0 goto :fail

:: ---- RENEW COMMAND ----

echo.
echo [15/20] renew
%CERTZ% renew dev.pfx --password TestPass123 --out renewed.pfx --out-password RenewPass123
if %errorlevel% neq 0 goto :fail

:: ---- MONITOR COMMANDS ----

echo.
echo [16/20] monitor
%CERTZ% monitor .
if %errorlevel% neq 0 goto :fail

echo.
echo [17/20] monitor --format json
%CERTZ% monitor . --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- VERIFY COMMAND ----

echo.
echo [18/20] verify
%CERTZ% verify --file dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

:: ---- STORE COMMANDS ----

echo.
echo [19/20] list
%CERTZ% list
if %errorlevel% neq 0 goto :fail

echo.
echo [20/20] install
%CERTZ% install --file dev.pfx --password TestPass123 --sn My --sl CurrentUser
if %errorlevel% neq 0 goto :fail

:: ---- DONE ----

echo.
echo ========================================
echo  All 20 smoke tests passed!
echo ========================================
exit /b 0

:fail
echo.
echo ========================================
echo  SMOKE TEST FAILED
echo ========================================
exit /b 1
