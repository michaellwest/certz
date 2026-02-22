@echo off
echo ========================================
echo  certz Windows Smoke Tests
echo ========================================
echo.

set CERTZ=C:\app\certz.exe
set WORK=C:\app\testwork

mkdir %WORK% 2>nul
cd /d %WORK%

:: ---- BASIC COMMANDS ----

echo [1/22] --version
%CERTZ% --version
if %errorlevel% neq 0 goto :fail

echo.
echo [2/22] --help
%CERTZ% --help >nul
if %errorlevel% neq 0 goto :fail

echo.
echo [3/22] examples
%CERTZ% examples >nul
if %errorlevel% neq 0 goto :fail

:: ---- CREATE COMMANDS ----

echo.
echo [4/22] create dev
%CERTZ% create dev test.local --file dev.pfx --cert dev.pem --key dev.key --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [5/22] create ca
%CERTZ% create ca --name "Test CA" --file ca.pfx --cert ca.pem --key ca.key --password CaPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [6/22] create dev --ephemeral
%CERTZ% create dev ephemeral.local --ephemeral
if %errorlevel% neq 0 goto :fail

:: ---- INSPECT COMMANDS ----

echo.
echo [7/22] inspect pem
%CERTZ% inspect dev.pem
if %errorlevel% neq 0 goto :fail

echo.
echo [8/22] inspect pfx
%CERTZ% inspect dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [9/22] inspect --format json
%CERTZ% inspect dev.pem --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- LINT COMMANDS ----

echo.
echo [10/22] lint
%CERTZ% lint dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [11/22] lint --format json
%CERTZ% lint dev.pfx --password TestPass123 --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- CONVERT COMMANDS ----

echo.
echo [12/22] convert pem to der
%CERTZ% convert dev.pem --to der
if %errorlevel% neq 0 goto :fail

echo.
echo [13/22] convert der to pem
%CERTZ% convert dev.der --to pem --output roundtrip.pem
if %errorlevel% neq 0 goto :fail

echo.
echo [14/22] convert pem to pfx
%CERTZ% convert dev.pem --to pfx --key dev.key --password ConvertPass123 --output converted.pfx
if %errorlevel% neq 0 goto :fail

:: ---- RENEW COMMAND ----

echo.
echo [15/22] renew
%CERTZ% renew dev.pfx --password TestPass123 --out renewed.pfx --out-password RenewPass123
if %errorlevel% neq 0 goto :fail

:: ---- MONITOR COMMANDS ----

echo.
echo [16/22] monitor .
%CERTZ% monitor .
if %errorlevel% neq 0 goto :fail

echo.
echo [17/22] monitor . --format json
%CERTZ% monitor . --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- PASSWORD MAP TESTS ----

echo.
echo [18/22] monitor --password-map
echo dev.pfx=TestPass123> passwords.txt
echo ca.pfx=CaPass123>> passwords.txt
echo converted.pfx=ConvertPass123>> passwords.txt
echo renewed.pfx=RenewPass123>> passwords.txt
%CERTZ% monitor . --password-map passwords.txt
if %errorlevel% neq 0 goto :fail

echo.
echo [19/22] monitor --password-map --format json
%CERTZ% monitor . --password-map passwords.txt --format json >nul
if %errorlevel% neq 0 goto :fail

:: ---- STORE COMMANDS ----

echo.
echo [20/22] install
%CERTZ% install --file dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

echo.
echo [21/22] list
%CERTZ% list
if %errorlevel% neq 0 goto :fail

:: ---- VERIFY COMMAND (after install so cert is trusted) ----

echo.
echo [22/22] verify
%CERTZ% verify --file dev.pfx --password TestPass123
if %errorlevel% neq 0 goto :fail

:: ---- DONE ----

echo.
echo ========================================
echo  All 22 smoke tests passed!
echo ========================================
exit /b 0

:fail
echo.
echo ========================================
echo  SMOKE TEST FAILED
echo ========================================
exit /b 1
