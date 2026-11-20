@echo off
title Stop LOTO Services
cd /d "%~dp0"

echo ===============================================================================
echo                    Stopping LockOut-TagOut Services
echo ===============================================================================
taskkill /T /F /FI "WINDOWTITLE eq LOTO App Backend*" >nul 2>&1
taskkill /T /F /IM lot-gateway.exe >nul 2>&1
echo [OK] All LOTO processes stopped.
echo ===============================================================================
pause
