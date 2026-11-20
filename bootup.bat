@echo off
title LockOut-TagOut (LOTO) Launcher
cd /d "%~dp0"

echo ===============================================================================
echo                LockOut-TagOut (LOTO) System Bootstrapper
echo ===============================================================================

rem 1. Environment configuration
set "LOT_DATA_DIR=%~dp0lot-data"
set "LOT_BIND=127.0.0.1:8080"
set "LOT_UPSTREAM=http://127.0.0.1:8000"
set "LOT_GATEWAY_URL=http://127.0.0.1:8080"
set "LOT_APP_HOST=127.0.0.1"
set "LOT_APP_PORT=8000"
set "LOT_REQUIRE_FACE=1"

rem 2. Stop any existing lingering instances
echo [1/4] Stopping any previous instances...
taskkill /T /F /FI "WINDOWTITLE eq LOTO App Backend*" >nul 2>&1
taskkill /T /F /IM lot-gateway.exe >nul 2>&1

rem 3. Ensure data directory and initial lock state
echo [2/4] Checking data directory and state...
if not exist "%LOT_DATA_DIR%" mkdir "%LOT_DATA_DIR%"
if not exist "%LOT_DATA_DIR%\lock-state.json" (
    echo {"state":"NORMAL","anomalies":0,"reason":"none","since":0,"initiator":null}> "%LOT_DATA_DIR%\lock-state.json"
)

rem 4. Build gateway if executable is missing
if not exist "user_gateway\target\debug\lot-gateway.exe" (
    echo [3/4] Building user_gateway lot-gateway.exe...
    cargo build --manifest-path user_gateway\Cargo.toml
    if errorlevel 1 (
        echo [ERROR] Failed to compile user_gateway. Please check Rust installation.
        pause
        exit /b 1
    )
) else (
    echo [3/4] Gateway binary verified.
)

rem 5. Launch App Backend (Python FastAPI on port 8000)
echo [4/4] Launching App Backend on http://127.0.0.1:8000 ...
start "LOTO App Backend [Port 8000]" cmd /k python main.py

rem 6. Launch Zero-Trust Gateway (Rust on port 8080)
echo Launching Zero-Trust Gateway on http://127.0.0.1:8080 ...
start "LOTO Gateway [Port 8080]" cmd /k user_gateway\target\debug\lot-gateway.exe

rem Wait 2 seconds using ping (safe on all Windows versions)
ping -n 3 127.0.0.1 >nul

rem Open default browser to gateway UI
echo Opening UI in default browser: http://127.0.0.1:8080/
start http://127.0.0.1:8080/

echo.
echo ===============================================================================
echo   LockOut-TagOut (LOTO) Case Vault is RUNNING!
echo ===============================================================================
echo   Web UI / Gateway:  http://127.0.0.1:8080/
echo   App Backend:       http://127.0.0.1:8000/
echo   Data Directory:    %LOT_DATA_DIR%
echo.
echo   Enrolled Demo Keyfiles (load via browser file picker in UI):
echo     - %LOT_DATA_DIR%\alice.keyfile.json (Rank 1 - Constable)
echo     - %LOT_DATA_DIR%\bob.keyfile.json   (Rank 3 - Sub-Inspector)
echo     - %LOT_DATA_DIR%\carol.keyfile.json (Rank 5 - Superintendent)
echo.
echo   To stop the servers at any time, run shutdown.bat or close their windows.
echo ===============================================================================
echo.
pause
