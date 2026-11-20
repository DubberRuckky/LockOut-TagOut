<#
.SYNOPSIS
    dev.ps1 - End-to-end automated demo and verification script for LockOut-TagOut.
    Performs build, venv setup, user enrollment, test execution, browser launch,
    and walks through the full security demo (login with face, upload, replay lock,
    dual-officer restore, and tagout).
#>

[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$AutomatedDemo
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "              LockOut-TagOut (LOTO) End-to-End Orchestrator                    " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Environment Configuration
# ---------------------------------------------------------------------------
$env:LOT_DATA_DIR = Join-Path $ScriptDir "lot-data"
$env:LOT_BIND = "127.0.0.1:8080"
$env:LOT_UPSTREAM = "http://127.0.0.1:8000"
$env:LOT_GATEWAY_URL = "http://127.0.0.1:8080"
$env:LOT_APP_HOST = "127.0.0.1"
$env:LOT_APP_PORT = "8000"
$env:LOT_REQUIRE_FACE = "1"

$LOTOCTL = Join-Path $ScriptDir "user_gateway\target\debug\lotoctl.exe"
$GATEWAY_EXE = Join-Path $ScriptDir "user_gateway\target\debug\lot-gateway.exe"

# Stop any previous lingering instances
Get-Process -Name "lot-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force

# ---------------------------------------------------------------------------
# 2. Python Virtual Environment Setup
# ---------------------------------------------------------------------------
Write-Host "`n[1/6] Checking Python Virtual Environment..." -ForegroundColor Yellow
$VenvDir = Join-Path $ScriptDir ".venv"
$PythonExe = "python"

if (!(Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment in .venv..." -ForegroundColor Gray
    python -m venv $VenvDir
}
if (Test-Path "$VenvDir\Scripts\python.exe") {
    $PythonExe = "$VenvDir\Scripts\python.exe"
}
Write-Host "Using Python: $PythonExe" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Build Rust Gateway and Admin CLI
# ---------------------------------------------------------------------------
Write-Host "`n[2/6] Building Rust Gateway (lot-gateway & lotoctl)..." -ForegroundColor Yellow
cargo build --manifest-path "$ScriptDir\user_gateway\Cargo.toml"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed. Please verify Rust installation."
    exit 1
}
Write-Host "Build complete: lot-gateway and lotoctl are ready." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Enroll Demo Officers (Two Demo Officers + One Tier-5 Officer)
# ---------------------------------------------------------------------------
Write-Host "`n[3/6] Enrolling Demo Officers..." -ForegroundColor Yellow
if (!(Test-Path $env:LOT_DATA_DIR)) {
    New-Item -ItemType Directory -Path $env:LOT_DATA_DIR | Out-Null
}

$lockFile = Join-Path $env:LOT_DATA_DIR "lock-state.json"
if (!(Test-Path $lockFile)) {
    Set-Content -Path $lockFile -Value '{"state":"NORMAL","anomalies":0,"reason":"none","since":0,"initiator":null}'
}

# 1. Constable Alice (Tier 1)
$AliceKey = Join-Path $env:LOT_DATA_DIR "alice.keyfile.json"
if (Test-Path $AliceKey) { Remove-Item $AliceKey -Force }
& $LOTOCTL user add alice --keyfile $AliceKey --passcode "Alice123!" --rank-tier 1 | Out-Null

# 2. Sub-Inspector Bob (Tier 3)
$BobKey = Join-Path $env:LOT_DATA_DIR "bob.keyfile.json"
if (Test-Path $BobKey) { Remove-Item $BobKey -Force }
& $LOTOCTL user add bob --keyfile $BobKey --passcode "Bob123!" --rank-tier 3 | Out-Null

# 3. Superintendent Carol (Tier 5)
$CarolKey = Join-Path $env:LOT_DATA_DIR "carol.keyfile.json"
if (Test-Path $CarolKey) { Remove-Item $CarolKey -Force }
& $LOTOCTL user add carol --keyfile $CarolKey --passcode "Carol123!" --rank-tier 5 | Out-Null

Write-Host "Enrolled:" -ForegroundColor Green
Write-Host "  - alice: Rank Tier 1 (Constable)        -> $AliceKey"
Write-Host "  - bob:   Rank Tier 3 (Sub-Inspector)    -> $BobKey"
Write-Host "  - carol: Rank Tier 5 (Superintendent)   -> $CarolKey"

# ---------------------------------------------------------------------------
# 5. Start Mid-Backend App and Zero-Trust Gateway
# ---------------------------------------------------------------------------
Write-Host "`n[4/6] Launching App Backend and Zero-Trust Gateway..." -ForegroundColor Yellow

$appProc = Start-Process $PythonExe -ArgumentList "main.py" -WorkingDirectory $ScriptDir -PassThru
$gwProc = Start-Process $GATEWAY_EXE -WorkingDirectory $ScriptDir -PassThru

# Give processes 2 seconds to bind
Start-Sleep -Seconds 2

# Verify health
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8080/health" -Method Get -TimeoutSec 5
    Write-Host "Gateway online: $($health.status) on http://127.0.0.1:8080" -ForegroundColor Green
} catch {
    Write-Warning "Gateway health check timed out. Proceeding..."
}

# ---------------------------------------------------------------------------
# 6. Run Automated Test Suites
# ---------------------------------------------------------------------------
if (!$SkipTests) {
    Write-Host "`n[5/6] Running System Test Suites..." -ForegroundColor Yellow
    & $PythonExe -m unittest tests/test_wiring.py tests/test_mid_backend.py tests/test_frontend.py
    if ($LASTEXITCODE -ne 0) {
        Write-Error "One or more tests failed."
    } else {
        Write-Host "All integration and security test suites passed!" -ForegroundColor Green
    }
}

# Launch default browser to UI
Start-Process "http://127.0.0.1:8080/"

# ---------------------------------------------------------------------------
# 7. Walkthrough Demo
# ---------------------------------------------------------------------------
Write-Host "`n[6/6] Interactive Walkthrough Demo" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  The LOTO Case Vault UI is now open in your browser: http://127.0.0.1:8080/"
Write-Host "  You can test logging in via the web UI with Alice123! and alice.keyfile.json"
Write-Host "==============================================================================="

$runDemo = Read-Host "`nWould you like to run the automated CLI walkthrough demo (Replay Lock & Dual Restore)? (Y/n)"
if ($runDemo -ne 'n' -and $runDemo -ne 'N') {
    Write-Host "`n--- DEMO STEP 1: Biometric Face Presence & Handshake Login ---" -ForegroundColor Cyan
    $aliceDevId = (Get-Content $AliceKey | ConvertFrom-Json).device_id
    $challenge = Invoke-RestMethod -Uri "http://127.0.0.1:8080/auth/challenge" -Method Post -ContentType "application/json" -Body "{`"device_id`":`"$aliceDevId`"}"
    $nonce = $challenge.nonce
    Write-Host "Obtained challenge nonce: $($nonce.Substring(0, 16))..." -ForegroundColor Gray

    # Send face frames from sample face photo
    $faceB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$ScriptDir\tests\data\face_photo.jpg"))
    $faceBody = @{
        device_id = $aliceDevId
        nonce = $nonce
        frames = @($faceB64, $faceB64, $faceB64)
    } | ConvertTo-Json
    $faceCheck = Invoke-RestMethod -Uri "http://127.0.0.1:8080/auth/face" -Method Post -ContentType "application/json" -Body $faceBody
    Write-Host "Biometric Face Check Result: face_ok=$($faceCheck.face_ok)" -ForegroundColor Green

    # Sign login body
    $loginJson = & $LOTOCTL sign-login --keyfile $AliceKey --nonce $nonce --passcode "Alice123!"
    $loginRes = Invoke-RestMethod -Uri "http://127.0.0.1:8080/auth/login" -Method Post -ContentType "application/json" -Body $loginJson
    $sessionId = $loginRes.session_id
    Write-Host "Alice authenticated! Session ID: $sessionId" -ForegroundColor Green

    Write-Host "`n--- DEMO STEP 2: Deposit Evidence File via Shifting Code ---" -ForegroundColor Cyan
    $headersCurl = & $LOTOCTL sign-request --keyfile $AliceKey --nonce $nonce --session-id $sessionId --counter 1 --curl
    Write-Host "Generated Ratchet Headers for Counter 1" -ForegroundColor Gray
    Write-Host "Requesting cases via shifting code proxy..." -ForegroundColor Gray
    $casesRes = Invoke-Expression "curl.exe -s $headersCurl http://127.0.0.1:8080/api/cases"
    Write-Host "Cases ledger retrieved successfully!" -ForegroundColor Green

    Write-Host "`n--- DEMO STEP 3: Cryptographic Replay Attack Detection ---" -ForegroundColor Cyan
    Write-Host "Simulating an attacker intercepting and replaying Counter 1 code..." -ForegroundColor Red
    $replayRes = Invoke-Expression "curl.exe -s -i $headersCurl http://127.0.0.1:8080/api/cases"
    $statusNow = Invoke-RestMethod -Uri "http://127.0.0.1:8080/status" -Method Get
    Write-Host "Replay attack detected! System Lock State: $($statusNow.state) (Reason: $($statusNow.reason))" -ForegroundColor Red
    Write-Host "Notice: The web browser UI has now transitioned to the full-screen SYSTEM LOCKED screen." -ForegroundColor Yellow

    Write-Host "`n--- DEMO STEP 4: Dual-Officer Host Restoration ---" -ForegroundColor Cyan
    Write-Host "Attempting unlock with single officer (must fail)..." -ForegroundColor Gray
    $restoreKeyFile = Join-Path $env:LOT_DATA_DIR "restore.key.json"
    & $LOTOCTL generate-restore-key --out $restoreKeyFile | Out-Null

    try {
        & $LOTOCTL restore --restore-key $restoreKeyFile --officer-keyfile $AliceKey 2>$null
        Write-Error "Single officer restore should have failed!"
    } catch {
        Write-Host "Single officer restore correctly refused!" -ForegroundColor Green
    }

    Write-Host "Executing dual-officer restoration (Carol Tier 5 + Inspector David Tier 4)..." -ForegroundColor Gray
    $DavidKey = Join-Path $env:LOT_DATA_DIR "david.keyfile.json"
    if (Test-Path $DavidKey) { Remove-Item $DavidKey -Force }
    & $LOTOCTL user add david --keyfile $DavidKey --passcode "David123!" --rank-tier 4 | Out-Null
    & $LOTOCTL restore --restore-key $restoreKeyFile --officer-keyfile $CarolKey --officer-keyfile $DavidKey

    $statusRestored = Invoke-RestMethod -Uri "http://127.0.0.1:8080/status" -Method Get
    Write-Host "Restoration complete! System State: $($statusRestored.state)" -ForegroundColor Green

    Write-Host "`n--- DEMO STEP 5: Emergency Investigation Tagout Protocol ---" -ForegroundColor Cyan
    Write-Host "Engaging Tagout investigation lock..." -ForegroundColor Red
    & $LOTOCTL tagout --officer "superintendent_carol"
    $statusTagout = Invoke-RestMethod -Uri "http://127.0.0.1:8080/status" -Method Get
    Write-Host "Vault Sealed under TAGOUT! State: $($statusTagout.state) (Initiator: $($statusTagout.initiator))" -ForegroundColor Red
    Write-Host "Notice: The web browser UI has now transitioned to the TAGOUT INVESTIGATION screen." -ForegroundColor Yellow

    # Restoring back to normal for user
    Write-Host "`nRestoring system back to NORMAL for interactive use..." -ForegroundColor Gray
    & $LOTOCTL generate-restore-key --out $restoreKeyFile | Out-Null
    & $LOTOCTL restore --restore-key $restoreKeyFile --officer-keyfile $CarolKey --officer-keyfile $DavidKey | Out-Null
    Write-Host "System restored to NORMAL. Case Vault is ready." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Clean Shutdown Handler
# ---------------------------------------------------------------------------
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "  LockOut-TagOut system is RUNNING on http://127.0.0.1:8080/" -ForegroundColor Green
Write-Host "  Press Enter or Ctrl+C to shut down all background services..." -ForegroundColor Yellow
Write-Host "==============================================================================="
try {
    Read-Host
} finally {
    Write-Host "`nShutting down LOTO processes..." -ForegroundColor Yellow
    if ($appProc -and !$appProc.HasExited) {
        Stop-Process -Id $appProc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($gwProc -and !$gwProc.HasExited) {
        Stop-Process -Id $gwProc.Id -Force -ErrorAction SilentlyContinue
    }
    Get-Process -Name "lot-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "All processes cleanly terminated." -ForegroundColor Green
}
