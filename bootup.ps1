# bootup.ps1 - PowerShell launcher for LockOut-TagOut
$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$env:LOT_DATA_DIR = "$ScriptDir\lot-data"
$env:LOT_BIND = "127.0.0.1:8080"
$env:LOT_UPSTREAM = "http://127.0.0.1:8000"
$env:LOT_GATEWAY_URL = "http://127.0.0.1:8080"
$env:LOT_APP_HOST = "127.0.0.1"
$env:LOT_APP_PORT = "8000"
$env:LOT_REQUIRE_FACE = "1"

# Stop existing instances
Get-Process -Name "lot-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force

if (!(Test-Path $env:LOT_DATA_DIR)) {
    New-Item -ItemType Directory -Path $env:LOT_DATA_DIR | Out-Null
}
$lockFile = Join-Path $env:LOT_DATA_DIR "lock-state.json"
if (!(Test-Path $lockFile)) {
    Set-Content -Path $lockFile -Value '{"state":"NORMAL","anomalies":0,"reason":"none","since":0,"initiator":null}'
}

if (!(Test-Path "user_gateway\target\debug\lot-gateway.exe")) {
    Write-Host "Compiling user_gateway..." -ForegroundColor Cyan
    cargo build --manifest-path user_gateway\Cargo.toml
}

Write-Host "Starting App Backend on http://127.0.0.1:8000 ..." -ForegroundColor Green
$appProc = Start-Process python -ArgumentList "main.py" -WorkingDirectory $ScriptDir -PassThru

Write-Host "Starting Zero-Trust Gateway on http://127.0.0.1:8080 ..." -ForegroundColor Green
$gwProc = Start-Process "user_gateway\target\debug\lot-gateway.exe" -WorkingDirectory $ScriptDir -PassThru

Start-Sleep -Seconds 2
Start-Process "http://127.0.0.1:8080/"

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "  LockOut-TagOut (LOTO) Case Vault is RUNNING!" -ForegroundColor Green
Write-Host "  Web UI / Gateway: http://127.0.0.1:8080/"
Write-Host "  App Backend:      http://127.0.0.1:8000/"
Write-Host "  Data Directory:   $($env:LOT_DATA_DIR)"
Write-Host "`n  Press Enter to stop all servers and exit..." -ForegroundColor Yellow
Write-Host "==============================================================================="
Read-Host

if ($appProc) { Stop-Process -Id $appProc.Id -Force -ErrorAction SilentlyContinue }
if ($gwProc) { Stop-Process -Id $gwProc.Id -Force -ErrorAction SilentlyContinue }
Get-Process -Name "lot-gateway" -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "All LOTO services stopped." -ForegroundColor Yellow
