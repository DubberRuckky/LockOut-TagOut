# PowerShell launcher for Smoke-Test Dashboard
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
Write-Host "Starting LOTO Gateway Smoke-Test Dashboard on http://127.0.0.1:5000 ..." -ForegroundColor Cyan
python "$ScriptDir\dashboard\server.py"
