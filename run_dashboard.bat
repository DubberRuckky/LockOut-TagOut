@echo off
title LOTO Gateway Smoke Test Dashboard
cd /d "%~dp0"
echo Starting LOTO Gateway Smoke-Test Dashboard...
python dashboard\server.py
pause
