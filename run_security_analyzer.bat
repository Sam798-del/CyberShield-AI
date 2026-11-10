@echo off
title CyberShield AI - Security Analyzer Launcher
echo ===================================================
echo   Starting CyberShield AI Security Analyzer Suite
echo ===================================================

start "CyberShield Analyzer API (Port 5050)" cmd /k "cd /d %~dp0security-analyzer && python app.py"
timeout /t 2 /nobreak >nul

start "CyberShield Main Web Server (Port 5000)" cmd /k "cd /d %~dp0 && python app.py"
timeout /t 2 /nobreak >nul

start http://localhost:5000/pages/security-analyzer.html

echo Both servers are running!
echo Web UI: http://localhost:5000/pages/security-analyzer.html
echo API:    http://localhost:5050/api/analyzer/health

