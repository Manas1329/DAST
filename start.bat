@echo off
echo ========================================
echo   Starting Sentinel DAST Environments
echo ========================================
echo.

echo [1/2] Booting Python Backend API Server on Port 8002...
start "Sentinel API Server" cmd /k "python backend\compliance_app.py"

echo [2/2] Booting Static Frontend Server on Port 8000...
start "Sentinel Frontend Web Server" cmd /k "cd frontend && python -m http.server 8000"

echo.
echo Waiting for servers to initialize...
timeout /t 2 /nobreak > nul

echo Launching browser...
start http://localhost:8000
