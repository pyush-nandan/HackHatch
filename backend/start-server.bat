@echo off
echo ================================================
echo  Web Security Guardian - Quick Setup
echo ================================================
echo.

echo [1/3] Installing Python dependencies...
cd backend
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    echo Try running: python -m pip install -r requirements.txt
    pause
    exit /b 1
)

echo.
echo [2/3] Testing backend server...
echo Starting server on http://localhost:5000
echo.
echo IMPORTANT: 
echo - Keep this window OPEN while using the extension
echo - Press Ctrl+C to stop the server
echo.
echo [3/3] Next steps:
echo 1. Install Chrome extension from: ..\extension
echo 2. Open dashboard: ..\dashboard\dashboard.html
echo.
echo ================================================
echo  Starting Web Security Guardian API...
echo ================================================
echo.

python app.py
