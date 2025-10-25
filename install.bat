@echo off
REM Installation script for Jarvis on Windows
REM This script sets up a local environment for Jarvis
REM 
REM Created by orpheus497

echo ======================================
echo   Jarvis v1.0.0 Local Setup Script
echo ======================================
echo.
echo Peer-to-Peer Encrypted Messenger
echo Created by orpheus497
echo.

REM Check for Python 3
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python 3 is required but not found.
    echo Please install Python 3.8 or higher from python.org
    pause
    exit /b 1
)

echo Found Python
python --version

REM Check if pip is available
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo Error: pip is required but not found.
    echo Please ensure pip is installed with Python.
    pause
    exit /b 1
)

REM Create virtual environment
set VENV_DIR=venv
if not exist "%VENV_DIR%" (
    echo Creating Python virtual environment in '.\%VENV_DIR%'...
    python -m venv "%VENV_DIR%"
) else (
    echo Virtual environment already exists.
)

REM Activate and install dependencies
echo Installing dependencies...
call "%VENV_DIR%\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install .
call deactivate

REM Create launcher script
set LAUNCHER_SCRIPT=run_jarvis.bat
echo Creating launcher script '.\%LAUNCHER_SCRIPT%'...
(
echo @echo off
echo REM Launcher for Jarvis
echo REM Activates the virtual environment and runs the application
echo.
echo REM Get the directory where the script is located
echo set DIR=%%~dp0
echo.
echo REM Activate virtual environment and run Jarvis
echo call "%%DIR%%venv\Scripts\activate.bat"
echo python -m jarvis %%*
echo call deactivate
) > "%LAUNCHER_SCRIPT%"

echo.
echo ✓ Setup complete!
echo.
echo To run Jarvis, execute:
echo   %LAUNCHER_SCRIPT%
echo.
echo Or simply:
echo   jarvis
echo.
echo To remove the local environment, run:
echo   uninstall.bat
echo.
pause
