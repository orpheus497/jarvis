@echo off
REM Uninstallation script for Jarvis on Windows
REM Removes the virtual environment and launcher scripts
REM 
REM Created by orpheus497

echo ======================================
echo   Jarvis Uninstall Script
echo ======================================
echo.

set /p CONFIRM="Remove Jarvis environment? (y/N): "
if /i not "%CONFIRM%"=="y" (
    echo Uninstall cancelled.
    pause
    exit /b 0
)

REM Remove virtual environment
if exist "venv" (
    echo Removing virtual environment...
    rmdir /s /q venv
)

REM Remove launcher script
if exist "run_jarvis.bat" (
    echo Removing launcher script...
    del /q run_jarvis.bat
)

echo.
echo ✓ Uninstall complete!
echo.
echo Note: Your data files have been preserved:
echo   - Identity: %%APPDATA%%\Jarvis\identity.enc
echo   - Contacts: %%APPDATA%%\Jarvis\contacts.json
echo   - Messages: %%APPDATA%%\Jarvis\messages.json
echo   - Groups: %%APPDATA%%\Jarvis\groups.json
echo.
echo To completely remove all data, delete the data directory:
echo   rmdir /s /q "%%APPDATA%%\Jarvis"
echo.
pause
