@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

title GrokX Protocol Register

set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python not found. Run setup.bat first.
        pause
        exit /b 1
    )
    set "PYTHON_EXE=python"
)

echo Starting GrokX protocol registration (console)...
if "%~1"=="" (
    "%PYTHON_EXE%" "%~dp0register_protocol.py" --cli
) else (
    "%PYTHON_EXE%" "%~dp0register_protocol.py" %*
)
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" echo Program exited with code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%
