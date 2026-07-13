@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Creating venv and installing deps...
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -U pip
python -m pip install -r requirements.txt
echo.
echo Done. Edit config.json (mail API / domains / proxy), then run start.bat
pause
