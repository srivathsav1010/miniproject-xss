@echo off
echo Starting XSS Shield Pro...
cd /d "%~dp0"
call venv\Scripts\activate 2>nul
python backend\app.py
pause
