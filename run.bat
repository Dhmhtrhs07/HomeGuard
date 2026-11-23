@echo off
REM HomeGuard - double-click to start (Windows)
cd /d "%~dp0"
set PY=python
where python >nul 2>nul || set PY=py
%PY% -m pip install -q -r requirements.txt
%PY% app.py
pause
