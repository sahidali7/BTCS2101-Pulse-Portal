@echo off
cd /d "%~dp0"
echo ==========================================
echo BTCS2101 Student-Faculty Portal
 echo ==========================================
where py >nul 2>nul
if errorlevel 1 (set PYTHON=python) else (set PYTHON=py -3)
if not exist venv\Scripts\python.exe (
  echo Creating Python virtual environment...
  %PYTHON% -m venv venv
  if errorlevel 1 goto error
)
echo Installing required packages...
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto error
echo Starting application at http://127.0.0.1:5000
venv\Scripts\python.exe app.py
goto end
:error
echo Setup failed. Ensure Python 3.10+ is installed and internet is available.
pause
:end
