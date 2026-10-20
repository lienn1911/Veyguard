@echo off
setlocal
cd /d "%~dp0"
set "NODE_EXE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
where node.exe >nul 2>nul && set "NODE_EXE=node.exe"
if not exist "%NODE_EXE%" if not "%NODE_EXE%"=="node.exe" goto :missing_node
if not exist "node_modules\vite\bin\vite.js" goto :missing_packages
where python.exe >nul 2>nul || goto :missing_python
if not exist data mkdir data
start "" /min powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath 'python.exe' -ArgumentList '-m','services.api' -WorkingDirectory '%~dp0' -WindowStyle Hidden -RedirectStandardOutput 'data/api.out.log' -RedirectStandardError 'data/api.err.log'"
if not defined SOC_DESK_PORT set "SOC_DESK_PORT=5174"
echo Starting SOC Desk at http://127.0.0.1:%SOC_DESK_PORT%
if not defined SOC_TRIAGE_NO_BROWSER start "" /min powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:%SOC_DESK_PORT%'"
"%NODE_EXE%" "node_modules\vite\bin\vite.js" --host 127.0.0.1 --port %SOC_DESK_PORT% --strictPort
if errorlevel 1 (
  echo.
  echo Server could not start. Check if port %SOC_DESK_PORT% is already in use.
  pause
)
exit /b
:missing_node
echo Node.js was not found. Install the LTS version from https://nodejs.org/en/download
pause
exit /b 1
:missing_packages
echo Project packages are missing. Read README.md for installation steps.
pause
exit /b 1
:missing_python
echo Python was not found. Install Python or add it to PATH.
pause
exit /b 1
