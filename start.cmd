@echo off
setlocal
cd /d "%~dp0"
set "NODE_EXE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
where node.exe >nul 2>nul && set "NODE_EXE=node.exe"
if not exist "%NODE_EXE%" if not "%NODE_EXE%"=="node.exe" goto :missing_node
where python.exe >nul 2>nul || goto :missing_python
if not exist "node_modules\vite\bin\vite.js" goto :install_packages
"%NODE_EXE%" -e "require('esbuild')" >nul 2>nul
if errorlevel 1 goto :install_packages
goto :packages_ready

:install_packages
where npm.cmd >nul 2>nul || goto :missing_npm
echo Installing missing frontend packages...
call npm.cmd install --include=optional
if errorlevel 1 goto :install_failed
if not exist "node_modules\vite\bin\vite.js" goto :install_failed
"%NODE_EXE%" -e "require('esbuild')" >nul 2>nul
if errorlevel 1 goto :install_failed

:packages_ready
python -c "import services.api" >nul 2>nul
if errorlevel 1 (
  echo Installing missing Python packages...
  python -m pip install -r requirements.txt
  if errorlevel 1 goto :python_packages_failed
  python -c "import services.api" >nul 2>nul
  if errorlevel 1 goto :python_packages_failed
)
if defined SOC_TRIAGE_CHECK_ONLY (
  echo SOC Desk startup checks passed.
  exit /b 0
)
if not exist data mkdir data
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\restart-api.ps1" -ProjectRoot "%~dp0."
if errorlevel 1 goto :api_start_failed
if not defined SOC_DESK_PORT set "SOC_DESK_PORT=5174"
echo Starting SOC Desk at http://127.0.0.1:%SOC_DESK_PORT%
if not defined SOC_TRIAGE_NO_BROWSER start "" /min powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:%SOC_DESK_PORT%'"
"%NODE_EXE%" "node_modules\vite\bin\vite.js" --host 127.0.0.1 --port %SOC_DESK_PORT% --strictPort
if errorlevel 1 (
  echo.
  echo Frontend server stopped. Read the error above for the cause.
  pause
)
exit /b
:api_start_failed
echo SOC Desk API could not start. Review the error above and data\api.err.log.
pause
exit /b 1
:missing_node
echo Node.js was not found. Install the LTS version from https://nodejs.org/en/download
pause
exit /b 1
:missing_npm
echo npm was not found. Install Node.js LTS with npm from https://nodejs.org/en/download
pause
exit /b 1
:install_failed
echo Frontend packages could not be installed. Run npm install --include=optional in this folder and review the error above.
pause
exit /b 1
:python_packages_failed
echo Python packages could not be installed. Run python -m pip install -r requirements.txt and review the error above.
pause
exit /b 1
:missing_python
echo Python was not found. Install Python or add it to PATH.
pause
exit /b 1
