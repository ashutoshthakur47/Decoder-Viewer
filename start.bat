@echo off
rem Windows launcher (same steps as start.sh).
rem Backend: FastAPI on http://127.0.0.1:8000   UI: Vite on http://127.0.0.1:5173
setlocal
cd /d "%~dp0"
title decoder-viewer

rem --- refuse to start twice (ports busy) ------------------------------------
for %%P in (8000 5173) do (
  netstat -ano | findstr /r /c:":%%P .*LISTENING" >nul && (
    echo Port %%P is already in use. Close the other copy of the analyzer ^(or the program using it^) and run again.
    pause
    exit /b 1
  )
)

rem --- Python environment -----------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment in .venv ...
  python -m venv .venv 2>nul || py -3 -m venv .venv || (
    echo Python 3.10+ is required and was not found on PATH.
    pause
    exit /b 1
  )
)
echo Checking backend dependencies ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r backend\requirements.txt || (
  echo Installing backend dependencies failed.
  pause
  exit /b 1
)

rem --- Node / frontend --------------------------------------------------------
where npm >nul 2>nul || (
  echo Node.js 18+ and npm are required and were not found on PATH.
  pause
  exit /b 1
)
rem node_modules installed from WSL lacks the Windows esbuild binary: install it too.
if not exist "frontend\node_modules\@esbuild\win32-x64" (
  echo Installing frontend dependencies ...
  pushd frontend
  call npm install --no-audit --no-fund || (popd & echo npm install failed. & pause & exit /b 1)
  popd
)

rem --- start both services in their own minimized windows ---------------------
start "backend" /min /d "%~dp0backend" "%~dp0.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
start "UI" /min /d "%~dp0frontend" cmd /c npm run dev -- --host 127.0.0.1 --port 5173 --strictPort

echo Waiting for the backend ...
for /l %%i in (1,1,60) do (
  curl -s -o nul http://127.0.0.1:8000/api/health && goto ready
  ping -n 2 127.0.0.1 >nul
)
echo The backend did not start: open the "backend" window to see the error.
goto wait

:ready
ping -n 3 127.0.0.1 >nul
start "" http://127.0.0.1:5173
echo.
echo   UI   http://127.0.0.1:5173
echo   API  http://127.0.0.1:8000/docs

:wait
echo.
echo Press any key in this window to stop both.
pause >nul
for %%P in (8000 5173) do (
  for /f "tokens=5" %%I in ('netstat -ano ^| findstr /r /c:":%%P .*LISTENING"') do taskkill /PID %%I /T /F >nul 2>&1
)
echo Stopped.
endlocal
