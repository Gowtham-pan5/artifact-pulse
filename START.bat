@echo off
setlocal EnableDelayedExpansion
title Artifact-Pulse Launcher
cd /d "%~dp0"

REM ############################################################
REM  Artifact-Pulse — one-click launcher
REM  Starts: Flask API (:5000) + React UI (:5173) + browser
REM ############################################################

set "PYTHONPATH="

echo.
echo  ============================================
echo    ARTIFACT-PULSE  ^|  Forensic Triage Suite
echo  ============================================
echo.

REM ---------- Python check ----------
where python >nul 2>nul
if errorlevel 1 (
    echo [X] Python not found on PATH. Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

REM ---------- Node check (Vite 7 needs 20.19+ / 22.12+) ----------
where node >nul 2>nul
if errorlevel 1 (
    echo [X] Node.js not found on PATH. Install Node 22.12+ from https://nodejs.org
    pause
    exit /b 1
)
for /f "delims=" %%v in ('node --version') do set "NODE_V=%%v"
node -e "const [M,m]=process.versions.node.split('.').map(Number);process.exit((M===20&&m>=19)||(M===22&&m>=12)||M>=23?0:1)" >nul 2>nul
if errorlevel 1 (
    echo [X] Node version too old ^(%NODE_V%^). Vite 7 requires 20.19+ or 22.12+.
    echo     Download the latest LTS from https://nodejs.org
    pause
    exit /b 1
)

REM ---------- Backend venv + deps ----------
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)
if not exist ".venv\Lib\site-packages\flask" (
    echo [*] Installing backend dependencies...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [X] pip install failed.
        pause
        exit /b 1
    )
)

REM ---------- Frontend deps ----------
if not exist "artifact-pulse-ui\node_modules" (
    echo [*] Installing frontend dependencies ^(npm install^)...
    pushd artifact-pulse-ui
    call npm install --legacy-peer-deps
    if errorlevel 1 (
        popd
        echo [X] npm install failed.
        pause
        exit /b 1
    )
    popd
)

REM ---------- Start Flask API ----------
echo [*] Checking if API is already running on :5000 ...
curl -s -o nul --max-time 2 http://127.0.0.1:5000/api/health >nul 2>nul
if not errorlevel 1 (
    echo [OK] API already running, skipping start.
    set API_READY=1
    goto api_ok
)
echo [*] Starting Flask API on http://127.0.0.1:5000 ...
start "Artifact-Pulse API (close to stop)" cmd /k "cd /d %~dp0 && set PYTHONPATH= && .venv\Scripts\python.exe -m web.app"

echo [*] Waiting for API (first boot can take a while)...
set API_READY=0
for /l %%i in (1,1,90) do (
    curl -s -o nul --max-time 2 http://127.0.0.1:5000/api/health >nul 2>nul
    if not errorlevel 1 (
        set API_READY=1
        goto api_ok
    )
    timeout /t 1 /nobreak >nul
)
:api_ok
if not "%API_READY%"=="1" (
    echo [X] API did not respond on :5000 within 60s. Check the API window.
    pause
    exit /b 1
)
echo [OK] API is up.

REM ---------- Start Vite UI ----------
echo [*] Checking if UI is already running on :5173 ...
curl -s -o nul --max-time 2 http://localhost:5173 >nul 2>nul
if not errorlevel 1 (
    echo [OK] UI already running, skipping start.
    set UI_READY=1
    goto ui_ok
)
echo [*] Starting React UI on http://localhost:5173 ...
start "Artifact-Pulse UI (close to stop)" cmd /k "cd /d %~dp0artifact-pulse-ui && npm run dev"

echo [*] Waiting for UI...
set UI_READY=0
for /l %%i in (1,1,90) do (
    curl -s -o nul --max-time 2 http://localhost:5173 >nul 2>nul
    if not errorlevel 1 (
        set UI_READY=1
        goto ui_ok
    )
    timeout /t 1 /nobreak >nul
)
:ui_ok
if not "%UI_READY%"=="1" (
    echo [X] UI did not respond on :5173 within 90s. Check the UI window.
    pause
    exit /b 1
)
echo [OK] UI is up.

echo.
echo  ============================================
echo    READY ^| opening http://localhost:5173
echo    Flow: click "run pipeline" to scan THIS
echo          machine, then browse artifacts,
echo          anomalies, chain ^& reports.
echo    Close the two windows to stop the servers.
echo  ============================================
echo.
start "" http://localhost:5173
endlocal
