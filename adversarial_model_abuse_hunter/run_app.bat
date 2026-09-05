@echo off
cd /d "%~dp0"
set PORT=8502
:checkport
netstat -ano -p tcp | findstr :%PORT% >nul
if not errorlevel 1 (
    set /a PORT=%PORT%+1
    goto checkport
)
where py >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Starting Streamlit on port %PORT%
    python -m streamlit run app.py --server.headless true --server.port %PORT% --server.address 127.0.0.1
) else (
    echo Starting Streamlit on port %PORT%
    py -m streamlit run app.py --server.headless true --server.port %PORT% --server.address 127.0.0.1
)
