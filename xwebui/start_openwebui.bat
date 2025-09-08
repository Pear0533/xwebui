@echo off
echo Starting Open WebUI (Frontend + Backend)...
echo.
echo Starting Backend...
start cmd /k "cd backend && python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload"
timeout /t 5 /nobreak
echo.
echo Starting Frontend...
set NODE_OPTIONS=--max-old-space-size=4096
start cmd /k "npm run dev"
echo.
echo Open WebUI is starting...
echo Frontend will be available at: http://localhost:5173
echo Backend API docs at: http://localhost:8080/docs
timeout /t 10
start http://localhost:5173
