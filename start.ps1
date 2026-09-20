# AegisAI Startup Script
Write-Host "Starting AegisAI..." -ForegroundColor Cyan

# Start Backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "cd '$PSScriptRoot\server'; if (Test-Path venv\Scripts\activate.ps1) { .\venv\Scripts\activate.ps1 }; uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

# Start Frontend
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "cd '$PSScriptRoot\client'; npm run dev"

Write-Host "Backend: http://localhost:8000" -ForegroundColor Green
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Green
Write-Host "API Docs: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "Live Attack Replay Streamer: .\server\venv\Scripts\python.exe server\scripts\replay_attacks.py" -ForegroundColor Magenta
