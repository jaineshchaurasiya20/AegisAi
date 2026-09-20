# ==============================================================================
# AegisAI 2.0 — CLI Daemon & Service Control Utility (aegisctl)
# ==============================================================================
# Usage:
#   .\aegisctl.ps1 status      - Check daemon & taskbar controller status
#   .\aegisctl.ps1 start       - Silently start background engine & tray icon
#   .\aegisctl.ps1 stop        - Stop background daemon and tray processes
#   .\aegisctl.ps1 restart     - Restart background engine and tray controller
#   .\aegisctl.ps1 enable      - Register Windows logon permission prompt
#   .\aegisctl.ps1 disable     - Unregister Windows logon startup prompt
#   .\aegisctl.ps1 test-alert  - Trigger a test native OS desktop toast notification
#   .\aegisctl.ps1 test-prompt - Open logon permission prompt dialog for preview
# ==============================================================================

param (
    [Parameter(Position=0)]
    [ValidateSet("status", "start", "stop", "restart", "enable", "disable", "test-alert", "test-prompt", "help")]
    [string]$Command = "status"
)

$ErrorActionPreference = "Continue"

$rootDir = $PSScriptRoot
$serverDir = Join-Path $rootDir "server"
$pythonwPath = Join-Path $serverDir "venv\Scripts\pythonw.exe"
$pythonPath = Join-Path $serverDir "venv\Scripts\python.exe"
$trayScript = Join-Path $serverDir "app\collector\tray_agent.py"
$launcherScript = Join-Path $serverDir "scripts\logon_launcher.py"
$installScript = Join-Path $serverDir "scripts\install_startup_prompt.ps1"
$uninstallScript = Join-Path $serverDir "scripts\uninstall_startup_prompt.ps1"

if (-not (Test-Path $pythonwPath)) { $pythonwPath = "pythonw.exe" }
if (-not (Test-Path $pythonPath)) { $pythonPath = "python.exe" }

function Get-AegisStatus {
    Write-Host "`n=== AegisAI 2.0 Daemon Status ===" -ForegroundColor Cyan
    
    # Check port 8000
    $backendPort = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
    $isListening = $null -ne $backendPort
    
    # Check Uvicorn health endpoint
    $healthStatus = "Unreachable"
    if ($isListening) {
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($resp -and $resp.status) {
                $healthStatus = "Operational (v$($resp.version))"
            } else {
                $healthStatus = "Listening"
            }
        } catch {
            $healthStatus = "Starting / Initializing"
        }
    }

    # Check Tray processes
    $trayProcs = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%tray_agent.py%'" -ErrorAction SilentlyContinue

    # Check Registry Startup status
    $regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regValue = Get-ItemProperty -Path $regKey -Name "AegisAILauncher" -ErrorAction SilentlyContinue
    $startupEnabled = $null -ne $regValue

    Write-Host "Backend Service (Port 8000) : " -NoNewline
    if ($isListening) {
        Write-Host "RUNNING " -ForegroundColor Green -NoNewline
        Write-Host "[$healthStatus, PID: $($backendPort.OwningProcess)]" -ForegroundColor Gray
    } else {
        Write-Host "STOPPED" -ForegroundColor Red
    }

    Write-Host "Taskbar System Tray Agent   : " -NoNewline
    if ($trayProcs) {
        $pids = ($trayProcs | ForEach-Object { $_.ProcessId }) -join ", "
        Write-Host "ACTIVE " -ForegroundColor Green -NoNewline
        Write-Host "[PID: $pids]" -ForegroundColor Gray
    } else {
        Write-Host "INACTIVE" -ForegroundColor Yellow
    }

    Write-Host "Windows Logon Auto-Prompt   : " -NoNewline
    if ($startupEnabled) {
        Write-Host "ENABLED " -ForegroundColor Green -NoNewline
        Write-Host "(HKCU Run Key active)" -ForegroundColor Gray
    } else {
        Write-Host "DISABLED" -ForegroundColor Gray
    }
    Write-Host ""
}

function Start-AegisDaemon {
    Write-Host "[*] Launching AegisAI background daemon and system tray controller..." -ForegroundColor Cyan
    
    # Run tray agent via pythonw.exe in background (which also manages Uvicorn)
    Start-Process -FilePath $pythonwPath `
                  -ArgumentList "`"$trayScript`"" `
                  -WorkingDirectory $serverDir `
                  -WindowStyle Hidden

    Start-Sleep -Milliseconds 1500
    Get-AegisStatus
    Write-Host "[+] AegisAI is running in the system tray." -ForegroundColor Green
    Write-Host "    Dashboard: http://localhost:8000 (or http://localhost:5173 with Vite)" -ForegroundColor Yellow
    Write-Host "    API Docs:  http://localhost:8000/docs" -ForegroundColor Yellow
}

function Stop-AegisDaemon {
    Write-Host "[*] Stopping AegisAI background processes..." -ForegroundColor Cyan
    
    # Kill Tray Agent
    $trayProcs = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%tray_agent.py%'" -ErrorAction SilentlyContinue
    if ($trayProcs) {
        foreach ($p in $trayProcs) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }

    # Kill Uvicorn / port 8000 listeners
    $backendPorts = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
    if ($backendPorts) {
        $pids = $backendPorts | ForEach-Object { $_.OwningProcess } | Select-Object -Unique
        foreach ($pidToKill in $pids) {
            if ($pidToKill -gt 4) {
                # Terminate process tree
                taskkill /F /T /PID $pidToKill 2>$null | Out-Null
                Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Kill any AegisAI interactive PowerShell processes or pythonw instances
    $aegisPsProcs = Get-CimInstance Win32_Process | Where-Object { 
        ($_.CommandLine -like "*uvicorn app.main:app*" -or $_.CommandLine -like "*tray_agent.py*" -or $_.CommandLine -like "*logon_launcher.py*") -and $_.ProcessId -ne $PID
    }
    if ($aegisPsProcs) {
        foreach ($p in $aegisPsProcs) {
            taskkill /F /T /PID $p.ProcessId 2>$null | Out-Null
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Milliseconds 800
    Write-Host "[+] AegisAI background services stopped." -ForegroundColor Green
    Get-AegisStatus
}

function Send-TestAlert {
    Write-Host "[*] Sending test native OS desktop threat notification..." -ForegroundColor Cyan
    $normalizedServerDir = $serverDir -replace '\\', '/'
    & $pythonPath -c "import sys; sys.path.insert(0, '$normalizedServerDir'); from app.core.notifications import notify_threat_alert; notify_threat_alert('DDoS LOIC HTTP Flood (Volumetric)', 'CRITICAL', '198.51.100.44', 80, 'trapped_in_honeypot', force=True)"
    Write-Host "[+] Notification dispatched to Windows notification center." -ForegroundColor Green
}

function Show-TestPrompt {
    Write-Host "[*] Displaying AegisAI Logon Permission Dialog..." -ForegroundColor Cyan
    & $pythonPath $launcherScript
}

switch ($Command) {
    "status"      { Get-AegisStatus }
    "start"       { Start-AegisDaemon }
    "stop"        { Stop-AegisDaemon }
    "restart"     { Stop-AegisDaemon; Start-Sleep -Seconds 1; Start-AegisDaemon }
    "enable"      { & $installScript }
    "disable"     { & $uninstallScript }
    "test-alert"  { Send-TestAlert }
    "test-prompt" { Show-TestPrompt }
    "help" {
        Write-Host "AegisAI CLI Daemon Manager"
        Write-Host "Commands:"
        Write-Host "  .\aegisctl.ps1 status      - Check daemon & taskbar controller status"
        Write-Host "  .\aegisctl.ps1 start       - Silently start background engine & tray icon"
        Write-Host "  .\aegisctl.ps1 stop        - Stop background daemon and tray processes"
        Write-Host "  .\aegisctl.ps1 restart     - Restart background engine and tray controller"
        Write-Host "  .\aegisctl.ps1 enable      - Register Windows logon permission prompt"
        Write-Host "  .\aegisctl.ps1 disable     - Unregister Windows logon startup prompt"
        Write-Host "  .\aegisctl.ps1 test-alert  - Trigger a test native OS desktop toast notification"
        Write-Host "  .\aegisctl.ps1 test-prompt - Open logon permission prompt dialog for preview"
    }
}
