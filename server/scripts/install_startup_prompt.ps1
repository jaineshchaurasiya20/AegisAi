# AegisAI — Register Logon Permission Launcher in Windows Registry
# =================================================================
# Adds AegisAILauncher to HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
# Does not require Administrator privileges.

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$serverDir = Split-Path -Parent $scriptDir
$pythonwPath = Join-Path $serverDir "venv\Scripts\pythonw.exe"
$launcherScript = Join-Path $scriptDir "logon_launcher.py"

if (-not (Test-Path $pythonwPath)) {
    $pythonwPath = "pythonw.exe"
}

if (-not (Test-Path $launcherScript)) {
    Write-Error "Launcher script not found at $launcherScript"
    exit 1
}

$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regValueName = "AegisAILauncher"
$regValueData = "`"$pythonwPath`" `"$launcherScript`""

try {
    Set-ItemProperty -Path $regKey -Name $regValueName -Value $regValueData -Force
    Write-Host "[+] AegisAI Logon Permission Launcher registered successfully in Windows Registry." -ForegroundColor Green
    Write-Host "    Key:   $regKey" -ForegroundColor Gray
    Write-Host "    Name:  $regValueName" -ForegroundColor Gray
    Write-Host "    Value: $regValueData" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to register startup launcher: $_"
    exit 1
}
