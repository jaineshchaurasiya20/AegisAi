# build_installer.ps1
# AegisAI 2.0 — Standalone Desktop Executable Build Script

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "       AegisAI 2.0 Desktop Executable Builder           " -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# Step 1: Build React Production Frontend
Write-Host "[1/3] Building React Production Frontend (Vite)..." -ForegroundColor Yellow
Set-Location "$rootDir\client"
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Frontend build failed!" -ForegroundColor Red
    exit 1
}
Set-Location $rootDir
Write-Host "[+] React bundle compiled into client/dist/" -ForegroundColor Green

# Step 2: Compile PyInstaller Standalone Executable
Write-Host "`n[2/3] Packaging Backend & Frontend into AegisAI.exe..." -ForegroundColor Yellow
$pyinstaller = "$rootDir\server\venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $pyinstaller)) {
    $pyinstaller = "pyinstaller"
}

& $pyinstaller --noconfirm "$rootDir\aegisai.spec"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] PyInstaller build failed!" -ForegroundColor Red
    exit 1
}

# Step 3: Verify Output
Write-Host "`n[3/3] Verifying AegisAI.exe Executable..." -ForegroundColor Yellow
$outputExe = "$rootDir\dist\AegisAI.exe"

if (Test-Path $outputExe) {
    $fileSizeMB = [math]::Round((Get-Item $outputExe).Length / 1MB, 2)
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] AegisAI.exe successfully created!" -ForegroundColor Green
    Write-Host " Output Location: $outputExe" -ForegroundColor White
    Write-Host " File Size: $fileSizeMB MB" -ForegroundColor White
    Write-Host "========================================================`n" -ForegroundColor Green
    Write-Host "To run: Double-click dist\AegisAI.exe or execute in PowerShell." -ForegroundColor Cyan
    Write-Host "The application will launch the system tray icon and open http://localhost:8000 in your browser.`n" -ForegroundColor Cyan
} else {
    Write-Host "`n[!] BUILD FAILED: dist/AegisAI.exe was not created." -ForegroundColor Red
    exit 1
}
