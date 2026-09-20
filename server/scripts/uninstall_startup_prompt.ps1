# AegisAI — Unregister Logon Permission Launcher from Windows Registry
# =====================================================================
# Removes AegisAILauncher from HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regValueName = "AegisAILauncher"

try {
    $existing = Get-ItemProperty -Path $regKey -Name $regValueName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Remove-ItemProperty -Path $regKey -Name $regValueName -Force
        Write-Host "[+] AegisAI Logon Permission Launcher removed from Windows Registry." -ForegroundColor Yellow
    } else {
        Write-Host "[i] AegisAI startup entry was not registered in Windows Registry." -ForegroundColor Gray
    }
} catch {
    Write-Error "Failed to unregister startup launcher: $_"
    exit 1
}
