# Removes the KEM agent locally (run elevated). Lifts any internet block first.
$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated PowerShell.' -ForegroundColor Red; exit 1 }

$actions = Join-Path $env:ProgramFiles 'KEM\kem-actions.ps1'
if (Test-Path $actions) {
    . $actions
    Initialize-Kem (Join-Path $env:ProgramData 'KEM')
    Stop-ScheduledTask -TaskName $KemTaskName -ErrorAction SilentlyContinue
    Uninstall-KemAgent
} else {
    Remove-NetFirewallRule -Group 'KEM-Isolation' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'KEM Agent' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:ProgramFiles 'KEM') -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item (Join-Path $env:ProgramData 'KEM') -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'KEM agent removed. (The device can be deleted from the dashboard with "Forget".)' -ForegroundColor Green
