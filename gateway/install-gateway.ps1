# KEM Teacher Gateway installer.
# Installs the relay (gateway/relay.py) on a lab PC and registers it to start at boot.
# The relay lets student agents reach the central server through this machine.
#
# Usage (elevated PowerShell):
#   .\install-gateway.ps1 -Server https://kem.example.com -Token ABCD-EFGH-JKLM
#
# Requires Python 3.8+ on PATH (python.org installer, "Add to PATH" ticked).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$Port = 8171,
    [string]$InstallDir = "$env:ProgramFiles\KEM-Gateway"
)

$ErrorActionPreference = 'Stop'

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated (Administrator) PowerShell."
    }
}

function Find-Python {
    foreach ($c in @('python', 'python3', 'py')) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) {
            $v = & $cmd.Source --version 2>&1
            if ($LASTEXITCODE -eq 0) { return $cmd.Source }
        }
    }
    throw "Python 3.8+ was not found on PATH. Install it from https://www.python.org/ (tick 'Add python.exe to PATH')."
}

Require-Admin
$python = Find-Python
Write-Host "Using Python: $python"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$src = Join-Path $PSScriptRoot 'relay.py'
if (-not (Test-Path $src)) { throw "relay.py not found next to this installer." }
Copy-Item $src (Join-Path $InstallDir 'relay.py') -Force

$configPath = Join-Path $InstallDir 'gateway.json'
$env:KEM_GATEWAY_CONFIG = $configPath

Write-Host "Enrolling gateway with $Server ..."
& $python (Join-Path $InstallDir 'relay.py') enroll --server $Server --token $Token --listen-port $Port
if ($LASTEXITCODE -ne 0) { throw "Gateway enrollment failed." }

# Register a scheduled task that runs the relay as SYSTEM at startup (and keeps it running).
$taskName = 'KEM Gateway Relay'
$action = New-ScheduledTaskAction -Execute $python `
    -Argument "`"$(Join-Path $InstallDir 'relay.py')`" run" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$settings.ExecutionTimeLimit = 'PT0S'   # no time limit

# The task needs the config path in its environment; bake it into a tiny launcher instead.
$launcher = Join-Path $InstallDir 'run-gateway.cmd'
"@echo off`r`nset KEM_GATEWAY_CONFIG=$configPath`r`n`"$python`" `"$(Join-Path $InstallDir 'relay.py')`" run" |
    Set-Content -Path $launcher -Encoding ASCII
$action = New-ScheduledTaskAction -Execute $launcher -WorkingDirectory $InstallDir

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

# Open the local firewall for student agents on the LAN.
try {
    New-NetFirewallRule -DisplayName "KEM Gateway (student agents)" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $Port -Profile Any -ErrorAction Stop | Out-Null
} catch { Write-Warning "Could not add firewall rule automatically: $($_.Exception.Message)" }

Write-Host ""
Write-Host "Teacher Gateway installed and running."
Write-Host "Point student agents at:  http://$($env:COMPUTERNAME):$Port"
Write-Host "Use a DEVICE token (for the same lab) when enrolling students against that URL."
