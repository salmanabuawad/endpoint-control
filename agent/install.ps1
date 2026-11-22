# KEM agent installer. Run in an elevated PowerShell on the endpoint:
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Server https://kem.example.com -Token ABCD-EFGH-JKLM
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [switch]$NoBaseline
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Server = $Server.TrimEnd('/')

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Please run this installer from an elevated PowerShell (Run as Administrator).' -ForegroundColor Red; exit 1 }
if ($Server -notmatch '^https://') { Write-Host 'WARNING: server URL is not HTTPS - the device secret will travel unencrypted.' -ForegroundColor Yellow }

$installDir = Join-Path $env:ProgramFiles 'KEM'
$dataDir = Join-Path $env:ProgramData 'KEM'
New-Item -ItemType Directory -Path $installDir, $dataDir -Force | Out-Null

Write-Host '[1/6] Fetching agent files...'
foreach ($f in 'kem-agent.ps1', 'kem-actions.ps1', 'kem-classroom.ps1', 'uninstall.ps1') {
    $local = Join-Path $PSScriptRoot $f
    $dest = Join-Path $installDir $f
    if ($PSScriptRoot -and (Test-Path $local) -and ($PSScriptRoot -ne $installDir)) { Copy-Item $local $dest -Force }
    else { Invoke-WebRequest -Uri "$Server/agent/$f" -OutFile $dest -UseBasicParsing }
}
# Lock the program folder so standard users can't tamper with scripts that run as SYSTEM.
& icacls.exe $installDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

. (Join-Path $installDir 'kem-actions.ps1')
Initialize-Kem $dataDir
Protect-KemDataDir

Write-Host '[2/6] Registering with the management server...'
Get-ScheduledTask -TaskName $KemTaskName -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
try { $cfg = Register-KemDevice -Server $Server -Token $Token }
catch {
    $detail = $_.ErrorDetails.Message
    Write-Host "Registration failed: $($_.Exception.Message) $detail" -ForegroundColor Red
    exit 1
}
Write-Host "      Device id: $($cfg.device_id)"

Write-Host '[3/6] Creating the KEM Agent scheduled task (SYSTEM, at startup)...'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$installDir\kem-agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $KemTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'KEM endpoint management agent' -Force | Out-Null

Write-Host '[4/5] Ensuring the KEM managed admin account...'
try { Write-Host ('      ' + (Install-KemManagedAdmin)) }
catch { Write-Host "      Could not create managed admin: $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host '[5/6] Creating baseline restore point (used by "Reset to baseline")...'
if ($NoBaseline) { Write-Host '      skipped (-NoBaseline)' }
else {
    try { Write-Host ('      ' + (New-KemBaseline)) }
    catch { Write-Host "      Could not create baseline: $($_.Exception.Message)" -ForegroundColor Yellow }
}

Write-Host '[6/6] Starting agent...'
Start-ScheduledTask -TaskName $KemTaskName
Write-Host "Done. $env:COMPUTERNAME should appear in the dashboard within a few seconds." -ForegroundColor Green
