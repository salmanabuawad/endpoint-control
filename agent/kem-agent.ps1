# KEM agent - main loop. Started at boot by the "KEM Agent" scheduled task (runs as SYSTEM).
#   -DataDir  override C:\ProgramData\KEM (used for testing)
#   -Once     run a single check-in cycle and exit (used for testing)
param(
    [string]$DataDir = (Join-Path $env:ProgramData 'KEM'),
    [switch]$Once
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ActionsPath = Join-Path $PSScriptRoot 'kem-actions.ps1'
. $ActionsPath
Initialize-Kem $DataDir

$cfg = Get-KemConfig
if (-not $cfg) { Write-KemLog 'No config.json - run install.ps1 first.' 'ERROR'; exit 2 }
$headers = Get-KemAuthHeaders $cfg
Write-KemLog "Agent v$KemVersion starting (device $($cfg.device_id), server $($cfg.server))"

$interval = 15
$nextInventory = [datetime]::MinValue
$nextSoftware = [datetime]::MinValue
$nextIsolationCheck = [datetime]::MinValue
$results = New-Object System.Collections.ArrayList     # results waiting to be delivered
$queue = New-Object System.Collections.Queue           # long-running commands waiting for the worker
$job = $null; $jobCmd = $null
$failures = 0
$nextUpdateTry = [datetime]::MinValue
$updateCmd = $null                                      # pending 'update_agent' command

function Add-Result($Id, $R) {
    $item = @{ id = $Id; status = $R.status; output = "$($R.output)"; exit_code = $R.exit_code }
    if ($null -ne $R.data) { $item.data = $R.data }
    [void]$results.Add($item)
}

while ($true) {
    # --- finished background job?
    if ($job -and $job.State -ne 'Running') {
        try {
            $raw = Receive-Job $job -ErrorAction Stop | Select-Object -Last 1
            $r = $raw | ConvertFrom-Json
            Add-Result $jobCmd.id @{ status = $r.status; output = $r.output; exit_code = $r.exit_code; data = $r.data }
        } catch {
            Add-Result $jobCmd.id @{ status = 'failed'; output = "Worker error: $($_.Exception.Message)" }
        }
        Write-KemLog "Command $($jobCmd.id) ($($jobCmd.type)) finished"
        if ($jobCmd.type -in 'install_software', 'uninstall_software', 'run_script') { $nextSoftware = [datetime]::MinValue }
        if ($jobCmd.type -in 'create_baseline', 'install_updates', 'service_action') { $nextInventory = [datetime]::MinValue }
        if ($jobCmd.type -eq 'set_uplink') { $cfg = Get-KemConfig; $headers = Get-KemAuthHeaders $cfg }
        Remove-Job $job -Force
        $job = $null; $jobCmd = $null
    }
    # --- start next long-running command
    if (-not $job -and $queue.Count) {
        $jobCmd = $queue.Dequeue()
        [void]$results.Add(@{ id = $jobCmd.id; status = 'running' })
        $job = Start-Job -ArgumentList $ActionsPath, $DataDir, ($jobCmd | ConvertTo-Json -Depth 6 -Compress), $cfg.server -ScriptBlock {
            param($ActionsPath, $DataDir, $CmdJson, $Server)
            $ProgressPreference = 'SilentlyContinue'
            . $ActionsPath
            Initialize-Kem $DataDir
            $cmd = $CmdJson | ConvertFrom-Json
            try { $r = Invoke-KemCommand $cmd $Server }
            catch { $r = @{ status = 'failed'; output = "$($_.Exception.Message)" } }
            Write-KemLog "Command $($cmd.id) ($($cmd.type)) -> $($r.status)"
            $r | ConvertTo-Json -Depth 12 -Compress
        }
        Write-KemLog "Command $($jobCmd.id) ($($jobCmd.type)) started in background"
    }

    try {
        if ((Get-Date) -ge $nextIsolationCheck) {
            $nextIsolationCheck = (Get-Date).AddMinutes(5)
            try { Assert-KemIsolation $cfg.server } catch { Write-KemLog "Isolation check failed: $($_.Exception.Message)" 'WARN' }
            try { Assert-KemWebFilter } catch { Write-KemLog "Web filter check failed: $($_.Exception.Message)" 'WARN' }
            try { Assert-KemUsbStorage } catch { Write-KemLog "USB policy check failed: $($_.Exception.Message)" 'WARN' }
            try { Remove-KemUiTasks } catch { }
        }

        # Screen broadcast: only touch the AV-sensitive classroom module while a broadcast is active,
        # so a normal station never loads it (and never risks an AV block at the core level).
        if ((Get-KemState 'broadcast_src') -or (Get-KemState 'broadcast_view')) {
            try {
                if (-not (Get-Command Sync-KemBroadcastView -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'kem-classroom.ps1') }
                if (Get-Command Sync-KemBroadcastView -ErrorAction SilentlyContinue) {
                    Invoke-KemBroadcastSource $cfg.server
                    Sync-KemBroadcastView $cfg.server $cfg
                }
            } catch { Write-KemLog "Broadcast error: $($_.Exception.Message)" 'WARN' }
        }

        $tel = Get-KemTelemetry
        if ($jobCmd) { $tel.busy = "$($jobCmd.type)" }
        $body = @{ agent_version = $KemVersion; telemetry = $tel }
        if ((Get-Date) -ge $nextInventory) { $body.inventory = Get-KemInventory; $nextInventory = (Get-Date).AddMinutes(10) }
        if ((Get-Date) -ge $nextSoftware) { $body.software = @(Get-KemSoftware); $nextSoftware = (Get-Date).AddHours(6) }
        $sent = @($results.ToArray())
        if ($sent.Count) { $body.results = $sent }

        # When a teacher station (uplink) is set, the agent stays on it until the admin server sends a
        # set_uplink command to clear it. It does NOT fall back to the central server on its own.
        $activeServer = if ($cfg.PSObject.Properties.Name -contains 'uplink' -and $cfg.uplink) { "$($cfg.uplink)" } else { $cfg.server }
        $resp = Invoke-KemApi -Server $activeServer -Path '/api/agent/checkin' -Body $body -Headers $headers
        foreach ($s in $sent) { $results.Remove($s) }
        $failures = 0
        if ($resp.interval) { $interval = [int]$resp.interval }

        foreach ($cmd in @($resp.commands)) {
            if (-not $cmd) { continue }
            Write-KemLog "Received command $($cmd.id) ($($cmd.type))"
            if ($cmd.type -notin $KemInlineTypes) { $queue.Enqueue($cmd); continue }
            try {
                switch ($cmd.type) {
                    'refresh_inventory' {
                        $nextInventory = [datetime]::MinValue; $nextSoftware = [datetime]::MinValue
                        Add-Result $cmd.id @{ status = 'success'; output = 'Inventory and software list will be uploaded with the next check-in.' }
                    }
                    'reboot' {
                        $delay = [Math]::Max(15, [int]$cmd.params.delay)
                        $msg = $(if ($cmd.params.message) { "$($cmd.params.message)" } else { 'Your IT administrator is restarting this computer.' })
                        Send-KemReport $cfg @(@{ id = $cmd.id; status = 'running'; output = "Reboot scheduled in $delay s." })
                        & shutdown.exe /r /t $delay /c $msg /d p:4:1 | Out-Null
                    }
                    'reset_device' {
                        Send-KemReport $cfg @(@{ id = $cmd.id; status = 'running'; output = "Starting $($cmd.params.mode)..." })
                        $out = switch ($cmd.params.mode) {
                            'restore_baseline'        { Restore-KemBaseline }
                            'factory_reset'           { Invoke-KemFactoryReset $false }
                            'factory_reset_keep_data' { Invoke-KemFactoryReset $true }
                            default                   { throw "Unknown reset mode $($cmd.params.mode)" }
                        }
                        Send-KemReport $cfg @(@{ id = $cmd.id; status = 'running'; output = "$out" })
                    }
                    'uninstall_agent' {
                        Send-KemReport $cfg @(@{ id = $cmd.id; status = 'success'; output = 'Agent removed: isolation lifted, scheduled task and files deleted.' })
                        Write-KemLog 'Uninstalling agent on server request'
                        Uninstall-KemAgent
                        Set-Location $env:SystemRoot
                        Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
                        exit 0
                    }
                    'set_hostname' {
                        $r = Rename-KemComputer $cmd.params
                        if ($r.status -eq 'success' -and [bool]$cmd.params.reboot -and $env:COMPUTERNAME -ne "$($cmd.params.hostname)") {
                            $delay = [Math]::Max(5, [int]$cmd.params.reboot_delay)
                            Send-KemReport $cfg @(@{ id = $cmd.id; status = 'success'; output = "$($r.output) Rebooting in $delay s." })
                            & shutdown.exe /r /t $delay /c 'KEM is renaming this computer.' /d p:4:1 | Out-Null
                        } else {
                            Add-Result $cmd.id $r
                        }
                    }
                    'update_agent' { $updateCmd = $cmd; $nextUpdateTry = [datetime]::MinValue }
                    default {
                        Add-Result $cmd.id (Invoke-KemCommand $cmd $cfg.server)
                        if ($cmd.type -in 'set_web_filter', 'usb_storage') { $nextInventory = [datetime]::MinValue }
                    }
                }
            } catch {
                Write-KemLog "Command $($cmd.id) failed: $($_.Exception.Message)" 'ERROR'
                Add-Result $cmd.id @{ status = 'failed'; output = "$($_.Exception.Message)" }
            }
        }
        # --- self-update: the server announces the agent version it hands out
        $rel = $resp.agent
        if ($updateCmd -and -not $rel) { Add-Result $updateCmd.id @{ status = 'failed'; output = 'Server did not send release information.' }; $updateCmd = $null }
        if ($rel -and $rel.version) {
            if ($rel.version -eq $KemVersion) {
                if ($updateCmd) { Add-Result $updateCmd.id @{ status = 'success'; output = "Already up to date (v$KemVersion)." }; $updateCmd = $null }
            } elseif (-not $job -and -not $queue.Count -and (Get-Date) -ge $nextUpdateTry -and -not $Once) {
                $nextUpdateTry = (Get-Date).AddHours(1)
                try {
                    Write-KemLog "Updating agent v$KemVersion -> v$($rel.version)"
                    Update-KemAgentFiles $rel $cfg.server $PSScriptRoot
                    $done = @($results.ToArray())
                    if ($updateCmd) { $done += @{ id = $updateCmd.id; status = 'success'; output = "Updated from v$KemVersion to v$($rel.version); agent restarting." } }
                    if ($done.Count) { Send-KemReport $cfg $done }
                    Restart-KemAgentTask
                    Write-KemLog 'Agent files updated - restarting'
                    exit 0
                } catch {
                    Write-KemLog "Agent update failed: $($_.Exception.Message)" 'ERROR'
                    if ($updateCmd) { Add-Result $updateCmd.id @{ status = 'failed'; output = "Update failed: $($_.Exception.Message)" }; $updateCmd = $null }
                }
            }
        }
        # Deliver inline results right away instead of waiting a full interval.
        if ($results.Count -and -not $Once) { Start-Sleep -Seconds 1; continue }
    } catch {
        $failures++
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        Write-KemLog "Check-in failed ($failures): $($_.Exception.Message)" 'WARN'
        if ($code -eq 401) { Write-KemLog 'Server rejected this device (forgotten or re-enrolled elsewhere). Re-run install.ps1 with a new token.' 'ERROR' }
        if ($Once -and $failures -ge 3) { Write-Error "Check-in failed: $($_.Exception.Message)" -ErrorAction Continue; break }
    }

    if ($Once) {
        if ($job) { Wait-Job $job -Timeout 600 | Out-Null; continue }
        if ($queue.Count -or $results.Count) { continue }
        break
    }
    # Back off while the server is unreachable (max 5 min).
    $sleep = [Math]::Min(300, $interval * [Math]::Pow(2, [Math]::Min($failures, 5)))
    Start-Sleep -Seconds ([int]$sleep)
}
