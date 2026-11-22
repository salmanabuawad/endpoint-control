# KEM agent - action library (dot-sourced by kem-agent.ps1, install.ps1 and background jobs).
# Windows PowerShell 5.1, runs as SYSTEM.

$script:KemVersion  = '1.11.0'
$script:KemTaskName = 'KEM Agent'
$script:KemGatewayTask = 'KEM Gateway Relay'   # scheduled task when this station is a teacher station
$script:KemAdminUser = 'kemadmin'   # install-created managed local admin (interactive logon denied)
$script:KemRuleGroup = 'KEM-Isolation'
if (-not $script:KemDataDir) { $script:KemDataDir = Join-Path $env:ProgramData 'KEM' }
$script:KemInstallDir = Join-Path $env:ProgramFiles 'KEM'

Add-Type -AssemblyName System.Numerics

# ------------------------------------------------------------------ basics

function Initialize-Kem([string]$DataDir) {
    if ($DataDir) { $script:KemDataDir = $DataDir }
    if (-not (Test-Path $script:KemDataDir)) { New-Item -ItemType Directory -Path $script:KemDataDir -Force | Out-Null }
}

function Write-KemLog([string]$Message, [string]$Level = 'INFO') {
    try {
        $log = Join-Path $script:KemDataDir 'agent.log'
        if ((Test-Path $log) -and (Get-Item $log).Length -gt 5MB) { Move-Item $log "$log.1" -Force }
        Add-Content -Path $log -Value ("{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message) -Encoding UTF8
    } catch { }
}

function Get-KemUnixTime([datetime]$Date = (Get-Date)) {
    return [int64]([DateTimeOffset]$Date).ToUnixTimeSeconds()
}

function Get-KemState([string]$Key) {
    $f = Join-Path $script:KemDataDir "state-$Key.json"
    if (Test-Path $f) { try { return Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
    return $null
}

function Set-KemState([string]$Key, $Value) {
    $f = Join-Path $script:KemDataDir "state-$Key.json"
    if ($null -eq $Value) { Remove-Item $f -Force -ErrorAction SilentlyContinue; return }
    ($Value | ConvertTo-Json -Depth 6 -Compress) | Set-Content -Path $f -Encoding UTF8
}

function Get-KemConfig {
    $f = Join-Path $script:KemDataDir 'config.json'
    if (-not (Test-Path $f)) { return $null }
    return Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Protect-KemDataDir {
    # Only SYSTEM and Administrators may read the device secret.
    & icacls.exe $script:KemDataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

function Get-KemHexBytes([byte[]]$Bytes) {
    $sb = New-Object System.Text.StringBuilder ($Bytes.Length * 2)
    foreach ($b in $Bytes) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}
function Get-KemSha256Hex([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (Get-KemHexBytes $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))) } finally { $sha.Dispose() }
}
function Get-KemSha256HexBytes([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (Get-KemHexBytes $sha.ComputeHash($Bytes)) } finally { $sha.Dispose() }
}
function Get-KemHmacHex([string]$Key, [string]$Message) {
    $h = New-Object System.Security.Cryptography.HMACSHA256
    $h.Key = [Text.Encoding]::UTF8.GetBytes($Key)
    try { return (Get-KemHexBytes $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))) } finally { $h.Dispose() }
}

function Invoke-KemApi {
    param([string]$Server, [string]$Path, $Body, [hashtable]$Headers = @{}, [int]$TimeoutSec = 60)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $json = $Body | ConvertTo-Json -Depth 12 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    # Sign the request with the device secret-derived key so the raw secret never travels on the wire
    # (HMAC over timestamp + nonce + method + path + body hash). Verified by the central server.
    $h = @{}; foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    if ($h.ContainsKey('X-Device-Secret')) {
        $key = Get-KemSha256Hex ([string]$h['X-Device-Secret'])
        $h.Remove('X-Device-Secret')
        $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $nonce = [guid]::NewGuid().ToString('N')
        $canonical = "$ts`n$nonce`nPOST`n$Path`n$(Get-KemSha256HexBytes $bytes)"
        $h['X-KEM-Ts'] = "$ts"; $h['X-KEM-Nonce'] = $nonce; $h['X-KEM-Sig'] = (Get-KemHmacHex $key $canonical)
    }
    return Invoke-RestMethod -Uri ($Server.TrimEnd('/') + $Path) -Method Post -Body $bytes `
        -ContentType 'application/json; charset=utf-8' -Headers $h -TimeoutSec $TimeoutSec -UseBasicParsing
}

function Get-KemAuthHeaders($Config) {
    return @{ 'X-Device-Id' = $Config.device_id; 'X-Device-Secret' = $Config.secret }
}

function Send-KemReport($Config, [array]$Results) {
    try { Invoke-KemApi -Server $Config.server -Path '/api/agent/report' -Body @{ results = $Results } -Headers (Get-KemAuthHeaders $Config) -TimeoutSec 20 | Out-Null }
    catch { Write-KemLog "report failed: $($_.Exception.Message)" 'WARN' }
}

function Register-KemDevice([string]$Server, [string]$Token) {
    $guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
    $body = @{ token = $Token; hostname = $env:COMPUTERNAME; machine_guid = "$guid"; agent_version = $script:KemVersion }
    $resp = Invoke-KemApi -Server $Server -Path '/api/agent/enroll' -Body $body
    $cfg = [ordered]@{ server = $Server.TrimEnd('/'); device_id = $resp.device_id; secret = $resp.secret; enrolled = (Get-KemUnixTime) }
    ($cfg | ConvertTo-Json) | Set-Content -Path (Join-Path $script:KemDataDir 'config.json') -Encoding UTF8
    return [pscustomobject]$cfg
}

function Invoke-KemProcess {
    param([string]$FilePath, [string]$Arguments = '', [int]$TimeoutSec = 1800)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
    if ($timedOut) { try { $p.Kill() } catch { } }
    $p.WaitForExit()
    $text = ($out.Result + "`n" + $err.Result).Trim()
    # Drop progress-bar noise (carriage-return redraws, spinners, block characters).
    $clean = ($text -split "`n" | ForEach-Object { ($_.TrimEnd("`r") -split "`r")[-1] } |
        Where-Object { $_.Trim() -and $_ -notmatch '^\s*[-\\|/]\s*$' -and $_ -notmatch '[\u2580-\u259F]{3,}' }) -join "`n"
    if ($timedOut) { $clean += "`n[KEM] Timed out after $TimeoutSec seconds - process killed." }
    return @{ exit_code = $(if ($timedOut) { -1 } else { $p.ExitCode }); output = $clean }
}

# ------------------------------------------------------------------ telemetry & inventory

function Get-KemTelemetry {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        @{ drive = $_.DeviceID; size_gb = [math]::Round($_.Size / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1) } })
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })
    $iso = Get-KemState 'isolation'
    return @{
        hostname     = $env:COMPUTERNAME
        user         = "$($cs.UserName)"
        boot_time    = Get-KemUnixTime $os.LastBootUpTime
        cpu_pct      = $(if ($null -ne $cpu) { [math]::Round($cpu, 1) } else { $null })
        mem_total_mb = [math]::Round($os.TotalVisibleMemorySize / 1KB)
        mem_free_mb  = [math]::Round($os.FreePhysicalMemory / 1KB)
        system_drive = $env:SystemDrive
        disks        = $disks
        ips          = $ips
        isolated     = [bool]($iso -and $iso.enabled)
        allow_lan    = [bool]($iso -and $iso.allow_lan)
        web_filter   = @(Get-KemWebFilterDomains).Count
        usb_mode     = Get-KemUsbMode
    }
}

function Get-KemInventory {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = @(Get-CimInstance Win32_Processor)[0]
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $inv = [ordered]@{
        os_name = $os.Caption; os_version = $os.Version; os_build = "$($os.BuildNumber).$($cv.UBR)"
        display_version = "$($cv.DisplayVersion)"; arch = $os.OSArchitecture
        manufacturer = $cs.Manufacturer; model = $cs.Model; serial = "$($bios.SerialNumber)".Trim(); bios_version = $bios.SMBIOSBIOSVersion
        cpu_name = "$($cpu.Name)".Trim(); cores = $cpu.NumberOfCores; logical = $cpu.NumberOfLogicalProcessors
        ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        domain = $cs.Domain; part_of_domain = [bool]$cs.PartOfDomain
    }
    # Laptop vs desktop
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    $chassis = @((Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes)
    $laptopTypes = 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32
    $inv.chassis = $(if ($battery -or ($chassis | Where-Object { $laptopTypes -contains $_ })) { 'laptop' } else { 'desktop' })
    if ($battery) { $inv.battery_pct = $battery.EstimatedChargeRemaining }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $inv.defender = @{
            antivirus_enabled = [bool]$mp.AntivirusEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled
            signature_age_days = $mp.AntivirusSignatureAge; quick_scan_age_days = $mp.QuickScanAge
            signature_version = "$($mp.AntivirusSignatureVersion)"
        }
    } catch { }
    try { $inv.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { @{ name = "$($_.Name)"; enabled = [bool]($_.Enabled -eq 'True' -or $_.Enabled -eq 1) } }) } catch { }
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $inv.bitlocker = "$($bl.ProtectionStatus) ($($bl.VolumeStatus))"
    } catch { }
    try {
        $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { $inv.last_hotfix = @{ id = $hf.HotFixID; date = $hf.InstalledOn.ToString('yyyy-MM-dd') } }
    } catch { }
    $inv.pending_reboot = [bool]((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'))
    try { $inv.adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up' | ForEach-Object { @{ name = $_.Name; mac = $_.MacAddress; speed = "$($_.LinkSpeed)" } }) } catch { }
    $base = Get-KemState 'baseline'
    if ($base) { $inv.baseline = $base }
    $inv.web_filter = @(Get-KemWebFilterDomains)
    $inv.usb_mode = Get-KemUsbMode
    return $inv
}

function Get-KemSoftware {
    $paths = @(
        @{ p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; s = 'machine' },
        @{ p = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; s = 'machine' },
        @{ p = 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; s = 'user' }
    )
    $seen = @{}
    $list = foreach ($entry in $paths) {
        Get-ItemProperty $entry.p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName -and -not $_.ReleaseType } |
            ForEach-Object {
                $key = "$($_.DisplayName)|$($_.DisplayVersion)"
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $date = "$($_.InstallDate)"
                    if ($date -match '^(\d{4})(\d{2})(\d{2})$') { $date = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
                    @{ name = "$($_.DisplayName)".Trim(); version = "$($_.DisplayVersion)"; publisher = "$($_.Publisher)".Trim(); installed = $date; scope = $entry.s }
                }
            }
    }
    return @($list | Sort-Object { $_.name })
}

# ------------------------------------------------------------------ internet isolation
# Implemented with *block* rules (block beats allow in Windows Firewall), each covering every
# remote address EXCEPT the management server, loopback/link-local/multicast and (optionally) the LAN.
# DNS (53), DHCP (67/547) and NTP (123) stay open so the agent can still resolve and reach the server.

function ConvertTo-KemBigInt([System.Net.IPAddress]$Ip) {
    $b = $Ip.GetAddressBytes()
    [Array]::Reverse($b)
    return New-Object System.Numerics.BigInteger -ArgumentList (, [byte[]]($b + [byte]0))
}

function ConvertFrom-KemBigInt([System.Numerics.BigInteger]$N, [int]$Len) {
    $src = $N.ToByteArray()
    $out = New-Object byte[] $Len
    [Array]::Copy($src, $out, [Math]::Min($src.Length, $Len))
    [Array]::Reverse($out)
    return ([System.Net.IPAddress]::new($out)).ToString()
}

function Get-KemCidrRange([string]$Cidr) {
    $parts = $Cidr.Split('/')
    $addr = [System.Net.IPAddress]::Parse($parts[0])
    $len = $addr.GetAddressBytes().Length
    $bits = $(if ($parts.Count -gt 1) { [int]$parts[1] } else { $len * 8 })
    $size = [System.Numerics.BigInteger]::Pow(2, $len * 8 - $bits)
    $n = ConvertTo-KemBigInt $addr
    $start = [System.Numerics.BigInteger]::Subtract($n, [System.Numerics.BigInteger]::Remainder($n, $size))
    $end = [System.Numerics.BigInteger]::Subtract([System.Numerics.BigInteger]::Add($start, $size), 1)
    return [pscustomobject]@{ Start = $start; End = $end; Len = $len }
}

function Get-KemComplement([array]$Excluded, [int]$Len) {
    # Every address of this family NOT inside $Excluded, as firewall range strings.
    $max = [System.Numerics.BigInteger]::Subtract([System.Numerics.BigInteger]::Pow(2, $Len * 8), 1)
    $cursor = [System.Numerics.BigInteger]::Zero
    $ranges = New-Object System.Collections.Generic.List[string]
    $fmt = {
        param($a, $b)
        if ($a -eq $b) { ConvertFrom-KemBigInt $a $Len } else { (ConvertFrom-KemBigInt $a $Len) + '-' + (ConvertFrom-KemBigInt $b $Len) }
    }
    foreach ($r in ($Excluded | Where-Object { $_.Len -eq $Len } | Sort-Object Start)) {
        if ($r.Start -gt $cursor) { $ranges.Add((& $fmt $cursor ([System.Numerics.BigInteger]::Subtract($r.Start, 1)))) }
        $next = [System.Numerics.BigInteger]::Add($r.End, 1)
        if ($next -gt $cursor) { $cursor = $next }
    }
    if ($cursor -le $max) { $ranges.Add((& $fmt $cursor $max)) }
    return $ranges.ToArray()
}

function Get-KemServerAddresses([string]$Server) {
    $hostName = ([Uri]$Server).Host
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($hostName, [ref]$ip)) { return @($ip.ToString()) }
    return @([System.Net.Dns]::GetHostAddresses($hostName) | ForEach-Object { $_.ToString() } | Sort-Object -Unique)
}

function Get-KemIsolationRanges([string[]]$ServerIps, [bool]$AllowLan) {
    $keep = @('127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255/32', '::1/128', 'fe80::/10', 'ff00::/8')
    if ($AllowLan) { $keep += @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7') }
    $keep += $ServerIps
    $excluded = @($keep | ForEach-Object { Get-KemCidrRange $_ })
    return @((Get-KemComplement $excluded 4) + (Get-KemComplement $excluded 16))
}

function Enable-KemIsolation([string]$Server, [bool]$AllowLan) {
    $serverIps = @(Get-KemServerAddresses $Server)
    if (-not $serverIps) { throw "Cannot resolve management server address - refusing to isolate (the device would be unreachable)." }
    $ranges = Get-KemIsolationRanges $serverIps $AllowLan
    Remove-NetFirewallRule -Group $script:KemRuleGroup -ErrorAction SilentlyContinue
    $common = @{ Group = $script:KemRuleGroup; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; RemoteAddress = $ranges; ErrorAction = 'Stop' }
    New-NetFirewallRule @common -DisplayName 'KEM isolation (TCP)' -Protocol TCP -RemotePort '1-52', '54-65535' | Out-Null
    New-NetFirewallRule @common -DisplayName 'KEM isolation (UDP)' -Protocol UDP -RemotePort '1-52', '54-66', '68-122', '124-546', '548-65535' | Out-Null
    New-NetFirewallRule @common -DisplayName 'KEM isolation (ICMPv4)' -Protocol ICMPv4 | Out-Null
    New-NetFirewallRule @common -DisplayName 'KEM isolation (ICMPv6)' -Protocol ICMPv6 | Out-Null
    # Rules only work while the firewall is on.
    Set-NetFirewallProfile -All -Enabled True
    Set-KemState 'isolation' @{ enabled = $true; allow_lan = $AllowLan; server_ips = $serverIps; applied = (Get-KemUnixTime) }
    $msg = "Internet blocked. Still allowed: management server ($($serverIps -join ', ')), DNS, DHCP, NTP"
    if ($AllowLan) { $msg += ', local network' }
    $fw = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
    if ($fw) { $msg += "`nWARNING: firewall profile(s) still disabled: $($fw.Name -join ', ') - a 3rd-party firewall may be in control." }
    return $msg
}

function Disable-KemIsolation {
    Remove-NetFirewallRule -Group $script:KemRuleGroup -ErrorAction SilentlyContinue
    Set-KemState 'isolation' $null
    return 'Internet access restored (KEM isolation rules removed).'
}

function Assert-KemIsolation([string]$Server) {
    # Re-apply isolation if someone deleted the rules, or if the server's IP changed.
    $st = Get-KemState 'isolation'
    if (-not ($st -and $st.enabled)) { return }
    $rules = @(Get-NetFirewallRule -Group $script:KemRuleGroup -ErrorAction SilentlyContinue)
    $ips = @()
    try { $ips = @(Get-KemServerAddresses $Server) } catch { }
    $ipsChanged = $ips.Count -and (Compare-Object $ips @($st.server_ips))
    if ($rules.Count -lt 4 -or $ipsChanged) {
        Write-KemLog "Isolation drift detected (rules=$($rules.Count), ipsChanged=$([bool]$ipsChanged)) - re-applying" 'WARN'
        Enable-KemIsolation $Server ([bool]$st.allow_lan) | Out-Null
    }
}

# ------------------------------------------------------------------ software

function Get-KemWinget {
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # As SYSTEM winget is not on PATH - find the newest App Installer package.
    $dirs = Get-ChildItem (Join-Path $env:ProgramFiles 'WindowsApps') -Directory -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -ErrorAction SilentlyContinue
    $best = $dirs | Sort-Object { try { [version]($_.Name.Split('_')[1]) } catch { [version]'0.0' } } -Descending |
        Where-Object { Test-Path (Join-Path $_.FullName 'winget.exe') } | Select-Object -First 1
    if ($best) { return (Join-Path $best.FullName 'winget.exe') }
    throw 'winget (App Installer) was not found on this device. Install "App Installer" from the Microsoft Store, or use an installer URL instead.'
}

function Install-KemSoftware($P) {
    if ($P.method -eq 'winget') {
        $winget = Get-KemWinget
        $base = "install --id `"$($P.package_id)`" --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"
        $r = Invoke-KemProcess $winget "$base --scope machine" 3600
        # 0x8A150010 = no installer for the requested scope; retry with the package default.
        if ($r.exit_code -eq -1978335216) { $r = Invoke-KemProcess $winget $base 3600 }
        # 0x8A15002B = already installed / no newer version.
        $ok = $r.exit_code -in @(0, -1978335189)
        return @{ status = $(if ($ok) { 'success' } else { 'failed' }); exit_code = $r.exit_code; output = $r.output }
    }
    # Direct download
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $dl = Join-Path $script:KemDataDir 'downloads'
    New-Item -ItemType Directory -Path $dl -Force | Out-Null
    $name = [IO.Path]::GetFileName(([Uri]$P.url).AbsolutePath)
    if (-not $name -or $name -notmatch '\.(msi|exe)$') { $name = 'installer.exe' }
    $file = Join-Path $dl ("{0}-{1}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)), $name)
    try {
        Invoke-WebRequest -Uri $P.url -OutFile $file -UseBasicParsing -TimeoutSec 1800
        $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
        if ($P.sha256 -and $hash -ne $P.sha256.ToLower()) {
            return @{ status = 'failed'; output = "Checksum mismatch. Expected $($P.sha256), got $hash. Installer NOT run." }
        }
        $sig = Get-AuthenticodeSignature $file
        $head = "Downloaded $name ($([math]::Round((Get-Item $file).Length / 1MB, 1)) MB, sha256 $hash, signature: $($sig.Status) $($sig.SignerCertificate.Subject))"
        if ($file -like '*.msi') {
            $r = Invoke-KemProcess 'msiexec.exe' "/i `"$file`" /qn /norestart $($P.args)" 3600
        } else {
            $r = Invoke-KemProcess $file "$($P.args)" 3600
        }
        $ok = $r.exit_code -in @(0, 3010, 1641)
        $tail = $(if ($r.exit_code -eq 3010) { "`nInstalled - a reboot is required to finish." } else { '' })
        return @{ status = $(if ($ok) { 'success' } else { 'failed' }); exit_code = $r.exit_code; output = "$head`n$($r.output)$tail".Trim() }
    } finally {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
}

function Uninstall-KemSoftware($P) {
    if ($P.package_id) {
        $winget = Get-KemWinget
        $r = Invoke-KemProcess $winget "uninstall --id `"$($P.package_id)`" --exact --silent --accept-source-agreements --disable-interactivity" 1800
        return @{ status = $(if ($r.exit_code -eq 0) { 'success' } else { 'failed' }); exit_code = $r.exit_code; output = $r.output }
    }
    $name = "$($P.name)"
    if (-not $name) { return @{ status = 'failed'; output = 'No package id or program name given.' } }
    # Uninstall a registry-listed program by its DisplayName, using its own uninstall string.
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $app = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)".Trim() -eq $name } | Select-Object -First 1
    if ($app) {
        $cmd = if ($app.QuietUninstallString) { "$($app.QuietUninstallString)" } else { "$($app.UninstallString)" }
        if (-not $cmd) { return @{ status = 'failed'; output = "No uninstall command recorded for '$name'." } }
        if ($cmd -match 'msiexec') {
            $cmd = $cmd -replace '(?i)/I', '/X'
            if ($cmd -notmatch '(?i)/q') { $cmd = "$cmd /qn /norestart" }
        }
        $r = Invoke-KemProcess 'cmd.exe' "/c $cmd" 1800
        $ok = $r.exit_code -in @(0, 3010, 1605, 1614)
        return @{ status = $(if ($ok) { 'success' } else { 'failed' }); exit_code = $r.exit_code; output = "Uninstalled '$name' via its uninstaller. $($r.output)" }
    }
    # Not in the registry list - try winget by name as a fallback.
    $winget = Get-KemWinget
    $r = Invoke-KemProcess $winget "uninstall --name `"$name`" --silent --accept-source-agreements --disable-interactivity" 1800
    return @{ status = $(if ($r.exit_code -eq 0) { 'success' } else { 'failed' }); exit_code = $r.exit_code; output = $r.output }
}

function Invoke-KemScript($P, [string]$CommandId) {
    $dir = Join-Path $script:KemDataDir 'scripts'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $file = Join-Path $dir "cmd-$CommandId.ps1"
    $prefix = "[Console]::OutputEncoding = [Text.Encoding]::UTF8`r`n`$ProgressPreference = 'SilentlyContinue'`r`n"
    # UTF-8 *with* BOM so Windows PowerShell 5.1 parses non-ASCII (e.g. Hebrew) correctly.
    [IO.File]::WriteAllText($file, $prefix + $P.script, (New-Object System.Text.UTF8Encoding $true))
    try {
        $r = Invoke-KemProcess 'powershell.exe' "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$file`"" ([int]$P.timeout)
        return @{ status = $(if ($r.exit_code -eq 0) { 'success' } else { 'failed' }); exit_code = $r.exit_code; output = $r.output }
    } finally { Remove-Item $file -Force -ErrorAction SilentlyContinue }
}

function Start-KemDefenderScan($P) {
    $type = $(if ($P.scan_type -eq 'full') { 'FullScan' } else { 'QuickScan' })
    Start-MpScan -ScanType $type -ErrorAction Stop
    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-24) })
    $msg = "$type finished."
    if ($threats.Count) {
        $msg += "`nThreats detected in the last 24h: $($threats.Count)"
        $msg += "`n" + (($threats | ForEach-Object { "- $($_.Resources -join ', ') [action $($_.ThreatStatusID)]" }) -join "`n")
    } else { $msg += ' No threats detected in the last 24h.' }
    return @{ status = 'success'; output = $msg }
}

# ------------------------------------------------------------------ baseline / reset

function New-KemBaseline {
    $drive = "$env:SystemDrive\"
    Enable-ComputerRestore -Drive $drive -ErrorAction Stop
    # Windows normally allows only one restore point per 24h - lift that limit.
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord
    & vssadmin.exe Resize ShadowStorage /For=$env:SystemDrive /On=$env:SystemDrive /MaxSize=10% 2>&1 | Out-Null
    $desc = 'KEM Baseline ' + (Get-Date -Format 'yyyy-MM-dd HH:mm')
    Checkpoint-Computer -Description $desc -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    $rp = Get-ComputerRestorePoint | Where-Object { $_.Description -eq $desc } | Select-Object -Last 1
    if (-not $rp) { throw 'Windows did not create the restore point (System Restore may be disabled by policy).' }
    $state = @{ sequence = [int]$rp.SequenceNumber; description = $desc; created = (Get-KemUnixTime) }
    Set-KemState 'baseline' $state
    return "Baseline restore point #$($rp.SequenceNumber) created: $desc"
}

function Restore-KemBaseline {
    $st = Get-KemState 'baseline'
    if (-not $st) { throw 'No baseline exists on this device. Create one first.' }
    $rp = Get-ComputerRestorePoint | Where-Object { $_.SequenceNumber -eq $st.sequence }
    if (-not $rp) { throw "Baseline restore point #$($st.sequence) no longer exists (Windows may have purged it to free space). Create a new baseline." }
    Restore-Computer -RestorePoint $st.sequence -Confirm:$false -ErrorAction Stop   # reboots the machine
    return "Restoring to #$($st.sequence) - the device is rebooting."
}

function Invoke-KemFactoryReset([bool]$KeepUserData) {
    # Uses the MDM RemoteWipe CSP through the WMI bridge (must run as SYSTEM).
    $ns = 'root\cimv2\mdm\dmmap'
    $method = $(if ($KeepUserData) { 'doWipePersistUserDataMethod' } else { 'doWipeMethod' })
    $inst = Get-CimInstance -Namespace $ns -ClassName 'MDM_RemoteWipe' -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'" -ErrorAction Stop
    if (-not $inst) { throw 'MDM RemoteWipe is not available on this Windows edition/build.' }
    $session = New-CimSession
    $params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
    $params.Add([Microsoft.Management.Infrastructure.CimMethodParameter]::Create('param', '', 'String', 'In'))
    $session.InvokeMethod($ns, $inst, $method, $params) | Out-Null
    return "Factory reset ($method) started. Windows will reboot into recovery; the agent will be removed."
}

function Uninstall-KemAgent {
    # Lift every restriction KEM applied - nothing would be left to manage it.
    Disable-KemIsolation | Out-Null
    if (@(Get-KemWebFilterDomains).Count) { try { Set-KemWebFilter @{ domains = @() } | Out-Null } catch { } }
    if (Get-KemState 'usb') { try { Set-KemUsbStorage 'allow' | Out-Null } catch { } }
    try { Remove-KemUiTasks } catch { }
    Unregister-ScheduledTask -TaskName $script:KemTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $script:KemInstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------ Windows Update (patch management)

function ConvertTo-KemUpdateRecord($U) {
    $cats = @($U.Categories | ForEach-Object { "$($_.Name)" })
    $sev = "$($U.MsrcSeverity)"
    $isDriver = ($U.Type -eq 2)
    $security = (-not $isDriver) -and (($sev -in 'Critical', 'Important') -or ($cats -contains 'Security Updates') -or ($cats -contains 'Critical Updates'))
    $date = ''
    try { $date = ([datetime]$U.LastDeploymentChangeTime).ToString('yyyy-MM-dd') } catch { }
    return @{
        id = "$($U.Identity.UpdateID)"; title = "$($U.Title)"
        kb = (@($U.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', ')
        severity = $sev; categories = ($cats -join ', ')
        size_mb = [math]::Round([double]$U.MaxDownloadSize / 1MB, 1)
        driver = [bool]$isDriver; security = [bool]$security
        upgrade = [bool]($cats -contains 'Upgrades')
        reboot = [bool]($U.InstallationBehavior.RebootBehavior -ne 0)
        date = $date; downloaded = [bool]$U.IsDownloaded
    }
}

function Find-KemUpdates {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'KEM'
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
    return @{ session = $session; updates = @($result.Updates | ForEach-Object { $_ }) }
}

function Get-KemRebootRequired {
    try { return [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch { return $false }
}

function Format-KemUpdateSummary([array]$Records) {
    $sec = @($Records | Where-Object { $_.security }).Count
    $msg = "$($Records.Count) update(s) available, $sec security."
    foreach ($r in ($Records | Select-Object -First 25)) {
        $flag = $(if ($r.security) { '[security] ' } elseif ($r.driver) { '[driver] ' } else { '' })
        $msg += "`n- $flag$($r.title)"
    }
    if ($Records.Count -gt 25) { $msg += "`n... and $($Records.Count - 25) more" }
    return $msg
}

function Invoke-KemUpdateScan {
    $found = Find-KemUpdates
    $records = @($found.updates | ForEach-Object { ConvertTo-KemUpdateRecord $_ })
    $reboot = Get-KemRebootRequired
    $msg = Format-KemUpdateSummary $records
    if ($reboot) { $msg += "`nA reboot is pending to finish earlier updates." }
    return @{ status = 'success'; output = $msg; data = @{ updates = $records; reboot_required = $reboot } }
}

function Install-KemUpdates($P) {
    $found = Find-KemUpdates
    $session = $found.session
    $wanted = New-Object -ComObject Microsoft.Update.UpdateColl
    $ids = @($P.update_ids)
    foreach ($u in $found.updates) {
        $r = ConvertTo-KemUpdateRecord $u
        $take = switch ("$($P.scope)") {
            'selected' { $ids -contains $r.id }
            'security' { $r.security }
            default    { (-not $r.driver -or [bool]$P.include_drivers) -and -not $r.upgrade }
        }
        if ($take) {
            if (-not $u.EulaAccepted) { $u.AcceptEula() }
            [void]$wanted.Add($u)
        }
    }
    $log = New-Object System.Collections.Generic.List[string]
    $rebootNeeded = $false
    $failed = 0
    if ($wanted.Count -eq 0) {
        $log.Add('Nothing to install for this selection.')
    } else {
        $log.Add("Downloading $($wanted.Count) update(s)...")
        $dl = $session.CreateUpdateDownloader()
        $dl.Updates = $wanted
        [void]$dl.Download()
        $ready = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $wanted) {
            if ($u.IsDownloaded) { [void]$ready.Add($u) } else { $failed++; $log.Add("  download failed: $($u.Title)") }
        }
        if ($ready.Count) {
            $log.Add("Installing $($ready.Count) update(s)...")
            $inst = $session.CreateUpdateInstaller()
            $inst.Updates = $ready
            $res = $inst.Install()
            $codes = @{ 0 = 'not started'; 1 = 'in progress'; 2 = 'installed'; 3 = 'installed with errors'; 4 = 'FAILED'; 5 = 'aborted' }
            for ($i = 0; $i -lt $ready.Count; $i++) {
                $ur = $res.GetUpdateResult($i)
                if ($ur.ResultCode -notin 2, 3) { $failed++ }
                $hr = $(if ($ur.HResult) { ' (0x{0:X8})' -f $ur.HResult } else { '' })
                $log.Add("  $($codes[[int]$ur.ResultCode])$hr : $($ready.Item($i).Title)")
            }
            $rebootNeeded = [bool]$res.RebootRequired
        }
    }
    # Fresh list for the dashboard.
    $records = @()
    try { $records = @((Find-KemUpdates).updates | ForEach-Object { ConvertTo-KemUpdateRecord $_ }) } catch { }
    $rebootNeeded = $rebootNeeded -or (Get-KemRebootRequired)
    if ($rebootNeeded) {
        if ($P.reboot -eq 'if_needed') {
            $delay = [Math]::Max(60, [int]$P.reboot_delay)
            & shutdown.exe /r /t $delay /c 'Your IT administrator installed Windows updates. This computer will restart.' /d p:2:17 | Out-Null
            $log.Add("Reboot required - restarting in $delay seconds.")
        } else { $log.Add('Reboot required to finish (not restarting - reboot was set to "never").') }
    }
    $log.Add("$($records.Count) update(s) still available.")
    return @{ status = $(if ($failed) { 'failed' } else { 'success' }); output = ($log -join "`n")
        data = @{ updates = $records; reboot_required = $rebootNeeded } }
}

# ------------------------------------------------------------------ web filter (hosts file)
# Blocked domains are pointed at 0.0.0.0 in a managed section of the hosts file. Browsers' own
# DNS-over-HTTPS is disabled by policy so they use the system resolver (which reads the hosts file).

$script:KemHostsBegin = '# >>> KEM web filter - managed by KEM, do not edit >>>'
$script:KemHostsEnd   = '# <<< KEM web filter <<<'
if (-not $script:KemHostsPath) { $script:KemHostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }

function Get-KemWebFilterDomains {
    $st = Get-KemState 'webfilter'
    if ($st -and $st.domains) { return @($st.domains) }
    return @()
}

function Get-KemHostsLines([string[]]$Domains) {
    $lines = New-Object System.Collections.Generic.List[string]
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($d in $Domains) {
        $bare = $(if ($d.StartsWith('www.')) { $d.Substring(4) } else { $d })
        foreach ($n in @($bare, "www.$bare", "m.$bare")) { if (-not $names.Contains($n)) { $names.Add($n) } }
    }
    foreach ($n in $names) { $lines.Add("0.0.0.0 $n"); $lines.Add(":: $n") }
    return $lines.ToArray()
}

function Write-KemHostsFile([string[]]$Domains) {
    $path = $script:KemHostsPath
    $text = ''
    if (Test-Path $path) { $text = [IO.File]::ReadAllText($path) }
    $kept = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -eq $script:KemHostsBegin) { $inside = $true; continue }
        if ($line -eq $script:KemHostsEnd) { $inside = $false; continue }
        if (-not $inside) { $kept.Add($line) }
    }
    while ($kept.Count -and -not $kept[$kept.Count - 1].Trim()) { $kept.RemoveAt($kept.Count - 1) }
    if ($Domains.Count) {
        $kept.Add('')
        $kept.Add($script:KemHostsBegin)
        foreach ($l in (Get-KemHostsLines $Domains)) { $kept.Add($l) }
        $kept.Add($script:KemHostsEnd)
    }
    $new = ($kept -join "`r`n") + "`r`n"
    for ($i = 1; $i -le 5; $i++) {
        try { [IO.File]::WriteAllText($path, $new, (New-Object System.Text.UTF8Encoding $false)); break }
        catch { if ($i -eq 5) { throw }; Start-Sleep -Milliseconds 400 }   # antivirus may hold the file briefly
    }
}

function Test-KemHostsFile([string[]]$Domains) {
    $path = $script:KemHostsPath
    $text = $(if (Test-Path $path) { [IO.File]::ReadAllText($path) } else { '' })
    $m = [regex]::Match($text, [regex]::Escape($script:KemHostsBegin) + '\r?\n([\s\S]*?)' + [regex]::Escape($script:KemHostsEnd))
    $have = $(if ($m.Success) { @($m.Groups[1].Value -split "`r?`n" | Where-Object { $_ }) } else { @() })
    return ($have -join "`n") -eq ((Get-KemHostsLines $Domains) -join "`n")
}

function Set-KemBrowserDohPolicy([bool]$Disable) {
    $chromium = 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
    $ff = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'
    if ($Disable) {
        foreach ($k in $chromium) {
            New-Item -Path $k -Force | Out-Null
            Set-ItemProperty -Path $k -Name DnsOverHttpsMode -Value 'off' -Type String
        }
        New-Item -Path $ff -Force | Out-Null
        Set-ItemProperty -Path $ff -Name Enabled -Value 0 -Type DWord
        Set-ItemProperty -Path $ff -Name Locked -Value 1 -Type DWord
    } else {
        foreach ($k in $chromium) { Remove-ItemProperty -Path $k -Name DnsOverHttpsMode -ErrorAction SilentlyContinue }
        Remove-Item -Path $ff -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Set-KemWebFilter($P, [switch]$NoPolicy) {
    $domains = @($P.domains | Where-Object { $_ } | ForEach-Object { "$_".ToLower() } | Select-Object -Unique)
    Write-KemHostsFile $domains
    if (-not $NoPolicy) { Set-KemBrowserDohPolicy ($domains.Count -gt 0) }
    & ipconfig.exe /flushdns | Out-Null
    if ($domains.Count) {
        Set-KemState 'webfilter' @{ domains = $domains; applied = (Get-KemUnixTime) }
        return "Web filter active: $($domains.Count) domain(s) blocked (plus their www. and m. sub-domains). Browser DNS-over-HTTPS disabled by policy; browsers may need a restart to pick up the change."
    }
    Set-KemState 'webfilter' $null
    return 'Web filter removed - all websites allowed.'
}

function Assert-KemWebFilter {
    $domains = @(Get-KemWebFilterDomains)
    if (-not $domains.Count) { return }
    if (-not (Test-KemHostsFile $domains)) {
        Write-KemLog 'Web filter section missing or modified - re-applying' 'WARN'
        Write-KemHostsFile $domains
        & ipconfig.exe /flushdns | Out-Null
    }
}

# ------------------------------------------------------------------ USB storage control

$script:KemRemovableKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
$script:KemRemovableDisk = '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'

function Get-KemUsbMode {
    try {
        $all = Get-ItemProperty -Path $script:KemRemovableKey -ErrorAction SilentlyContinue
        if ($all -and $all.Deny_All -eq 1) { return 'block' }
        $disk = Get-ItemProperty -Path (Join-Path $script:KemRemovableKey $script:KemRemovableDisk) -ErrorAction SilentlyContinue
        if ($disk -and $disk.Deny_Read -eq 1) { return 'block' }
        if ($disk -and $disk.Deny_Write -eq 1) { return 'read_only' }
    } catch { }
    return 'allow'
}

function Set-KemUsbStorage([string]$Mode) {
    $root = $script:KemRemovableKey
    $disk = Join-Path $root $script:KemRemovableDisk
    New-Item -Path $disk -Force | Out-Null
    Set-ItemProperty -Path $root -Name Deny_All -Value $(if ($Mode -eq 'block') { 1 } else { 0 }) -Type DWord
    Set-ItemProperty -Path $disk -Name Deny_Read -Value $(if ($Mode -eq 'block') { 1 } else { 0 }) -Type DWord
    Set-ItemProperty -Path $disk -Name Deny_Write -Value $(if ($Mode -ne 'allow') { 1 } else { 0 }) -Type DWord
    # Also stop the USB mass-storage drivers from loading for newly connected drives.
    foreach ($svc in 'USBSTOR', 'UASPStor') {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        if (Test-Path $k) { Set-ItemProperty -Path $k -Name Start -Value $(if ($Mode -eq 'block') { 4 } else { 3 }) -Type DWord }
    }
    if ($Mode -eq 'allow') { Set-KemState 'usb' $null } else { Set-KemState 'usb' @{ mode = $Mode; applied = (Get-KemUnixTime) } }
    $what = @{ allow = 'USB storage allowed.'; read_only = 'USB storage is now read-only (files can be opened, not copied to the drive).'; block = 'USB storage blocked (flash drives, external disks, phones as storage).' }[$Mode]
    return "$what Drives that are already plugged in may need to be re-connected (or the PC restarted)."
}

function Assert-KemUsbStorage {
    $st = Get-KemState 'usb'
    if ($st -and $st.mode -and (Get-KemUsbMode) -ne $st.mode) {
        Write-KemLog "USB policy changed locally - re-applying '$($st.mode)'" 'WARN'
        Set-KemUsbStorage $st.mode | Out-Null
    }
}

# ------------------------------------------------------------------ processes & services

function Get-KemProcessList {
    $cores = [Environment]::ProcessorCount
    $first = @{}
    foreach ($p in Get-Process) { try { $first[$p.Id] = $p.TotalProcessorTime.TotalMilliseconds } catch { } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 1000
    try { $procs = @(Get-Process -IncludeUserName -ErrorAction Stop) } catch { $procs = @(Get-Process) }
    $ms = $sw.Elapsed.TotalMilliseconds
    $list = foreach ($p in $procs) {
        if ($p.Id -eq 0) { continue }
        $cpu = $null
        try { if ($first.ContainsKey($p.Id)) { $cpu = [math]::Round(100 * ($p.TotalProcessorTime.TotalMilliseconds - $first[$p.Id]) / $ms / $cores, 1) } } catch { }
        $path = ''; try { $path = "$($p.Path)" } catch { }
        $started = $null; try { $started = Get-KemUnixTime $p.StartTime } catch { }
        @{ pid = $p.Id; name = $p.ProcessName; cpu = $cpu; mem_mb = [math]::Round($p.WorkingSet64 / 1MB, 1)
            user = "$($p.UserName)"; path = $path; started = $started; session = $p.SessionId }
    }
    $list = @($list | Sort-Object { $_.mem_mb } -Descending)
    $top = ($list | Select-Object -First 8 | ForEach-Object { "$($_.name) ($($_.mem_mb) MB)" }) -join ', '
    return @{ status = 'success'; output = "$($list.Count) processes. Largest: $top"; data = $list }
}

function Stop-KemProcess($P) {
    if ($P.pid) {
        $id = [int]$P.pid
        if ($id -eq $PID) { throw 'Refusing to stop the KEM agent itself.' }
        $p = Get-Process -Id $id -ErrorAction Stop
        Stop-Process -Id $id -Force -ErrorAction Stop
        return "Stopped $($p.ProcessName) (PID $id)."
    }
    $procs = @(Get-Process -Name $P.name -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID })
    if (-not $procs) { throw "No running process named '$($P.name)'." }
    $procs | Stop-Process -Force -ErrorAction Stop
    return "Stopped $($procs.Count) process(es) named $($P.name)."
}

function Get-KemServiceList {
    $list = @(Get-CimInstance Win32_Service | Sort-Object DisplayName | ForEach-Object {
        @{ name = $_.Name; display = "$($_.DisplayName)"; state = "$($_.State)"; start = "$($_.StartMode)"
            account = "$($_.StartName)"; pid = [int]$_.ProcessId; description = "$($_.Description)".Substring(0, [Math]::Min(200, "$($_.Description)".Length)) }
    })
    $running = @($list | Where-Object { $_.state -eq 'Running' }).Count
    $autoStopped = @($list | Where-Object { $_.start -eq 'Auto' -and $_.state -ne 'Running' }).Count
    return @{ status = 'success'; output = "$($list.Count) services, $running running, $autoStopped automatic but stopped."; data = $list }
}

# Services the agent depends on (or that keep the device manageable / isolated).
$script:KemProtectedServices = @('Schedule', 'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'mpssvc', 'BFE', 'Winmgmt', 'LSM', 'SamSs', 'Dnscache', 'Dhcp', 'nsi', 'EventLog')

function Invoke-KemServiceAction($P) {
    $svc = Get-Service -Name $P.name -ErrorAction Stop
    $name = $svc.Name
    if ($name -in $script:KemProtectedServices -and ($P.action -in 'stop', 'restart' -or $P.startup -eq 'disabled')) {
        throw "Refusing to stop or disable '$name' - Windows or the KEM agent depends on it."
    }
    $done = @()
    if ($P.startup) {
        $type = @{ automatic = 'Automatic'; manual = 'Manual'; disabled = 'Disabled' }["$($P.startup)"]
        Set-Service -Name $name -StartupType $type -ErrorAction Stop
        $done += "startup set to $type"
    }
    switch ("$($P.action)") {
        'start'   { Start-Service -Name $name -ErrorAction Stop; $done += 'started' }
        'stop'    { Stop-Service -Name $name -Force -ErrorAction Stop; $done += 'stopped' }
        'restart' { Restart-Service -Name $name -Force -ErrorAction Stop; $done += 'restarted' }
    }
    $svc = Get-Service -Name $name
    return "$($svc.DisplayName) ($name): $($done -join ', '). Now $($svc.Status)."
}

# ------------------------------------------------------------------ actions in the signed-in user's session
# The agent runs as SYSTEM in session 0, which has no desktop. To show a message, lock the screen or take a
# screenshot it starts a short-lived scheduled task as the signed-in user, through a hidden launcher.

function Get-KemConsoleUser {
    $u = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $u) { throw 'No user is signed in on this computer.' }
    return "$u"
}

function Get-KemHiddenLauncher {
    $vbs = "Dim sh: Set sh = CreateObject(""WScript.Shell"")`r`n" +
           "WScript.Quit sh.Run(""powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand "" & WScript.Arguments(0), 0, True)`r`n"
    # Must be readable by standard users but writable only by admins: the program folder.
    $dir = $script:KemInstallDir
    if (-not (Test-Path $dir)) { $dir = Join-Path $env:TEMP 'KEM' ; New-Item -ItemType Directory $dir -Force | Out-Null }
    $path = Join-Path $dir 'kem-hidden.vbs'
    if (-not (Test-Path $path) -or [IO.File]::ReadAllText($path) -ne $vbs) { [IO.File]::WriteAllText($path, $vbs, [Text.Encoding]::ASCII) }
    return $path
}

function Remove-KemUiTasks {
    Get-ScheduledTask -TaskName 'KEM-UI-*' -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Running' } |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    Get-ChildItem (Join-Path $env:ProgramData 'KEM-ui') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -lt (Get-Date).AddHours(-1) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-KemAsUser([string]$Script, [int]$TimeoutSec = 60, [switch]$NoWait) {
    $user = Get-KemConsoleUser
    Remove-KemUiTasks
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    $name = 'KEM-UI-' + [guid]::NewGuid().ToString('N').Substring(0, 10)
    $action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ("//B //Nologo `"{0}`" {1}" -f (Get-KemHiddenLauncher), $enc)
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances Parallel
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $name
    if ($NoWait) { return @{ user = $user; exit_code = $null } }   # left for Remove-KemUiTasks to clean up
    try {
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        Start-Sleep -Milliseconds 700
        while ((Get-ScheduledTask -TaskName $name).State -in 'Running', 'Queued') {
            if ((Get-Date) -gt $deadline) { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue; throw "Timed out after $TimeoutSec s in $user's session." }
            Start-Sleep -Milliseconds 300
        }
        $code = [int64](Get-ScheduledTaskInfo -TaskName $name).LastTaskResult
        if ($code -eq 267011) { throw "Windows did not start the task in $user's session." }   # 0x41303 = has not run
        return @{ user = $user; exit_code = $code }
    } finally { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue }
}

function ConvertTo-KemPsLiteral([string]$Text) {
    # Embed arbitrary (e.g. Hebrew) text in a generated script without quoting problems.
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    return "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64')))"
}

function Send-KemUserMessage($P) {
    $opts = 'DefaultDesktopOnly'
    if ("$($P.text)$($P.title)" -match '[\u0590-\u06FF]') { $opts += ', RtlReading, RightAlign' }   # Hebrew / Arabic
    $script = "Add-Type -AssemblyName System.Windows.Forms`n" +
        "[void][System.Windows.Forms.MessageBox]::Show($(ConvertTo-KemPsLiteral $P.text), $(ConvertTo-KemPsLiteral $P.title), 'OK', 'Information', 'Button1', '$opts')"
    $r = Invoke-KemAsUser $script -NoWait
    return "Message shown to $($r.user)."
}

function Invoke-KemSessionAction($P) {
    if ($P.action -eq 'logoff') {
        $r = Invoke-KemAsUser '& shutdown.exe /l /f' 30
        return "Signed out $($r.user)."
    }
    $r = Invoke-KemAsUser '& rundll32.exe user32.dll,LockWorkStation' 30
    return "Screen locked for $($r.user)."
}

# ------------------------------------------------------------------ agent self-update

function Update-KemAgentFiles($Release, [string]$Server, [string]$InstallDir) {
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tmp = Join-Path $script:KemDataDir 'update'
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $names = @($Release.files.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($n in $names) {
            if ($n -notmatch '^[a-z-]+\.ps1$') { throw "Unexpected file name '$n'" }
            $f = Join-Path $tmp $n
            Invoke-WebRequest -Uri "$($Server.TrimEnd('/'))/agent/$n" -OutFile $f -UseBasicParsing -TimeoutSec 120
            $hash = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
            if ($hash -ne "$($Release.files.$n)".ToLower()) { throw "Checksum mismatch for $n" }
            $tokens = $null; $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$errors)
            if ($errors.Count) { throw "Downloaded $n does not parse: $($errors[0].Message)" }
        }
        foreach ($n in $names) { Copy-Item (Join-Path $tmp $n) (Join-Path $InstallDir $n) -Force }
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

function Restart-KemAgentTask {
    # Started through WMI so the helper is not a child of this task (it must outlive our exit).
    $cmd = "cmd.exe /c ping -n 6 127.0.0.1 >nul & schtasks.exe /Run /TN `"$script:KemTaskName`""
    Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } | Out-Null
}

# ------------------------------------------------------------------ dispatcher

# Commands that run inside the main loop (fast, or must coordinate with the loop).
$script:KemInlineTypes = @('block_internet', 'unblock_internet', 'refresh_inventory', 'reboot', 'reset_device', 'uninstall_agent',
    'set_web_filter', 'usb_storage', 'list_processes', 'kill_process', 'list_services', 'send_message', 'lock_session',
    'update_agent', 'set_hostname')

function Copy-KemDistributedFile($P) {
    # Download a file over TLS and place it in a folder on this machine (optionally SHA-256 verified).
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $dest = "$($P.dest)"
    if (-not $dest) { return @{ status = 'failed'; output = 'No destination folder given.' } }
    $name = "$($P.filename)"
    if (-not $name) { try { $name = [IO.Path]::GetFileName(([Uri]$P.url).AbsolutePath) } catch { $name = '' } }
    if (-not $name) { return @{ status = 'failed'; output = 'Could not determine a file name; set one explicitly.' } }
    try { New-Item -ItemType Directory -Path $dest -Force | Out-Null } catch { return @{ status = 'failed'; output = "Cannot create folder '$dest': $_" } }
    $target = Join-Path $dest $name
    if ((Test-Path $target) -and -not [bool]$P.overwrite) {
        return @{ status = 'failed'; output = "A file named '$name' already exists and overwrite is off." }
    }
    $tmp = Join-Path $script:KemDataDir ('dist-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        Invoke-WebRequest -Uri $P.url -OutFile $tmp -UseBasicParsing -TimeoutSec 1800
        $hash = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
        if ($P.sha256 -and $hash -ne "$($P.sha256)".ToLower()) {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            return @{ status = 'failed'; output = "Checksum mismatch. Expected $($P.sha256), got $hash. File NOT placed." }
        }
        $size = [math]::Round((Get-Item $tmp).Length / 1MB, 2)
        Move-Item -Path $tmp -Destination $target -Force
        return @{ status = 'success'; output = "Placed '$name' ($size MB, sha256 $hash) in $dest" }
    } catch {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        return @{ status = 'failed'; output = "Download or placement failed: $_" }
    }
}

function Set-KemAppPolicy($P) {
    # Apply an AppLocker executable allowlist. ALWAYS keeps the Windows default allow-rules
    # (Program Files, Windows dir, Administrators) so the OS and installed apps keep running,
    # and defaults to AuditOnly (log, do not block). Only Exe is configured; MSI/Script/DLL stay
    # NotConfigured (allowed). WARNING: not yet exercised on real hardware - test off-production first.
    $mode = "$($P.mode)"
    $xmlFile = Join-Path $script:KemDataDir 'applocker.xml'
    if ($mode -eq 'off') {
        try {
            Set-Content -Path $xmlFile -Value '<AppLockerPolicy Version="1"></AppLockerPolicy>' -Encoding ASCII
            Set-AppLockerPolicy -XmlPolicy $xmlFile -ErrorAction Stop
            return @{ status = 'success'; output = 'Application allowlist removed (AppLocker policy cleared).' }
        } catch { return @{ status = 'failed'; output = "Could not clear AppLocker: $_" } }
    }
    try { Set-Service AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service AppIDSvc -ErrorAction SilentlyContinue } catch {}
    $enforce = if ($mode -eq 'enforce') { 'Enabled' } else { 'AuditOnly' }
    $esc = {
        param($s)
        ("$s") -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace "'", '&apos;' -replace '"', '&quot;'
    }
    $rule = {
        param($name, $sid, $path)
        $id = [guid]::NewGuid().ToString()
        "<FilePathRule Id='$id' Name='$(& $esc $name)' Description='KEM' UserOrGroupSid='$sid' Action='Allow'><Conditions><FilePathCondition Path='$(& $esc $path)' /></Conditions></FilePathRule>"
    }
    $rulesXml = ''
    $rulesXml += & $rule 'KEM default: Program Files' 'S-1-1-0' '%PROGRAMFILES%\*'
    $rulesXml += & $rule 'KEM default: Windows' 'S-1-1-0' '%WINDIR%\*'
    $rulesXml += & $rule 'KEM default: Administrators' 'S-1-5-32-544' '*'
    foreach ($r in @($P.rules)) {
        $v = "$($r.value)"
        if ("$($r.type)" -eq 'filename') { $rulesXml += & $rule "KEM allow $v" 'S-1-1-0' "*\$v" }
        else { $rulesXml += & $rule "KEM allow $v" 'S-1-1-0' $v }
    }
    $xml = "<AppLockerPolicy Version='1'><RuleCollection Type='Exe' EnforcementMode='$enforce'>$rulesXml</RuleCollection></AppLockerPolicy>"
    try {
        Set-Content -Path $xmlFile -Value $xml -Encoding ASCII
        Set-AppLockerPolicy -XmlPolicy $xmlFile -ErrorAction Stop
        $n = @($P.rules).Count
        return @{ status = 'success'; output = "Applied AppLocker allowlist (mode: $enforce) - $n custom allow rule(s) plus the Windows defaults." }
    } catch {
        return @{ status = 'failed'; output = "Could not apply AppLocker policy: $_" }
    }
}

function Launch-KemApp($P) {
    # Launch an approved program or URL in the signed-in user's session (not as SYSTEM).
    if ("$($P.target)" -eq 'url') {
        $script = "Start-Process $(ConvertTo-KemPsLiteral $P.value)"
    } else {
        $script = "Start-Process -FilePath $(ConvertTo-KemPsLiteral $P.value)"
        if ("$($P.args)") { $script += " -ArgumentList $(ConvertTo-KemPsLiteral $P.args)" }
    }
    $r = Invoke-KemAsUser $script -NoWait
    return "Launched in $($r.user)'s session: $($P.value)"
}

function Rename-KemComputer($P) {
    # Rename this computer. A reboot (scheduled by the caller) is required for the new name to take effect.
    $new = "$($P.hostname)"
    if ($new -notmatch '^(?!-)(?!\d+$)[A-Za-z0-9-]{1,15}(?<!-)$') {
        return @{ status = 'failed'; output = "Invalid computer name '$new'." }
    }
    if ($env:COMPUTERNAME -eq $new) {
        return @{ status = 'success'; output = "Computer is already named '$new'; nothing to do." }
    }
    try {
        Rename-Computer -NewName $new -Force -ErrorAction Stop
        return @{ status = 'success'; output = "Renamed '$($env:COMPUTERNAME)' to '$new' (reboot required to apply)." }
    } catch {
        return @{ status = 'failed'; output = "Rename failed: $($_.Exception.Message)" }
    }
}

function Set-KemDenyInteractiveLogon([string]$Account) {
    # Deny interactive + remote-interactive (RDP) logon for a local account, via the local security policy.
    # Network, batch and service logons stay allowed so the account still works for management.
    $sid = $null
    try { $sid = (Get-LocalUser -Name $Account -ErrorAction Stop).SID.Value } catch { return }
    if (-not $sid) { return }
    $work = Join-Path $script:KemDataDir ('secpol-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $inf = "$work.inf"; $db = "$work.sdb"
    try {
        & secedit.exe /export /areas USER_RIGHTS /cfg $inf /quiet | Out-Null
        $lines = Get-Content $inf
        $out = New-Object System.Collections.Generic.List[string]
        $have = @{}
        foreach ($ln in $lines) {
            $m = [regex]::Match($ln, '^(SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight)\s*=\s*(.*)$')
            if ($m.Success) {
                $key = $m.Groups[1].Value
                $vals = @($m.Groups[2].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($vals -notcontains "*$sid") { $vals += "*$sid" }
                $out.Add("$key = " + ($vals -join ','))
                $have[$key] = $true
            } else {
                $out.Add($ln)
            }
        }
        foreach ($key in 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
            if (-not $have[$key]) {
                for ($i = 0; $i -lt $out.Count; $i++) {
                    if ($out[$i] -match '^\[Privilege Rights\]') { $out.Insert($i + 1, "$key = *$sid"); break }
                }
            }
        }
        Set-Content -Path $inf -Value $out -Encoding Unicode
        & secedit.exe /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    } catch {
        Write-KemLog "Could not set deny-interactive for '$Account': $($_.Exception.Message)" 'WARN'
    } finally {
        Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
    }
}

function Set-KemLocalAdminPassword($P) {
    # Set (and create if needed) the password of a managed local administrator account.
    # The account is kept a member of Administrators and denied interactive/RDP logon.
    $account = "$($P.account)"
    if (-not $account) { $account = $script:KemAdminUser }
    $pw = "$($P.password)"
    if ($pw.Length -lt 8) { return @{ status = 'failed'; output = 'Password too short.' } }
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    try {
        $existing = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
        if ($existing) {
            Set-LocalUser -Name $account -Password $sec -ErrorAction Stop
            try { Set-LocalUser -Name $account -PasswordNeverExpires $true -ErrorAction SilentlyContinue } catch {}
            Enable-LocalUser -Name $account -ErrorAction SilentlyContinue
        } else {
            New-LocalUser -Name $account -Password $sec -FullName 'KEM managed admin' `
                -Description 'KEM managed local administrator (interactive logon denied)' `
                -PasswordNeverExpires -ErrorAction Stop | Out-Null
        }
        if ([bool]$P.ensure_admin -or -not $existing) {
            $grp = (Get-LocalGroup -SID 'S-1-5-32-544').Name
            if (-not (Get-LocalGroupMember -Group $grp -Member $account -ErrorAction SilentlyContinue)) {
                Add-LocalGroupMember -Group $grp -Member $account -ErrorAction SilentlyContinue
            }
        }
        Set-KemDenyInteractiveLogon $account
        return @{ status = 'success'; output = "Password set for local admin '$account' (member of Administrators, interactive logon denied)." }
    } catch {
        return @{ status = 'failed'; output = "Could not set password for '$account': $($_.Exception.Message)" }
    }
}

function Install-KemManagedAdmin {
    # Ensure the managed admin account exists (called at install). If it does not exist yet, create it
    # with a random, unused password - the real password is set later from the dashboard. Interactive
    # logon is denied either way, so the random password is never needed for a console/RDP sign-in.
    $account = $script:KemAdminUser
    try {
        if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {
            Set-KemDenyInteractiveLogon $account
            return "Managed admin '$account' already present."
        }
        $bytes = New-Object byte[] 18
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $rand = [Convert]::ToBase64String($bytes) + 'aA1!'
        $sec = ConvertTo-SecureString $rand -AsPlainText -Force
        New-LocalUser -Name $account -Password $sec -FullName 'KEM managed admin' `
            -Description 'KEM managed local administrator (interactive logon denied)' `
            -PasswordNeverExpires -ErrorAction Stop | Out-Null
        $grp = (Get-LocalGroup -SID 'S-1-5-32-544').Name
        Add-LocalGroupMember -Group $grp -Member $account -ErrorAction SilentlyContinue
        Set-KemDenyInteractiveLogon $account
        return "Created managed admin '$account' (Administrators, interactive logon denied). Set its password from the dashboard."
    } catch {
        return "Could not create managed admin '$account': $($_.Exception.Message)"
    }
}

function Test-KemUplink([string]$Url) {
    # True if a teacher-station relay is answering at this uplink URL.
    if (-not $Url) { return $false }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod -Uri ($Url.TrimEnd('/') + '/healthz') -TimeoutSec 4 -UseBasicParsing
        return [bool]$r.ok
    } catch { return $false }
}

function Set-KemUplink($P) {
    # Re-home this agent to a teacher station (or clear it to talk to central directly). The
    # central server in config.server is always kept as the fallback.
    $f = Join-Path $script:KemDataDir 'config.json'
    $cfg = Get-KemConfig
    if (-not $cfg) { return @{ status = 'failed'; output = 'No config to update.' } }
    $url = "$($P.url)".TrimEnd('/')
    if ($url) {
        $cfg | Add-Member -NotePropertyName uplink -NotePropertyValue $url -Force
        $msg = "Uplink set to $url (central server kept as automatic fallback)."
    } else {
        if ($cfg.PSObject.Properties.Name -contains 'uplink') { $cfg.PSObject.Properties.Remove('uplink') }
        $msg = 'Uplink cleared; talking to the central server directly.'
    }
    ($cfg | ConvertTo-Json -Depth 8) | Set-Content -Path $f -Encoding UTF8
    return @{ status = 'success'; output = $msg }
}

function Get-KemGatewayPython {
    foreach ($c in @('python', 'python3', 'py')) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { try { & $cmd.Source --version *> $null; if ($LASTEXITCODE -eq 0) { return $cmd.Source } } catch {} }
    }
    return $null
}

function Enable-KemTeacherStation($P, [string]$Server) {
    # Promote this station to the class teacher station: fetch the relay, write its config from the
    # server-minted gateway credentials, and run it at boot so classmates can reach central through it.
    $py = Get-KemGatewayPython
    if (-not $py) { return @{ status = 'failed'; output = 'Python 3.8+ is required to act as a teacher station but was not found on PATH.' } }
    $dir = Join-Path $env:ProgramFiles 'KEM-Gateway'
    try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch { return @{ status = 'failed'; output = "Cannot create $dir : $($_.Exception.Message)" } }
    $relay = Join-Path $dir 'relay.py'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri ($Server.TrimEnd('/') + '/gateway/relay.py') -OutFile $relay -UseBasicParsing
    } catch { return @{ status = 'failed'; output = "Could not download relay.py: $($_.Exception.Message)" } }
    $port = [int]$P.listen_port; if ($port -lt 1) { $port = 8171 }
    $cfgPath = Join-Path $dir 'gateway.json'
    $gw = [ordered]@{ central_url = $Server.TrimEnd('/'); gateway_id = "$($P.gateway_id)"; gateway_secret = "$($P.gateway_secret)";
        hostname = $env:COMPUTERNAME; lab_id = "$($P.lab_id)"; listen_host = '0.0.0.0'; listen_port = $port; heartbeat_seconds = 30 }
    ($gw | ConvertTo-Json) | Set-Content -Path $cfgPath -Encoding ASCII
    $launcher = Join-Path $dir 'run-gateway.cmd'
    "@echo off`r`nset KEM_GATEWAY_CONFIG=$cfgPath`r`n`"$py`" `"$relay`" run" | Set-Content -Path $launcher -Encoding ASCII
    $action = New-ScheduledTaskAction -Execute $launcher -WorkingDirectory $dir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    $settings.ExecutionTimeLimit = 'PT0S'
    try { Register-ScheduledTask -TaskName $script:KemGatewayTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null }
    catch { return @{ status = 'failed'; output = "Could not register the gateway task: $($_.Exception.Message)" } }
    try { New-NetFirewallRule -DisplayName 'KEM Gateway (student agents)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any -ErrorAction Stop | Out-Null } catch {}
    try { Start-ScheduledTask -TaskName $script:KemGatewayTask } catch {}
    return @{ status = 'success'; output = "Teacher station active: relay listening on port $port (gateway $($P.gateway_id))." }
}

function Disable-KemTeacherStation {
    try { Get-ScheduledTask -TaskName $script:KemGatewayTask -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $script:KemGatewayTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Remove-NetFirewallRule -DisplayName 'KEM Gateway (student agents)' -ErrorAction SilentlyContinue } catch {}
    Remove-Item (Join-Path (Join-Path $env:ProgramFiles 'KEM-Gateway') 'gateway.json') -Force -ErrorAction SilentlyContinue
    return @{ status = 'success'; output = 'Teacher station stopped; this station no longer relays for the class.' }
}

function Get-KemSecurity {
    # A privacy-safe security snapshot: Defender status + recent threat names, and AGGREGATE counts of
    # security events (no usernames, IPs or personal data).
    $out = @{ collected = (Get-KemUnixTime) }
    try {
        $m = Get-MpComputerStatus -ErrorAction Stop
        $out.defender = @{ realtime = [bool]$m.RealTimeProtectionEnabled; antivirus = [bool]$m.AntivirusEnabled;
            signature_age_days = [int]$m.AntivirusSignatureAge; tamper_protection = [bool]$m.IsTamperProtected;
            behavior_monitor = [bool]$m.BehaviorMonitorEnabled }
    } catch { $out.defender = $null }
    try {
        $out.threats = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending |
            Select-Object -First 25 | ForEach-Object { @{ name = "$($_.ThreatName)"; action_ok = [bool]$_.ActionSuccess } })
    } catch { $out.threats = @() }
    $labels = @{ '4625' = 'failed_logons'; '4740' = 'account_lockouts'; '4720' = 'new_local_accounts';
        '4728' = 'added_to_global_group'; '4732' = 'added_to_local_group'; '7045' = 'new_services'; '1102' = 'security_log_cleared' }
    $counts = @{}
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4740, 4720, 4728, 4732, 7045, 1102; StartTime = (Get-Date).AddDays(-7) } -ErrorAction Stop
        foreach ($g in ($ev | Group-Object Id)) { $counts[$labels["$($g.Name)"]] = $g.Count }
    } catch { }
    $out.event_counts_7d = $counts
    return $out
}

function Send-KemSecurity([string]$Server) {
    $cfg = Get-KemConfig
    if (-not $cfg) { return @{ status = 'failed'; output = 'No agent config.' } }
    try {
        $snap = Get-KemSecurity
        Invoke-KemApi -Server $Server -Path '/api/agent/security' -Body @{ snapshot = $snap } -Headers (Get-KemAuthHeaders $cfg) -TimeoutSec 60 | Out-Null
        return @{ status = 'success'; output = "Security snapshot collected ($(@($snap.threats).Count) threat record(s), $(@($snap.event_counts_7d.Keys).Count) event type(s))." }
    } catch {
        return @{ status = 'failed'; output = "Security scan failed: $($_.Exception.Message)" }
    }
}

function Get-KemLicenses {
    # Windows product key / edition / activation. The OEM (firmware) key is the full 25-char key used
    # to re-activate this hardware; retail/VL installs expose only the last 5 chars via the OS API.
    $list = @()
    $oem = ''
    try { $oem = "$((Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop).OA3xOriginalProductKey)".Trim() } catch { }
    $edition = ''; $status = ''; $partial = ''
    try {
        $p = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop | Select-Object -First 1
        if ($p) {
            $edition = "$($p.Name)"; $partial = "$($p.PartialProductKey)"
            $status = switch ([int]$p.LicenseStatus) { 1 { 'Activated' } 0 { 'Unlicensed' } 2 { 'Grace' } 3 { 'Out-of-tolerance grace' } 5 { 'Notification' } default { "status $($p.LicenseStatus)" } }
        }
    } catch { }
    if ($oem) {
        $list += @{ product = 'Windows'; edition = $edition; status = $status; source = 'firmware (OEM)'; key = $oem }
    } elseif ($partial) {
        $list += @{ product = 'Windows'; edition = $edition; status = $status; source = 'installed (partial)'; key = "*****-*****-*****-*****-$partial" }
    } else {
        $list += @{ product = 'Windows'; edition = $edition; status = $status; source = ''; key = '' }
    }
    return $list
}

function Send-KemLicenses([string]$Server) {
    $cfg = Get-KemConfig
    if (-not $cfg) { return @{ status = 'failed'; output = 'No agent config.' } }
    try {
        $lic = Get-KemLicenses
        Invoke-KemApi -Server $Server -Path '/api/agent/licenses' -Body @{ licenses = $lic } -Headers (Get-KemAuthHeaders $cfg) -TimeoutSec 60 | Out-Null
        return @{ status = 'success'; output = "Collected $(@($lic).Count) license record(s)." }
    } catch {
        return @{ status = 'failed'; output = "License collection failed: $($_.Exception.Message)" }
    }
}

function Update-KemSoftware($P) {
    # winget upgrade for one package (by id) or everything (--all).
    try { $wg = Get-KemWinget } catch { return @{ status = 'failed'; output = "$($_.Exception.Message)" } }
    try {
        if ([bool]$P.all) {
            $out = & $wg upgrade --all --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-String
            return @{ status = 'success'; output = ("Upgrade all:`n" + $out).Trim() }
        }
        if ("$($P.package_id)") {
            $id = "$($P.package_id)"
            $out = & $wg upgrade --id $id --exact --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-String
            return @{ status = 'success'; output = ("Upgrade ${id}:`n" + $out).Trim() }
        }
        $name = "$($P.name)"
        $out = & $wg upgrade --name $name --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-String
        return @{ status = 'success'; output = ("Upgrade ${name}:`n" + $out).Trim() }
    } catch {
        return @{ status = 'failed'; output = "Upgrade failed: $($_.Exception.Message)" }
    }
}

# ------------------------------------------------------------------ AI investigation probes
# Fixed, read-only diagnostics that the server's AI investigation may request by id. Nothing here changes
# the machine. User names are left out and profile paths masked (the server redacts again before AI use).

function Hide-KemUserPath([string]$s) {
    if (-not $s) { return $s }
    return ($s -replace '(?i)(\\Users\\)(?!Public\\|Default\\)[^\\/\s"'']+', '$1<user>')
}

function Get-KemFolderMB([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    return [math]::Round(($sum / 1MB), 1)
}

function Get-KemEventSummary([string]$Log, [int]$Hours) {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $Log; Level = 1, 2; StartTime = (Get-Date).AddHours(-$Hours) } -MaxEvents 500 -ErrorAction SilentlyContinue)
    $groups = @($ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 12)
    $bySource = @(foreach ($g in $groups) {
        $e = $g.Group | Select-Object -First 1
        $msg = "$($e.Message)"; if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
        @{ source = $g.Name; count = $g.Count; event_id = $e.Id; last = (Get-KemUnixTime $e.TimeCreated); sample = (Hide-KemUserPath $msg) }
    })
    return @{ log = $Log; hours = $Hours; total = $ev.Count; capped_at = 500; by_source = $bySource }
}

function Get-KemProbeTopProcesses {
    $cores = [Environment]::ProcessorCount
    $first = @{}
    foreach ($p in Get-Process) { try { $first[$p.Id] = $p.TotalProcessorTime.TotalMilliseconds } catch { } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 1500
    $ms = $sw.Elapsed.TotalMilliseconds
    $rows = @(foreach ($p in Get-Process) {
        if ($p.Id -eq 0) { continue }
        $cpu = 0
        try { if ($first.ContainsKey($p.Id)) { $cpu = [math]::Round(100 * ($p.TotalProcessorTime.TotalMilliseconds - $first[$p.Id]) / $ms / $cores, 1) } } catch { }
        [pscustomobject]@{ name = $p.ProcessName; cpu = $cpu; mem_mb = [math]::Round($p.WorkingSet64 / 1MB, 1) }
    })
    return @{ count = $rows.Count; logical_cpus = $cores
        by_cpu = @($rows | Sort-Object cpu -Descending | Select-Object -First 15)
        by_memory = @($rows | Sort-Object mem_mb -Descending | Select-Object -First 15) }
}

function Get-KemProbeMemory {
    $os = Get-CimInstance Win32_OperatingSystem
    $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object {
        @{ path = "$($_.Name)"; size_mb = $_.AllocatedBaseSize; used_mb = $_.CurrentUsage; peak_mb = $_.PeakUsage } })
    return @{ total_mb = [math]::Round($os.TotalVisibleMemorySize / 1KB); free_mb = [math]::Round($os.FreePhysicalMemory / 1KB)
        commit_limit_mb = [math]::Round($os.TotalVirtualMemorySize / 1KB); commit_free_mb = [math]::Round($os.FreeVirtualMemory / 1KB)
        pagefiles = $pf }
}

function Get-KemProbeDiskSpace {
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        @{ drive = $_.DeviceID; fs = "$($_.FileSystem)"; size_gb = [math]::Round($_.Size / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1) } })
    $userTemp = 0
    foreach ($u in @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $mb = Get-KemFolderMB (Join-Path $u.FullName 'AppData\Local\Temp'); if ($mb) { $userTemp += $mb }
    }
    return @{ volumes = $vols; folders_mb = @{
        windows_temp = (Get-KemFolderMB "$env:SystemRoot\Temp")
        user_temp_total = [math]::Round($userTemp, 1)
        update_download_cache = (Get-KemFolderMB "$env:SystemRoot\SoftwareDistribution\Download")
        recycle_bin = (Get-KemFolderMB "$env:SystemDrive\`$Recycle.Bin") } }
}

function Get-KemProbeDiskHealth {
    $disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        @{ name = "$($_.FriendlyName)"; media = "$($_.MediaType)"; bus = "$($_.BusType)"; size_gb = [math]::Round($_.Size / 1GB)
            health = "$($_.HealthStatus)"; operational = (@($_.OperationalStatus) -join ',') } })
    $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | ForEach-Object {
        @{ predict_failure = [bool]$_.PredictFailure; reason = $_.Reason } })
    return @{ disks = $disks; smart = $smart }
}

function Get-KemProbeStoppedServices {
    $list = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | Select-Object -First 60 | ForEach-Object {
        @{ name = $_.Name; display = "$($_.DisplayName)"; state = "$($_.State)"; exit_code = $_.ExitCode } })
    return @{ count = $list.Count; services = $list; note = 'Delayed/trigger-start services are often legitimately stopped.' }
}

function Get-KemProbeAppCrashes {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 300 -ErrorAction SilentlyContinue)
    $rows = @($ev | ForEach-Object {
        $prog = ''; try { $prog = "$($_.Properties[0].Value)" } catch { }
        [pscustomobject]@{ program = $prog; kind = $(if ($_.Id -eq 1000) { 'crash' } else { 'hang' }); at = (Get-KemUnixTime $_.TimeCreated) } })
    $groups = @($rows | Group-Object program, kind | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        $g = $_.Group
        @{ program = $g[0].program; kind = $g[0].kind; count = $_.Count; last = ($g | Measure-Object at -Maximum).Maximum } })
    return @{ days = 7; total = $rows.Count; by_program = $groups }
}

function Get-KemProbeShutdowns {
    $os = Get-CimInstance Win32_OperatingSystem
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 6008, 1001; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 200 -ErrorAction SilentlyContinue)
    return @{ last_boot = (Get-KemUnixTime $os.LastBootUpTime); uptime_hours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        kernel_power_41 = @($ev | Where-Object { $_.Id -eq 41 }).Count
        unexpected_shutdown_6008 = @($ev | Where-Object { $_.Id -eq 6008 }).Count
        bugcheck_1001 = @($ev | Where-Object { $_.Id -eq 1001 -and $_.ProviderName -match 'WER-SystemErrorReporting|BugCheck' }).Count
        recent = @($ev | Select-Object -First 10 | ForEach-Object { @{ id = $_.Id; source = $_.ProviderName; at = (Get-KemUnixTime $_.TimeCreated) } }) }
}

function Get-KemProbeStartup {
    $items = @()
    $keys = @(@{ k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; s = 'machine' },
              @{ k = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; s = 'machine (32-bit)' })
    foreach ($h in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $keys += @{ k = "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"; s = 'user' }
    }
    foreach ($k in $keys) {
        $props = Get-ItemProperty -Path $k.k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $cmd = Hide-KemUserPath "$($p.Value)"; if ($cmd.Length -gt 200) { $cmd = $cmd.Substring(0, 200) }
            $items += @{ name = $p.Name; scope = $k.s; command = $cmd }
        }
    }
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
        @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    foreach ($f in $folders) {
        foreach ($x in @(Get-ChildItem -LiteralPath $f -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $items += @{ name = $x.Name; scope = 'startup folder'; command = (Hide-KemUserPath $x.FullName) }
        }
    }
    $logonTasks = 0
    try { $logonTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and @($_.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }).Count }).Count } catch { }
    return @{ count = $items.Count; items = @($items | Select-Object -First 80); enabled_logon_tasks = $logonTasks }
}

function Get-KemProbeDrivers {
    $list = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode<>0' -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object {
        @{ name = "$($_.Name)"; class = "$($_.PNPClass)"; error_code = $_.ConfigManagerErrorCode; status = "$($_.Status)" } })
    return @{ count = $list.Count; devices = $list }
}

function Get-KemProbeNetwork {
    $ads = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Not Present' } | ForEach-Object {
        @{ name = $_.Name; description = "$($_.InterfaceDescription)"; status = "$($_.Status)"; speed = "$($_.LinkSpeed)"; media = "$($_.MediaType)" } })
    $gw = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object { $_.IPv4DefaultGateway.NextHop }) | Select-Object -First 1
    $ping = $null
    if ($gw) {
        $r = @(Test-Connection -ComputerName $gw -Count 4 -ErrorAction SilentlyContinue)
        $ping = @{ sent = 4; received = $r.Count; avg_ms = $(if ($r.Count) { [math]::Round(($r | Measure-Object ResponseTime -Average).Average, 1) } else { $null }) }
    }
    $dns = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { Resolve-DnsName 'www.microsoft.com' -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $dns = @{ ok = $true; ms = $sw.ElapsedMilliseconds } }
    catch { $dns = @{ ok = $false; ms = $sw.ElapsedMilliseconds; error = "$($_.Exception.Message)" } }
    $apipa = [bool](@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { "$($_.IPAddress)" -like '169.254.*' }).Count)
    $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique).Count
    return @{ adapters = $ads; has_default_gateway = [bool]$gw; gateway_ping = $ping; dns_lookup = $dns; apipa_address = $apipa; dns_server_count = $dnsServers }
}

function Get-KemProbeInternet([string]$Server) {
    $targets = @(@{ label = 'kem_server'; url = $Server.TrimEnd('/') + '/' }, @{ label = 'microsoft'; url = 'https://www.microsoft.com/' },
                 @{ label = 'windows_update'; url = 'https://update.microsoft.com/' })
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $res = @(foreach ($t in $targets) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $r = Invoke-WebRequest -Uri $t.url -Method Head -UseBasicParsing -TimeoutSec 15 -MaximumRedirection 3
            @{ target = $t.label; reachable = $true; status = [int]$r.StatusCode; ms = $sw.ElapsedMilliseconds }
        } catch {
            $resp = $null; try { $resp = $_.Exception.Response } catch { }
            if ($resp) { @{ target = $t.label; reachable = $true; status = [int]$resp.StatusCode; ms = $sw.ElapsedMilliseconds } }
            else { $m = "$($_.Exception.Message)"; @{ target = $t.label; reachable = $false; ms = $sw.ElapsedMilliseconds; error = $m.Substring(0, [Math]::Min(200, $m.Length)) } }
        }
    })
    $proxy = ((& netsh.exe winhttp show proxy 2>&1 | Out-String) -replace '\s+', ' ').Trim()
    return @{ checks = $res; winhttp_proxy = $proxy.Substring(0, [Math]::Min(300, $proxy.Length)) }
}

function Get-KemProbeUpdateHistory {
    $s = New-Object -ComObject Microsoft.Update.Session
    $searcher = $s.CreateUpdateSearcher()
    $n = $searcher.GetTotalHistoryCount()
    $hist = @()
    if ($n -gt 0) {
        $hist = @($searcher.QueryHistory(0, [Math]::Min(15, $n)) | ForEach-Object {
            $title = "$($_.Title)"; if ($title.Length -gt 150) { $title = $title.Substring(0, 150) }
            $res = switch ([int]$_.ResultCode) { 2 { 'Succeeded' } 3 { 'Succeeded with errors' } 4 { 'Failed' } 5 { 'Aborted' } default { "code $($_.ResultCode)" } }
            @{ title = $title; result = $res; hresult = ('0x{0:X8}' -f [int]$_.HResult); at = (Get-KemUnixTime $_.Date) } })
    }
    return @{ total_history = $n; recent = $hist }
}

function Get-KemProbeDefender {
    $m = Get-MpComputerStatus -ErrorAction Stop
    $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 | ForEach-Object {
        @{ threat_id = $_.ThreatID; at = (Get-KemUnixTime $_.InitialDetectionTime); action_success = [bool]$_.ActionSuccess
            resources = (@($_.Resources | Select-Object -First 3 | ForEach-Object { Hide-KemUserPath "$_" }) -join ' | ') } })
    $threats = @(Get-MpThreat -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
        @{ threat_id = $_.ThreatID; name = "$($_.ThreatName)"; severity = $_.SeverityID; active = [bool]$_.IsActive } })
    return @{ antivirus_enabled = [bool]$m.AntivirusEnabled; realtime = [bool]$m.RealTimeProtectionEnabled; tamper_protected = [bool]$m.IsTamperProtected
        running_mode = "$($m.AMRunningMode)"; signature_age_days = $m.AntivirusSignatureAge; quick_scan_age_days = $m.QuickScanAge
        full_scan_age_days = $m.FullScanAge; engine = "$($m.AMEngineVersion)"; detections = $det; threats = $threats }
}

function Invoke-KemInvestigation($P, [string]$Server) {
    $res = @{}; $ok = 0; $ids = @($P.probes)
    foreach ($id in $ids) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $data = switch ("$id") {
                'top_processes'         { Get-KemProbeTopProcesses }
                'memory_pressure'       { Get-KemProbeMemory }
                'disk_space'            { Get-KemProbeDiskSpace }
                'disk_health'           { Get-KemProbeDiskHealth }
                'stopped_auto_services' { Get-KemProbeStoppedServices }
                'system_errors'         { Get-KemEventSummary 'System' 24 }
                'application_errors'    { Get-KemEventSummary 'Application' 24 }
                'app_crashes'           { Get-KemProbeAppCrashes }
                'unexpected_shutdowns'  { Get-KemProbeShutdowns }
                'startup_programs'      { Get-KemProbeStartup }
                'driver_problems'       { Get-KemProbeDrivers }
                'network_status'        { Get-KemProbeNetwork }
                'internet_connectivity' { Get-KemProbeInternet $Server }
                'update_history'        { Get-KemProbeUpdateHistory }
                'defender_details'      { Get-KemProbeDefender }
                default                 { throw "Unknown probe '$id'" }
            }
            $res["$id"] = @{ ok = $true; ms = $sw.ElapsedMilliseconds; data = $data }; $ok++
        } catch {
            $res["$id"] = @{ ok = $false; ms = $sw.ElapsedMilliseconds; error = (Hide-KemUserPath "$($_.Exception.Message)") }
        }
    }
    return @{ status = 'success'; output = "Investigation: collected $ok of $($ids.Count) probe(s)."; data = @{ probes = $res } }
}

$script:KemClassroomTypes = @('request_screenshot', 'lock_input', 'broadcast_capture', 'show_broadcast', 'stop_broadcast', 'show_alert', 'clear_alert')

function Import-KemClassroom {
    # Dot-source the classroom module (screen/input/broadcast) into the CALLER's scope on demand, so its
    # AV-sensitive code is never loaded at agent startup. Returns $true if its functions are available.
    if (Get-Command Set-KemInputLock -ErrorAction SilentlyContinue) { return $true }
    $f = Join-Path $script:KemInstallDir 'kem-classroom.ps1'
    if (-not (Test-Path $f)) { return $false }
    try { . $f } catch { }
    return [bool](Get-Command Set-KemInputLock -ErrorAction SilentlyContinue)
}

function Invoke-KemCommand($Command, [string]$Server) {
    $p = $Command.params
    if ($Command.type -in $script:KemClassroomTypes) {
        # Load the classroom module into this scope; if AV blocks it, fail just this command, not the agent.
        $mod = Join-Path $script:KemInstallDir 'kem-classroom.ps1'
        if (Test-Path $mod) { try { . $mod } catch { } }
        if (-not (Get-Command Set-KemInputLock -ErrorAction SilentlyContinue)) {
            return @{ status = 'failed'; output = 'Classroom features (screen view, input lock, broadcast, alert) could not load on this station - most likely blocked by antivirus without a code-signed agent. Core management is unaffected.' }
        }
    }
    switch ($Command.type) {
        'block_internet'     { return @{ status = 'success'; output = (Enable-KemIsolation $Server ([bool]$p.allow_lan)) } }
        'unblock_internet'   { return @{ status = 'success'; output = (Disable-KemIsolation) } }
        'install_software'   { return Install-KemSoftware $p }
        'uninstall_software' { return Uninstall-KemSoftware $p }
        'run_script'         { return Invoke-KemScript $p "$($Command.id)" }
        'defender_scan'      { return Start-KemDefenderScan $p }
        'create_baseline'    { return @{ status = 'success'; output = (New-KemBaseline) } }
        'scan_updates'       { return Invoke-KemUpdateScan }
        'install_updates'    { return Install-KemUpdates $p }
        'set_web_filter'     { return @{ status = 'success'; output = (Set-KemWebFilter $p) } }
        'usb_storage'        { return @{ status = 'success'; output = (Set-KemUsbStorage "$($p.mode)") } }
        'distribute_file'    { return Copy-KemDistributedFile $p }
        'set_app_policy'     { return Set-KemAppPolicy $p }
        'launch_app'         { return @{ status = 'success'; output = (Launch-KemApp $p) } }
        'list_processes'     { return Get-KemProcessList }
        'kill_process'       { return @{ status = 'success'; output = (Stop-KemProcess $p) } }
        'list_services'      { return Get-KemServiceList }
        'service_action'     { return @{ status = 'success'; output = (Invoke-KemServiceAction $p) } }
        'send_message'       { return @{ status = 'success'; output = (Send-KemUserMessage $p) } }
        'lock_session'       { return @{ status = 'success'; output = (Invoke-KemSessionAction $p) } }
        'set_local_admin_password' { return Set-KemLocalAdminPassword $p }
        'set_uplink'             { return Set-KemUplink $p }
        'become_teacher_station' { return Enable-KemTeacherStation $p $Server }
        'stop_teacher_station'   { return Disable-KemTeacherStation }
        'request_screenshot'     { return Send-KemScreenshot $Server }
        'lock_input'             { return Set-KemInputLock $p }
        'broadcast_capture'      { return Set-KemBroadcastSource $p }
        'show_broadcast'         { return Show-KemBroadcast $p }
        'stop_broadcast'         { return Stop-KemBroadcast }
        'show_alert'             { return Show-KemAlert $p }
        'clear_alert'            { return Clear-KemAlert }
        'security_scan'          { return Send-KemSecurity $Server }
        'collect_keys'           { return Send-KemLicenses $Server }
        'update_software'        { return Update-KemSoftware $p }
        'investigate'            { return Invoke-KemInvestigation $p $Server }
        default              { return @{ status = 'failed'; output = "Unsupported command type '$($Command.type)' for this agent version." } }
    }
}
