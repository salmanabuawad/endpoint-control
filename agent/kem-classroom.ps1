# KEM agent - classroom module (screen view, input lock, broadcast, sticky alert).
# Loaded ON DEMAND by kem-actions.ps1 / kem-agent.ps1 only when one of these features is used, so the
# AV-sensitive code here (screen capture, BlockInput) is never scanned at agent startup and cannot stop
# the core agent from running. On an AV-protected station without a code-signed agent, loading this
# module may be blocked - in which case only these features are unavailable; check-in, inventory and
# policy enforcement continue normally. Windows PowerShell 5.1, runs as SYSTEM. Pure ASCII.

function Send-KemScreenshot([string]$Server, [switch]$Quiet) {
    # Capture the signed-in user's desktop (in their session) and upload a JPEG. A spot-check shows the
    # user a brief "viewed by IT" indicator; broadcast frames (-Quiet) do not, since the user is
    # voluntarily presenting their own screen. Capture runs in the user session, never covertly.
    $cfg = Get-KemConfig
    if (-not $cfg) { return @{ status = 'failed'; output = 'No agent config.' } }
    $out = Join-Path $env:PUBLIC ('kem-screen-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.jpg')
    $indicator = @'
  $f = New-Object System.Windows.Forms.Form
  $f.FormBorderStyle = 'None'; $f.StartPosition = 'Manual'; $f.TopMost = $true; $f.BackColor = 'Black'
  $f.Size = New-Object System.Drawing.Size 320,36; $f.Location = New-Object System.Drawing.Point 20,20
  $f.ShowInTaskbar = $false
  $l = New-Object System.Windows.Forms.Label; $l.Dock = 'Fill'; $l.ForeColor = 'White'
  $l.TextAlign = 'MiddleCenter'; $l.Text = 'Your screen was viewed by IT'; $f.Controls.Add($l)
  $t = New-Object System.Windows.Forms.Timer; $t.Interval = 2500; $t.Add_Tick({ $f.Close() }); $t.Start()
  $f.ShowDialog() | Out-Null
'@
    $cap = @'
try {
  Add-Type -AssemblyName System.Windows.Forms, System.Drawing
  $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $bmp = New-Object System.Drawing.Bitmap $vs.Width, $vs.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($vs.Location, [System.Drawing.Point]::Empty, $vs.Size)
  $g.Dispose()
  $enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
  $prm = New-Object System.Drawing.Imaging.EncoderParameters 1
  $prm.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]55)
  $bmp.Save('OUTPATH', $enc, $prm); $bmp.Dispose()
INDICATOR
} catch { }
'@
    $cap = $cap -replace 'INDICATOR', ($(if ($Quiet) { '' } else { $indicator }))
    $r = Invoke-KemAsUser ($cap -replace 'OUTPATH', ($out -replace '\\', '\\')) -TimeoutSec 30
    if (-not (Test-Path $out)) { return @{ status = 'failed'; output = "Capture failed (no active session?): $($r.output)" } }
    try {
        $bytes = [IO.File]::ReadAllBytes($out)
        $b64 = [Convert]::ToBase64String($bytes)
        Invoke-KemApi -Server $Server -Path '/api/agent/screenshot' -Body @{ image_b64 = $b64; mime = 'image/jpeg' } `
            -Headers (Get-KemAuthHeaders $cfg) -TimeoutSec 60 | Out-Null
        return @{ status = 'success'; output = "Screen captured ($([math]::Round($bytes.Length / 1KB)) KB) and uploaded." }
    } catch {
        return @{ status = 'failed'; output = "Upload failed: $($_.Exception.Message)" }
    } finally {
        Remove-Item $out -Force -ErrorAction SilentlyContinue
    }
}

function Set-KemInputLock($P) {
    # Freeze or release the station's keyboard and mouse. The lock runs inside the user's session and
    # re-asserts itself until the sentinel is cleared.
    $sentinel = Join-Path $env:PUBLIC 'kem-input-lock.flag'
    if ("$($P.mode)" -eq 'unlock') {
        Remove-Item $sentinel -Force -ErrorAction SilentlyContinue
        return @{ status = 'success'; output = 'Keyboard and mouse unlocked.' }
    }
    Set-Content -Path $sentinel -Value 'locked' -Force -ErrorAction SilentlyContinue
    $watcher = @'
Add-Type -Namespace Kem -Name Input -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool BlockInput(bool fBlock);'
$flag = 'SENTINEL'
$n = 0
while ((Test-Path $flag) -and $n -lt 7200) { [void][Kem.Input]::BlockInput($true); Start-Sleep -Milliseconds 400; $n++ }
[void][Kem.Input]::BlockInput($false)
'@
    Invoke-KemAsUser ($watcher -replace 'SENTINEL', ($sentinel -replace '\\', '\\')) -NoWait
    return @{ status = 'success'; output = 'Keyboard and mouse locked (until unlocked; Ctrl+Alt+Del can still interrupt).' }
}

function Set-KemBroadcastSource($P) {
    # The source (teacher) station: turn periodic screen capture on/off. The agent main loop does the
    # actual capturing on each tick while this is on.
    if ([bool]$P.on) {
        Set-KemState 'broadcast_src' (@{ on = $true; interval = [int]$P.interval })
        return @{ status = 'success'; output = "Broadcasting this screen (every $([int]$P.interval)s)." }
    }
    Set-KemState 'broadcast_src' $null
    return @{ status = 'success'; output = 'Stopped broadcasting this screen.' }
}

function Show-KemBroadcast($P) {
    # A viewer (student) station: mark that a broadcast should be shown full-screen, and (optionally)
    # lock input so the class watches. The main loop pulls frames and drives the viewer window.
    Set-KemState 'broadcast_view' (@{ source = "$($P.source)"; lock = [bool]$P.lock_input })
    if ([bool]$P.lock_input) { Set-KemInputLock @{ mode = 'lock' } | Out-Null }
    return @{ status = 'success'; output = "Showing broadcast from $($P.source)." }
}

function Stop-KemBroadcast {
    Set-KemState 'broadcast_view' $null
    Set-KemInputLock @{ mode = 'unlock' } | Out-Null
    Remove-Item (Join-Path $env:PUBLIC 'kem-broadcast.flag') -Force -ErrorAction SilentlyContinue
    return @{ status = 'success'; output = 'Broadcast viewer closed.' }
}

function Show-KemAlert($P) {
    # A sticky full-width banner shown in the signed-in user's session until a clear_alert arrives.
    $flag = Join-Path $env:PUBLIC 'kem-alert.flag'
    Set-Content -Path $flag -Value 'on' -Force -ErrorAction SilentlyContinue
    $tpl = @'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$flag = FLAGPATH
$f = New-Object System.Windows.Forms.Form
$f.FormBorderStyle = 'None'; $f.StartPosition = 'Manual'; $f.TopMost = $true; $f.ShowInTaskbar = $false
$f.BackColor = [System.Drawing.Color]::FromArgb(185, 28, 28)
$scr = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$f.Width = $scr.Width; $f.Height = 96; $f.Location = New-Object System.Drawing.Point 0, 0
$ti = New-Object System.Windows.Forms.Label; $ti.Dock = 'Top'; $ti.Height = 30; $ti.ForeColor = 'White'
$ti.TextAlign = 'MiddleCenter'; $ti.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold); $ti.Text = TITLE
$bo = New-Object System.Windows.Forms.Label; $bo.Dock = 'Fill'; $bo.ForeColor = 'White'
$bo.TextAlign = 'MiddleCenter'; $bo.Font = New-Object System.Drawing.Font('Segoe UI', 13); $bo.Text = BODY
$f.Controls.Add($bo); $f.Controls.Add($ti)
$tm = New-Object System.Windows.Forms.Timer; $tm.Interval = 1000; $tm.Add_Tick({ if (-not (Test-Path $flag)) { $f.Close() } }); $tm.Start()
$f.Add_FormClosing({ param($s, $e) if (Test-Path $flag) { $e.Cancel = $true } })
$f.ShowDialog() | Out-Null
'@
    $script = $tpl -replace 'FLAGPATH', (ConvertTo-KemPsLiteral $flag) `
        -replace 'TITLE', (ConvertTo-KemPsLiteral "$($P.title)") `
        -replace 'BODY', (ConvertTo-KemPsLiteral "$($P.text)")
    Invoke-KemAsUser $script -NoWait
    return @{ status = 'success'; output = 'Alert shown on the station.' }
}

function Clear-KemAlert {
    Remove-Item (Join-Path $env:PUBLIC 'kem-alert.flag') -Force -ErrorAction SilentlyContinue
    return @{ status = 'success'; output = 'Alert cleared.' }
}

function Invoke-KemBroadcastSource([string]$Server) {
    # Called each main-loop tick while broadcasting: capture+upload a frame when due.
    $s = Get-KemState 'broadcast_src'
    if (-not $s -or -not $s.on) { return }
    $iv = [int]$s.interval; if ($iv -lt 1) { $iv = 2 }
    if ($script:KemNextBroadcast -and (Get-Date) -lt $script:KemNextBroadcast) { return }
    $script:KemNextBroadcast = (Get-Date).AddSeconds($iv)
    try { Send-KemScreenshot $Server -Quiet | Out-Null } catch { }
}

function Sync-KemBroadcastView([string]$Server, $Config) {
    # Called each tick on a viewer station: pull the latest broadcast frame and keep a full-screen viewer up.
    $v = Get-KemState 'broadcast_view'
    $img = Join-Path $env:PUBLIC 'kem-broadcast.jpg'
    $flag = Join-Path $env:PUBLIC 'kem-broadcast.flag'
    if (-not $v) { return }
    $bytes = [Text.Encoding]::UTF8.GetBytes('{}')
    $key = Get-KemSha256Hex ([string]$Config.secret)
    $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); $nonce = [guid]::NewGuid().ToString('N')
    $canonical = "$ts`n$nonce`nPOST`n/api/agent/broadcast-frame`n$(Get-KemSha256HexBytes $bytes)"
    $h = @{ 'X-Device-Id' = $Config.device_id; 'X-KEM-Ts' = "$ts"; 'X-KEM-Nonce' = $nonce; 'X-KEM-Sig' = (Get-KemHmacHex $key $canonical) }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $resp = Invoke-WebRequest -Uri ($Server.TrimEnd('/') + '/api/agent/broadcast-frame') -Method Post -Body $bytes `
            -ContentType 'application/json; charset=utf-8' -Headers $h -TimeoutSec 20 -UseBasicParsing
        if ($resp.StatusCode -eq 200 -and $resp.Content.Length -gt 0) { [IO.File]::WriteAllBytes($img, $resp.Content) }
    } catch { }
    if (-not (Test-Path $flag)) {
        Set-Content -Path $flag -Value 'on' -Force -ErrorAction SilentlyContinue
        $viewer = @'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$img = 'IMGPATH'; $flag = 'FLAGPATH'
$f = New-Object System.Windows.Forms.Form
$f.FormBorderStyle = 'None'; $f.WindowState = 'Maximized'; $f.TopMost = $true; $f.BackColor = 'Black'; $f.ShowInTaskbar = $false
$pb = New-Object System.Windows.Forms.PictureBox; $pb.Dock = 'Fill'; $pb.SizeMode = 'Zoom'; $f.Controls.Add($pb)
$cap = New-Object System.Windows.Forms.Label; $cap.Dock = 'Top'; $cap.Height = 26; $cap.ForeColor = 'White'
$cap.TextAlign = 'MiddleCenter'; $cap.Text = 'Your teacher is presenting'; $f.Controls.Add($cap)
$t = New-Object System.Windows.Forms.Timer; $t.Interval = 800
$t.Add_Tick({ if (-not (Test-Path $flag)) { $f.Close(); return }; try { if (Test-Path $img) { $b = [IO.File]::ReadAllBytes($img); $ms = New-Object IO.MemoryStream (,$b); $pb.Image = [System.Drawing.Image]::FromStream($ms) } } catch { } })
$t.Start(); $f.ShowDialog() | Out-Null
'@
        $viewer = $viewer -replace 'IMGPATH', ($img -replace '\\', '\\') -replace 'FLAGPATH', ($flag -replace '\\', '\\')
        try { Invoke-KemAsUser $viewer -NoWait } catch { }
    }
}
