# OtpWidget - hover-to-expand desktop TOTP widget (PowerShell + WPF, no install needed)
# https://github.com/  (see README.md)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# script dir (works both as .ps1 and when compiled to .exe with ps2exe)
if ($MyInvocation.MyCommand.Path) { $script:Dir = Split-Path -Parent $MyInvocation.MyCommand.Path }
else { $script:Dir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
# All user data lives in %APPDATA%\OtpWidget so every copy of the widget (exe, script, unzipped
# folder) sees the same accounts. Files found next to the executable are migrated once.
$script:DataDir     = Join-Path $env:APPDATA 'OtpWidget'
New-Item -ItemType Directory -Force $script:DataDir | Out-Null
foreach ($f in 'secrets.txt', 'secrets.json', 'state.json') {
    $old = Join-Path $script:Dir $f; $new = Join-Path $script:DataDir $f
    if ((Test-Path $old) -and -not (Test-Path $new)) { Copy-Item $old $new }
}
$script:SecretsJson = Join-Path $script:DataDir 'secrets.json'
$script:SecretsTxt  = Join-Path $script:DataDir 'secrets.txt'
$script:StatePath   = Join-Path $script:DataDir 'state.json'
$script:LibDir      = Join-Path $script:DataDir 'lib'

# startup log (small, for diagnosing "it did not start" reports)
$script:LogPath = Join-Path $script:DataDir 'startup.log'
function Write-Log([string]$msg) {
    try {
        $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $msg
        Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
        if ((Get-Item $script:LogPath).Length -gt 200KB) { Get-Content $script:LogPath -Tail 200 | Set-Content $script:LogPath -Encoding UTF8 }
    } catch { }
}
Write-Log ("start  exe=" + [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName + "  dir=" + $script:Dir)

# single instance: a second launch just exits (the first one keeps running)
$script:Mutex = New-Object System.Threading.Mutex($false, 'Local\OtpWidget-single-instance')
if (-not $script:Mutex.WaitOne(0, $false)) { Write-Log 'exit: another instance is already running'; exit }

# WPF hardware rendering makes some graphics drivers (seen with Intel) reserve ~1 GB per window.
# The widget is tiny, so software rendering is more than enough and keeps memory near 100 MB.
[System.Windows.Media.RenderOptions]::ProcessRenderMode = [System.Windows.Interop.RenderMode]::SoftwareOnly
$script:ZXingUrl    = 'https://www.nuget.org/api/v2/package/ZXing.Net/0.16.9'
$script:ZXingLoaded = $false
$script:Accounts    = @()

# ---------- TOTP ----------
function ConvertFrom-Base32 {
    param([string]$s)
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $s = ($s.ToUpper() -replace '[^A-Z2-7]', '')
    $bits = 0; $value = 0
    $out = New-Object System.Collections.Generic.List[byte]
    foreach ($c in $s.ToCharArray()) {
        $value = (($value -shl 5) -bor $alphabet.IndexOf($c)) -band 0xFFFFFF
        $bits += 5
        if ($bits -ge 8) {
            $bits -= 8
            $out.Add([byte](($value -shr $bits) -band 0xFF))
        }
    }
    return ,$out.ToArray()
}

function Get-Totp {
    param([byte[]]$Key, [int]$Digits = 6, [int]$Period = 30)
    $counter = [long][math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / $Period)
    $bytes = [BitConverter]::GetBytes($counter)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1 (,$Key)
    $hash = $hmac.ComputeHash($bytes)
    $hmac.Dispose()
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $code = (([int]$hash[$offset] -band 0x7F) -shl 24) -bor ([int]$hash[$offset + 1] -shl 16) -bor ([int]$hash[$offset + 2] -shl 8) -bor [int]$hash[$offset + 3]
    return ($code % [int][math]::Pow(10, $Digits)).ToString().PadLeft($Digits, '0')
}

function Parse-OtpUri {
    param([string]$uri)
    if ($uri -notmatch '^otpauth://totp/([^?]*)\?(.*)$') { return $null }
    $label = [Uri]::UnescapeDataString($Matches[1]).Trim()
    $q = @{}
    foreach ($kv in ($Matches[2] -split '&')) {
        $p = $kv -split '=', 2
        if ($p.Count -eq 2) { $q[$p[0].ToLower()] = [Uri]::UnescapeDataString($p[1]) }
    }
    if (-not $q['secret']) { return $null }
    $label = $label.TrimEnd(':').Trim()
    $name = $label
    if ($q['issuer']) {
        if (-not $label) { $name = $q['issuer'] }
        elseif ($label -notmatch ':' -and $label -ne $q['issuer']) { $name = "$($q['issuer']): $label" }
    }
    if (-not $name) { $name = '계정' }
    $digits = 6; if ($q['digits']) { $digits = [int]$q['digits'] }
    $period = 30; if ($q['period']) { $period = [int]$q['period'] }
    return @{ name = $name; secret = $q['secret']; digits = $digits; period = $period; uri = $uri }
}

function New-OtpUri {
    param([string]$Name, [string]$Secret)
    $secret = ($Secret.ToUpper() -replace '[^A-Z2-7]', '')
    $label = [Uri]::EscapeDataString($Name)
    return "otpauth://totp/${label}?secret=${secret}&issuer=${label}"
}

function Load-Accounts {
    $list = @()
    if (Test-Path $script:SecretsJson) {
        try {
            $json = Get-Content $script:SecretsJson -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($e in $json) {
                if ($e.uri) { $a = Parse-OtpUri $e.uri; if ($a) { $list += $a } }
                elseif ($e.secret) {
                    $d = 6; if ($e.digits) { $d = [int]$e.digits }
                    $p = 30; if ($e.period) { $p = [int]$e.period }
                    $list += @{ name = [string]$e.name; secret = [string]$e.secret; digits = $d; period = $p }
                }
            }
        } catch { }
    }
    if (Test-Path $script:SecretsTxt) {
        foreach ($line in (Get-Content $script:SecretsTxt -Encoding UTF8)) {
            $line = $line.Trim()
            if ($line -like 'otpauth://*') { $a = Parse-OtpUri $line; if ($a) { $list += $a } }
        }
    }
    foreach ($a in $list) { $a.key = ConvertFrom-Base32 $a.secret }
    return ,$list
}

# ---------- Adding accounts ----------
function Add-AccountFromUri {
    param([string]$Uri)
    $a = Parse-OtpUri $Uri
    if (-not $a) { return "올바른 otpauth://totp 링크가 아닙니다" }
    $norm = ($a.secret.ToUpper() -replace '[^A-Z2-7]', '')
    foreach ($ex in $script:Accounts) {
        if ((($ex.secret).ToUpper() -replace '[^A-Z2-7]', '') -eq $norm) { return "이미 등록됨: $($ex.name)" }
    }
    Add-Content -Path $script:SecretsTxt -Value $Uri.Trim() -Encoding UTF8
    Build-Rows
    return "추가됨: $($a.name)"
}

# Import every otpauth://totp/... link found anywhere in a text (backup exports, JSON, pasted lines...)
function Import-OtpText {
    param([string]$Text)
    $uris = @([regex]::Matches($Text, 'otpauth://totp/[^\s"''<>]+') | ForEach-Object { $_.Value } | Select-Object -Unique)
    if ($uris.Count -eq 0) { return 'otpauth://totp 링크를 찾지 못했습니다' }
    $added = 0; $skipped = 0; $bad = 0
    $known = @{}
    foreach ($ex in $script:Accounts) { $known[(($ex.secret).ToUpper() -replace '[^A-Z2-7]', '')] = $true }
    foreach ($u in $uris) {
        $a = Parse-OtpUri $u
        if (-not $a) { $bad++; continue }
        $norm = ($a.secret.ToUpper() -replace '[^A-Z2-7]', '')
        if ($known[$norm]) { $skipped++; continue }
        Add-Content -Path $script:SecretsTxt -Value $u.Trim() -Encoding UTF8
        $known[$norm] = $true; $added++
    }
    if ($added -gt 0) { Build-Rows }
    $msg = "${added}개 계정 가져옴"
    if ($skipped) { $msg += ", ${skipped}개는 이미 등록됨" }
    if ($bad) { $msg += ", ${bad}개는 잘못된 링크" }
    return $msg
}

function Import-BackupFile {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = 'otpauth 링크가 들어 있는 백업/내보내기 파일 선택'
    $dlg.Filter = '백업 파일 (*.txt;*.json;*.csv)|*.txt;*.json;*.csv|모든 파일 (*.*)|*.*'
    if ($dlg.ShowDialog() -ne $true) { return '취소됨' }
    try { $text = Get-Content $dlg.FileName -Raw -Encoding UTF8 } catch { return "파일을 읽을 수 없습니다: $($_.Exception.Message)" }
    return (Import-OtpText $text)
}

function Ensure-ZXing {
    if ($script:ZXingLoaded) { return $true }
    $dll = Join-Path $script:LibDir 'zxing.dll'
    if (-not (Test-Path $dll)) {
        try {
            Show-Status 'QR 라이브러리(ZXing.Net) 다운로드 중...'
            $script:Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
            New-Item -ItemType Directory -Force $script:LibDir | Out-Null
            $tmp = Join-Path $env:TEMP 'zxing_net.nupkg.zip'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $script:ZXingUrl -OutFile $tmp -UseBasicParsing
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead($tmp)
            $entry = $zip.Entries | Where-Object { $_.FullName -eq 'lib/net47/zxing.dll' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dll, $true)
            $zip.Dispose()
            Remove-Item $tmp -ErrorAction SilentlyContinue
            Unblock-File $dll -ErrorAction SilentlyContinue
        } catch {
            Show-Status "QR 라이브러리 다운로드 실패: $($_.Exception.Message)"
            return $false
        }
    }
    try {
        Add-Type -AssemblyName System.Drawing, System.Windows.Forms
        Add-Type -Path $dll
        $script:ZXingLoaded = $true
        return $true
    } catch {
        Show-Status "zxing.dll을 불러올 수 없습니다: $($_.Exception.Message)"
        return $false
    }
}

function Decode-QrTexts {
    param([System.Drawing.Bitmap]$Bitmap)
    $r = New-Object ZXing.BarcodeReader
    $r.AutoRotate = $true
    $r.Options.TryHarder = $true
    $r.Options.PossibleFormats = [ZXing.BarcodeFormat[]]@([ZXing.BarcodeFormat]::QR_CODE)
    $res = $r.DecodeMultiple($Bitmap)
    if (-not $res) { return @() }
    return @($res | ForEach-Object { $_.Text })
}

function Capture-Screen {
    $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
    $g.Dispose()
    return $bmp
}

function Import-QrTexts {
    param([string[]]$Texts)
    $otp = @($Texts | Where-Object { $_ -like 'otpauth://totp/*' })
    if ($otp.Count -eq 0) {
        if ($Texts.Count -eq 0) { return 'QR 코드를 찾지 못했습니다' }
        return 'QR은 찾았지만 OTP(otpauth://totp) 코드가 아닙니다'
    }
    $msgs = @()
    foreach ($u in $otp) { $msgs += (Add-AccountFromUri $u) }
    return ($msgs -join ' | ')
}

function Scan-QrOnScreen {
    param($HideWindows = @())
    if (-not (Ensure-ZXing)) { return 'QR 라이브러리를 사용할 수 없습니다' }
    $saved = @{}
    foreach ($w in $HideWindows) { $saved[$w] = $w.Opacity; $w.Opacity = 0 }
    $script:Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
    Start-Sleep -Milliseconds 250
    try { $bmp = Capture-Screen } finally { foreach ($w in $HideWindows) { $w.Opacity = $saved[$w] } }
    try { $texts = Decode-QrTexts $bmp } finally { $bmp.Dispose() }
    return (Import-QrTexts $texts)
}

function Scan-QrFromClipboard {
    if (-not (Ensure-ZXing)) { return 'QR 라이브러리를 사용할 수 없습니다' }
    if (-not [System.Windows.Forms.Clipboard]::ContainsImage()) { return '클립보드에 이미지가 없습니다' }
    $img = [System.Windows.Forms.Clipboard]::GetImage()
    $bmp = New-Object System.Drawing.Bitmap $img
    try { $texts = Decode-QrTexts $bmp } finally { $bmp.Dispose(); $img.Dispose() }
    return (Import-QrTexts $texts)
}

# ---------- UI ----------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        WindowStyle="None" AllowsTransparency="True" Background="Transparent"
        Topmost="True" ShowInTaskbar="False" ResizeMode="NoResize"
        SizeToContent="WidthAndHeight" Left="0" Top="0">
  <StackPanel Name="Root" Background="#01000000">
    <Border Name="IconBorder" Width="46" Height="46" CornerRadius="23" Background="#1F2937"
            BorderBrush="#4B5563" BorderThickness="1" HorizontalAlignment="Left" Cursor="Hand">
      <Border.Effect><DropShadowEffect BlurRadius="8" ShadowDepth="1" Opacity="0.5"/></Border.Effect>
      <TextBlock Text="OTP" Foreground="#F9FAFB" FontFamily="Segoe UI" FontWeight="Bold" FontSize="13"
                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
    <Border Name="Panel" Visibility="Collapsed" Margin="0,4,0,0" Width="270" CornerRadius="10"
            Background="#1F2937" BorderBrush="#4B5563" BorderThickness="1" Padding="6">
      <Border.Effect><DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.5"/></Border.Effect>
      <StackPanel>
        <StackPanel Name="Items"/>
        <TextBlock Name="Status" Visibility="Collapsed" Foreground="#FBBF24" FontFamily="Segoe UI" FontSize="11"
                   Margin="8,6,8,2" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>
  </StackPanel>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$script:Window = [Windows.Markup.XamlReader]::Load($reader)
$script:Root   = $script:Window.FindName('Root')
$script:Icon   = $script:Window.FindName('IconBorder')
$script:Panel  = $script:Window.FindName('Panel')
$script:Items  = $script:Window.FindName('Items')
$script:Status = $script:Window.FindName('Status')
$script:Rows   = @()

# position: saved spot, or (first run) the top-right of the monitor the mouse is on
$wa = [System.Windows.SystemParameters]::WorkArea
$script:Window.Left = $wa.Right - 320
$script:Window.Top  = $wa.Top + 20
try {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $scr = [System.Windows.Forms.Screen]::FromPoint([System.Windows.Forms.Cursor]::Position)
    $scale = $wa.Width / [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width   # px -> WPF units
    $script:Window.Left = ($scr.WorkingArea.Right * $scale) - 320
    $script:Window.Top  = ($scr.WorkingArea.Top * $scale) + 20
} catch { }
if (Test-Path $script:StatePath) {
    try {
        $st = Get-Content $script:StatePath -Raw | ConvertFrom-Json
        if ($st.left -ne $null -and $st.top -ne $null) {
            # only restore the saved spot if it is on a monitor that exists right now
            # (a laptop undocked from its second screen would otherwise show the widget off-screen)
            $vsL = [System.Windows.SystemParameters]::VirtualScreenLeft; $vsT = [System.Windows.SystemParameters]::VirtualScreenTop
            $vsR = $vsL + [System.Windows.SystemParameters]::VirtualScreenWidth; $vsB = $vsT + [System.Windows.SystemParameters]::VirtualScreenHeight
            $cx = [double]$st.left + 23; $cy = [double]$st.top + 23
            if ($cx -ge $vsL -and $cx -le $vsR -and $cy -ge $vsT -and $cy -le $vsB) {
                $script:Window.Left = [double]$st.left
                $script:Window.Top  = [double]$st.top
            }
        }
    } catch { }
}
function Save-State {
    @{ left = $script:IconLeft; top = $script:IconTop } | ConvertTo-Json | Set-Content $script:StatePath -Encoding UTF8
}

function Format-Code([string]$c) {
    if ($c.Length -eq 6) { return $c.Substring(0,3) + ' ' + $c.Substring(3) }
    if ($c.Length -eq 8) { return $c.Substring(0,4) + ' ' + $c.Substring(4) }
    return $c
}

# status toast inside the panel
$script:StatusTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:StatusTimer.Interval = [TimeSpan]::FromSeconds(4)
$script:StatusTimer.Add_Tick({
    $script:StatusTimer.Stop()
    $script:Status.Visibility = 'Collapsed'
    if (-not $script:Root.IsMouseOver) { Collapse-Panel } else { Expand-Panel }
})
function Show-Status([string]$msg, [int]$seconds = 4) {
    $script:Status.Text = $msg
    $script:Status.Visibility = 'Visible'
    Expand-Panel
    $script:StatusTimer.Stop()
    $script:StatusTimer.Interval = [TimeSpan]::FromSeconds($seconds)
    $script:StatusTimer.Start()
}

function Build-Rows {
    $script:Items.Children.Clear()
    $script:Rows = @()
    $script:Accounts = Load-Accounts
    if ($script:Accounts.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = "등록된 계정이 없습니다.`n아이콘을 우클릭하세요:`n - 화면의 QR 코드 스캔`n - 백업 파일 가져오기`n - 계정 추가 (링크/키 붙여넣기)`n`n계정 파일: %APPDATA%\OtpWidget\secrets.txt"
        $tb.Foreground = '#D1D5DB'; $tb.Margin = '8'; $tb.FontFamily = 'Segoe UI'; $tb.FontSize = 12
        $script:Items.Children.Add($tb) | Out-Null
        return
    }
    foreach ($a in $script:Accounts) {
        $row = New-Object System.Windows.Controls.Border
        $row.CornerRadius = '6'; $row.Padding = '8,6'; $row.Margin = '0,2'
        $row.Background = '#374151'; $row.Cursor = 'Hand'
        $row.Tag = $a

        $grid = New-Object System.Windows.Controls.Grid
        foreach ($i in 1..3) { $rd = New-Object System.Windows.Controls.RowDefinition; $rd.Height = 'Auto'; $grid.RowDefinitions.Add($rd) }

        $name = New-Object System.Windows.Controls.TextBlock
        $name.Text = $a.name; $name.Foreground = '#9CA3AF'; $name.FontSize = 11; $name.FontFamily = 'Segoe UI'
        $name.TextTrimming = 'CharacterEllipsis'
        [System.Windows.Controls.Grid]::SetRow($name, 0)

        $code = New-Object System.Windows.Controls.TextBlock
        $code.Text = '--- ---'; $code.Foreground = '#F9FAFB'; $code.FontSize = 24; $code.FontWeight = 'Bold'
        $code.FontFamily = 'Consolas'; $code.Margin = '0,1,0,3'
        [System.Windows.Controls.Grid]::SetRow($code, 1)

        $track = New-Object System.Windows.Controls.Border
        $track.Height = 3; $track.CornerRadius = '2'; $track.Background = '#4B5563'
        $bar = New-Object System.Windows.Controls.Border
        $bar.Height = 3; $bar.CornerRadius = '2'; $bar.Background = '#34D399'; $bar.HorizontalAlignment = 'Left'
        $track.Child = $bar
        [System.Windows.Controls.Grid]::SetRow($track, 2)

        $grid.Children.Add($name) | Out-Null
        $grid.Children.Add($code) | Out-Null
        $grid.Children.Add($track) | Out-Null
        $row.Child = $grid

        $row.Add_MouseEnter({ $this.Background = '#4B5563' })
        $row.Add_MouseLeave({ $this.Background = '#374151' })
        $row.Add_MouseLeftButtonUp({
            $acct = $this.Tag
            $c = Get-Totp -Key $acct.key -Digits $acct.digits -Period $acct.period
            [System.Windows.Clipboard]::SetText($c)
            $nameTb = $this.Child.Children[0]
            $nameTb.Text = '복사됨!'; $nameTb.Foreground = '#34D399'
            $t = New-Object System.Windows.Threading.DispatcherTimer
            $t.Interval = [TimeSpan]::FromMilliseconds(900)
            $t.Tag = @{ tb = $nameTb; name = $acct.name }
            $t.Add_Tick({ $this.Stop(); $this.Tag.tb.Text = $this.Tag.name; $this.Tag.tb.Foreground = '#9CA3AF' })
            $t.Start()
        })

        $script:Items.Children.Add($row) | Out-Null
        $script:Rows += @{ acct = $a; code = $code; bar = $bar; track = $track }
    }
    Update-Codes
}

function Update-Codes {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($r in $script:Rows) {
        $a = $r.acct
        $r.code.Text = Format-Code (Get-Totp -Key $a.key -Digits $a.digits -Period $a.period)
        $remain = $a.period - ($now % $a.period)
        $w = $r.track.ActualWidth
        if ($w -le 0) { $w = 240 }
        $r.bar.Width = $w * ($remain / $a.period)
        if ($remain -le 5) { $r.bar.Background = '#F87171' } else { $r.bar.Background = '#34D399' }
    }
}

# ---------- Add-account dialog ----------
function Show-AddDialog {
    [xml]$dx = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="OtpWidget - 계정 추가" Width="440" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterScreen" Topmost="True" Background="#1F2937" FontFamily="Segoe UI">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#374151"/>
      <Setter Property="Foreground" Value="#F9FAFB"/>
      <Setter Property="BorderBrush" Value="#4B5563"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#111827"/>
      <Setter Property="Foreground" Value="#F9FAFB"/>
      <Setter Property="BorderBrush" Value="#4B5563"/>
      <Setter Property="Padding" Value="6,4"/>
    </Style>
  </Window.Resources>
  <StackPanel Margin="16">
    <TextBlock Text="1) 가장 쉬움: QR 코드를 화면에 띄운 뒤" Foreground="#D1D5DB"/>
    <StackPanel Orientation="Horizontal" Margin="0,8,0,14">
      <Button Name="BtnScan" Content="화면의 QR 코드 스캔" FontWeight="Bold" Background="#2563EB"/>
      <Button Name="BtnClip" Content="클립보드 이미지에서 QR 읽기"/>
    </StackPanel>
    <TextBlock Text="2) 또는 백업 파일 가져오기 (Authenticator 확장 등에서 내보낸 파일)" Foreground="#D1D5DB"/>
    <StackPanel Orientation="Horizontal" Margin="0,8,0,14">
      <Button Name="BtnFile" Content="백업 파일 가져오기..."/>
    </StackPanel>
    <TextBlock Text="3) 또는 여기에 붙여넣기: otpauth:// 링크(여러 줄 가능) 또는 시크릿 키" Foreground="#D1D5DB"/>
    <TextBox Name="Input" Height="72" TextWrapping="Wrap" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" Margin="0,6,0,8"/>
    <TextBlock Text="이름 (시크릿 키만 붙여넣을 때 필요)" Foreground="#9CA3AF" FontSize="11"/>
    <TextBox Name="NameBox" Margin="0,4,0,8"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button Name="BtnAdd" Content="추가"/>
      <Button Name="BtnClose" Content="닫기" Margin="0"/>
    </StackPanel>
    <TextBlock Name="DStatus" Foreground="#FBBF24" Margin="0,10,0,0" TextWrapping="Wrap"/>
  </StackPanel>
</Window>
"@
    $dlg = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $dx))
    $script:Dlg = $dlg
    $script:DStatus = $dlg.FindName('DStatus')
    # NOTE: $input is a reserved automatic variable in PowerShell - never use it as a control name
    $script:DlgInput = $dlg.FindName('Input'); $script:DlgName = $dlg.FindName('NameBox')

    $dlg.FindName('BtnScan').Add_Click({
        $script:DStatus.Text = '화면 스캔 중...'
        $script:DStatus.Text = Scan-QrOnScreen -HideWindows @($script:Dlg, $script:Window)
    })
    $dlg.FindName('BtnClip').Add_Click({ $script:DStatus.Text = Scan-QrFromClipboard })
    $dlg.FindName('BtnFile').Add_Click({ $script:DStatus.Text = Import-BackupFile })
    $dlg.FindName('BtnAdd').Add_Click({
        $txt = [string]$script:DlgInput.Text
        $txt = $txt.Trim()
        if (-not $txt) { $script:DStatus.Text = '링크나 시크릿 키를 먼저 붙여넣으세요'; return }
        if ($txt -match 'otpauth://totp/') {
            $msg = Import-OtpText $txt
        } else {
            $secret = ($txt.ToUpper() -replace '[^A-Z2-7]', '')
            if ($secret.Length -lt 8) { $script:DStatus.Text = 'Base32 시크릿 키 형식이 아닙니다'; return }
            $n = ([string]$script:DlgName.Text).Trim(); if (-not $n) { $n = '계정' }
            $msg = Add-AccountFromUri (New-OtpUri -Name $n -Secret $secret)
        }
        $script:DStatus.Text = $msg
        if ($msg -like '추가됨:*' -or ($msg -like '*가져옴*' -and $msg -notlike '0개*')) { $script:DlgInput.Text = ''; $script:DlgName.Text = '' }
    })
    $dlg.FindName('BtnClose').Add_Click({ $script:Dlg.Close() })
    $dlg.ShowDialog() | Out-Null
}

# ---------- expand / collapse, keeping the panel on screen ----------
# The icon's own position is kept in IconLeft/IconTop. When the panel opens and there is
# no room to the right (or below), the window is shifted so the panel opens leftwards/upwards.
$script:IconLeft = $script:Window.Left
$script:IconTop  = $script:Window.Top
$script:Expanded = $false

function Get-WorkAreaDip {
    # work area of the monitor under the icon, in WPF units (handles DPI scaling)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $src = [System.Windows.PresentationSource]::FromVisual($script:Window)
        $toDev = $src.CompositionTarget.TransformToDevice
        $fromDev = $src.CompositionTarget.TransformFromDevice
        $px = $toDev.Transform((New-Object System.Windows.Point ($script:IconLeft + 23), ($script:IconTop + 23)))
        $scr = [System.Windows.Forms.Screen]::FromPoint((New-Object System.Drawing.Point ([int]$px.X), ([int]$px.Y)))
        $wa = $scr.WorkingArea
        $tl = $fromDev.Transform((New-Object System.Windows.Point $wa.Left, $wa.Top))
        $br = $fromDev.Transform((New-Object System.Windows.Point $wa.Right, $wa.Bottom))
        return @{ Left = $tl.X; Top = $tl.Y; Right = $br.X; Bottom = $br.Y }
    } catch {
        $wa = [System.Windows.SystemParameters]::WorkArea
        return @{ Left = $wa.Left; Top = $wa.Top; Right = $wa.Right; Bottom = $wa.Bottom }
    }
}

function Expand-Panel {
    Update-Codes
    $script:Panel.Visibility = 'Visible'
    $script:Window.UpdateLayout()
    $w = $script:Window.ActualWidth; $h = $script:Window.ActualHeight
    $wa = Get-WorkAreaDip
    $iconW = $script:Icon.ActualWidth
    if (($script:IconLeft + $w) -gt $wa.Right -and ($script:IconLeft + $iconW - $w) -ge $wa.Left) {
        # open to the left: keep the icon where it is, hang the panel off its right edge
        $script:Icon.HorizontalAlignment = 'Right'
        $script:Window.Left = $script:IconLeft + $iconW - $w
    } else {
        $script:Icon.HorizontalAlignment = 'Left'
        $script:Window.Left = $script:IconLeft
    }
    $top = $script:IconTop
    if (($top + $h) -gt $wa.Bottom) { $top = [Math]::Max($wa.Top, $wa.Bottom - $h) }
    $script:Window.Top = $top
    $script:Expanded = $true
}

function Collapse-Panel {
    $script:Panel.Visibility = 'Collapsed'
    $script:Icon.HorizontalAlignment = 'Left'
    $script:Window.Left = $script:IconLeft
    $script:Window.Top  = $script:IconTop
    $script:Expanded = $false
}

$script:Collapse = New-Object System.Windows.Threading.DispatcherTimer
$script:Collapse.Interval = [TimeSpan]::FromMilliseconds(450)
$script:Collapse.Add_Tick({
    $script:Collapse.Stop()
    if ($script:Status.Visibility -ne 'Visible') { Collapse-Panel }
})

$script:Root.Add_MouseEnter({
    $script:Collapse.Stop()
    if (-not $script:Expanded) { Expand-Panel }
})
$script:Root.Add_MouseLeave({ $script:Collapse.Start() })

# drag (collapse first so the icon is the whole window while dragging)
$script:Icon.Add_MouseLeftButtonDown({
    $script:Collapse.Stop()
    Collapse-Panel
    try { $script:Window.DragMove() } catch { }
    # keep the icon inside the virtual screen
    $vs = [System.Windows.SystemParameters]::VirtualScreenLeft, [System.Windows.SystemParameters]::VirtualScreenTop,
          [System.Windows.SystemParameters]::VirtualScreenWidth, [System.Windows.SystemParameters]::VirtualScreenHeight
    $iconW = $script:Icon.ActualWidth; $iconH = $script:Icon.ActualHeight
    $script:IconLeft = [Math]::Min([Math]::Max($script:Window.Left, $vs[0]), $vs[0] + $vs[2] - $iconW)
    $script:IconTop  = [Math]::Min([Math]::Max($script:Window.Top,  $vs[1]), $vs[1] + $vs[3] - $iconH)
    $script:Window.Left = $script:IconLeft; $script:Window.Top = $script:IconTop
    Save-State
    if ($script:Root.IsMouseOver) { Expand-Panel }
})

# ---------- Start with Windows (HKCU Run registry key; the copy that turned it on is what starts) ----------
$script:RunKey     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$script:RunName    = 'OtpWidget'
$script:StartupLnk = Join-Path ([Environment]::GetFolderPath('Startup')) 'OtpWidget.lnk'   # legacy location
function Get-StartupCommand {
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ((Split-Path -Leaf $exe) -ieq 'powershell.exe') {
        # running as script: launch via the vbs (no console window)
        return '"' + (Join-Path $env:WINDIR 'System32\wscript.exe') + '" "' + (Join-Path $script:Dir 'OtpWidget.vbs') + '"'
    }
    return '"' + $exe + '"'
}
$script:TaskName = 'OtpWidget'
function Test-Startup {
    if (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue) { return $true }
    $v = (Get-ItemProperty -Path $script:RunKey -Name $script:RunName -ErrorAction SilentlyContinue).$script:RunName
    return ([bool]$v -or (Test-Path $script:StartupLnk))
}
function Set-Startup([bool]$on) {
    # clear every older mechanism first (Startup-folder shortcut, Run key) so only one launcher exists
    Remove-Item $script:StartupLnk -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $script:RunKey -Name $script:RunName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (-not $on) { return '윈도우 시작 시 자동 실행: 꺼짐' }
    # preferred: a logon task in Task Scheduler - starts right at logon, before Explorer's startup-app delay
    try {
        $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        if ((Split-Path -Leaf $exe) -ieq 'powershell.exe') {
            $action = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\wscript.exe') -Argument ('"' + (Join-Path $script:Dir 'OtpWidget.vbs') + '"')
        } else {
            $action = New-ScheduledTaskAction -Execute $exe
        }
        $trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 4
        Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Settings $settings -Force -ErrorAction Stop | Out-Null
        return '윈도우 시작 시 자동 실행: 켜짐 (로그인 즉시)'
    } catch {
        # fallback: HKCU Run key (works everywhere, starts a little later)
        New-Item -Path $script:RunKey -Force | Out-Null
        Set-ItemProperty -Path $script:RunKey -Name $script:RunName -Value (Get-StartupCommand)
        return '윈도우 시작 시 자동 실행: 켜짐'
    }
}

# context menu
$menu = New-Object System.Windows.Controls.ContextMenu
# NOTE: PowerShell variables are case-insensitive - do not name anything here $items (would clobber $script:Items)
$menuDefs = @(
    @{ h = '화면의 QR 코드 스캔';        a = { Show-Status (Scan-QrOnScreen -HideWindows @($script:Window)) } },
    @{ h = '계정 추가...';               a = { Show-AddDialog } },
    @{ h = '백업 파일 가져오기...';       a = { Show-Status (Import-BackupFile) } },
    @{ h = '새로고침';                  a = { Build-Rows; Show-Status "새로고침 완료 ($($script:Accounts.Count)개 계정)" } },
    'sep',
    @{ h = '윈도우 시작 시 자동 실행';    check = $true; a = { Show-Status (Set-Startup $this.IsChecked) } },
    'sep',
    @{ h = '종료';                      a = { $script:Window.Close() } }
)
foreach ($def in $menuDefs) {
    if ($def -eq 'sep') { $menu.Items.Add((New-Object System.Windows.Controls.Separator)) | Out-Null; continue }
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = $def.h
    if ($def.check) { $mi.IsCheckable = $true; $script:StartupMenuItem = $mi }
    $mi.Add_Click($def.a)
    $menu.Items.Add($mi) | Out-Null
}
$menu.Add_Opened({ $script:StartupMenuItem.IsChecked = (Test-Startup) })
$script:Icon.ContextMenu = $menu

# tick
$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromSeconds(1)
$script:Timer.Add_Tick({ if ($script:Panel.Visibility -eq 'Visible') { Update-Codes } })
$script:Timer.Start()

Build-Rows

# first run (no accounts yet): open the panel for a few seconds so the tiny icon is not missed
$script:Window.Add_ContentRendered({
    if ($script:Accounts.Count -eq 0) {
        Show-Status 'OtpWidget이 실행되었습니다. 이 아이콘은 항상 화면 위에 떠 있습니다.' 10
    }
})
Write-Log ("ready  accounts=" + $script:Accounts.Count + "  pos=" + [int]$script:Window.Left + "," + [int]$script:Window.Top)
try {
    $script:Window.ShowDialog() | Out-Null
    Write-Log 'exit: closed by user'
} catch {
    Write-Log ('error: ' + $_.Exception.Message)
    throw
}
