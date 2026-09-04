# OtpWidget - hover-to-expand desktop TOTP widget (PowerShell + WPF, no install needed)
# https://github.com/  (see README.md)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# script dir (works both as .ps1 and when compiled to .exe with ps2exe)
if ($MyInvocation.MyCommand.Path) { $script:Dir = Split-Path -Parent $MyInvocation.MyCommand.Path }
else { $script:Dir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
$script:SecretsJson = Join-Path $script:Dir 'secrets.json'
$script:SecretsTxt  = Join-Path $script:Dir 'secrets.txt'
$script:StatePath   = Join-Path $script:Dir 'state.json'
$script:LibDir      = Join-Path $script:Dir 'lib'
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
    if (-not $name) { $name = 'Account' }
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
    if (-not $a) { return "Not a valid otpauth://totp link" }
    $norm = ($a.secret.ToUpper() -replace '[^A-Z2-7]', '')
    foreach ($ex in $script:Accounts) {
        if ((($ex.secret).ToUpper() -replace '[^A-Z2-7]', '') -eq $norm) { return "Already added: $($ex.name)" }
    }
    Add-Content -Path $script:SecretsTxt -Value $Uri.Trim() -Encoding UTF8
    Build-Rows
    return "Added: $($a.name)"
}

function Ensure-ZXing {
    if ($script:ZXingLoaded) { return $true }
    $dll = Join-Path $script:LibDir 'zxing.dll'
    if (-not (Test-Path $dll)) {
        try {
            Show-Status 'Downloading QR library (ZXing.Net)...'
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
            Show-Status "QR library download failed: $($_.Exception.Message)"
            return $false
        }
    }
    try {
        Add-Type -AssemblyName System.Drawing, System.Windows.Forms
        Add-Type -Path $dll
        $script:ZXingLoaded = $true
        return $true
    } catch {
        Show-Status "Could not load zxing.dll: $($_.Exception.Message)"
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
        if ($Texts.Count -eq 0) { return 'No QR code found' }
        return 'QR found, but it is not an OTP (otpauth://totp) code'
    }
    $msgs = @()
    foreach ($u in $otp) { $msgs += (Add-AccountFromUri $u) }
    return ($msgs -join ' | ')
}

function Scan-QrOnScreen {
    param($HideWindows = @())
    if (-not (Ensure-ZXing)) { return 'QR library unavailable' }
    $saved = @{}
    foreach ($w in $HideWindows) { $saved[$w] = $w.Opacity; $w.Opacity = 0 }
    $script:Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
    Start-Sleep -Milliseconds 250
    try { $bmp = Capture-Screen } finally { foreach ($w in $HideWindows) { $w.Opacity = $saved[$w] } }
    try { $texts = Decode-QrTexts $bmp } finally { $bmp.Dispose() }
    return (Import-QrTexts $texts)
}

function Scan-QrFromClipboard {
    if (-not (Ensure-ZXing)) { return 'QR library unavailable' }
    if (-not [System.Windows.Forms.Clipboard]::ContainsImage()) { return 'No image in clipboard' }
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

# position
$wa = [System.Windows.SystemParameters]::WorkArea
$script:Window.Left = $wa.Right - 320
$script:Window.Top  = $wa.Top + 20
if (Test-Path $script:StatePath) {
    try {
        $st = Get-Content $script:StatePath -Raw | ConvertFrom-Json
        if ($st.left -ne $null) { $script:Window.Left = [double]$st.left }
        if ($st.top  -ne $null) { $script:Window.Top  = [double]$st.top }
    } catch { }
}
function Save-State {
    @{ left = $script:Window.Left; top = $script:Window.Top } | ConvertTo-Json | Set-Content $script:StatePath -Encoding UTF8
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
    if (-not $script:Root.IsMouseOver) { $script:Panel.Visibility = 'Collapsed' }
})
function Show-Status([string]$msg) {
    $script:Status.Text = $msg
    $script:Status.Visibility = 'Visible'
    $script:Panel.Visibility = 'Visible'
    Update-Codes
    $script:StatusTimer.Stop(); $script:StatusTimer.Start()
}

function Build-Rows {
    $script:Items.Children.Clear()
    $script:Rows = @()
    $script:Accounts = Load-Accounts
    if ($script:Accounts.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = "No accounts yet.`nRight-click the icon:`n - Scan QR on screen`n - Add account (paste link / key)"
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
            $nameTb.Text = 'Copied!'; $nameTb.Foreground = '#34D399'
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
        Title="OtpWidget - Add account" Width="440" SizeToContent="Height" ResizeMode="NoResize"
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
    <TextBlock Text="1) Easiest: show the QR code on screen, then" Foreground="#D1D5DB"/>
    <StackPanel Orientation="Horizontal" Margin="0,8,0,14">
      <Button Name="BtnScan" Content="Scan QR on screen" FontWeight="Bold" Background="#2563EB"/>
      <Button Name="BtnClip" Content="QR from clipboard image"/>
    </StackPanel>
    <TextBlock Text="2) Or paste an otpauth:// link or the secret key" Foreground="#D1D5DB"/>
    <TextBox Name="Input" Height="56" TextWrapping="Wrap" AcceptsReturn="True" Margin="0,6,0,8"/>
    <TextBlock Text="Name (only needed when pasting a bare secret key)" Foreground="#9CA3AF" FontSize="11"/>
    <TextBox Name="NameBox" Margin="0,4,0,8"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button Name="BtnAdd" Content="Add"/>
      <Button Name="BtnClose" Content="Close" Margin="0"/>
    </StackPanel>
    <TextBlock Name="DStatus" Foreground="#FBBF24" Margin="0,10,0,0" TextWrapping="Wrap"/>
  </StackPanel>
</Window>
"@
    $dlg = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $dx))
    $script:Dlg = $dlg
    $script:DStatus = $dlg.FindName('DStatus')
    $input = $dlg.FindName('Input'); $nameBox = $dlg.FindName('NameBox')

    $dlg.FindName('BtnScan').Add_Click({
        $script:DStatus.Text = 'Scanning screen...'
        $script:DStatus.Text = Scan-QrOnScreen -HideWindows @($script:Dlg, $script:Window)
    })
    $dlg.FindName('BtnClip').Add_Click({ $script:DStatus.Text = Scan-QrFromClipboard })
    $dlg.FindName('BtnAdd').Add_Click({
        $txt = $input.Text.Trim()
        if (-not $txt) { $script:DStatus.Text = 'Paste a link or a secret key first'; return }
        $msgs = @()
        $lines = @($txt -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $uris = @($lines | Where-Object { $_ -like 'otpauth://*' })
        if ($uris.Count -gt 0) {
            foreach ($u in $uris) { $msgs += (Add-AccountFromUri $u) }
        } else {
            $secret = ($txt.ToUpper() -replace '[^A-Z2-7]', '')
            if ($secret.Length -lt 8) { $script:DStatus.Text = 'That does not look like a Base32 secret key'; return }
            $n = $nameBox.Text.Trim(); if (-not $n) { $n = 'Account' }
            $msgs += (Add-AccountFromUri (New-OtpUri -Name $n -Secret $secret))
        }
        $script:DStatus.Text = ($msgs -join ' | ')
        if ($script:DStatus.Text -like 'Added:*') { $input.Text = ''; $nameBox.Text = '' }
    })
    $dlg.FindName('BtnClose').Add_Click({ $script:Dlg.Close() })
    $dlg.ShowDialog() | Out-Null
}

# hover expand / collapse
$script:Collapse = New-Object System.Windows.Threading.DispatcherTimer
$script:Collapse.Interval = [TimeSpan]::FromMilliseconds(450)
$script:Collapse.Add_Tick({
    $script:Collapse.Stop()
    if ($script:Status.Visibility -ne 'Visible') { $script:Panel.Visibility = 'Collapsed' }
})

$script:Root.Add_MouseEnter({
    $script:Collapse.Stop()
    if ($script:Panel.Visibility -ne 'Visible') { Update-Codes; $script:Panel.Visibility = 'Visible' }
})
$script:Root.Add_MouseLeave({ $script:Collapse.Start() })

# drag
$script:Icon.Add_MouseLeftButtonDown({
    try { $script:Window.DragMove() } catch { }
    Save-State
})

# ---------- Start with Windows (shortcut in the user's Startup folder) ----------
$script:StartupLnk = Join-Path ([Environment]::GetFolderPath('Startup')) 'OtpWidget.lnk'
function Test-Startup { return (Test-Path $script:StartupLnk) }
function Set-Startup([bool]$on) {
    if (-not $on) { Remove-Item $script:StartupLnk -ErrorAction SilentlyContinue; return 'Start with Windows: off' }
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($script:StartupLnk)
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ((Split-Path -Leaf $exe) -ieq 'powershell.exe') {
        # running as script: launch via the vbs (no console window)
        $lnk.TargetPath = Join-Path $env:WINDIR 'System32\wscript.exe'
        $lnk.Arguments  = '"' + (Join-Path $script:Dir 'OtpWidget.vbs') + '"'
    } else {
        $lnk.TargetPath = $exe
        $lnk.Arguments  = ''
    }
    $lnk.WorkingDirectory = $script:Dir
    $lnk.Description = 'OtpWidget'
    $lnk.Save()
    return 'Start with Windows: on'
}

# context menu
$menu = New-Object System.Windows.Controls.ContextMenu
# NOTE: PowerShell variables are case-insensitive - do not name anything here $items (would clobber $script:Items)
$menuDefs = @(
    @{ h = 'Scan QR on screen';     a = { Show-Status (Scan-QrOnScreen -HideWindows @($script:Window)) } },
    @{ h = 'Add account...';        a = { Show-AddDialog } },
    @{ h = 'Reload accounts';       a = { Build-Rows; Show-Status "Reloaded ($($script:Accounts.Count) accounts)" } },
    @{ h = 'Open secrets folder';   a = { Start-Process explorer.exe $script:Dir } },
    'sep',
    @{ h = 'Start with Windows';    check = $true; a = { Show-Status (Set-Startup $this.IsChecked) } },
    'sep',
    @{ h = 'Exit';                  a = { $script:Window.Close() } }
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
$script:Window.ShowDialog() | Out-Null
