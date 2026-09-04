# Generates assets\otp.ico (round dark badge with "OTP") - same look as the widget icon.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$out = Join-Path $PSScriptRoot 'assets\otp.ico'
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null

function New-BadgePng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
    $g.Clear([System.Drawing.Color]::Transparent)
    $pad = [Math]::Max(1, $size * 0.03)
    $rect = New-Object System.Drawing.RectangleF $pad, $pad, ($size - 2*$pad), ($size - 2*$pad)
    $fill = New-Object System.Drawing.SolidBrush ([System.Drawing.ColorTranslator]::FromHtml('#1F2937'))
    $pen  = New-Object System.Drawing.Pen ([System.Drawing.ColorTranslator]::FromHtml('#4B5563')), ([Math]::Max(1, $size * 0.04))
    $g.FillEllipse($fill, $rect); $g.DrawEllipse($pen, $rect)
    $font = New-Object System.Drawing.Font('Segoe UI', [single]($size * 0.30), [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $fmt = New-Object System.Drawing.StringFormat; $fmt.Alignment = 'Center'; $fmt.LineAlignment = 'Center'
    $g.DrawString('OTP', $font, [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF 0, ($size*0.02), $size, $size), $fmt)
    $g.Dispose()
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = @{}
foreach ($s in $sizes) { $images[$s] = New-BadgePng $s }

# ICO container: header + directory entries + PNG payloads
$bw = New-Object IO.BinaryWriter ([IO.File]::Create($out))
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($s in $sizes) {
    $data = $images[$s]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$data.Length); $bw.Write([uint32]$offset)
    $offset += $data.Length
}
foreach ($s in $sizes) { $bw.Write($images[$s]) }
$bw.Close()
Write-Host "Icon written: $out"
