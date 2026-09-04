# Builds dist\OtpWidget.exe from OtpWidget.ps1 using ps2exe (downloaded from PowerShell Gallery if not installed).
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null

if (-not (Get-Command Invoke-ps2exe -ErrorAction SilentlyContinue)) {
    $tools = Join-Path $root 'tools\ps2exe'
    if (-not (Test-Path (Join-Path $tools 'ps2exe.psd1'))) {
        Write-Host 'Downloading ps2exe from PowerShell Gallery...'
        New-Item -ItemType Directory -Force $tools | Out-Null
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $zip = Join-Path $env:TEMP 'ps2exe.zip'
        Invoke-WebRequest 'https://www.powershellgallery.com/api/v2/package/ps2exe' -OutFile $zip -UseBasicParsing
        Expand-Archive $zip $tools -Force
        Remove-Item $zip
    }
    Import-Module (Join-Path $tools 'ps2exe.psd1') -Force
}

$out = Join-Path $dist 'OtpWidget.exe'
Invoke-ps2exe -inputFile (Join-Path $root 'OtpWidget.ps1') -outputFile $out `
    -noConsole -STA -title 'OtpWidget' -product 'OtpWidget' -description 'Desktop TOTP widget' `
    -version '1.0.0.0' -copyright 'MIT License'

Copy-Item (Join-Path $root 'secrets.example.txt') (Join-Path $dist 'secrets.example.txt') -Force
Copy-Item (Join-Path $root 'README.md') (Join-Path $dist 'README.md') -Force
Write-Host "Built: $out"
