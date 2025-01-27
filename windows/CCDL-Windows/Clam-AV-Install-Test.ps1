# Download and install ClamAV
$clamavInstallerPath = "$env:TEMP\clamav-win-x64.msi"
Write-Host "Downloading ClamAV installer..."

$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile("https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.msi", $clamavInstallerPath)

Write-Host "Installing ClamAV..."
Start-Process -FilePath $clamavInstallerPath -ArgumentList "/quiet /norestart" -Wait

# Configure ClamAV for regular scans
Write-Host "Scheduling ClamAV scans..."
$clamAVConfigPath = "C:\Program Files\ClamAV\clamd.conf"
Set-Content -Path $clamAVConfigPath -Value 'LogFile "C:\Program Files\ClamAV\clamd.log"'
schtasks /create /sc daily /tn "ClamAV Scan" /tr "C:\Program Files\ClamAV\clamscan.exe -r C:\" /st 02:00

# Verify installation
if (-Not (Test-Path "C:\Program Files\ClamAV\clamscan.exe")) {
    Write-Host "ClamAV installation failed."
    exit 1
}

# Ensure the log file path is valid
if (-Not (Test-Path "C:\Program Files\ClamAV\clamd.log")) {
    New-Item -ItemType File -Path "C:\Program Files\ClamAV\clamd.log"
}