# PowerShell script to install and configure Splunk Universal Forwarder on Windows Server 2019
# This was originally written in Bash, then translated to Powershell. An AI was (obviously) used heavily in this process. I don't know a lick of Powershell, so 
# this is 70% AI, 25% forums, and 5% me pushing buttons until it worked.
# this is 55% AI (Bash to Powershell conversion), 25% forums, and 20% me pushing buttons until it worked.
#
# IMPORTANT NOTE: Because of how my environment is set up, I needed to set custom server names in this config, else all my Windows servers would show the sane hostname in Splunk.
#   For this script, the hostname is set to "Windows-AD" by default. To change this, go to lines 33 and 65.
#
# Samuel Brucker 2024 - 2025

# Define variables
$SPLUNK_VERSION = "9.4.0"
$SPLUNK_BUILD = "6b4ebe426ca6"
$SPLUNK_MSI = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-x64-release.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI}"
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
$INDEXER_IP = "172.20.241.20"
$RECEIVER_PORT = "9997"

Write-Host "AD or Docker? (1 for AD, 2 for Docker): "
$choice = Read-Host

# Download Splunk Universal Forwarder MSI
Write-Host "Downloading Splunk Universal Forwarder MSI..."
Invoke-WebRequest -Uri $SPLUNK_DOWNLOAD_URL -OutFile $SPLUNK_MSI

# Install Splunk Universal Forwarder
Write-Host "Installing Splunk Universal Forwarder..."
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $SPLUNK_MSI AGREETOLICENSE=Yes RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} /quiet" -Wait

if ($choice -eq 1) {

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."
@"
[default]
host = ActiveDirectory

[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://Application]
dsiabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://DNS Server]
disabled = 0
index = main

[WinEventLog://Directory Service]
disabled = 0
index = main

[WinEventLog://Windows Powershell]
disabled = 0
index = main
"@ | Out-File -FilePath $inputsConfPath -Encoding ASCII

# Disable KVStore if necessary
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"
Write-Host "Setting custom hostname for the logs..."
@"
[general]
serverName = ActiveDirectory
hostnameOption = shortname
"@ | Out-File -FilePath $serverConfPath -Encoding ASCII

} elseif ($choice -eq 2) {

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."
@"
[default]
host = Docker_Remote

[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://Application]
dsiabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://DNS Server]
disabled = 0
index = main

[WinEventLog://Directory Service]
disabled = 0
index = main

[WinEventLog://Windows Powershell]
disabled = 0
index = main
"@ | Out-File -FilePath $inputsConfPath -Encoding ASCII

# Disable KVStore if necessary
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"
Write-Host "Setting custom hostname for the logs..."
@"
[general]
serverName = Docker_Remote
hostnameOption = shortname
"@ | Out-File -FilePath $serverConfPath -Encoding ASCII

} else {
    Write-Host "Invalid choice. Please enter 1 or 2."
    exit
}

# Start Splunk Universal Forwarder service
Write-Host "Starting Splunk Universal Forwarder service..."
Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "start" -Wait

# Set Splunk Universal Forwarder to start on boot
Write-Host "Setting Splunk Universal Forwarder to start on boot..."
Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "enable boot-start" -Wait

Write-Host "Splunk Universal Forwarder installation and configuration complete!"