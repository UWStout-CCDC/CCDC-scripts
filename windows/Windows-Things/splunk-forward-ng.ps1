# Splunk forwarder script adapted from https://github.com/SEMO-Cyber/CyberDefenseTeamPrep/blob/main/Splunk/ and modified to better suit our use case
# Thanks to SEMO Cyber Defense Team for the original script

# Define variables
$SPLUNK_VERSION = "9.4.0"
$SPLUNK_BUILD = "6b4ebe426ca6"
$SPLUNK_MSI = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-x64-release.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI}"
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
$INDEXER_IP = "172.20.241.20"
$RECEIVER_PORT = "9997"

# Get system hostname
$hostname = hostname

# Download Splunk Universal Forwarder MSI
Write-Host "Downloading Splunk Universal Forwarder MSI..."
Invoke-WebRequest -Uri $SPLUNK_DOWNLOAD_URL -OutFile $SPLUNK_MSI

# Install Splunk Universal Forwarder
Write-Host "Installing Splunk Universal Forwarder..."
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $SPLUNK_MSI AGREETOLICENSE=Yes RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} /quiet" -Wait

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."
@"
[default]
host = $hostname

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
serverName = $hostname
hostnameOption = shortname
"@ | Out-File -FilePath $serverConfPath -Encoding ASCII

# Start Splunk Universal Forwarder service
Write-Host "Starting Splunk Universal Forwarder service..."
Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "start" -Wait

# Set Splunk Universal Forwarder to start on boot
Write-Host "Setting Splunk Universal Forwarder to start on boot..."
Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "enable boot-start" -Wait

Write-Host "Splunk Universal Forwarder installation and configuration complete!"