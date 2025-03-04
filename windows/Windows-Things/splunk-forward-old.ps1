# Install and configure Splunk forwarder

#For more on what the script is doing check here: 
#https://docs.splunk.com/Documentation/Forwarder/9.1.1/Forwarder/InstallaWindowsuniversalforwarderfromaninstaller

#NOTE: Process is still partially manual but easier than editing the file now

#TODO:
# - Add script to run on initial setup script
# - Finish automations once IP is known
# - Add files to monitor as soon as known

$url = "https://download.splunk.com/products/universalforwarder/releases/9.4.0/windows/splunkforwarder-9.4.0-6b4ebe426ca6-windows-x64.msi"

Invoke-WebRequest -Uri $url -OutFile splunkforwarder-9.4.0-6b4ebe426ca6-windows-x64.msi

Write-Host "If forwarder installed does not install, download forwarder from web browser at this site: $url"
Write-Host "If installer does download, ignore the above."

# $username = Read-Host -Prompt 'Enter username for new user to run Splunk Forwarder as'
$password = Read-Host -Prompt 'Enter a new password for Splunk forwarder: '
$server = 172.20.241.20 # Change as needed
$forwardPort = 9997
$deploymentPort = 8089

$recieve = $server + ":" + $forwardPort
$deployment = $server + ":" + $deploymentPort

#Used for testing inputs
#Write-Host "$username, $password, $server, $recievePort, $deploymentPort, $recieve, $deployment"

msiexec.exe /i splunkforwarder-9.4.0-6b4ebe426ca6-windows-x64.msi  AGREETOLICENSE=yes SPLUNKPASSWORD=$password RECEIVING_INDEXER=$recieve DEPLOYMENT_SERVER=$deployment WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 ENABLEADMON=1 /quiet