# Install and configure Splunk forwarder

#For more on what the script is doing check here: 
#https://docs.splunk.com/Documentation/Forwarder/9.1.1/Forwarder/InstallaWindowsuniversalforwarderfromaninstaller

#NOTE: Process is still partially manual but easier than editing the file now

#TODO:
# - Add script to run on initial setup script
# - Finish automations once IP is known
# - Add files to monitor as soon as known

$url = https://download.splunk.com/products/universalforwarder/releases/9.1.1/windows/splunkforwarder-9.1.1-64e843ea36b1-x86-release.msi

Invoke-WebRequest -Uri $url -OutFile splunkforwarder-9.1.1-64e843ea36b1-x86-release.msi

Write-Host "If forwarder installed does not install, download forwarder from web browser at this site: $url"
Write-Host "If installer does download, ignore the above."

$username = Read-Host -Prompt 'Enter username for new user to run Splunk Forwarder as'
$password = Read-Host -Prompt 'Enter password for Splunk forwarder user'
$server = Read-Host -Prompt 'Enter Splunk Server IP'
$forwardPort = 9997
$deploymentPort = 8089

$recieve = $server + ":" + $forwardPort
$deployment = $server + ":" + $deploymentPort

#Used for testing inputs
#Write-Host "$username, $password, $server, $recievePort, $deploymentPort, $recieve, $deployment"

msiexec.exe /i splunkforwarder-9.0.4-de405f4a7979-x64-release.msi  AGREETOLICENSE=yes SPLUNKUSERNAME=$username SPLUNKPASSWORD=$password RECEIVING_INDEXER=$recieve DEPLOYMENT_SERVER=$deployment WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 ENABLEADMON=1 /quiet