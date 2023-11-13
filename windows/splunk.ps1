#TODO:
# - Add script to run on initial setup script
# - Automate below tasks

# Install and configure Splunk forwarder

#Will automate eventually but for now change manually:

# Replace <domain\username> and <pass> with the desired username and password
# you want the forwarder to run as

# Change the <username> and <password> to desired username and password for creating
# an admin user for the forwarder

# Change <host:port> to be the hostname or IP of the splunk server

# Add any MONITOR_PATH="<directory_path>" ` as needed (the '`' specifies a newline)
# change <directory_path> to the file you want monitored

msiexec.exe /i splunkforwarder-9.0.3-dd0128b1f8cd-x64-release.msi AGREETOLICENSE=Yes ` 
LOGON_USERNAME="<domain\username>" LOGON_PASSWORD="<pass>" RECEIVING_INDEXER="<host:port>" DEPLOYMENT_SERVER="<host:port>" `
WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 ENABLEADMON=1 `
SPLUNKUSERNAME=<username> SPLUNKPASSWORD=<password> `
MONITOR_PATH="<directory_path>" `
MONITOR_PATH="<directory_path>"