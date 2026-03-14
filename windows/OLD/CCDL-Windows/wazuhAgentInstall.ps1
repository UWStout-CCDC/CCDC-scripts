# wazuhAgentInstall.ps1
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to use to install Wazuh agent on Windows machines.
#
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

$windowsHost = Read-Host "Enter the Windows host name 'winAD' or 'docker'"

# Validate input
while ($windowsHost -ne "winAD" -and $windowsHost -ne "docker") {
    Write-Host "Invalid input!"
    $windowsHost = Read-Host "Enter the Windows host name 'winAD' or 'docker'"
}

# Install the Wazuh agent
if ($windowsHost -eq "winAD") {
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:temp\wazuh-agent /q WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='winAD'
} else {
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:temp\wazuh-agent /q WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='docker'
}

# Start the Wazuh agent service
NET START WazuhSvc

Write-Output "Wazuh agent started successfully!"