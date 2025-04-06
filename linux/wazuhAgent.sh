#!/bin/bash
# Wazuh agent certificate installation script
# wazuhAgent.sh
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to install wazuh agent for all supported platforms
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

# Set variable for the Wazuh manager IP address
# WAZUH_MANAGER='172.20.242.50'

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Case to determine the specific box
# fullname="USER INPUT"
read -p "Enter Box - Options: 'debianDNS' 'splunk' 'ecomm' 'webmail' 'ubuntuWeb'" boxname

while [ "$boxname" != "debianDNS" ] && [ "$boxname" != "splunk" ] && [ "$boxname" != "ecomm" ] && [ "$boxname" != "webmail" ] && [ "$boxname" != "ubuntuWeb" ]
do
  echo "Invalid input!"
  read -p "Enter Box - Options: 'debianDNS' 'splunk' 'ecomm' 'webmail' 'ubuntuWeb'" boxname
done

# Create a case to install the agent for UbuntuWrk as the manager
case $boxname in
  debianDNS)
    echo "Installing Wazuh agent for Debian DNS"
    # Add your installation commands here
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.2-1_amd64.deb && WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='debianDNS' dpkg -i ./wazuh-agent_4.11.2-1_amd64.deb
    ;;
  splunk)
    echo "Installing Wazuh agent for Splunk"
    curl -o wazuh-agent_4.11.2-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.2-1.x86_64.rpm && WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='splunk' rpm -ihv wazuh-agent_4.11.2-1.x86_64.rpm
    ;;
  ecomm)
    echo "Installing Wazuh agent for Ecomm"
    curl -o wazuh-agent_4.11.2-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.2-1.x86_64.rpm && WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='ecomm' rpm -ihv wazuh-agent_4.11.2-1.x86_64.rpm
    ;;
  webmail)
    echo "Installing Wazuh agent for Webmail"
    curl -o wazuh-agent_4.11.2-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.2-1.x86_64.rpm && WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='webmail' rpm -ihv wazuh-agent_4.11.2-1.x86_64.rpm
    ;;
  ubuntuWeb)
    echo "Installing Wazuh agent for Ubuntu Web"
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.2-1_amd64.deb && WAZUH_MANAGER='172.20.242.50' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='ubuntuWeb' dpkg -i ./wazuh-agent_4.11.2-1_amd64.deb
    ;;
esac

# Start and enable the Wazuh agent service
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "Wazuh agent installation completed for $boxname"