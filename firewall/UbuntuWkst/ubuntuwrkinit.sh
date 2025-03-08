#!/bin/bash
#
# ubuntuwrkinit.sh
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to use during init of Ubuntu Workstation
# Current OS: Ubuntu 20.04.6 LTS x86_64

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Definitions
CCDC_DIR="/ccdc"
CCDC_BACKUP="$CCDC_DIR/backup"
CCDC_ETC="$CCDC_DIR/etc"
CCDC_LOGS="$CCDC_DIR/logs"
SCRIPT_DIR="$CCDC_DIR/scripts"

# make directories and set current directory
mkdir -p $CCDC_DIR
mkdir -p $CCDC_ETC
mkdir -p $SCRIPT_DIR
mkdir -p $CCDC_BACKUP
mkdir -p $CCDC_LOGS
cd $CCDC_DIR

# Define Methods
prompt() {
  case "$2" in 
    y) def="[Y/n]" ;;
    n) def="[y/N]" ;;
    *) echo "INVALID PARAMETER!!!!"; exit ;;
  esac
  read -p "$1 $def" ans
  case $ans in
    y|Y) true ;;
    n|N) false ;;
    *) [[ "$def" != "[y/N]" ]] ;;
  esac
}

# Copy scripts
if [ ! -f "$CCDC_ETC/PAConfig.txt" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/firewall/firewall/PaloAlto/PAConfig.txt -O $CCDC_ETC/PAConfig.txt
fi
if [ ! -f "$SCRIPT_DIR/iptables.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/firewall/firewall/UbuntuWkst/iptables.sh -O $SCRIPT_DIR/iptables.sh
fi
if [ ! -f "$SCRIPT_DIR/ubuntuwrkinit.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/firewall/firewall/UbuntuWkst/ubuntuwrkinit.sh -O $SCRIPT_DIR/ubuntuwrkinit.sh
fi
if [ ! -f "$SCRIPT_DIR/monitor.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/firewall/firewall/UbuntuWkst/monitor.sh -O $SCRIPT_DIR/monitor.sh
fi

# Make scripts executable
chmod +x $SCRIPT_DIR/iptables.sh
chmod +x $SCRIPT_DIR/ubuntuwrkinit.sh
chmod +x $SCRIPT_DIR/monitor.sh
chmod +x $SCRIPT_DIR/clamavscan.sh

# change password on workstation
echo "Please change the password for the default admin account"
# user="USER INPUT"
read -p "Enter user: " user
passwd $user

#change password for root account
echo "Please change the password for the root account"
passwd root

# update the system
echo "Updating the system"
sudo apt-get update
sudo apt-get upgrade
sudo apt-get dist-upgrade

if prompt "Would you like to change the current IP addressing?" y
then
  # Change ip addressing
  echo "Please change the IP address of the workstation"
  apt-get install net-tools
  interface=$(ifconfig | grep -oP 'ens[0-9]+' | head -n 1)
  echo "Configuring Interface: $interface"

  # Set the IP address. This can be changed but might affect the firewall rules on Palo Alto.
  ubuntuIpAddr="172.20.242.50"
  ubuntuNetmask="255.255.255.0"
  ubuntuGateway="172.20.242.254"
  ubuntuDNS="9.9.9.9"

  # IPv6 Addressing
  ubuntuIPv6Addr="fd00:3::50"
  ubuntuIPv6Netmask="64"
  ubuntuIPv6Gateway="fd00:3::1"

  # Set the IP address
  echo "Setting IP address to $ubuntuIpAddr"
  ip addr add $ubuntuIpAddr/$ubuntuNetmask dev $interface
  ip route add default via $ubuntuGateway
  echo "nameserver $ubuntuDNS" > /etc/resolv.conf
  ip -6 addr add $ubuntuIPv6Addr/$ubuntuIPv6Netmask dev $interface
  ip -6 route add default via $ubuntuIPv6Gateway
fi

# Set up iptables rules
# Run the scripts
echo "Creating iptables rules"
bash $SCRIPT_DIR/iptables.sh

# Add monitoring
echo "Adding monitoring"
bash $SCRIPT_DIR/monitor.sh

# Install clamav
echo "Installing ClamAV"
apt-get install clamav clamav-daemon -y
systemctl enable clamav-daemon
systemctl start clamav-daemon
systemctl enable clamav-freshclam
systemctl start clamav-freshclam

# Set up ClamAV scan cron job
if prompt "Would you like to set up a ClamAV scan cron job?" y
then
  # Define the scan script
  SCAN_SCRIPT="$SCRIPT_DIR/clamavscan.sh"

  # Define the cron job entry
  CRON_JOB="*/30 * * * * $SCAN_SCRIPT" # Run every 30 minutes

  # Ensure the scan script exists and is executable
  if [ ! -f "$SCAN_SCRIPT" ]; then
      echo "Error: ClamAV scan script not found at $SCAN_SCRIPT"
      exit 1
  fi
  chmod +x "$SCAN_SCRIPT"

  # Check if the cron job already exists
  crontab -l 2>/dev/null | grep -F "$SCAN_SCRIPT" > /dev/null

  if [ $? -eq 0 ]; then
      echo "ClamAV scan cron job already exists. No changes made."
  else
      # Add the new cron job
      (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
      echo "ClamAV scan cron job added successfully!"
  fi
fi

# Kernel hardening
echo "Kernel hardening"
# TODO: Add kernel hardening steps here

echo "Script complete"
echo "Please reboot the system"
exit 0