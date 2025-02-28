#!/bin/bash
#
# ubuntuwrkinit.sh
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to use during init of Ubuntu Workstation
# Current OS: Ubuntu 20.04.6 LTS x86_64
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

# Create Color code for error messages
RED_COLOR_CODE=31
GREEN_COLOR_CODE=32
BLUE_COLOR_CODE=34

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
    *) echo "$(tput setaf RED_COLOR_CODE)INVALID PARAMETER!!!!$(tput sgr0)"; exit ;;
  esac
  read -p "$1 $def" ans
  case $ans in
    y|Y) true ;;
    n|N) false ;;
    *) [[ "$def" != "[y/N]" ]] ;;
  esac
}

# Copy scripts
if [ ! -f "$CCDC_ETC/PAConfig.txt" ]; then # Check if the file exists
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/firewall/PaloAlto/PAConfig.txt -O $CCDC_ETC/PAConfig.txt
fi
if [ ! -f "$SCRIPT_DIR/iptables.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/firewall/UbuntuWkst/iptables.sh -O $SCRIPT_DIR/iptables.sh
fi
if [ ! -f "$SCRIPT_DIR/ubuntuwrkinit.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/firewall/UbuntuWkst/ubuntuwrkinit.sh -O $SCRIPT_DIR/ubuntuwrkinit.sh
fi
if [ ! -f "$SCRIPT_DIR/monitor.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/firewall/UbuntuWkst/monitor.sh -O $SCRIPT_DIR/monitor.sh
fi
if [ ! -f "$SCRIPT_ETC/legal_banner.txt" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/general/legal_banner.txt -O $SCRIPT_DIR/legal_banner.txt
fi
if [ ! -f "$SCRIPT_DIR/clamavscan.sh" ]; then
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/firewall/UbuntuWkst/clamavscan.sh -O $SCRIPT_DIR/clamavscan.sh
fi
# Make scripts executable
chmod +x $SCRIPT_DIR/iptables.sh
chmod +x $SCRIPT_DIR/ubuntuwrkinit.sh
chmod +x $SCRIPT_DIR/monitor.sh
chmod +x $SCRIPT_DIR/clamavscan.sh

# change password on workstation
echo "$(tput setaf BLUE_COLOR_CODE)Please change the password for the default admin account$(tput sgr0)"
# user="USER INPUT"
read -p "Enter user: " user
passwd $user

#change password for root account
echo "Please change the password for the root account"
passwd root

# Set up legal banner
echo "Setting up legal banner"
cat $SCRIPT_DIR/legal_banner.txt > /etc/issue.net

# update the system
echo "Updating the system"
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y

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
  ubuntuIPv6Addr="fd00:2::50"
  ubuntuIPv6Netmask="64"
  ubuntuIPv6Gateway="fd00:2::1"

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

# Remove unnecessary packages
echo "$(tput setaf BLUE_COLOR_CODE)Removing unnecessary packages$(tput sgr0)"
# Remove LibreOffice, Thunderbird, Rhythmbox, Shotwell, and other unnecessary packages
apt remove --purge libreoffice* thunderbird* rhythmbox* -y
apt remove --purge shotwell* -y
apt remove --purge gnome-2048 aisleriot atomix gnome-chess five-or-more hitori iagno gnome-klotski lightsoff gnome-mahjongg gnome-mines gnome-nibbles quadrapassel four-in-a-row gnome-robots gnome-sudoku swell-foop tali gnome-taquin gnome-tetravex -y && sudo apt autoremove -y
apt remove --purge gnome-todo* -y
apt remove --purge gnome-calendar* -y
apt remove --purge gnome-weather* -y
apt remove --purge gnome-maps* -y
apt remove --purge gnome-photos* -y
# Remove CUPS (Common Unix Printing System)
apt-get remove --purge cups* -y
# Remove Avahi (Zeroconf networking)
apt-get remove --purge avahi* -y
# Remove Bluetooth
apt-get remove --purge bluez* -y
# Remove unused programing languages
apt-get remove --purge perl* ruby* -y # Leaving python for now

# Hardening
echo "Hardening the System"
apt-get install debian-goodies debsums fail2ban -y


echo "Script complete"
echo "Please reboot the system"
exit 0