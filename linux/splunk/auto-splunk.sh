#!/bin/bash

###################################
##    Splunk Specific Configs    ##
###################################

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Changing default admin password
cd /opt/splunk/bin
echo "Enter admin password:" read -s admin_password
echo "Enter new password:" read -s password
./splunk edit user <username> -auth admin:<admin_password> -password <password>

# Install tools
yum install iptables wget git aide

# Install scripts
wget wget http://tinyurl.com/bddawdwe -O init.sh
chmod +x init.sh
./init.sh

# cron and at security
rm /etc/cron.deny
rm /etc/at.deny

touch /etc/cron.allow
echo "root" >> /etc/cron.allow

touch /etc/at.allow
echo "root" >> /etc/at.allow

# Stop SSH
service sshd stop
systemctl disable --now sshd

# AIDE setup
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Install GUI
yum groupinstall "Server with GUI" -y
yum install firefox
systemctl set-default graphical.target
systemctl isolate graphical.target