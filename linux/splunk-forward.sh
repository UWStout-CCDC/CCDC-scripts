#!/bin/bash
#
# splunk.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Install and configure the splunk forwarder

# TODO:
# Fix outputs
# Fix ordering and commands so that the users are created properly and the install happens properly

if [[ $EUID -ne 0 ]]; then
  echo 'Must be run as root, exiting!'
  exit 1
fi

# Confirm Splunk server IP
read -p "Enter the Splunk server IP [default: 172.20.241.20]: " SPLUNK_SERVER_IP
SPLUNK_SERVER_IP=${SPLUNK_SERVER_IP:-172.20.241.20}
if [[ -z "$SPLUNK_SERVER_IP" ]]; then
  echo 'Splunk server IP cannot be empty!'
  exit 1
fi

# Create splunkfwd user and group
useradd -m splunkfwd
groupadd splunkfwd

# Create Splunk directory
export SPLUNK_HOME="/opt/splunkforwarder"
mkdir $SPLUNK_HOME

# Install Splunk
wget -O splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz "https://download.splunk.com/products/universalforwarder/releases/9.1.1/linux/splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz"
tar -xzvf splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz -C /opt
cd /opt/splunkforwarder/bin

# Set permissions
chown -R splunkfwd:splunkfwd $SPLUNK_HOME

# Changing default admin password
cd /opt/splunkforwarder/bin
echo "Enter Splunk Web UI admin password:"
read -s admin_password
echo "Enter new Splunk Web UI admin password:"
read -s password
./splunk edit user admin -auth admin:$admin_password -password $password

# Start the splunk forwarder, and automatically accept the license
echo "Starting Splunk and accepting license"
./splunk start --accept-license --answer-yes --auto-ports --no-prompt
# Add the server to forward to (ip needs to be the first param)
echo "Adding server to forward to $SPLUNK_SERVER_IP. Use admin credentials"
./splunk add forward-server "$SPLUNK_SERVER_IP":9997 # User will have to input the same creds here
# Server to poll updates from (same as above, but a different port)
echo "Setting deployment server. Use admin credentials"
./splunk set deploy-poll "$SPLUNK_SERVER_IP":8089 # User will have to input the same creds here

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ]
  then
    ./splunk add monitor $1
  fi
}

# Add files to log
echo "Adding log files to monitor"
# Log files
monitor /var/log/syslog
monitor /var/log/messages
# SSH
monitor /var/log/auth.log
monitor /var/log/secure
# HTTP
monitor /var/log/httpd/
# MySQL
monitor /var/log/mysql.log
monitor /var/log/mysqld.log
# TODO: add more files

# == Configure options ==

# Set Splunk to start as Splunk user
./splunk enable boot-start -user splunkfwd

# Restart Splunk
./splunk restart
