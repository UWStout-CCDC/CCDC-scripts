#!/bin/bash
#
# splunk.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Install and configure the splunk forwarder

if [[ $EUID -ne 0 ]]; then
  echo 'Must be run as root, exiting!'
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo 'Must specify a forward-server! (This is the server Splunk-enterprise is on)'
  echo 'ex: sudo ./splunk.sh 192.168.0.5'
  exit 1
fi

# Install Splunk
wget -O splunkforwarder-8.2.5-77015bc7a462-Linux-x86_64.tgz "https://download.splunk.com/products/universalforwarder/releases/8.2.5/linux/splunkforwarder-8.2.5-77015bc7a462-Linux-x86_64.tgz"
tar -xzvf splunkforwarder-8.2.5-77015bc7a462-Linux-x86_64.tgz -C /opt
cd /opt/splunkforwarder/bin

# Request and confirm password
PASSWD_CONFIRM='!'
while [[ "$PASSWD" != "$PASSWD_CONFIRM" || -z "$PASSWD" ]]
do
  read -sr -p "Create splunk user password: " PASSWD
  echo ""
  read -sr -p "Confirm password: " PASSWD_CONFIRM
  echo ""
done

# Start the splunk forwarder, and automatically accept the license
./splunk start --accept-license --answer-yes --auto-ports --no-prompt --seed-password $PASSWD
# Add the server to forward to (ip needs to be the first param)
./splunk add forward-server "$1":9997 # User will have to input the same creds here
# Server to poll updates from (same as above, but a different port)
./splunk set deploy-poll "$1":8089 # User will have to input the same creds here

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ]
  then
    ./splunk add monitor $1
  fi
}

# Add files to log
monitor /var/log/syslog
monitor /var/log/messages
# Apache
monitor /var/log/apache/access.log
monitor /var/log/apache/error.log
monitor /var/log/apache2/access.log
monitor /var/log/apache2/error.log
# SSH
monitor /var/log/auth.log
monitor /var/log/secure

#monitor /var/log/httpd/*_log
#watch /var/log/https/modsec_*.log
monitor /var/log/mysql.log
monitor /var/log/mysqld.log
# TODO: add more files

# == Configure options ==

# Add Splunk user
useradd -d /opt/splunkforwarder splunk
groupadd splunk
usermod -a -G splunk splunk

# Set Splunk to start as Splunk user
./splunk enable boot-start -user splunk
#which systemd && ./splunk enable boot-start -systemd-managed 1 -user splunk 
chown -R splunk /opt/splunkforwarder

# Edit system options
#sed -i 's/"$SPLUNK_HOME\/bin\/splunk" start --no-prompt --answer-yes/su - splunk -c '\''"$SPLUNK_HOME\/bin\/splunk" start --no-prompt --answer-yes'\''/g' /etc/init.d/splunk
#sed -i 's/"$SPLUNK_HOME\/bin\/splunk" stop/su - splunk -c '\''"$SPLUNK_HOME\/bin\/splunk" stop'\''/g' /etc/init.d/splunk
#sed -i 's/"$SPLUNK_HOME\/bin\/splunk" restart/su - splunk -c '\''"$SPLUNK_HOME\/bin\/splunk" restart'\''/g' /etc/init.d/splunk
#sed -i 's/"$SPLUNK_HOME\/bin\/splunk" status/su - splunk -c '\''"$SPLUNK_HOME\/bin\/splunk" status'\''/g' /etc/init.d/splunk

# This doesn't always seem to be able to restart on it's own, so we just kill it
killall splunkd
/opt/splunkforwarder/bin/splunk restart
