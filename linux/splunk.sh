#!/bin/bash
#
# splunk.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Install and configure the splunk forwarder

if [[ $EUID -ne 0 ]]; then
	printf 'Must be run as root, exiting!\n'
	exit 1
fi

if [[ $# -lt 1 ]]; then
	printf 'Must specify a forward-server! (This is the server Splunk-enterprise is on)\nex: sudo ./makeforwarder.sh 192.168.0.5'
	exit 1
fi

# Install Splunk
wget -O splunkforwarder-8.0.2-a7f645ddaf91-Linux-x86_64.tgz 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.0.2&product=universalforwarder&filename=splunkforwarder-8.0.2-a7f645ddaf91-Linux-x86_64.tgz&wget=true'
tar -xzvf splunkforwarder-8.0.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt
cd /opt/splunkforwarder/bin

# Start the splunk forwarder, and automatically accept the license
./splunk start --accept-license # User will have to input creds here
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
monitor /var/log/apache/access.log
monitor /var/log/apache/error.log
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

/opt/splunkforwarder/bin/splunk restart
