#!/bin/bash
#
# splunk-forward.sh
#
# Scripted install and configuration of the splunk forwarder for the CCDC competition

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

# Install Splunk Forwarder
# Splunk Forwarder 9.4.0 - Current version as of this commit
wget -O splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz "https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz"
tar -xzvf splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz -C /opt
# Splunk Forwarder 9.1.1 - Switch out the version if you need an older one
# wget -O splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz "https://download.splunk.com/products/universalforwarder/releases/9.1.1/linux/splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz"
# tar -xzvf splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz -C /opt

# Set permissions
chown -R splunkfwd:splunkfwd $SPLUNK_HOME

# Start the splunk forwarder, and automatically accept the license
echo "Starting Splunk and accepting license"
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt
$SPLUNK_HOME/bin/splunk enable boot-start

# Changing default admin password
cd /opt/splunkforwarder/bin
default_password=changeme
echo "Enter new Splunk admin password:"
read -s password
$SPLUNK_HOME/bin/splunk edit user admin -auth admin:$default_password -password $password

# Add the server to forward to (ip needs to be the first param)
echo "Adding server to forward to $SPLUNK_SERVER_IP. Use admin credentials"
$SPLUNK_HOME/bin/splunk add forward-server $SPLUNK_SERVER_IP:9997 -auth admin:$password # User will have to input the same creds here

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ]
  then
    ./splunk add monitor $1
  fi
}

cd $SPLUNK_HOME/bin
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
