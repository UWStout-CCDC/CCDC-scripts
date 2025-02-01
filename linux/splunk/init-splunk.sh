#!/bin/bash

###################################
##    Splunk Specific Configs    ##
###################################

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

#BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
BASE_URL="https://raw.githubusercontent.com/CCDC-Defense/CCDC-scripts/splunk-automation" # Used for testing in branch

# Changing default admin password
cd /opt/splunk/bin
echo "Enter admin password:"
read -s admin_password
echo "Enter new admin password:"
read -s password
./splunk edit user admin -auth admin:$admin_password -password $password


# Fix repos preemtively
cd ~
wget $BASE_URL/linux/splunk/CentOS-Base.repo -O CentOS-Base.repo
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
mv ~/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
yum clean all
rm -rf /var/cache/yum
yum makecache

# Install tools (if not already)
yum install iptables wget git aide net-tools -y

# Install scripts
wget wget $BASE_URL/linux/init.sh -O init.sh
chmod +x init.sh
./init.sh

# cron and at security
rm /etc/cron.deny
rm /etc/at.deny || echo "No at.deny to remove"

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

# Enable Splunk reciever
cd /opt/splunk/bin
./splunk enable listen 9997 -auth admin:$password
./splunk restart

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ]
  then
    ./splunk add monitor $1
  fi
}

# Add files to log
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

# Install GUI (broken  fix)
yum install epel-release -y
gui_installed=true
yum groupinstall "Server with GUI" -y --skip-broken && yum groupinstall “Xfce” -y --skip-broken || echo "Failed to install GUI" && gui_installed=false
if $gui_installed
then
    systemctl set-default graphical.target
    systemctl isolate graphical.target
    yum install firefox -y

echo "Splunk setup complete. Reboot to apply changes and clear in-memory beacons."