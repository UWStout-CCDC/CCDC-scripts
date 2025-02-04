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
BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/splunk-automation" # Used for testing in branch

# Changing default admin password
cd /opt/splunk/bin
echo "Enter Splunk Web UI admin password:"
read -s admin_password
echo "Enter new Splunk Web UI admin password:"
read -s password
./splunk edit user admin -auth admin:$admin_password -password $password


# Fix repos preemtively
echo -e "\e[33mFixing repos\e[0m"
cd ~
wget $BASE_URL/linux/splunk/CentOS-Base.repo -O CentOS-Base.repo
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
mv ~/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
yum clean all
rm -rf /var/cache/yum
yum makecache

# Install tools (if not already)
echo -e "\e[33mInstalling tools\e[0m"
yum install iptables wget git aide net-tools epel-release -y

# Install scripts
echo -e "\e[33mInstalling init script\e[0m"
wget $BASE_URL/linux/init.sh -O init.sh
chmod +x init.sh
./init.sh

# cron and at security
echo -e "\e[33mSetting cron and at security\e[0m"
echo "Locking down Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# Stop SSH
echo -e "\e[33mStopping SSH\e[0m"
service sshd stop
systemctl disable --now sshd

# AIDE setup
echo -e "\e[33mSetting up AIDE\e[0m"
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Enable Splunk reciever
echo -e "\e[33mEnabling Splunk receiver\e[0m"
cd /opt/splunk/bin
./splunk enable listen 9997 -auth admin:$password
./splunk restart

# Quick function to check if a file exists, and monitor it
echo -e "\e[33mAdding log files to monitor\e[0m"
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

# Install GUI
echo -e "\e[33mInstalling GUI\e[0m"
gui_installed=true
yum groupinstall "Server with GUI" -y || echo "Failed to install GUI" && gui_installed=false
if $gui_installed
then
    yum install firefox -y
    systemctl set-default graphical.target
    systemctl isolate graphical.target

echo "\e[33mSplunk setup complete. Reboot to apply changes and clear in-memory beacons.\e[0m"