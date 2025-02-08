#!/bin/bash

# This script is intended as a automated setup for Splunk on CentOS 7 for the CCDC competition.
# This makes a number of changes to the syste, to do a baseline setup for the system both security and Splunk wise.
# Many security configs were taken from our other scritps, others from this blog: https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon

################################
##    Splunk Specific Init    ##
################################

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

#BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/splunk-automation" # Used for testing in branch

# Install script dependencies
wget $BASE_URL/linux/splunk/CentOS-Base.repo -O CentOS-Base.repo
wget $BASE_URL/linux/init.sh -O init.sh
wget $BASE_UEL/linux/splunk/audit.rules

# Changing default Splunk Web UI admin password
cd /opt/splunk/bin
echo "Enter Splunk Web UI admin password:"
read -s admin_password
echo "Enter new Splunk Web UI admin password:"
read -s password
./splunk edit user admin -auth admin:$admin_password -password $password

# Fix repos preemtively
echo -e "\e[33mFixing repos\e[0m"
cd ~
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
mv ~/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
yum clean all
rm -rf /var/cache/yum
yum makecache

# Install tools (if not already)
echo -e "\e[33mInstalling tools\e[0m"
yum install iptables wget git aide net-tools audit audit-libs epel-release -y

# Run init script
echo -e "\e[33mRunning init script\e[0m"
chmod +x init.sh
./init.sh

# Cron and AT security
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

# Auditd setup
echo -e "\e[33mSetting up Auditd\e[0m"
systemctl enable auditd.service
systemctl start auditd.service

cat audit.rules >> /etc/audit/audit.rules

# Disable uncommon protocols
echo -e "\e[33mDisabling uncommon protocols\e[0m"
echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf

# Disable core dumps for users
echo -e "\e[33mDisabling core dumps for users\e[0m"
echo "* hard core 0" >> /etc/security/limits.conf

# Disable core dumps for SUID programs
echo -e "\e[33mDisabling core dumps for SUID programs\e[0m"
# Set runtime for fs.suid_dumpable
sysctl -q -n -w fs.suid_dumpable=0

# If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0"
#     else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf
if grep --silent ^fs.suid_dumpable /etc/sysctl.conf ; then
    sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/g' /etc/sysctl.conf
else
    echo "" >> /etc/sysctl.conf
    echo "# Set fs.suid_dumpable to 0 per security requirements" >> /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
fi

# Buffer Overflow Protection
echo -e "\e[33mSetting up buffer overflow protection\e[0m"
# Enables exec-shield
sysctl -w kernel.exec-shield=1
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
# Enable ASLR
sysctl -q -n -w kernel.randomize_va_space=2
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

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