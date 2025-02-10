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

BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
#BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/splunk-automation" # Used for testing in branch

# Install script dependencies
#wget $BASE_URL/linux/splunk/CentOS-Base.repo -O CentOS-Base.repo --no-check-certificate
wget $BASE_URL/linux/init.sh -O init.sh --no-check-certificate
wget $BASE_UEL/linux/splunk/audit.rules -O audit.rules --no-check-certificate

# Changing default Splunk Web UI admin password
cd /opt/splunk/bin
echo "Enter Splunk Web UI admin password:"
read -s admin_password
echo "Enter new Splunk Web UI admin password:"
read -s password
./splunk edit user admin -auth admin:$admin_password -password $password

# Fix repos preemtively (if CentOS)
# echo -e "\e[33mFixing repos\e[0m"
# cd ~
# mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
# mv ~/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
# yum clean all
# rm -rf /var/cache/yum
# yum makecache

# Update CA certs
# echo -e "\e[33mUpdating CA certificates\e[0m"
# yum update -y ca-certificates

# Install tools (if not already)
echo -e "\e[33mInstalling tools\e[0m"
yum install iptables wget git aide net-tools audit audit-libs epel-release -y
git clone https://github.com/CISOfy/lynis

# Run init script
echo -e "\e[33mRunning init script\e[0m"
chmod +x init.sh
./init.sh

#################################
##   Start Security Configs    ##
#################################

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

# Set DNS
echo -e "\e[33mSetting DNS\e[0m"
sed -i '/^nameserver/ i\nameserver 1.1.1.1' /etc/resolv.conf

# Auditd setup
echo -e "\e[33mSetting up Auditd\e[0m"
cat audit.rules >> /etc/audit/audit.rules
systemctl enable auditd.service
systemctl start auditd.service

# Disable uncommon protocols
echo -e "\e[33mDisabling uncommon protocols\e[0m"
echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf

# Disable core dumps for users
echo -e "\e[33mDisabling core dumps for users\e[0m"
echo "* hard core 0" >> /etc/security/limits.conf

# Secure sysctl.conf
echo -e "\e[33mSecuring sysctl.conf\e[0m"
cat <<-EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0
kernel.exec_shield = 1
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_max_syn_backlog = 1280
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.log_martians = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 3
EOF

################################
##    End Security Configs    ##
################################

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
fi

## These are done after the gui is installed as the gui sometimes reinstalls some of these services
# Bulk remove services
yum remove xinetd telnet-server rsh-server telnet rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd dovecot squid net-snmpd postfix -y

# Bulk disable services
systemctl disable xinetd
systemctl disable rexec
systemctl disable rsh
systemctl disable rlogin
systemctl disable ypbind
systemctl disable tftp
systemctl disable certmonger
systemctl disable cgconfig
systemctl disable cgred
systemctl disable cpuspeed
systemctl enable irqbalance
systemctl disable kdump
systemctl disable mdmonitor
systemctl disable messagebus
systemctl disable netconsole
systemctl disable ntpdate
systemctl disable oddjobd
systemctl disable portreserve
systemctl enable psacct
systemctl disable qpidd
systemctl disable quota_nld
systemctl disable rdisc
systemctl disable rhnsd
systemctl disable rhsmcertd
systemctl disable saslauthd
systemctl disable smartd
systemctl disable sysstat
systemctl enable crond
systemctl disable atd
systemctl disable nfslock
systemctl disable named
systemctl disable dovecot
systemctl disable squid
systemctl disable snmpd
systemctl disable postfix

# Disable rpc
systemctl disable rpcgssd
systemctl disable rpcsvcgssd
systemctl disable rpcidmapd

# Disable Network File Systems (netfs)
systemctl disable netfs

# Disable Network File System (nfs)
systemctl disable nfs

echo "\e[33mSplunk setup complete. Reboot to apply changes and clear in-memory beacons.\e[0m"