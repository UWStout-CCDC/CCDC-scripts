#!/bin/bash

# This script is intended as a automated setup for Splunk on CentOS 7 for the CCDC competition.
# This makes a number of changes to the syste, to do a baseline setup for the system both security and Splunk wise.
# Many security configs were taken from our other scritps, others from this blog: https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon

## NOTE ##
# To run any of these functions individually, run the script with the function name as an argument. For example:
# ./init-splunk.sh <function name> <args if any>

################################
##    Splunk Specific Init    ##
################################

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"

webUIPassword() {
  # Changing default Splunk Web UI admin password
  cd /opt/splunk/bin
  echo "Enter Splunk Web UI admin password:"
  read -s admin_password
  echo "Enter new Splunk Web UI admin password:"
  read -s password
  ./splunk edit user admin -auth admin:$admin_password -password $password
  cd ~
}

# CentOS is EOL so this likely won't ever be used anymore, uncomment if needed
#function fixCentOSRepos() {
  # Fix repos preemtively (if CentOS)
  # wget $BASE_URL/linux/splunk/CentOS-Base.repo -O CentOS-Base.repo --no-check-certificate
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
#}

disableSketchyTokens() {
  # Disabling sketchy auth tokens
  # Move auth tokens to temp directory to disable them
  echo -e "\e[33mDisabling sketchy auth tokens\e[0m"
  mkdir /tmp/sketchy_tokens
  mv /root/.xauthEkbntl /tmp/sketchy_tokens
  mv /root/.splunk/authToken_splunk_8089 /tmp/sketchy_tokens
}

installTools() {
  # Install tools (if not already)
  echo -e "\e[33mInstalling tools\e[0m"
  yum install iptables wget git aide net-tools audit audit-libs rkhunter epel-release -y
  cd /ccdc # Put lynis in a common location so it is not in the root home
  git clone https://github.com/CISOfy/lynis
  cd ~
}

backup() {
  echo -e "\e[33mCreating backup\e[0m"
  mkdir /ccdc/backups
  increment=$(date +%Y%m%d%H%M%S)
  # Backup the /opt/splunk/etc configuration directory
  tar -czvf splunk-etc-$increment.tgz /opt/splunk/etc -C /ccdc/backups
  # Backup the /etc directory
  tar -czvf system-etc-$increment.tgz /etc -C /ccdc/backups
}

restore() {
  echo -e "\e[33mRestoring backup\e[0m"
  # Get the newest backups
  newestSplunk=$(ls -t /ccdc/backups/splunk-etc-*.tgz | head -1 | sed 's/.*splunk-etc-\(.*\).tgz/\1/')
  newestSystem=$(ls -t /ccdc/backups/system-etc-*.tgz | head -1 | sed 's/.*system-etc-\(.*\).tgz/\1/')
  # Restore the /opt/splunk/etc configuration directory
  tar -xzvf /ccdc/backups/splunk-etc-$newestSplunk.tgz -C /opt/splunk
  tar -xzvf /ccdc/backups/system-etc-$newestSystem.tgz -C /
}

init() {
  # Init script
  # Download init script
  wget $BASE_URL/linux/init.sh -O init.sh --no-check-certificate
  # Run init script
  echo -e "\e[33mRunning init script\e[0m"
  chmod +x init.sh
  ./init.sh
}

#################################
##   Start Security Configs    ##
#################################

secureRootLogin() {
  # Only allow root login from console
  echo "tty1" > /etc/securetty
  chmod 700 /root
}

cronAndAtSecurity() {
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
}

stopSSH() {
  # Stop SSH
  echo -e "\e[33mStopping SSH\e[0m"
  service sshd stop
  systemctl disable --now sshd
}

setupAIDE() {
  # AIDE setup
  echo -e "\e[33mSetting up AIDE\e[0m"
  aide --init
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
}

setDNS() {
  # Set DNS
  echo -e "\e[33mSetting DNS\e[0m"
  INTERFACE=$(ip route | grep default | awk '{print $5}')
  sed -i 's/DNS1='.*'/DNS1=1.1.1.1/g' /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
  sed -i 's/DNS2='.*'/DNS2=9.9.9.9/g' /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
  systemctl restart network
}

setupAuditd() {
  # Auditd setup
  # Download audit rules
  wget $BASE_UEL/linux/splunk/audit.rules -O audit.rules --no-check-certificate
  # Run auditd setup
  echo -e "\e[33mSetting up Auditd\e[0m"
  cat audit.rules >> /etc/audit/audit.rules
  systemctl enable auditd.service
  systemctl start auditd.service
}

disableUncommonProtocols() {
  # Disable uncommon protocols
  echo -e "\e[33mDisabling uncommon protocols\e[0m"
  echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
  echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
  echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
  echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf
}

disableCoreDumps() {
  # Disable core dumps for users
  echo -e "\e[33mDisabling core dumps for users\e[0m"
  echo "* hard core 0" >> /etc/security/limits.conf
}

secureSysctl() {
# Secure sysctl.conf
# Rules are based off expected vaules from Lynis
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
fs.protected_fifos=2
dev.tty.ldisc_autoload=0
fs.protected_regular=2
EOF
}

secureGrub() {
  # Secure grub by ensuring the permissions are set to 600
  chmod 600 /boot/grub2/grub.cfg
}

setSELinuxPolicy() {
  # Ensure SELinux is enabled and enforcing
  # Check if SELINUX is already set to enforcing
  if grep -q SELINUX=enforcing /etc/selinux/config
  then
      echo "SELINUX already set to enforcing"
  else
      echo "Setting SELINUX to enforcing..."
      sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
  fi
}

################################
##    End Security Configs    ##
################################

setSplunkReciever() {
  # Enable Splunk reciever
  echo -e "\e[33mEnabling Splunk receiver\e[0m"
  cd /opt/splunk/bin
  ./splunk enable listen 9997 -auth admin:$password
  ./splunk restart
}

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ]
  then
    ./splunk add monitor $1
  fi
}

addMonitorFiles() {
  echo -e "\e[33mAdding log files to monitor\e[0m"
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
}

installGUI() {
  # Install GUI
  echo -e "\e[33mInstalling GUI\e[0m"
  gui_installed=true
  yum groupinstall "Server with GUI" -y || echo "\e[31mFailed to install GUI\e[0m" && gui_installed=false
  if $gui_installed
  then
      yum install firefox -y
      systemctl set-default graphical.target
      systemctl isolate graphical.target
  fi
}

bulkRemoveServices() {
  ## These are done after the gui is installed as the gui sometimes reinstalls some of these services
  # Bulk remove services
  echo -e "\e[33mRemoving unneeded services\e[0m"
  yum remove xinetd telnet-server rsh-server telnet rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd dovecot squid net-snmpd postfix libgcc -y
}

bulkDisableServices() {
  # Bulk disable services
  echo -e "\e[33mDisabling unneeded services\e[0m"
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
  echo -e "\e[33mDisabling rpc services\e[0m"
  systemctl disable rpcgssd
  systemctl disable rpcsvcgssd
  systemctl disable rpcidmapd

  # Disable Network File Systems (netfs)
  echo -e "\e[33mDisabling netfs\e[0m"
  systemctl disable netfs

  # Disable Network File System (nfs)
  echo -e "\e[33mDisabling nfs\e[0m"
  systemctl disable nfs
}

# Need to change IPs
setupIPv6() {
  # Check if changes were already made to the network config file
  if grep -q "IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
  then
      echo "Network config file already has IPv6 settings"
  else
      echo "Setting up IPv6..."
      # get the interface name
      INTERFACE=$(ip route | grep default | awk '{print $5}')
      echo "IPV6INIT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
      echo "IPV6ADDR=fd00:3::70/64" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
      echo "IPV6_DEFAULTGW=fd00:3::1" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
      systemctl restart network
  fi
}

##########################
## Backup/Restore Calls ##
##########################

# Check for manual backup argument and backup
if [[ "$1" == "backup" ]]; then
  echo -e "\e[33mStarting Backup!\e[0m"
  backup
  echo -e "\e[32mBackup complete!\e[0m" 
  exit 0
fi

# Check for restore argument and restore
if [[ "$1" == "restore" ]]; then
  echo -e "\e[33mStarting Restore of Latest Backup!\e[0m"
  restore
  echo -e "\e[32mRestore complete!\e[0m"
  exit 0
fi

#######################
##   Main Runnables  ##
#######################

# Add function calls in order of how you want them executed here
# Add the functions themselves above

webUIPassword
disableSketchyTokens
installTools
backup
init
secureRootLogin
cronAndAtSecurity
stopSSH
setupAIDE
setDNS
setupAuditd
disableUncommonProtocols
disableCoreDumps
secureSysctl
secureGrub
setSELinuxPolicy
setSplunkReciever
addMonitorFiles
installGUI
bulkRemoveServices
bulkDisableServices
backup

echo "\e[32mSplunk setup complete. Reboot to apply changes and clear in-memory beacons.\e[0m"