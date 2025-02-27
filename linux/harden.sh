#!/bin/bash

# This script is intended as a automated hardening script for RHEL and Debian based systems.
# This makes a number of changes to the system, to do a baseline setup for system security

## NOTE ##
# To run any of these functions individually, run the script with the function name as an argument. For example:
# ./harden.sh <function name> <args if any>
# Might error a bit but should still execute
#
# Code is in functions for easy readability and maintainability
# Got annoyed trying to reorder/copy giant blocks of code around

## TODO
# - TEST THE SCRIPT IN ENVIRONMENT
# - Update auditd.rules to use new rule set

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Definitions
CCDC_DIR="/ccdc"
CCDC_ETC="$CCDC_DIR/etc"
SCRIPT_DIR="$CCDC_DIR/scripts"
BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"

adminUser=""

# make directories and set current directory
mkdir -p $CCDC_DIR
mkdir -p $CCDC_ETC
mkdir -p $SCRIPT_DIR

# Detect OS and set var for package manager
if [ -f /etc/redhat-release ]; then
  OS="RHEL"
  PKG="yum"
elif [ -f /etc/centos-release ]; then
  OS="CentOS"
  PKG="yum"
elif [ -f /etc/debian_version ]; then
  OS="Debian"
  PKG="apt"
fi

#######################
## Helper Functions  ##
#######################

# get <file>
# prints the name of the file downloaded
get() {
  # only download if the file doesn't exist
  if [[ ! -f "$SCRIPT_DIR/$1" ]]
  then
    mkdir -p $(dirname "$SCRIPT_DIR/$1") 1>&2
    BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
    wget --no-check-certificate "$BASE_URL/$1" -O "$SCRIPT_DIR/$1" 1>&2
  fi
  echo "$SCRIPT_DIR/$1"
}

# replace <dir> <file> <new file>
replace() {
  mkdir -p $CCDC_ETC/$(dirname $2)
  cp $1/$2 $CCDC_ETC/$2.old
  mkdir -p $(dirname $1/$2)
  cp $(get $3) $1/$2
}

backup() {
  echo -e "\e[33mCreating backup\e[0m"
  if [ ! -d /ccdc/backups ]; then
    mkdir -p /ccdc/backups
  fi
  increment=$(date +%Y%m%d%H%M%S)
  # Backup the /etc directory
  tar -czvf /ccdc/backups/system-etc-$increment.tgz /etc
}

restore() {
  echo -e "\e[33mRestoring backup\e[0m"
  # Get the newest backups
  newestSystem=$(ls -t /ccdc/backups/system-etc-*.tgz | head -1 | sed 's/.*system-etc-\(.*\).tgz/\1/')
  # Restore the /opt/splunk/etc configuration directory
  tar -xzvf /ccdc/backups/system-etc-$newestSystem.tgz -C /
}


###########################
##   Security Configs    ##
###########################

changePasswords() {
  echo -e "\e[33mChanging passwords\e[0m"
  # Set root password
  while true; do
      echo "Enter new root password: "
      stty -echo
      read rootPass
      stty echo
      echo "Confirm root password: "
      stty -echo
      read confirmRootPass
      stty echo

      if [ "$rootPass" = "$confirmRootPass" ]; then
          break
      else
          echo "Passwords do not match. Please try again."
      fi
  done

  echo "root:$rootPass" | chpasswd

  # Set sysadmin password
  while true; do
      echo "Enter new sysadmin password: "
      stty -echo
      read sysadminPass
      stty echo
      echo "Confirm sysadmin password: "
      stty -echo
      read confirmSysadminPass
      stty echo

      if [ "$sysadminPass" = "$confirmSysadminPass" ]; then
          break
      else
          echo "Passwords do not match. Please try again."
      fi
  done

  echo "sysadmin:$sysadminPass" | chpasswd
}

createNewAdmin() {
  echo -e "\e[33mCreating new admin user\e[0m"
  echo "Enter new admin username: "
  read $adminUser
  useradd $adminUser

  while true; do
    echo "Enter password for user $adminUser:"
    stty -echo
    read pass
    stty echo
    echo "Confirm $adminUser password:"
    stty -echo
    read confirmPass

    if [ "$pass" = "$confirmPass" ]; then
        break
    else
        echo "Passwords do not match. Please try again."
    fi
  done
  echo "$adminUser:$pass" | chpasswd

  echo "Adding $adminUser sudo"
  usermod -aG wheel $adminUser
}

installTools() {
    # Install tools (if not already)
    echo -e "\e[33mInstalling tools\e[0m"

    if [ "$OS" == "RHEL" ] || [ "$OS" == "CentOS" ]; then
        yum update -y
        yum install epel-release iptables iptables-services wget git aide net-tools audit audit-libs rkhunter clamav -y
        yum autoremove -y
    elif [ "$OS" == "Debian" ]; then
        apt-get update
        apt-get install -y iptables iptables-services wget git aide net-tools audit auditd rkhunter clamav
        apt-get autoremove -y
    fi

    # Install Lynis
    if [ ! -d /ccdc/lynis ]; then
        cd /ccdc # Put lynis in a common location so it is not in the root home
        git clone https://github.com/CISOfy/lynis
        cd ~
    fi

    # Install Monitor Script
    if [ ! -f /ccdc/scripts/monitor.sh ]; then
        get linux/monitor/monitor.sh
        chmod +x /ccdc/scripts/monitor.sh
    fi
}

lockUnusedAccounts() {
  echo -e "\e[33mLocking unused accounts\e[0m"
  # Create custom nologin script, /sbin/nologin sometimes has a shell
  NOLOGIN=$SCRIPT_DIR/linux/nologin.sh
  cat <<EOF > $NOLOGIN
#!/bin/bash
echo "This account is unavailable."
EOF
  chmod a=rx $NOLOGIN
  # Get a list of users from /etc/passwd, and allow the user to select what users to keep with a simple yes/no prompt
  while read -r line; do
      # Get the username
      username=$(echo $line | cut -d: -f1)
      # Check if the user is root
      if [ "$username" == "root" ] || [ "$username" == "sysadmin" ] || [ "$username" == "$adminUser" ]; then
          # Skip the root user and the sysadmin user
          continue
      fi
      # Ask the user if they want to keep the user only if the user can login
      if [ $(echo $line | cut -d: -f7) != "/sbin/nologin" ] || [ $(echo $line | cut -d: -f7) != "$NOLOGIN" ]; then
          usermod -s $NOLOGIN $username
          passwd -l $username
      fi
    done < /etc/passwd
}

secureRootLogin() {
  # Only allow root login from console
  echo -e "\e[33mSecuring root login\e[0m"
  echo "tty1" > /etc/securetty
  chmod 700 /root
}

setUmask() {
  # Enable UMASK 077
  echo -e "\e[33mSetting UMASK\e[0m"
  echo "umask 077" >> /etc/bashrc
  umask 077
}

restrictUserCreation() {
  # Restrict user creation to root only
  echo -e "\e[33mRestricting user creation\e[0m"
  chmod 700 /usr/sbin/useradd
  chmod 700 /usr/sbin/groupadd
}

firewallSetup() {
    # Configure firewall rules using iptables
    echo -e "\e[33mSetting up firewall\e[0m"
    
    IPTABLES_SCRIPT="$SCRIPT_DIR/linux/iptables.sh"
    cat <<EOF > $IPTABLES_SCRIPT
if [[ \$EUID -ne 0 ]]
then
printf 'Must be run as root, exiting!\n'
exit 1
fi

# Empty all rules
iptables -t filter -F
iptables -t filter -X

# Block everything by default
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# Authorize already established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS (Needed for curl, and updates)
iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk
iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# SSH outbound
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

######## OUTBOUND SERVICES ###############

EOF

    chmod +x $IPTABLES_SCRIPT

    if prompt "HTTP(S) Server?" n
    then
    IS_HTTP_SERVER="y"
    cat <<-EOF >> $IPTABLES_SCRIPT
# HTTP/HTTPS (apache)
iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

EOF
    # TODO: add mod_sec and secure apache
    fi

    if prompt "DNS/NTP Server?" n
    then
    IS_DNS_SERVER="y"
    IS_NTP_SERVER="y"
    cat <<-EOF >> $IPTABLES_SCRIPT
# DNS (bind)
iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT

# NTP
iptables -t filter -A INPUT -p tcp --dport 123 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT

EOF
    # TODO: secure bind / named
    fi

    if prompt "MAIL Server?" n
    then
    IS_MAIL_SERVER="y"
    cat <<-EOF >> $IPTABLES_SCRIPT
# SMTP
iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT

# POP3
iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT

# IMAP
iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT

EOF
    # TODO: secure ?
    fi

    if prompt "Splunk Server?" n
    then
    IS_SPLUNK_SERVER="y"
    cat <<-EOF >> $IPTABLES_SCRIPT
# Splunk Web UI
iptables -t filter -A INPUT -p tcp --dport 8000 -j ACCEPT
# Splunk Forwarder
iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT
# Syslog (PA)
iptables -t filter -A INPUT -p tcp --dport 514 -j ACCEPT
EOF
    fi

    # Set firewall rules
    chmod +x $IPTABLES_SCRIPT
    bash $IPTABLES_SCRIPT

    mkdir /etc/iptables

    # Save the rules
    iptables-save > /etc/iptables/rules.v4

    #Disable firewalld
    systemctl stop firewalld
    systemctl disable firewalld

    # Create a systemd service to load the rules on boot (as a fallback for iptables-save)
    mkdir -p /etc/systemd/system/
    cat <<-EOF > /etc/systemd/system/ccdc_firewall.service
[Unit]
Description=ZDSFirewall
After=syslog.target network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $IPTABLES_SCRIPT
ExecStop=/sbin/iptables -F
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

securePermissions() {
  # Secure system permissions
  # Fix permissions (just in case)
  chown root:root /etc/group
  chmod a=r,u=rw /etc/group
  chown root:root /etc/sudoers
  chmod a=,ug=r /etc/sudoers
  chown root:root /etc/passwd
  chmod a=r,u=rw /etc/passwd
  if [ $(getent group shadow) ]; then
    chown root:shadow /etc/shadow
  else
    chown root:root /etc/shadow
  fi
  chmod a=,u=rw,g=r /etc/shadow
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

  echo "" > /etc/crontab
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

  # Disable prelinking altogether for aide
  if grep -q ^PRELINKING /etc/sysconfig/prelink
  then
    sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
  else
    echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
    echo "PRELINKING=no" >> /etc/sysconfig/prelink
  fi

  aide --init
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
}

setDNS() {
  # Set DNS
  echo -e "\e[33mSetting DNS\e[0m"
  
  INTERFACE=$(ip route | grep default | awk '{print $5}')
  sed -i '/^dns=/c\dns=1.1.1.1;9.9.9.9' /etc/NetworkManager/system-connections/$INTERFACE.nmconnection # Replace the IPs as needed
  systemctl restart NetworkManager
}

setLegalBanners() {
  replace /etc motd general/legal_banner.txt
  replace /etc issue general/legal_banner.txt
  replace /etc issue.net general/legal_banner.txt
}

setupAuditd() {
  # Auditd setup
  # Download audit rules
  wget $BASE_UEL/linux/splunk/audit.rules -O audit.rules --no-check-certificate # Change to use Kayne's rules
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
  echo -e "\e[33mSecuring grub\e[0m"
  chmod 600 /boot/grub2/grub.cfg
}

setSELinuxPolicy() {
  # Ensure SELinux is enabled and enforcing
  # Check if SELINUX is already set to enforcing
  echo -e "\e[33mSetting SELinux to enforcing\e[0m"
  if grep -q SELINUX=enforcing /etc/selinux/config
  then
      echo "SELINUX already set to enforcing"
  else
      echo "Setting SELINUX to enforcing..."
      sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
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

  #Disable CUPS (Internet Printing Protocol service), has a lot of exploits, disable it
  echo -e "\e[33mDisabling CUPS\e[0m"
  systemctl disable cups

  # Re-Disable SSH (if not already)
  echo -e "\e[33mDisabling SSH (again)\e[0m"
  systemctl disable sshd
}

setupIPv6() {
  # Check if changes were already made to the network config file
  if grep -q "IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
  then
    echo "Network config file already has IPv6 settings"
  else
    echo "Setting up IPv6..."
    echo "Enter the IPv6 address: "
    read addr
    echo "Enter the default gateway: "
    read dgw
    # get the interface name
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    echo "IPV6INIT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6ADDR=$addr" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6_DEFAULTGW=$dgw" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    systemctl restart network
  fi
}

disableRootSSH() {
  # Disable root SSH
  echo -e "\e[33mDisabling root SSH\e[0m"
  sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  systemctl restart sshd
}

initilizeClamAV() {
  # Initialize ClamAV
  echo -e "\e[33mInitializing ClamAV\e[0m"
  freshclam
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

changePasswords
createNewAdmin
installTools
backup
lockUnusedAccounts
secureRootLogin
setUmask
restrictUserCreation
firewallSetup
securePermissions
cronAndAtSecurity
stopSSH
setupAIDE
setDNS
setLegalBanners
setupAuditd
disableUncommonProtocols
disableCoreDumps
secureSysctl
secureGrub
setSELinuxPolicy
disableRootSSH
bulkRemoveServices
bulkDisableServices
setupIPv6
initilizeClamAV
backup

echo "\e[Hardening complete. Reboot to apply changes and clear in-memory beacons.\e[0m"