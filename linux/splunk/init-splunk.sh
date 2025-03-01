#!/bin/bash

# This script is intended as a automated setup for Splunk for the CCDC competition.
# This makes a number of changes to the system, to do a baseline setup for the system both security and Splunk wise.
# Some of the code was taken from our other scritps, other team's scripts, and from this blog: https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon

## NOTE ##
# To run any of these functions individually, run the script with the function name as an argument. For example:
# ./init-splunk.sh <function name> <args if any>
# Might error a bit but should still execute
#
# Code is in functions for easy readability and maintainability
# Got annoyed trying to reorder/copy giant blocks of code around

## TODO
# - TEST THE SCRIPT IN ENVIRONMENT
# - Make the script more monolithic
# - Double check I am not missing anything from SEMO, init.sh, or other scripts
# - Put splunk functions in a category for easier reading

################################
##    Splunk Specific Init    ##
################################

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

# make directories and set current directory
mkdir -p $CCDC_DIR
mkdir -p $CCDC_ETC
mkdir -p $SCRIPT_DIR

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

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ]
  then
    $SPLUNK_HOME/bin/splunk add monitor $1
  fi
}

restartSplunk() {
  echo -e "\e[33mRestarting Splunk\e[0m"
  $SPLUNK_HOME/bin/splunk restart
}

backup() {
  echo -e "\e[33mCreating backup\e[0m"
  if [ ! -d /ccdc/backups ]; then
    mkdir -p /ccdc/backups
  fi
  increment=$(date +%Y%m%d%H%M%S)
  # Backup the /opt/splunk/etc configuration directory
  tar -czvf /ccdc/backups/splunk-etc-$increment.tgz /opt/splunk/etc
  # Backup the /etc directory
  tar -czvf /ccdc/backups/system-etc-$increment.tgz /etc
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

#######################
## End Helper Funcs  ##
#######################

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
  read adminUser
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

webUIPassword() {
  # Changing default Splunk Web UI admin password
  echo "Enter Splunk Web UI admin password:"
  read -s admin_password
  echo "Enter new Splunk Web UI admin password:"
  read -s password
  $SPLUNK_HOME/bin/splunk edit user admin -auth admin:$admin_password -password $password
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
  if [ ! -d /tmp/sketchy_tokens ]; then
    mkdir -p /tmp/sketchy_tokens
  fi
  if [ -f /root/.xauth* ]; then
    mv /root/.xauth* /tmp/sketchy_tokens
  fi
  if [ -f /root/.splunk/authToken_splunk_8089 ]; then
    mv /root/.splunk/authToken_splunk_8089 /tmp/sketchy_tokens
  fi
}

installTools() {
  # Install tools (if not already)
  echo -e "\e[33mInstalling tools\e[0m"
  yum update -y
  yum install epel-release iptables iptables-services wget git aide net-tools audit audit-libs rkhunter clamav -y
  yum autoremove -y

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

# Dont want to use init.sh anymore, will use individual functions instead, avoids needing to download a dependency
#init() {
  # Init script
  # Download init script
  #wget $BASE_URL/linux/init.sh -O init.sh --no-check-certificate
  # Run init script
  #echo -e "\e[33mRunning init script\e[0m"
  #chmod +x init.sh
  #./init.sh
#}

#################################
##   Start Security Configs    ##
#################################

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
    if [ "$username" == "root" ] || [ "$username" == "sysadmin" ] || [ "$username" == "splunkadmin" ]; then
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
  if ! grep -q "^tty1$" /etc/securetty; then
    echo "tty1" >> /etc/securetty
  fi
  chmod 700 /root
}

setUmask() {
  # Enable UMASK 077
  echo -e "\e[33mSetting UMASK\e[0m"
  if ! grep -q "^umask 077" /etc/bashrc; then
    echo "umask 077" >> /etc/bashrc
  fi
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

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Set default policies
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow limited incoming ICMP traffic and log packets that don't fit the rules
#sudo iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 0:192 -m limit --limit 1/s --limit-burst 5 -j ACCEPT
#sudo iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 0:192 -j LOG --log-prefix "Rate-limit exceeded: " --log-level 4
#sudo iptables -A INPUT -p icmp --icmp-type echo-request -m length ! --length 0:192 -j LOG --log-prefix "Invalid size: " --log-level 4
#sudo iptables -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 1/s --limit-burst 5 -j ACCEPT
#sudo iptables -A INPUT -p icmp -j DROP

# Allow DNS traffic
iptables -A OUTPUT -p udp --dport 53 -m limit --limit 20/min --limit-burst 50 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m limit --limit 20/min --limit-burst 50 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# Allow HTTP/HTTPS traffic
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 100/min --limit-burst 200 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 100/min --limit-burst 200 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Allow Splunk-specific traffic
iptables -A INPUT -p tcp --dport 9997 -m conntrack --ctstate NEW -j ACCEPT  #Splunk Forwarders
iptables -A OUTPUT -p tcp --sport 9997 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp --dport 514 -m conntrack --ctstate NEW -j ACCEPT   #Logs from Palo
iptables -A OUTPUT -p tcp --sport 514 -m conntrack --ctstate ESTABLISHED -j ACCEPT

#sudo iptables -A INPUT -p tcp --dport 8089 -j ACCEPT   #NOT NEEDED
#sudo iptables -A OUTPUT -p tcp --sport 8089 -j ACCEPT  #NOT NEEDED

iptables -A INPUT -p tcp --dport 8000 -m conntrack --ctstate NEW -j ACCEPT  #Splunk webGUI
iptables -A OUTPUT -p tcp --sport 8000 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROP-IN:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
iptables -A OUTPUT -j LOG --log-prefix "DROP-OUT:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
EOF

  # Set firewall rules
  chmod +x $IPTABLES_SCRIPT
  bash $IPTABLES_SCRIPT

  if [ ! -d /etc/iptables ]; then
    mkdir /etc/iptables
  fi

  # Save the rules
  iptables-save > /etc/iptables/rules.v4

  #Disable firewalld
  systemctl stop firewalld
  systemctl disable firewalld

  # Create a systemd service to load the rules on boot (as a fallback for iptables-save)
  if [ ! -d /etc/systemd/system/ ]; then
    mkdir -p /etc/systemd/system/
  fi
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

  # Enable the service
  systemctl enable ccdc_firewall.service
  systemctl start ccdc_firewall.service
}

securePermissions() {
  # Secure Splunk configurations
  echo -e "\e[33mSecuring Splunk configurations\e[0m"
  chmod -R 700 "$SPLUNK_HOME/etc/system/local"
  chmod -R 700 "$SPLUNK_HOME/etc/system/default"
  chown -R splunk:splunk "$SPLUNK_HOME/etc"

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
  if [ ! -f /etc/cron.allow ]; then
    touch /etc/cron.allow
  fi
  chmod 600 /etc/cron.allow
  awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny

  echo "Locking down AT"
  if [ ! -f /etc/at.allow ]; then
    touch /etc/at.allow
  fi
  chmod 600 /etc/at.allow
  awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

  # Clear out cron jobs
  echo "" > /etc/crontab
}

clearPromptCommand() {
  # Clear the prompt command
  echo -e "\e[33mClearing prompt command\e[0m"
  unset PROMPT_COMMAND
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
  if ! grep -q "1.1.1.1" /etc/NetworkManager/system-connections/$INTERFACE.nmconnection; then
    sed -i '/^dns=/c\dns=1.1.1.1;9.9.9.9;172.20.240.20' /etc/NetworkManager/system-connections/$INTERFACE.nmconnection # Replace the IPs as needed
    systemctl restart NetworkManager
  fi
}

setLegalBanners() {
  replace /etc motd general/legal_banner.txt
  replace /etc issue general/legal_banner.txt
  replace /etc issue.net general/legal_banner.txt

#   cat > "$SPLUNK_HOME/etc/system/local/global-banner.conf" << EOF
# [BANNER_MESSAGE_SINGLETON]
# global_banner.visible = true
# global_banner.message = WARNING: NO UNAUTHORIZED ACCESS. Unauthorized users will be prosecuted and tried to the furthest extent of the law!
# global_banner.background_color = red
# EOF
}

setupAuditd() {
  # Auditd setup
  # Download audit rules
  wget $BASE_URL/linux/CustomAudit.rules -O audit.rules --no-check-certificate
  # Run auditd setup
  echo -e "\e[33mSetting up Auditd\e[0m"
  cat audit.rules > /etc/audit/audit.rules
  systemctl enable auditd.service
  systemctl start auditd.service
}

disableUncommonProtocols() {
  # Disable uncommon protocols
  echo -e "\e[33mDisabling uncommon protocols\e[0m"
  if ! grep -q "install dccp /bin/false" /etc/modprobe.d/dccp.conf; then
    echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
  fi
  if ! grep -q "install sctp /bin/false" /etc/modprobe.d/sctp.conf; then
    echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
  fi
  if ! grep -q "install rds /bin/false" /etc/modprobe.d/rds.conf; then
    echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
  fi
  if ! grep -q "install tipc /bin/false" /etc/modprobe.d/tipc.conf; then
    echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf
  fi
}

disableCoreDumps() {
  # Disable core dumps for users
  echo -e "\e[33mDisabling core dumps for users\e[0m"
  if ! grep -q "^* hard core 0" /etc/security/limits.conf; then
    echo "* hard core 0" >> /etc/security/limits.conf
  fi
}

secureSysctl() {
  # Secure sysctl.conf
  # Rules are based off expected vaules from Lynis
  echo -e "\e[33mSecuring sysctl.conf\e[0m"
  cat <<-EOF > /etc/sysctl.conf
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
  if ! grep -q SELINUX=enforcing /etc/selinux/config
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
  fi
}

disableVulnerableSplunkApps() {
  # Disable vulnerable Splunk apps
  echo -e "\e[33mDisabling vulnerable Splunk apps\e[0m"
  echo "Enter Splunk Web UI admin password:"
  read -s admin_password
  $SPLUNK_HOME/bin/splunk disable app splunk_secure_gateway -auth admin:$admin_password
  $SPLUNK_HOME/bin/splunk disable app splunk_archiver -auth admin:$admin_password
}

fixSplunkXMLParsingRCE() {
  # Fix Splunk XML parsing RCE vulnerability
  echo -e "\e[33mFixing Splunk XML parsing RCE vulnerability\e[0m"
  cd /opt/splunk/etc/system/local
  if [ ! -f web.conf ]; then
    touch web.conf
  fi

  if ! grep -q "enableSearchJobXslt = false" web.conf; then
    echo -e "[settings]\nenableSearchJobXslt = false" >> web.conf
  fi
  cd ~
}

################################
##    End Security Configs    ##
################################

setSplunkRecievers() {
  # Enable Splunk reciever
  echo -e "\e[33mEnabling Splunk receivers\e[0m"
  $SPLUNK_HOME/bin/splunk enable listen 9997 -auth admin:$password

  cat <<-EOF > "$SPLUNK_HOME/etc/system/local/inputs.conf"
#TCP input for Splunk forwarders (port 9997)
#Commented out to see listener in WebUI
[tcp://9997]
index = main
sourcetype = tcp:9997
connection_host = dns
disabled = false

[tcp://514]
sourcetype = pan:firewall
no_appending_timestamp = true
index = pan_logs
EOF
}

setupPaloApps() {
  #Add the index for Palo logs
  $SPLUNK_HOME/bin/splunk add index pan_logs

  # Install Palo Alto Networks apps
  echo -e "\e[33mInstalling Palo Alto Networks apps\e[0m"

  # Check if the Palo Alto Splunk app exists, if not, clone it
  if [ ! -d "$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks" ]; then
    git clone https://github.com/PaloAltoNetworks/SplunkforPaloAltoNetworks.git SplunkforPaloAltoNetworks
    mv SplunkforPaloAltoNetworks "$SPLUNK_HOME/etc/apps/"
  fi

  # Check if the Palo Alto Splunk add-on exists, if not, clone it
  if [ ! -d "$SPLUNK_HOME/etc/apps/Splunk_TA_paloalto" ]; then
    git clone https://github.com/PaloAltoNetworks/Splunk_TA_paloalto.git Splunk_TA_paloalto
    mv Splunk_TA_paloalto "$SPLUNK_HOME/etc/apps/"
  fi
}

disableDistrubutedSearch() {
  echo -e "\e[33mDisabling distributed search\e[0m"
  if ! grep -q "disabled = true" $SPLUNK_HOME/etc/system/local/distsearch.conf; then
    echo "[distributedSearch]" > $SPLUNK_HOME/etc/system/local/distsearch.conf
    echo "disabled = true" >> $SPLUNK_HOME/etc/system/local/distsearch.conf
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
    # get the interface name
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    echo "IPV6INIT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6ADDR=fd00:3::60/64" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6_DEFAULTGW=fd00:3::1" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
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
webUIPassword
disableSketchyTokens
installTools
backup
lockUnusedAccounts
secureRootLogin
setUmask
restrictUserCreation
firewallSetup
securePermissions
cronAndAtSecurity
clearPromptCommand
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
disableVulnerableSplunkApps
fixSplunkXMLParsingRCE
setSplunkRecievers
setupPaloApps
disableDistrubutedSearch
restartSplunk
addMonitorFiles
installGUI
disableRootSSH
bulkRemoveServices
bulkDisableServices
setupIPv6
initilizeClamAV
backup

echo "\e[32mSplunk setup complete. Reboot to apply changes and clear in-memory beacons.\e[0m"

# Only in a function so I can collapse this in my editor
functionList() {
  # List of all current functions (as of last commit)

  # Security Config Functions
  # changePasswords
  # createNewAdmin
  # installTools
  # lockUnusedAccounts
  # secureRootLogin
  # setUmask
  # restrictUserCreation
  # firewallSetup
  # securePermissions
  # cronAndAtSecurity
  # clearPromptCommand
  # stopSSH
  # setupAIDE
  # setDNS
  # setLegalBanners
  # setupAuditd
  # disableUncommonProtocols
  # disableCoreDumps
  # secureSysctl
  # secureGrub
  # setSELinuxPolicy
  # installGUI
  # bulkRemoveServices
  # bulkDisableServices
  # setupIPv6
  # disableRootSSH
  # initilizeClamAV

  # Splunk Specific Functions
  # webUIPassword
  # disableSketchyTokens
  # disableVulnerableSplunkApps
  # fixSplunkXMLParsingRCE
  # setSplunkRecievers
  # setupPaloApps
  # disableDistrubutedSearch
  # addMonitorFiles

  # List of helper functions
  # backup
  # restore
  # get
  # replace
  # monitor
  # restartSplunk

  # List of functions that are not currently being used
  # fixCentOSRepos
  # init
}