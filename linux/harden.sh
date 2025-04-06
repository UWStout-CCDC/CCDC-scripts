#!/bin/bash

# This script is intended as a automated hardening script for systems we may not have previous knowledge of in the CCDC environment.
# This makes a number of changes to the system to do a baseline setup for the system
# Some of the code was taken from our other scritps, other team's scripts, ai, and from this blog: https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon

###############################
##    Linux Agnostic Init    ##
###############################

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

# Color Variables
RED='\033[0;31m'
NC='\033[0m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'

# make directories and set current directory if they don't exist
[ ! -d "$CCDC_DIR" ] && mkdir -p $CCDC_DIR
[ ! -d "$CCDC_ETC" ] && mkdir -p $CCDC_ETC
[ ! -d "$SCRIPT_DIR" ] && mkdir -p $SCRIPT_DIR

# Detect OS
if command -v yum &> /dev/null; then
  PKG_MANAGER="yum"
elif command -v apt-get &> /dev/null; then
  PKG_MANAGER="apt-get"
elif command -v dnf &> /dev/null; then
  PKG_MANAGER="dnf"
else
  PKG_MANAGER="unknown"
fi

sendLog "Detected package manager: $PKG_MANAGER"

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

checkImmutable() {
  # Moves the chattr command to a different location if it exists
  if [ -f /bin/chattr ] || [ -f /usr/bin/chattr ]; then
    if [ -f /bin/chattr ]; then
      mv /bin/chattr /tmp/chattr
      sendLog "Moved /bin/chattr"
    fi
    if [ -f /usr/bin/chattr ]; then
      mv /usr/bin/chattr /tmp/chattr
      sendLog "Moved /usr/bin/chattr"
    fi
  fi

  # Check if the file is immutable and remove the immutable flag
  if [ -f $1 ] || [ -d $1 ];
  then
    if lsattr $1 | grep -q 'i'
    then
      /tmp/chattr -R -i $1
    fi
  fi
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
  # Restore the newest /etc configuration directory
  tar -xzvf /ccdc/backups/system-etc-$newestSystem.tgz -C /
}

sendLog(){
  if [ ! -f $LOGFILE ]; then
    mkdir -p $CCDC_DIR/logs
    touch $LOGFILE
  fi
  if [ -z "$1" ]; then
    echo "No message provided to log"
    return 1
  fi
  echo "$(date +"%x %X") - $1" >> $LOGFILE
}

sendError(){
  if [ ! -f $LOGFILE ]; then
    touch $LOGFILE
  fi
  if [ -z "$1" ]; then
    echo "No message provided to log"
    return 1
  fi
  echo "$RED$(date +"%x %X") - ERROR: $1$NC" >> $LOGFILE
}

#######################
## End Helper Funcs  ##
#######################

changePasswords() {
  echo -e "\e[33mChanging passwords\e[0m"
  # Set root password
  echo "Change passwords? (y/n)"
  read changePass
  if [ "$changePass" == "y" ]; then
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

    # If sysadmin exists set password
    if id "sysadmin" &>/dev/null; then
      echo "sysadmin user exists, setting password"
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
    else
      sendLog "sysadmin user does not exist, skipping!"
    fi
  else 
    sendLog "Skipping password change"
  fi
}

createNewAdmin() {
  echo -e "\e[33mCreating new admin user\e[0m"
  echo "Create new admin user? (y/n)"
  read createAdmin
  if [ "$createAdmin" == "y" ]; then
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
  else
    sendLog "Skipping admin user creation"
  fi
}

fixCentOSRepos() {
  # Fix repos preemtively (if CentOS)
  get linux/splunk/CentOS-Base.repo
  echo -e "\e[33mFixing repos\e[0m"
  cd ~
  mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
  cp $SCRIPT_DIR/linux/splunk/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
  yum clean all
  rm -rf /var/cache/yum
  yum makecache

  # Update CA certs
  echo -e "\e[33mUpdating CA certificates\e[0m"
  yum update -y ca-certificates
}

updateSystem() {
  # Update the system
  echo -e "\e[33mUpdating system\e[0m"
  case "$PKG_MANAGER" in
    yum)
      yum update -y
      ;;
    apt-get)
      apt-get update -y && apt-get upgrade -y
      ;;
    dnf)
      dnf update -y
      ;;
    *)
      sendError "Unsupported package manager: $PKG_MANAGER"
      exit 1
      ;;
  esac
}

installTools() {
  # Install tools based on detected distro
  echo -e "\e[33mInstalling tools\e[0m"
  case "$PKG_MANAGER" in
    yum|dnf)
      #Check for CentOS, will fix repos preemtively if it is
      if [ -f /etc/centos-release ]; then
        fixCentOSRepos
      fi
      $PKG_MANAGER install epel-release -y
      $PKG_MANAGER install iptables iptables-services git aide net-tools audit audit-libs rkhunter clamav -y
      ;;
    apt-get)
      apt-get update -y
      apt-get install iptables git aide net-tools auditd rkhunter clamav -y
      ;;
    *)
      sendError "Unsupported package manager: $PKG_MANAGER"
      exit 1
      ;;
  esac

  # Install Lynis
  if [ ! -f /ccdc/lynis ]; then
      cd /ccdc # Put lynis in a common location so it is not in the root home
      git clone https://github.com/CISOfy/lynis
      cd ~
  fi

  # Install Monitor Script
  if [ ! -f /ccdc/scripts/monitor.sh ]; then
      get linux/monitor/monitor.sh
      chmod +x /ccdc/scripts/linux/monitor/monitor.sh
  fi
}

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
      # Skip the root, sysadmin, and splunkadmin users
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

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROP-IN:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
iptables -A OUTPUT -j LOG --log-prefix "DROP-OUT:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence

# Bad Flag Combinations
# Prevent an attacker from sending flags for reconnaissance. 
# These kinds of packets  typically are not done as an attack.
iptables -N BAD_FLAGS
iptables -A INPUT -p tcp -j BAD_FLAGS

# Fragmented Packets
iptables -A INPUT -f -j LOG --log-prefix "IT Fragmented "
iptabes -A INPUT -f -j DROP

# NOT SURE WHAT THIS DOES, THINGS BREAK WITHOUT IT
iptables -I INPUT -m u32 --u32 "4 & 0x8000 = 0x8000" -j DROP

######## OUTBOUND SERVICES ###############
EOF

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

cronjail() {
  #////////////////////////////////////////
  # cronjail
  #////////////////////////////////////////
  # We will move all cron jobs to a jail directory so they can be reviewed before being re-enabled
  # Check if the cron jail directory exists, if it does not, create it
  if [ ! -d "$CCDC_ETC/cron.jail" ]; then
    mkdir -p $CCDC_ETC/cron.jail
  fi

  # Move all cron jobs to the jail directory in a folder indicating where they came from
  if [ -f "/etc/cron.deny" ]; then
    mv /etc/cron.deny $CCDC_ETC/cron.jail
    cat /dev/null > /etc/cron.deny
    sendLog "cron.deny moved to $CCDC_ETC/cron.jail"
  fi

  # if there is a cron.deny.rpmsave file, copy it to the jail directory, and rename it to cron.deny
  if [ -f "/etc/cron.deny.rpmsave" ]; then
    cp /etc/cron.deny.rpmsave $CCDC_ETC/cron.jail
    cat /dev/null > /etc/cron.deny.rpmsave
    mv /etc/cron.deny.rpmsave /etc/cron.deny
    sendLog "cron.deny.rpmsave moved to $CCDC_ETC/cron.jail"
  fi

  if [ -f "/etc/cron.allow" ]; then
    mv /etc/cron.allow $CCDC_ETC/cron.jail
    cat /dev/null > /etc/cron.allow
    sendLog "cron.allow moved to $CCDC_ETC/cron.jail"
  fi

  if [ -f "/etc/crontab" ]; then
    mv /etc/crontab $CCDC_ETC/cron.jail
    cat /dev/null > /etc/crontab
    sendLog "crontab moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/etc/cron.d" ] && [ "$(ls -A /etc/cron.d)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/cron.d
    mv /etc/cron.d/* $CCDC_ETC/cron.jail/cron.d
    sendLog "cron.d moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/etc/cron.daily" ] && [ "$(ls -A /etc/cron.daily)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/daily
    mv /etc/cron.daily/* $CCDC_ETC/cron.jail/daily
    sendLog "cron.daily moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/etc/cron.hourly" ] && [ "$(ls -A /etc/cron.hourly)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/hourly
    mv /etc/cron.hourly/* $CCDC_ETC/cron.jail/hourly
    sendLog "cron.hourly moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/etc/cron.monthly" ] && [ "$(ls -A /etc/cron.monthly)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/monthly
    mv /etc/cron.monthly/* $CCDC_ETC/cron.jail/monthly
    sendLog "cron.monthly moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/etc/cron.weekly" ] && [ "$(ls -A /etc/cron.weekly)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/weekly
    mv /etc/cron.weekly/* $CCDC_ETC/cron.jail/weekly
    sendLog "cron.weekly moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/var/spool/cron" ] && [ "$(ls -A /var/spool/cron)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/spool
    mv /var/spool/cron/* $CCDC_ETC/cron.jail/spool
    sendLog "cron spool moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/var/spool/at" ] && [ "$(ls -A /var/spool/at)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/at
    mv /var/spool/at/* $CCDC_ETC/cron.jail/at
    sendLog "at spool moved to $CCDC_ETC/cron.jail"
  fi

  if [ -d "/var/spool/atjobs" ] && [ "$(ls -A /var/spool/atjobs)" ]; then
    mkdir -p $CCDC_ETC/cron.jail/atjobs
    mv /var/spool/atjobs/* $CCDC_ETC/cron.jail/atjobs
    sendLog "atjobs spool moved to $CCDC_ETC/cron.jail"
  fi

  # Restart the cron service
  systemctl restart crond 2>/dev/null
  systemctl restart cron 2>/dev/null
  # Restart the atd service
  systemctl restart atd 2>/dev/null
  sendLog "Cron and atd services restarted"
}

check_for_malicious_bash() {
  # we need to check all of the bash configuration files to see if they ever set a trap, or set PROMPT_COMMAND
  # if they do, we need to check the contents of the trap or PROMPT_COMMAND and print them to a file, and remove them

  # Check if logs directory exists
  if [ ! -d /ccdc ]; then
      mkdir -p /ccdc/logs
  fi

  for FILE in /etc/bashrc /etc/profile /etc/profile.d/* /root/.bashrc /root/.bash_profile /root/.bash_logout /home/*/.bashrc /home/*/.bash_profile /home/*/.bash_logout /etc/bash.bashrc /etc/bash.bash_logout /etc/bash.bash_profile /root/.bash_login /home/*/.bash_login /root/.profile /home/*/.profile /etc/environment
  do
    if [ -f "$FILE" ]; then
      # check if the file contains a trap or PROMPT_COMMAND
      if grep -q "trap" "$FILE" || grep -q "PROMPT_COMMAND" $FILE || grep -q "watch" "$FILE"; then
          # get the contents of the trap or PROMPT_COMMAND
          if grep -q "^[^#]*trap" "$FILE"; then
            TRAP_CONTENT=$(grep "^[^#]*trap" "$FILE")
          fi
          if grep -q "^[^#]*PROMPT_COMMAND" "$FILE"; then
            PROMPT_COMMAND_CONTENT=$(grep "^[^#]*PROMPT_COMMAND" $FILE)
          fi
          if grep -q "^[^#]*watch" "$FILE"; then
            WATCH_CONTENT=$(grep "^[^#]*watch" $FILE)
          fi

          # remove the trap or PROMPT_COMMAND
          sed -i '/^[^#]*trap/d' "$FILE"
          # sed -i '/^[^#]*PROMPT_COMMAND/d' "$FILE" #This sometimes breaks the shell, need to further investigate
          sed -i '/^[^#]*watch/d' "$FILE"

          # print the contents of the trap or PROMPT_COMMAND to a file
          if [ -n "$TRAP_CONTENT" ]; then
            echo "$TRAP_CONTENT   Found in $FILE On $(date)" >> /ccdc/logs/malicious_bash.txt
            sendLog "Malicious trap found in $FILE"
          fi
          if [ -n "$PROMPT_COMMAND_CONTENT" ]; then
            echo "$PROMPT_COMMAND_CONTENT   Found in $FILE On $(date)" >> /ccdc/logs/malicious_bash.txt
            sendLog "Malicious PROMPT_COMMAND found in $FILE"
          fi
          if [ -n "$WATCH_CONTENT" ]; then
            echo "$WATCH_CONTENT   Found in $FILE On $(date)" >> /ccdc/logs/malicious_bash.txt
            sendLog "Malicious watch found in $FILE"
          fi
        fi
      fi
  done

  # set PROMPT_COMMAND to '', and remove any traps
  export PROMPT_COMMAND=''
  TRAPS=$(trap -p | awk '{print $NF}')
  for TRAP in $TRAPS
  do
    trap $TRAP
  done
}

stopSSH() {
  # Stop SSH
  echo -e "\e[33mStopping SSH\e[0m"
  systemctl stop sshd
  systemctl disable --now sshd
}

setupAIDE() {
  # AIDE setup
  echo -e "\e[33mSetting up AIDE\e[0m"

  # Disable prelinking altogether for aide
  if [ -f /etc/sysconfig/prelink ]; then
    if [ grep -q ^PRELINKING /etc/sysconfig/prelink ] && [ ! grep -q ^PRELINKING=no /etc/sysconfig/prelink ];
    then
      sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
    else
      echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
      echo "PRELINKING=no" >> /etc/sysconfig/prelink
    fi
  fi

  aide --init
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
}

setDNS() {
  # Set DNS
  echo -e "\e[33mSetting DNS\e[0m"
  INTERFACE=$(ip addr | awk '/state UP/ {print $2}' | cut -d: -f1)
  if command -v nmcli &> /dev/null; then
    nmcli con mod "$INTERFACE" ipv4.dns "1.1.1.1 9.9.9.9" # Replace the IPs as needed
    systemctl restart NetworkManager
  elif command -v resolvconf &> /dev/null; then
    echo "nameserver 1.1.1.1" | resolvconf -a "$INTERFACE"
    echo "nameserver 9.9.9.9" | resolvconf -a "$INTERFACE"
  else
    echo -e "nameserver 1.1.1.1\nnameserver 9.9.9.9" > /etc/resolv.conf
  fi
}

setLegalBanners() {
  replace /etc motd general/legal_banner.txt
  replace /etc issue general/legal_banner.txt
  replace /etc issue.net general/legal_banner.txt
}

setupAuditd() {
  # Auditd setup
  # Download audit rules
  get linux/CustomAudit.rules
  # Run auditd setup
  echo -e "\e[33mSetting up Auditd\e[0m"
  cat $SCRIPT_DIR/linux/CustomAudit.rules > /etc/audit/audit.rules
  systemctl start auditd.service
  systemctl enable auditd.service
}

disableUncommonProtocols() {
  # Disable uncommon protocols
  echo -e "\e[33mDisabling uncommon protocols\e[0m"
  if ! grep "install dccp /bin/false" /etc/modprobe.d/dccp.conf; then
    echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
  fi
  if ! grep "install sctp /bin/false" /etc/modprobe.d/sctp.conf; then
    echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
  fi
  if ! grep "install rds /bin/false" /etc/modprobe.d/rds.conf; then
    echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
  fi
  if ! grep "install tipc /bin/false" /etc/modprobe.d/tipc.conf; then
    echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf
  fi
}

disableCoreDumps() {
  # Disable core dumps for users
  echo -e "\e[33mDisabling core dumps for users\e[0m"
  if ! grep "^* hard core 0" /etc/security/limits.conf; then
    echo "* hard core 0" >> /etc/security/limits.conf
  fi
}

secureSysctl() {
  # Secure sysctl.conf
  # Rules are based off expected vaules from Lynis
  echo -e "\e[33mSecuring sysctl.conf\e[0m"

  if [ ! -f /etc/sysctl.conf ]; then
    touch /etc/sysctl.conf
  fi

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
  if ! grep -q SELINUX=enforcing /etc/selinux/config; then
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
  fi
}

moveBinaries() {
  # Move binaries commonly used for reverse shells to a different directory
  # Commment out lines for binaries you need and move those manually after you are done with them
  echo -e "\e[33mMoving binaries\e[0m"
  mkdir /etc/stb
  mv /usr/bin/curl /etc/stb/1
  mv /usr/bin/wget /etc/stb/2
  mv /usr/bin/ftp /etc/stb/3
  mv /usr/bin/sftp /etc/stb/4
  mv /usr/bin/aria2c /etc/stb/5
  mv /usr/bin/nc /etc/stb/6
  mv /usr/bin/socat /etc/stb/7
  mv /usr/bin/telnet /etc/stb/8
  mv /usr/bin/tftp /etc/stb/9
  mv /usr/bin/ncat /etc/stb/10
  mv /usr/bin/gdb /etc/stb/11  
  mv /usr/bin/strace /etc/stb/12 
  mv /usr/bin/ltrace /etc/stb/13
  sendLog "Binaries moved"
}

################################
##    End Security Configs    ##
################################

bulkRemoveServices() {
  ## These are done after the gui is installed as the gui sometimes reinstalls some of these services
  # Bulk remove services
  echo -e "\e[33mRemoving unneeded services\e[0m"
  yum remove xinetd telnet-server rsh-server telnet rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd dovecot squid net-snmpd postfix libgcc clang make cmake automake autoconf -y
}

bulkDisableServices() {
  # Bulk disable services
  echo -e "\e[33mDisabling unneeded services\e[0m"
  systemctl stop xinetd
  systemctl disable xinetd
  systemctl stop rexec
  systemctl disable rexec
  systemctl stop rsh
  systemctl disable rsh
  systemctl stop rlogin
  systemctl disable rlogin
  systemctl stop ypbind
  systemctl disable ypbind
  systemctl stop tftp
  systemctl disable tftp
  systemctl stop certmonger
  systemctl disable certmonger
  systemctl stop cgconfig
  systemctl disable cgconfig
  systemctl stop cgred
  systemctl disable cgred
  systemctl stop cpuspeed
  systemctl disable cpuspeed
  systemctl enable irqbalance
  systemctl stop kdump
  systemctl disable kdump
  systemctl stop mdmonitor
  systemctl disable mdmonitor
  systemctl stop messagebus
  systemctl disable messagebus
  systemctl stop netconsole
  systemctl disable netconsole
  systemctl stop ntpdate
  systemctl disable ntpdate
  systemctl stop oddjobd
  systemctl disable oddjobd
  systemctl stop portreserve
  systemctl disable portreserve
  systemctl enable psacct
  systemctl stop qpidd
  systemctl disable qpidd
  systemctl stop quota_nld
  systemctl disable quota_nld
  systemctl stop rdisc
  systemctl disable rdisc
  systemctl stop rhnsd
  systemctl disable rhnsd
  systemctl stop rhsmcertd
  systemctl disable rhsmcertd
  systemctl stop saslauthd
  systemctl disable saslauthd
  systemctl stop smartd
  systemctl disable smartd
  systemctl stop sysstat
  systemctl disable sysstat
  systemctl enable crond
  systemctl stop atd
  systemctl disable atd
  systemctl stop nfslock
  systemctl disable nfslock
  systemctl stop named
  systemctl disable named
  systemctl stop dovecot
  systemctl disable dovecot
  systemctl stop squid
  systemctl disable squid
  systemctl stop snmpd
  systemctl disable snmpd
  systemctl stop postfix
  systemctl disable postfix

  # Disable rpc
  echo -e "\e[33mDisabling rpc services\e[0m"
  systemctl disable rpcgssd
  systemctl disable rpcgssd
  systemctl disable rpcsvcgssd
  systemctl disable rpcsvcgssd
  systemctl disable rpcbind
  systemctl disable rpcidmapd

  # Disable Network File Systems (netfs)
  echo -e "\e[33mDisabling netfs\e[0m"
  systemctl stop netfs
  systemctl disable netfs

  # Disable Network File System (nfs)
  echo -e "\e[33mDisabling nfs\e[0m"
  systemctl stop nfs
  systemctl disable nfs

  #Disable CUPS (Internet Printing Protocol service), has a lot of exploits, disable it
  echo -e "\e[33mDisabling CUPS\e[0m"
  systemctl stop cups
  systemctl disable cups

  # Re-Disable SSH (if not already)
  echo -e "\e[33mDisabling SSH (again)\e[0m"
  systemctl stop sshd
  systemctl disable sshd
}

disableRootSSH() {
  # Disable root SSH
  echo -e "\e[33mDisabling root SSH\e[0m"
  if ! grep "PermitRootLogin yes" /etc/ssh/sshd_config; then
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  fi
}

initilizeClamAV() {
  # Initialize ClamAV
  echo -e "\e[33mInitializing ClamAV\e[0m"
  if [ which freshclam ]; then
    freshclam
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

if [[ "$1" == "check"]]; then
  echo -e "\e[33mChecking $2 for immutability!\e[0m"
  checkImmutable $2
  exit 0
fi

#######################
##   Main Runnables  ##
#######################

# Start script error logging
exec 2> /ccdc/harden.log

# Start the scripts for these to take care of the low hanging persistent right off the rip
cronjail &
check_for_malicious_bash &

wait

changePasswords # Should have already changed the passwords for root and sysadmin before running this so that you can skip this section
createNewAdmin
installTools
firewallSetup
lockUnusedAccounts
backup # Backup here so that we have a baseline before we start making changes
restrictUserCreation
disableRootSSH
stopSSH
cronAndAtSecurity
secureRootLogin
setUmask
securePermissions
setDNS
setLegalBanners
disableUncommonProtocols
disableCoreDumps
secureSysctl
secureGrub
setSELinuxPolicy
updateSystem
bulkRemoveServices
bulkDisableServices

initilizeClamAV > /dev/null 2>&1 &
clamav_pid=$!
setupAIDE > /dev/null 2>&1 &
aide_pid=$!
setupAuditd > /dev/null 2>&1 &
auditd_pid=$!

moveBinaries

backup > /dev/null 2>&1 &
backup_pid=$!

#output the services that we are still waiting on, and when they complete then put an ok message next to the service
while [ -e /proc/$clamav_pid ] || [ -e /proc/$aide_pid ] || [ -e /proc/$auditd_pid ] || [ -e /proc/$ipv6_pid ] || [ -e /proc/$backup_pid ]; do
    clear
    printf "Waiting for the final services to initialize...\n\n"
    printf "Waiting for ClamAV to initialize... $(if [ ! -e /proc/$clamav_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
    printf "Waiting for AIDE to initialize... $(if [ ! -e /proc/$aide_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
    printf "Waiting for Auditd to initialize... $(if [ ! -e /proc/$auditd_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
    printf "Waiting for backup to complete... $(if [ ! -e /proc/$backup_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
    sleep 5
    # remove the last 6 lines
done


clear
printf "Waiting for the final services to initialize...\n\n"
printf "Waiting for ClamAV to initialize... [$GREEN OK $NC]\n"
printf "Waiting for AIDE to initialize... [$GREEN OK $NC]\n"
printf "Waiting for Auditd to initialize... [$GREEN OK $NC]\n"
printf "Waiting for backup to complete... [$GREEN OK $NC]\n"

# End the script logging
exec 2>&1

echo -e "\e[32mHardening complete. Reboot to apply changes and clear in-memory beacons.\e[0m"