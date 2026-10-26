#!/bin/bash

# This script is intended as a automated setup for Splunk for the CCDC competition.
# This makes a number of changes to the system, to do a baseline setup for the system both security and Splunk wise.
# Some of the code was taken from our other scritps, other team's scripts, ai, and from this blog: https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon

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
#BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/splunk-scripting" # For testing
SPLUNK_HOME="/opt/splunk"
admin_password="changeme"
LOGFILE="$CCDC_DIR/logs/init-splunk.txt"

# Color Variables
RED='\033[0;31m'
NC='\033[0m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'

# make directories and set current directory if they don't exist
[ ! -d "$CCDC_DIR" ] && mkdir -p $CCDC_DIR
[ ! -d "$CCDC_ETC" ] && mkdir -p $CCDC_ETC
[ ! -d "$SCRIPT_DIR" ] && mkdir -p $SCRIPT_DIR

########################
##  Helper Functions  ##
########################

# get <file>
# prints the name of the file downloaded
get() {
  # only download if the file doesn't exist
  if [[ ! -f "$SCRIPT_DIR/$1" ]]
  then
    mkdir -p $(dirname "$SCRIPT_DIR/$1") 1>&2
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

  immutable=0
  # Check if the file is immutable and remove the immutable flag
  if [ -f $1 ] || [ -d $1 ];
  then
    if lsattr $1 | grep -q 'i'
    then
      immutable=1
    fi
  fi

  if [ $immutable -eq 1 ]; then
    /tmp/chattr -R -i $1
    sendLog "Removed immutable flag from $1"
  fi
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

upgradeSplunk() {
  echo -e "\e[33mUpgrading Splunk\e[0m"

  # Check if the upgradeSplunk.sh script exists
  if [ ! -f $SCRIPT_DIR/linux/splunk/upgradeSplunk.sh ]; then
    get linux/splunk/upgradeSplunk.sh
    chmod +x $SCRIPT_DIR/linux/splunk/upgradeSplunk.sh
  fi

  # Run the upgradeSplunk.sh script
  $SCRIPT_DIR/linux/splunk/upgradeSplunk.sh
}

#######################
## End Helper Funcs  ##
#######################

####################################
##  Start User/System Management  ##
####################################

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
  else 
    sendLog "Skipping password change"
  fi
}

createNewAdmin() {
  echo -e "\e[33mCreating new admin user\e[0m"
  echo "Create new admin user? (y/n)"
  read createAdmin
  if [ "$createAdmin" == "y" ]; then
    adminUser="splunkadmin"
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

webUIPassword() {
  # Changing default Splunk Web UI admin password
  # echo "Enter Splunk Web UI admin password:"
  # read -s admin_password
  echo "Enter new Splunk Web UI admin password:"
  read -s password
  $SPLUNK_HOME/bin/splunk edit user admin -auth admin:$admin_password -password $password
}

# CentOS is EOL so this likely won't ever be used anymore, uncomment if needed
#function fixCentOSRepos() {
  # Fix repos preemtively (if CentOS)
  # get linux/splunk/CentOS-Base.repo
  # echo -e "\e[33mFixing repos\e[0m"
  # cd ~
  # mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
  # cp $SCRIPT_DIR/linux/splunk/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
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

updateSystem() {
  # Update the system
  echo -e "\e[33mUpdating system\e[0m"
  yum update -y
  yum autoremove -y
}

installTools() {
  # Install tools (if not already)
  echo -e "\e[33mInstalling tools\e[0m"
  yum install epel-release -y
  yum install iptables iptables-services git aide net-tools audit audit-libs rkhunter clamav -y

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

  if [ ! -f /ccdc/scripts/upgradeSplunk.sh ]; then
      get linux/splunk/upgradeSplunk.sh
      chmod +x /ccdc/scripts/linux/splunk/upgradeSplunk.sh
  fi
}

# Dont want to use init.sh anymore, will use individual functions instead, avoids needing to download a dependency
#init() {
  # Init script
  # Download init script
  #get linux/init.sh
  # Run init script
  #echo -e "\e[33mRunning init script\e[0m"
  #chmod +x $SCRIPT_DIR/linux/init.sh
  #$SCRIPT_DIR/linux/init.sh
#}

##################################
##  End User/System Management  ##
##################################

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

# Splunk Web UI
iptables -t filter -A INPUT -p tcp --dport 8000 -j ACCEPT

# Splunk Forwarder
iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT

# Splunk Syslog (PA)
iptables -t filter -A INPUT -p tcp --dport 514 -j ACCEPT

# Bad Flag Combinations
# Prevent an attacker from sending flags for reconnaissance. 
# These kinds of packets  typically are not done as an attack.
iptables -N BAD_FLAGS
iptables -A INPUT -p tcp -j BAD_FLAGS

# Fragmented Packets
iptables -A INPUT -f -j LOG --log-prefix "IT Fragmented "
iptables -A INPUT -f -j DROP

# NOT SURE WHAT THIS DOES, THINGS BREAK WITHOUT IT
iptables -I INPUT -m u32 --u32 "4 & 0x8000 = 0x8000" -j DROP
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
  chown -R splunkadmin:splunkadmin "$SPLUNK_HOME/etc"

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
  if [ ! -d /ccdc/logs ]; then
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
          # sed -i '/^[^#]*PROMPT_COMMAND/d' "$FILE" #This sometimes breaks the shell, need to investigate further
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
  unset PROMPT_COMMAND # This is to ensure that the PROMPT_COMMAND is not set again
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
  INTERFACE=$(ip addr | grep -oP '^\d+: \Kens\S+' | sed -n 2p)
  sed -i '/^dns=/c\dns=1.1.1.1;9.9.9.9;172.20.240.20' /etc/NetworkManager/system-connections/$INTERFACE.nmconnection # Replace the IPs as needed
  systemctl restart NetworkManager
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
  if ! grep SELINUX=enforcing /etc/selinux/config; then
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
  fi
}

moveBinaries() {
  # Move binaries commonly used for reverse shells to a different directory
  # Commment out lines for binaries you need and move those manually after you are done with them
  echo -e "\e[33mMoving binaries\e[0m"
  mkdir /etc/stb
  #mv /usr/bin/curl /etc/stb/1
  #mv /usr/bin/wget /etc/stb/2
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

################################
##    Start Splunk Configs    ##
################################

configureSplunk() {
  # Disable vulnerable Splunk apps
  echo -e "\e[33mDisabling vulnerable Splunk apps\e[0m"
  if $SPLUNK_HOME/bin/splunk list app | grep -q splunk_secure_gateway; then
    $SPLUNK_HOME/bin/splunk disable app splunk_secure_gateway -auth admin:$admin_password
    sendLog "Splunk Secure Gateway disabled"
  fi
  if $SPLUNK_HOME/bin/splunk list app | grep -q splunk_archiver; then
    $SPLUNK_HOME/bin/splunk disable app splunk_archiver -auth admin:$admin_password
    sendLog "Splunk Archiver disabled"
  fi

  # Fix Splunk XML parsing RCE vulnerability
  echo -e "\e[33mFixing Splunk XML parsing RCE vulnerability\e[0m"
  cd /opt/splunk/etc/system/local
  if [ ! -f web.conf ]; then
    touch web.conf
  fi

  if ! grep "enableSearchJobXslt = false" web.conf; then
    echo -e "[settings]\nenableSearchJobXslt = false" >> web.conf
    sendLog "Splunk XML parsing RCE vulnerability fixed"
  fi
  cd ~

#   # Enable Splunk reciever
  echo -e "\e[33mEnabling Splunk receivers\e[0m"
  $SPLUNK_HOME/bin/splunk enable listen 9997 -auth admin:$password
  $SPLUNK_HOME/bin/splunk enable listen 514 -auth admin:$password

  cat <<-EOF > "$SPLUNK_HOME/etc/system/local/inputs.conf"
#TCP input for Splunk forwarders (port 9997 & 514)
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
  sendLog "Splunk receivers enabled"

  #Add the index for Palo logs
  $SPLUNK_HOME/bin/splunk add index pan_logs

  # Install Palo Alto Networks apps
  echo -e "\e[33mInstalling Palo Alto Networks apps\e[0m"

  # Check if the Palo Alto Splunk app exists, if not, clone it
  if [ ! -d "$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks" ]; then
    git clone https://github.com/PaloAltoNetworks/SplunkforPaloAltoNetworks.git SplunkforPaloAltoNetworks
    mv SplunkforPaloAltoNetworks "$SPLUNK_HOME/etc/apps/"
    sendLog "Palo Alto Splunk app installed"
  fi

  # Check if the Palo Alto Splunk add-on exists, if not, clone it
  if [ ! -d "$SPLUNK_HOME/etc/apps/Splunk_TA_paloalto" ]; then
    git clone https://github.com/PaloAltoNetworks/Splunk_TA_paloalto.git Splunk_TA_paloalto
    mv Splunk_TA_paloalto "$SPLUNK_HOME/etc/apps/"
    sendLog "Palo Alto Splunk add-on installed"
  fi

  echo -e "\e[33mDisabling distributed search\e[0m"

  if [ ! -f $SPLUNK_HOME/etc/system/local/distsearch.conf ]; then
    touch $SPLUNK_HOME/etc/system/local/distsearch.conf
  fi

  if ! grep "disabled = true" $SPLUNK_HOME/etc/system/local/distsearch.conf; then
    echo "[distributedSearch]" > $SPLUNK_HOME/etc/system/local/distsearch.conf
    echo "disabled = true" >> $SPLUNK_HOME/etc/system/local/distsearch.conf
    sendLog "Distributed search disabled"
  fi

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
  sendLog "Log files added to monitor"

  # Restart Splunk
  echo -e "\e[33mRestarting Splunk\e[0m"
  $SPLUNK_HOME/bin/splunk restart
  sendLog "Splunk restarted"

  sendLog "Splunk configured"
}

################################
##     End Splunk Configs     ##
################################

##############################
##  Finish System Configs   ##
##############################

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
    sendLog "GUI installed"
  fi
}

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

setupIPv6() {
  # Check if changes were already made to the network config file
  if grep -q "IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-*;
  then
    echo "Network config file already has IPv6 settings"
  else
    echo "Setting up IPv6..."
    # get the interface name
    INTERFACE=$(ip a | grep "2: " | awk '{print $2}' | cut -d: -f1)
    echo "IPV6INIT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6ADDR=fd00:3::60/64" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6_DEFAULTGW=fd00:3::1" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    systemctl restart NetworkManager
  fi
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

if [[ "$1" == "check" ]]; then
  echo -e "\e[33mChecking $2 for immutability!\e[0m"
  checkImmutable $2
  exit 0
fi

# Check for the update argument and update the system
if [[ "$1" == "upgrade" ]]; then
  echo -e "\e[33mStarting Splunk Upgrade!\e[0m"
  upgradeSplunk
  echo -e "\e[32mSplunk Upgrade complete!\e[0m"
  exit 0
fi

#######################
##   Main Runnables  ##
#######################

# Start script error logging
exec 2> /ccdc/init-splunk.log

# Start the scripts for these to take care of the low hanging persistent right off the rip
cronjail &
check_for_malicious_bash &

# Check if the splunk directory is immutable, red team really likes to do this
checkImmutable $SPLUNK_HOME &

wait

changePasswords # Should have already changed the passwords for root and sysadmin before running this so that you can skip this section
webUIPassword
createNewAdmin
installTools
firewallSetup
lockUnusedAccounts
restrictUserCreation
backup # Backup here so that we have a decent baseline before we start making tons of changes
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
disableSketchyTokens
configureSplunk
updateSystem
installGUI
bulkRemoveServices
bulkDisableServices

initilizeClamAV > /dev/null 2>&1 &
clamav_pid=$!
setupAIDE > /dev/null 2>&1 &
aide_pid=$!
setupAuditd > /dev/null 2>&1 &
auditd_pid=$!
setupIPv6 > /dev/null 2>&1 &
ipv6_pid=$!

# Move binaries after all changes to avoid issues. After restarting system, if the red team was using any of these binaries for scripts, they won't work anymore
# Still might be other persistence though
# These changes will be backed up in the final backup
moveBinaries

backup > /dev/null 2>&1 & # Backup again to save all our changes with our final baseline and hope to god that there isn't a ton of red team persistence saved in the backup
backup_pid=$!

#output the services that we are still waiting on, and when they complete then put an ok message next to the service
while [ -e /proc/$clamav_pid ] || [ -e /proc/$aide_pid ] || [ -e /proc/$auditd_pid ] || [ -e /proc/$ipv6_pid ] || [ -e /proc/$backup_pid ]; do
  clear
  printf "Waiting for the final services to initialize...\n\n"
  printf "Waiting for ClamAV to initialize... $(if [ ! -e /proc/$clamav_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
  printf "Waiting for AIDE to initialize... $(if [ ! -e /proc/$aide_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
  printf "Waiting for Auditd to initialize... $(if [ ! -e /proc/$auditd_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
  printf "Waiting for netconfig script to complete... $(if [ ! -e /proc/$ipv6_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
  printf "Waiting for backup to complete... $(if [ ! -e /proc/$backup_pid ]; then printf "[$GREEN OK $NC]\n"; else printf "[$RED WAITING $NC]\n"; fi)\n"
  sleep 5
done

clear
printf "Waiting for the final services to initialize...\n\n"
printf "Waiting for ClamAV to initialize... [$GREEN OK $NC]\n"
printf "Waiting for AIDE to initialize... [$GREEN OK $NC]\n"
printf "Waiting for Auditd to initialize... [$GREEN OK $NC]\n"
printf "Waiting for netconfig script to complete... [$GREEN OK $NC]\n"
printf "Waiting for backup to complete... [$GREEN OK $NC]\n"

# End the script logging
reset

echo -e "\e[32mSplunk setup complete. Reboot to apply changes and clear in-memory beacons.\e[0m"