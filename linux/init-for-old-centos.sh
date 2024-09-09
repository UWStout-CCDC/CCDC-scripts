#!/bin/sh
#
# init.sh
# Copyright (C) 2021 chibashr
#
# Distributed under terms of the MIT license.
# 
# Script to use during init of linux machine

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Definitions
CCDC_DIR="/ccdc"
CCDC_ETC="$CCDC_DIR/etc"
SCRIPT_DIR="$CCDC_DIR/scripts"

# make directories and set current directory
mkdir -p $CCDC_DIR
mkdir -p $CCDC_ETC
mkdir -p $SCRIPT_DIR
cd $CCDC_DIR

# if prompt <prompt> n; then; <cmds>; fi
# Defaults to NO
# if prompt <prompt> y; then; <cmds>; fi
# Defaults to YES
prompt() {
  case "$2" in 
    y) def="[Y/n]" ;;
    n) def="[y/N]" ;;
    *) echo "INVALID PARAMETER!!!!"; exit ;;
  esac
  read -p "$1 $def" ans
  case $ans in
    y|Y) true ;;
    n|N) false ;;
    *) [[ "$def" != "[y/N]" ]] ;;
  esac
}

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

# Grab script so it's guarnteed to be in /ccdc/scripts/linux
get linux/init.sh

# Grabs monitor.sh script for monitoring log, process, connections, etc
get linux/monitor.sh

bash $(get linux/log_state.sh)
SPLUNK_SCRIPT=$(get linux/splunk.sh)

#gets wanted username
echo "What would you like the admin account to be named?"
read username

PASSWD_SH=$SCRIPT_DIR/linux/passwd.sh
cat <<EOF > $PASSWD_SH
if [[ \$EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi
EOF

# Create custom nologin script, nologin has been replaced with a login shell in some systems
NOLOGIN=$SCRIPT_DIR/linux/nologin.sh
cat <<EOF > $NOLOGIN
#!/bin/bash
echo "This account is unavailable."
EOF
chmod a=rx $NOLOGIN

#removes the ability to log on of rogue users
awk -F: "{ print \"usermod -s $NOLOGIN \" \$1 }" /etc/passwd >> $PASSWD_SH
echo "usermod -s /bin/bash $username" >> $PASSWD_SH
echo "usermod -s /bin/bash root" >> $PASSWD_SH

groupadd wheel
groupadd sudo
cp /etc/sudoers $CCDC_ETC/sudoers
cat <<-EOF > /etc/sudoers
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
# User privilege specification
root    ALL=(ALL:ALL) ALL
$username ALL=(ALL:ALL) ALL
# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
%wheel   ALL=(ALL:ALL) ALL
# See sudoers(5) for more information on "@include" directives:
#@includedir /etc/sudoers.d
EOF

useradd -G wheel,sudo -m -s /bin/bash -U $username

echo "Set $username's password"
passwd $username
echo "Set root password"
passwd root

bash $PASSWD_SH

# Current IP address. We should assume this to be correct
IP_ADDR=$(ip addr show dev eth0 | grep -Po "inet \K\d+\.\d+\.\d+\.\d+")

if prompt "Is $IP_ADDR the correct IP address?" y
then
  echo "Configuring network interfaces"
else
  read -p "Enter the correct IP address: " IP_ADDR
fi

# Force sets the ip address and dns server
# TODO: Test this works on every server
cp /etc/network/interfaces $CCDC_ETC/interfaces
cat <<EOF > /etc/network/interfaces
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet static
  address ${IP_ADDR}
  netmask 255.255.255.0
  gateway ${IP_ADDR%.*}.254
  dns-nameserver 172.20.240.20 172.20.242.200 9.9.9.9
EOF

# Iptables
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
iptables -t filter -a OUTPUT -p udp --dport 123 -j accept
# Splunk
iptables -t filter -a OUTPUT -p tcp --dport 8000 -j accept
iptables -t filter -a OUTPUT -p tcp --dport 8089 -j accept
iptables -t filter -a OUTPUT -p tcp --dport 9997 -j accept
# SSH outbound
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
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
fi
bash $IPTABLES_SCRIPT

# Create systemd unit for the firewall
mkdir -p /etc/systemd/system/
cat <<-EOF > /etc/systemd/system/ccdc_firewall.service
[Unit]
Description=ZDSFirewall
After=syslog.target network.target
[Service]
Type=oneshot
ExecStart=$IPTABLES_SCRIPT
ExecStop=/sbin/iptables -F
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

# Set Legal banners
replace /etc motd general/legal_banner.txt
replace /etc issue general/legal_banner.txt
replace /etc issue.net general/legal_banner.txt

# Set permissions
chown -hR $username:$username $CCDC_DIR
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


# We might be able to get away with installing systemd on centos 6 to make every server the same

# !! DO LAST !! These will take a while

if type yum
then
  echo 'yum selected, upgrading'
  yum update && yum upgrade -y
  yum install -y ntp ntpdate screen openssh-client netcat
elif type apt-get
then
  echo 'apt selected, upgrading'
  apt-get update && apt-get upgrade -y
  apt-get install -y ntp ntpdate screen openssh-client netcat
else
  echo 'No package manager found'
fi

# SSH Server config
replace /etc ssh/sshd_config linux/sshd_config
# Disable all keys - sshd_config will set the server to check this file
mkdir -p /ccdc/ssh/
touch /ccdc/ssh/authorized_keys

if [[ ! -z "$IS_NTP_SERVER" ]] && type systemctl && type apt-get
then
  # TODO: There are multiple ways to do NTP. We need to check what each server uses.
  #server 172.20.240.20
  # timedatectl status
  apt-get install ntp-server
  replace /etc ntp.conf linux/ntp.conf
elif [[ ! -z "$IS_NTP_SERVER" ]]
then
  echo "NTP Servers are only supported on Debian"
else
  cp /etc/ntp.conf $CCDC_ETC/ntp.conf
  echo "
driftfile /var/lib/ntp/npt.drift
logfile /var/log/ntp.log
server 172.20.240.20 iburst
# Set hw clock as low priority
server 127.127.1.0
fudge 127.127.1.0 stratum 10
restrict -4 default kob notrap nomodify nopeer limited noquery noserve
restrict -6 default kob notrap nomodify nopeer limited noquery noserve
restrict 127.0.0.1
restrict ::1
tinker panic 0
tos maxdist 30
" > /etc/ntp.conf
fi

# Restart services
if type systemctl
then
  systemctl restart sshd
  systemctl restart iptables
  # TODO: Verify service name
  systemctl restart ntp
  systemctl enable ntp

  # Disable other firewalls
  # (--now also runs a start/stop with the enable/disable)
  systemctl disable --now firewalld
  systemctl disable --now ufw

  # Automatically apply IPTABLES_SCRIPT on boot
  systemctl enable --now ccdc_firewall.service

  # We want to use ntpd?
  systemctl disable --now systemd-timesyncd.service
  systemctl disable --now chronyd
else
  echo "!! non systemd systems are not supported !!"
  #exit
  #service sshd restart
  #service iptables restart
  # On non-systemd systems, the firewall will need to be reapplied in another way
fi

# Splunk forwarder
# We need to check to make sure this actually applies... the get sometimes fails
bash $SPLUNK_SCRIPT 172.20.241.20 


echo "Now restart the machine to guarntee all changes apply"
