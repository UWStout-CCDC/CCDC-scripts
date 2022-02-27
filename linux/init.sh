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
SCRIPT_DIR="$CCDC_DIR/scripts"

# make directories and set current directory
mkdir -p $CCDC_DIR
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
get() {
  # only download if the file doesn't exist
  if [[ ! -f "$SCRIPT_DIR/$1" ]]
  then
    mkdir -p $(dirname "$SCRIPT_DIR/$1")
    BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts-2020/master"
    wget "$BASE_URL/$1" -O "$SCRIPT_DIR/$1"
  fi
}

# replace <dir> <file> <new file>
replace() {
  get $3
  mkdir -p $CCDC_DIR/$(dirname $2)
  cp $1/$2 $CCDC_DIR/$2.old
  cp $SCRIPT_DIR/$3 $1/$2
}

# Grab script so it's guarnteed to be in /ccdc/scripts/linux
get linux/init.sh

get linux/log_state.sh && bash $SCRIPT_DIR/linux/log_state.sh

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

#removes the ability to log on of rogue users
awk -F: '{ print "usermod -s /sbin/nologin " $1 }' /etc/passwd >> $PASSWD_SH
echo "usermod -s /bin/bash $username" >> $PASSWD_SH
echo "usermod -s /bin/bash root" >> $PASSWD_SH

groupadd wheel
groupadd sudo
useradd -G wheel,sudo -m -s /bin/bash -U $username

echo "Set $username's password"
passwd $username
echo "Set root password"
passwd root

bash $PASSWD_SH

# Current IP address. We should assume this to be correct
IP_ADDR=$(ip addr | grep -Po "inet \K172\.\d+\.\d+\.\d+")

if prompt "Is $IP_ADDR the correct IP address?" y
then
  echo "Configuring network interfaces"
else
  read -p "Enter the correct IP address: " IP_ADDR
fi

# Force sets the ip address and dns server
# TODO: Test this works on every server
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
IPTABLES_SCRIPT="$SCRIPT_DIR/iptables.sh"
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
  cat <<-EOF >> $IPTABLES_SCRIPT
  # HTTP/HTTPS (apache) iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

EOF
fi


if prompt "DNS/NTP Server?" n
then
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

# TODO: There are multiple ways to do NTP. We need to check what each server uses.
#server 172.20.240.20
# timedatectl status
replace /etc ntp.conf linux/ntp.conf

# SSH Server config
replace /etc ssh/sshd_config linux/sshd_config
# Disable all keys - sshd_config will set the server to check this file
touch /ccdc/ssh/authorized_keys

# !! DO LAST !! These will take a while

if type yum
then
  echo 'yum selected, upgrading'
  yum update && yum upgrade -y
  yum install -y ntp screen openssh-client netcat
elif type apt-get
then
  echo 'apt selected, upgrading'
  apt-get update && apt-get upgrade -y
  apt-get install -y ntp screen openssh-client netcat
else
  echo 'No package manager found'
fi

# Restart services
if type systemctl
then
  systemctl restart sshd
  systemctl restart iptables
  # TODO: Verify service name
  systemctl restart ntp

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
get linux/splunk.sh && bash $SCRIPT_DIR/linux/splunk.sh 172.20.241.20


echo "Now restart the machine to guarntee all changes apply"
