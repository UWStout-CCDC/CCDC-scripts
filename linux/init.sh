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
DOWNLOAD_DIR="$CCDC_DIR/downloads"
SCRIPT_DIR="$CCDC_DIR/scripts"

mkdir -p $CCDC_DIR
cd $CCDC_DIR
mkdir -p $DOWNLOAD_DIR
mkdir -p $SCRIPT_DIR

confirm() {
  read -r -p "$1 [Y/n]:" RES
  [[ !("$RES" =~ ^([nN]).*$) ]]
}

get() {
  mkdir -p $(dirname "$DOWNLOAD_DIR/$1")
  wget "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts-2020/master/$1" -O "$DOWNLOAD_DIR/$1"
}

prompt() {
  read -p "$1 [y/N]" ans
  case $ans in
    y|Y) true ;;
    *) false ;;
  esac
}

get linux/log_state.sh
bash $DOWNLOAD_DIR/linux/log_state.sh

#gets wanted username
echo "What would you like the admin account to be named?"
read username

PASSWD_SH=$SCRIPT_DIR/linux/passwd.sh
cat << EOF > $PASSWD_SH
if [[ $EUID -ne 0 ]]
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

# Iptables
IPTABLES_SCRIPT="$SCRIPT_DIR/iptables.sh"
cat <<EOF > $IPTABLES_SCRIPT
if [[ $EUID -ne 0 ]]
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
iptables -t filter -a output -p udp --dport 123 -j accept

# Splunk
iptables -t filter -a output -p tcp --dport 8000 -j accept
iptables -t filter -a output -p tcp --dport 8089 -j accept
iptables -t filter -a output -p tcp --dport 9997 -j accept

######## OUTBOUND SERVICES ###############

# SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

EOF

confirm "HTTP(S) Server?" && cat <<EOF >> $IPTABLES_SCRIPT
# HTTP/HTTPS (apache) iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

EOF

confirm "DNS Server?" && cat <<EOF >> $IPTABLES_SCRIPT
# DNS (bind)
iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT

EOF

confirm "MAIL Server?" && cat <<EOF >> $IPTABLES_SCRIPT
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

confirm "NTP Server?" && cat <<EOF >> $IPTABLES_SCRIPT
# NTP
iptables -t filter -A INPUT -p tcp --dport 123 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT

EOF
bash $IPTABLES_SCRIPT

# SSH Server config
get linux/sshd_config

mkdir -p $CCDC_DIR/ssh/
cp /etc/ssh/sshd_config $CCDC_DIR/ssh/sshd_config.old
cp $DOWNLOAD_DIR/linux/sshd_config /etc/ssh/sshd_config

# Disable all keys - sshd_config will set the server to check this file
touch /ccdc/ssh/authorized_keys

# Restart service
if type systemctl
then
  systemctl restart sshd
else
  service sshd restart
fi

if type yum
then
  echo 'yum selected, upgrading'
  yum update && yum upgrade -y
elif type apt-get
then
 echo 'apt selected, upgrading'
  apt-get update && apt-get upgrade -y
else
  printf 'No package manager found'
fi

# Splunk forwarder
get linux/splunk.sh
bash $DOWNLOAD_DIR/linux/splunk.sh 172.20.241.20

get general/legal_banner.txt

mkdir -p $CCDC_DIR/
cp /etc/motd $CCDC_DIR/motd.old
cp $DOWNLOAD_DIR/general/legal_banner.txt /etc/motd

# Current IP address. We should assume this to be correct
IP_ADDR=$(ip addr | grep -Po "inet \K172\.\d+\.\d+\.\d+")

if prompt "Is $IP_ADDR the correct IP address?"
then
else
  read -p "Enter the correct IP address: " IP_ADDR
fi

# Force sets the ip address and dns server
# TODO: Test this works on every server
cat << EOF > /etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
  address ${IP_ADDR}
  netmask 255.255.255.0
  gateway ${IP_ADDR%.*}.254
  dns-nameserver 172.20.240.20 172.20.242.200 9.9.9.9
EOF

# We might be able to get away with installing systemd on centos 6 to make every server the same

# There are multiple ways to do NTP. We need to check what each server uses.
#server 172.20.240.20
# timedatectl status


# Now restart the machine to guarntee all changes apply.
