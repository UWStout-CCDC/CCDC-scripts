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

prompt() {
  read -p "$1 [y/N]" ans
  case $ans in
    y|Y) true ;;
    *) false ;;
  esac
}

#gets wanted username
echo "What would you like the admin account to be named?"
read username

cat << EOF > output.sh
if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi
EOF

#removes the ability to log on of rogue users
awk -F: '{ print "usermod -s /sbin/nologin " $1 }' /etc/passwd >> output.sh
echo "usermod -s /bin/bash $username" >> output.sh
echo "usermod -s /bin/bash root" >> output.sh

groupadd wheel
groupadd sudo
useradd -G wheel,sudo -m -s /bin/bash -U $username

echo "Set $username's password"
passwd $username
echo "Set root password"
passwd root

bash output.sh
bash /ccdc/scripts/linux/iptables.sh

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
bash /ccdc/scripts/linux/splunk.sh

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
