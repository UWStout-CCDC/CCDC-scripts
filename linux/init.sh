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

netstat -tulnp
