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

#removes the ability to log on of rogue users
awk -F: ‘{ print “usermod -s /bin/nologin “ $1 }’ /etc/passwd > output.sh
echo "usermod -s /bin/bash $username" >> output.sh
echo "usermod -s /bin/bash root" >> output.sh

useradd -G wheel,sudo -m -s /bin/bash -U $username

passwd $username
