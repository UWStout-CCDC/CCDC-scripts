#!/bin/sh
#
# init.sh
# Copyright (C) 2021 chibashr
#
# Distributed under terms of the MIT license.
# 
# Script to use during init of linux machine

#removes the ability to log on of rogue users
awk -F: ‘{ if ($3 > 1000) print “usermod -s /bin/nologin “ $1 }’ /etc/passwd > output.sh

#gets wanted username
echo "What would you like the admin account to be named?"
read username

#adds user to the wheel group
sudo usermod -a -G wheel $username

$username passwd
