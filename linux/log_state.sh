#! /bin/sh
#
# log_state.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
# 
# Script to export the current state of the machine to some files

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# All exported info will go here
EXPORT_DIR="/ccdc/state"

mkdir -p $EXPORT_DIR

echo "Netstat"
netstat -tulnp > $EXPORT_DIR/netstat

echo "Users"
awk -F':' '{
  printf("%d", $3)
  printf("\t%s", $1)
  if ($7 ~ ".*/false" || $7 ~ ".*/nologin") printf("\tnologin")
  else printf("\t%s", $7)
  printf("\t%s", $6)
  username = $1
  sprintf("grep %s /etc/shadow", username) | getline
  if ($2 ~ "\!\!?|\*") printf("\tlocked")
  else printf("\t-")
  sprintf("groups %s", username) | getline
  groups = $2
  gsub("[\t ]+", ",", groups)
  printf("\t%s", substr(groups, 2))
  print("")
}' /etc/passwd > $EXPORT_DIR/users

# Export Service status
echo "Services"
if type systemctl
then
  systemctl list-unit-files --type service > $EXPORT_DIR/installed_services
  systemctl list-units > $EXPORT_DIR/running_services
else
  service --status-all 2>&1 > $EXPORT_DIR/services
fi

# Export Ip configuration, DNS servers, NTP
echo "IP config"
ip addr > $EXPORT_DIR/ip_addr
ip route > $EXPORT_DIR/ip_route

# Export SSH server settings
cp --no-preserve=mode,ownership,timestamps /etc/ssh/sshd_config $EXPORT_DIR/sshd_config

# Export Password complexity settings
if [ -f "/etc/pam.d/system-auth" ]
then
  cp --no-preserve=mode,ownership,timestamps /etc/pam.d/system-auth $EXPORT_DIR/system-auth
fi
if [ -f "/etc/pam.d/common-password" ]
then
  cp --no-preserve=mode,ownership,timestamps /etc/pam.d/common-password $EXPORT_DIR/common-password
fi
cp --no-preserve=mode,ownership,timestamps /etc/login.defs $EXPORT_DIR/login.defs

# Export package lists
echo "Package lists"
if type apt
then
  apt list --installed | grep -v ",automatic" > $EXPORT_DIR/packages
elif type rpm
then
  rpm -qa > $EXPORT_DIR/packages
fi

# TODO
echo "System info"
touch $EXPORT_DIR/system_info
echo "# Uname" >> $EXPORT_DIR/system_info
uname -a >> $EXPORT_DIR/system_info
echo "# LSB" >> $EXPORT_DIR/system_info
lsb_release -a >> $EXPORT_DIR/system_info
echo "# Version" >> $EXPORT_DIR/system_info
cat /proc/version >> $EXPORT_DIR/system_info

echo "Sudoers"
cp /etc/sudoers $EXPORT_DIR/sudoers

echo "Cleaning up"
# set read only permissions for all of them
chmod ugoa=r $EXPORT_DIR/*

