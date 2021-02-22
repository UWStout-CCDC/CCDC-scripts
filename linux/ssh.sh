#! /bin/sh
#
# ssh.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Configure installed SSH server

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

EXPORT_DIR="/ccdc/ssh"

mkdir -p $EXPORT_DIR

# Config file is `sshd_config`
cp /etc/ssh/sshd_config $EXPORT_DIR
cp /ccdc/scripts/linux/sshd_config /etc/ssh/sshd_config

# Disable all keys - sshd_config will set the server to check this file
touch /ccdc/ssh/authorized_keys

# Restart service
systemctl restart ssh

