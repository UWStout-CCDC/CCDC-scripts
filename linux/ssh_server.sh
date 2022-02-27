#! /bin/sh
#
# ssh_server.sh
# Copyright (C) 2022 matthew <matthew@WINDOWS-05HIC4F>
#
# Distributed under terms of the MIT license.
#


if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Definitions
CCDC_DIR="/ccdc"
DOWNLOAD_DIR="$CCDC_DIR/downloads"
SCRIPT_DIR="$CCDC_DIR/scripts"

if type apt-get
then
  apt-get install -y openssh-server
else
  echo "!! This script was designed for the Ubuntu Web server !!"
  exit
fi

IPTABLES_SCRIPT="$SCRIPT_DIR/iptables.sh"
cat <<-EOF >> $IPTABLES_SCRIPT
# Ubuntu Web SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
EOF
bash $IPTABLES_SCRIPT

# How to transfer SSH keys across the network. Netcat can be used to create ad-hoc TCP connections.
# We create a netcat TCP listener (which only listens for one connection) and use netcat to transfer
# the public key across the network.
# nc -4lN -p 8000 > output

# Once we transfer the public key to the ubuntu web server, we can verify it's correct and enable it
# as an authorized ssh key. Then we can use rsync to transfer the files over ssh to the ubuntu web
# to act as a backup server
