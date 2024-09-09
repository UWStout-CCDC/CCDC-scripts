#! /bin/sh
#
# pull.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Download scripts from github

# Quck function to grab a script from the repo
DOWNLOAD_DIR="/ccdc/scripts"
mkdir -p $DOWNLOAD_DIR/linux
mkdir -p $DOWNLOAD_DIR/general
get() {
  wget "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master/$1" -O "$DOWNLOAD_DIR/$1"
}

get linux/log_state.sh
get linux/iptables.sh
get linux/ssh.sh
  get linux/sshd_config
  get general/legal_banner.txt
get linux/splunk.sh
get linux/init.sh
get linux/teler_config.yaml
get linux/monitor.sh
