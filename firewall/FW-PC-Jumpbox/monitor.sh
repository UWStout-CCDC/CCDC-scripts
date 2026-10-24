#!/bin/bash
#
# monitor.sh
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to montior the system using tmux and various scripts
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

BASE_URL=https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master #TODO: Update this URL to the correct branch

if [ $(whoami) != "root" ];then
  echo "THIS SCRIPT MUST BE RUN AS ROOT!"
  exit
fi

# install net-tools and psmisc if not installed
apt install net-tools -y
apt install psmisc -y
apt install aide -y
apt install tmux -y

# If /var/lib/aide/aide.db.gz does not exist
if [ ! -f "/var/lib/aide/aide.db.gz" ]; then
    echo "Creating aide database, this may take a few minutes"
    aide --init
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

# Check if the monitor scripts directory exists
if [ ! -d /ccdc/scripts/monitor ]; then
  echo "Monitor scripts directory does not exist, creating now..."
  mkdir -p /ccdc/scripts/monitor
fi

# Check if the tmp directory exists
if [ ! -d /ccdc/tmp ]; then
  echo "Tmp directory does not exist, creating now..."
  mkdir -p /ccdc/tmp
fi

# Install the monitor scripts
wget $BASE_URL/linux/monitor/monitor/bashrc.sh -O /ccdc/scripts/monitor/bashrc.sh
wget $BASE_URL/linux/monitor/monitor/binaries.sh -O /ccdc/scripts/monitor/binaries.sh
wget $BASE_URL/linux/monitor/monitor/connections.sh -O /ccdc/scripts/monitor/connections.sh
wget $BASE_URL/linux/monitor/monitor/cronjobs.sh -O /ccdc/scripts/monitor/cronjobs.sh
wget $BASE_URL/linux/monitor/monitor/file_changes.sh -O /ccdc/scripts/monitor/file_changes.sh
wget $BASE_URL/linux/monitor/monitor/logins.sh -O /ccdc/scripts/monitor/logins.sh
wget $BASE_URL/linux/monitor/monitor/processes.sh -O /ccdc/scripts/monitor/processes.sh

# Create a new tmux session
tmux new-session -d -s monitor

# create a new window for each script
tmux new-window -t monitor:1 -n "binaries" "bash /ccdc/scripts/monitor/binaries.sh"
tmux new-window -t monitor:2 -n "connections" "bash /ccdc/scripts/monitor/connections.sh"
tmux new-window -t monitor:3 -n "cronjobs" "bash /ccdc/scripts/monitor/cronjobs.sh"
tmux new-window -t monitor:4 -n "file_changes" "bash /ccdc/scripts/monitor/file_changes.sh"
tmux new-window -t monitor:5 -n "http_logs" "bash /ccdc/scripts/monitor/http_logs.sh"
tmux new-window -t monitor:6 -n "logins" "bash /ccdc/scripts/monitor/logins.sh"
tmux new-window -t monitor:7 -n "processes" "bash /ccdc/scripts/monitor/processes.sh"

# attach to the tmux session
tmux attach -t monitor