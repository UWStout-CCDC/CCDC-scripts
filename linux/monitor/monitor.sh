#!/bin/bash
BASE_URL=https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master #TODO: Update this URL to the correct branch

if [ $(whoami) != "root" ];then
  echo "THIS SCRIPT MUST BE RUN AS ROOT!"
  exit
fi

# check which package manager is installed and install net-tools and psmisc if not installed
if [ -z "$(which apt)" ]; then
    if [ -z "$(which yum)" ]; then
        if [ -z "$(which dnf)" ]; then
            echo -e "\e[31mNo package manager found\e[0m"
        else
            if [ -z "$(which netstat)" ]; then
                dnf install net-tools -y
            fi
            if [ -z "$(which pstree)" ]; then
                dnf install psmisc -y
            fi
            if [ -z "$(which aide)" ]; then
                dnf install aide -y
            fi
            if [ -z "$(which tmux)" ]; then
                dnf install tmux -y
            fi
        fi
    else
        if [ -z "$(which netstat)" ]; then
            yum install netstat -y
        fi
        if [ -z "$(which pstree)" ]; then
            yum install psmisc -y
        fi
        if [ -z "$(which aide)" ]; then
            yum install aide -y
        fi
        if [ -z "$(which tmux)" ]; then
            yum install tmux -y
        fi
    fi
else
    if [ -z "$(which netstat)" ]; then
        apt install net-tools -y
    fi
    if [ -z "$(which pstree)" ]; then
        apt install psmisc -y
    fi
    if [ -z "$(which aide)" ]; then
        apt install aide -y
    fi
    if [ -z "$(which tmux)" ]; then
        apt install tmux -y
    fi
fi

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