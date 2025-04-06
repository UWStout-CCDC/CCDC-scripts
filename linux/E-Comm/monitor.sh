#!/bin/bash
BASE_URL=https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master #TODO: Update this URL to the correct branch

if [ $(whoami) != "root" ];then
  echo "THIS SCRIPT MUST BE RUN AS ROOT!"
  exit
fi

# Ensure the correct things are installed
# Check if teler is installed, the binary is in /usr/bin/teler
if [ ! -f /usr/bin/teler ]; then
  echo "Teler is not installed, installing now..."
  wget https://github.com/teler-sh/teler/releases/download/v2.0.0/teler_2.0.0_linux_amd64.tar.gz
  tar -xvf teler_2.0.0_linux_amd64.tar.gz -C /usr/bin/ teler
fi

# Check if teler config file exists, in /ccdc/etc/teler.conf
if [ ! -f /ccdc/etc/teler.conf ]; then
  echo "Teler config file does not exist, creating now..."
  mkdir -p /ccdc/etc/
  wget $BASE_URL/linux/E-Comm/teler_config.yaml -O /ccdc/etc/teler_config.yaml
fi

# Check if aide is installed
if [ ! -f /usr/sbin/aide ]; then
  echo "Aide is not installed, installing now..."
  yum install -y aide
  # Initialize the aide database
  aide --init
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

# Check if tmux is installed
if [ ! -f /usr/bin/tmux ]; then
  echo "Tmux is not installed, installing now..."
  yum install -y tmux
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
if [ ! -f /ccdc/scripts/monitor/bashrc.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/bashrc.sh -O /ccdc/scripts/monitor/bashrc.sh
fi
if [ ! -f /ccdc/scripts/monitor/binaries.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/binaries.sh -O /ccdc/scripts/monitor/binaries.sh
fi
if [ ! -f /ccdc/scripts/monitor/connections.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/connections.sh -O /ccdc/scripts/monitor/connections.sh
fi
if [ ! -f /ccdc/scripts/monitor/cronjobs.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/cronjobs.sh -O /ccdc/scripts/monitor/cronjobs.sh
fi
if [ ! -f /ccdc/scripts/monitor/file_changes.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/file_changes.sh -O /ccdc/scripts/monitor/file_changes.sh
fi
if [ ! -f /ccdc/scripts/monitor/http_logs.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/http_logs.sh -O /ccdc/scripts/monitor/http_logs.sh
fi
if [ ! -f /ccdc/scripts/monitor/logins.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/logins.sh -O /ccdc/scripts/monitor/logins.sh
fi
if [ ! -f /ccdc/scripts/monitor/processes.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/processes.sh -O /ccdc/scripts/monitor/processes.sh
fi
if [ ! -f /ccdc/scripts/monitor/monitor_bash_files.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/monitor_bash_files.sh -O /ccdc/scripts/monitor/monitor_bash_files.sh
fi
if [ ! -f /ccdc/scripts/monitor/monitor_services.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/monitor_services.sh -O /ccdc/scripts/monitor/monitor_services.sh
fi
if [ ! -f /ccdc/scripts/monitor/monitor_http.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/monitor_http.sh -O /ccdc/scripts/monitor/monitor_http.sh
fi
if [ ! -f /ccdc/scripts/monitor/service-check.sh ]; then
  wget $BASE_URL/linux/E-Comm/monitor/service-check.sh -O /ccdc/scripts/monitor/service-check.sh
fi

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
tmux new-window -t monitor:8 -n "monitor_bash_files" "bash /ccdc/scripts/monitor/monitor_bash_files.sh"
tmux new-window -t monitor:9 -n "active_services" "bash /ccdc/scripts/monitor/monitor_services.sh"
tmux new-window -t monitor:10 -n "Non SE Logs" "bash /ccdc/scripts/monitor/monitor_http.sh"
tmux new-window -t monitor:11 -n "service-check" "bash /ccdc/scripts/monitor/service-check.sh"


# attach to the tmux session
tmux attach -t monitor