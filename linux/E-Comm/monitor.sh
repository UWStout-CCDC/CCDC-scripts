#!/bin/bash
BASE_URL=https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/better-monitor.sh #TODO: Update this URL to the correct branch

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

# Install the monitor scripts
wget $BASE_URL/linux/E-Comm/monitor/bashrc.sh -O /ccdc/scripts/monitor/bashrc.sh
wget $BASE_URL/linux/E-Comm/monitor/binaries.sh -O /ccdc/scripts/monitor/binaries.sh
wget $BASE_URL/linux/E-Comm/monitor/connections.sh -O /ccdc/scripts/monitor/connections.sh
wget $BASE_URL/linux/E-Comm/monitor/cronjobs.sh -O /ccdc/scripts/monitor/cronjobs.sh
wget $BASE_URL/linux/E-Comm/monitor/file_changes.sh -O /ccdc/scripts/monitor/file_changes.sh
wget $BASE_URL/linux/E-Comm/monitor/http_logs.sh -O /ccdc/scripts/monitor/http_logs.sh
wget $BASE_URL/linux/E-Comm/monitor/logins.sh -O /ccdc/scripts/monitor/logins.sh
wget $BASE_URL/linux/E-Comm/monitor/processes.sh -O /ccdc/scripts/monitor/processes.sh




# Create a new tmux session
tmux new-session -d -s monitor

# create a new window for each script
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/bashrc.sh" C-m
tmux split-window -h -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/binaries.sh" C-m
tmux split-window -v -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/connections.sh" C-m
tmux split-window -v -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/cronjobs.sh" C-m
tmux split-window -v -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/file_changes.sh" C-m
tmux split-window -v -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/http_logs.sh" C-m
tmux split-window -v -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/logins.sh" C-m
tmux split-window -v -t monitor
tmux send-keys -t monitor "bash /ccdc/scripts/monitor/processes.sh" C-m

# attach to the tmux session
tmux attach -t monitor