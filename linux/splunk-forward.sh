#!/bin/bash

# Splunk Universal Forwarder installation script for Linux

# Script taken from https://github.com/SEMO-Cyber/CyberDefenseTeamPrep/blob/main/Splunk/linuxSplunkForwarderInstall.sh
# Modified slightly to work better for our use case

# Define Splunk Forwarder variables
# Splunk UF 9.4.0 download link: https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz
SPLUNK_VERSION="9.4.0"
SPLUNK_BUILD="6b4ebe426ca6"
SPLUNK_PACKAGE_TGZ="splunkforwarder-$SPLUNK_VERSION-$SPLUNK_BUILD-linux-amd64.tgz"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/$SPLUNK_VERSION/linux/$SPLUNK_PACKAGE_TGZ"
INSTALL_DIR="/opt/splunkforwarder"
INDEXER_IP="172.20.241.20"
RECEIVER_PORT="9997"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=$(openssl rand -base64 64)
# Fileter out special characters from the password
ADMIN_PASSWORD=$(echo "$ADMIN_PASSWORD" | tr -cd '[:alnum:]')


# Pretty colors :)
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'  #No Color - resets the color back to default

# Make sure this is being run as root or sudo
if [[ $EUID -ne 0 ]]; then
    echo "${RED}This script must be run as root or with sudo.${NC}"
    exit 1
fi

# Check the OS and install the necessary packageå
if [ -f /etc/os-release ]; then
  . /etc/os-release
else
  echo "${RED}Unable to detect the operating system. Aborting.${NC}"
  exit 1
fi

# Output detected OS
echo "${GREEN}Detected OS ID: $ID ${NC}"

# Function to create the Splunk user and group
create_splunk_user() {
  if ! id -u splunk &>/dev/null; then
    echo "${BLUE}Creating splunk user and group...${NC}"
    sudo groupadd splunk
    sudo useradd -r -g splunk -d $INSTALL_DIR splunk
  else
    echo "${GREEN}Splunk user already exists.${NC}"
  fi
}

# Function to install Splunk Forwarder
# Blame the length on CentOS 
install_splunk() {
  local max_retries=3
  local retry_count=0
  local download_success=false

  echo "${BLUE}Downloading Splunk Forwarder tarball...${NC}"

  while [ $retry_count -lt $max_retries ] && [ $download_success = false ]; do
    if [ $retry_count -eq 0 ]; then
      # First attempt: Try with certificate verification
      wget -O $SPLUNK_PACKAGE_TGZ $SPLUNK_DOWNLOAD_URL
      local status=$?
    else
      # Subsequent attempts: Try without certificate verification
      echo "${YELLOW}Certificate verification failed, attempting download without certificate check...${NC}"
      wget --no-check-certificate -O $SPLUNK_PACKAGE_TGZ $SPLUNK_DOWNLOAD_URL
      local status=$?
    fi

    if [ $status -eq 0 ]; then
      download_success=true
    else
      retry_count=$((retry_count + 1))
      echo "${RED}Download failed (attempt $retry_count/$max_retries). Retrying in 5 seconds...${NC}"
      sleep 5
    fi
  done

  if [ $download_success = false ]; then
    echo "${RED}All download attempts failed. Aborting installation.${NC}"
    return 1
  fi

  echo "${BLUE}Extracting Splunk Forwarder tarball...${NC}"
  sudo tar -xvzf $SPLUNK_PACKAGE_TGZ -C /opt
  rm -f $SPLUNK_PACKAGE_TGZ

  echo "${BLUE}Setting permissions...${NC}"
  create_splunk_user
  sudo chown -R splunk:splunk $INSTALL_DIR
}


# Function to set admin credentials
set_admin_credentials() {
  echo "${BLUE}Setting admin credentials...${NC}"
  USER_SEED_FILE="$INSTALL_DIR/etc/system/local/user-seed.conf"
  sudo bash -c "cat > $USER_SEED_FILE" <<EOL
[user_info]
USERNAME = $ADMIN_USERNAME
PASSWORD = $ADMIN_PASSWORD
EOL
  sudo chown splunk:splunk $USER_SEED_FILE
  echo "${GREEN}Admin credentials set.${NC}"
}

# Function to set up OS-specific monitors
setup_monitors() {
  echo "${BLUE}Setting up monitors for $ID...${NC}"
  MONITOR_CONFIG="$INSTALL_DIR/etc/system/local/inputs.conf"
  
  case $ID in
    centos)
      OS_MONITORS="
#[default]
#host = CentOS7_Ecomm

[monitor:///var/log/yum.log]
index = main
sourcetype = package_manager

[monitor:///var/log/httpd/access_log]
index = main
sourtype = apache

[monitor:///var/log/httpd/error_log]
index = main
sourcetype = apache

[monitor:///var/log/mariadb/mariadb.log]
index = main
sourcetype = mysql

[monitor:///var/log/messages]
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
index = main
sourcetype = auth

[monitor:///var/log/syslog]
index = main
sourcetype = syslog

[monitor:///var/log/cron]
index = main
sourcetype = cron

[monitor:///var/log/secure]
index = main
sourecetype = secure

#Test log
[monitor:///tmp/test.log]
index = main
sourcetype = test"
      ;;
      
    fedora)
      OS_MONITORS="
#[default]
#host = Fedora21_Webmail

[monitor:///var/log/maillog]
index = main
sourcetype = postfix

[monitor:///var/log/dovecot.log]
index = main
sourcetype = dovecot

[monitor:///var/log/mariadb/mariadb.log]
index = main
sourcetype = mysql

#IT IS RECOMMENDED THAT YOU DISABLE ROUNDCUBE AND HTTPD. AS OF 2025 QUALS, IT IS NOT SCORED
[monitor:///var/log/roundcubemail/errors]
index = main

[monitor:///var/log/httpd/access_log]
index = main
sourcetype = apache

[monitor:///var/log/httpd/error_log]
index = main
sourcetype = apache

[monitor:///var/log/cron]
index = main
sourcetype = cron

[monitor:///var/log/messages]
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
index = main
sourcetype = auth

[monitor:///var/log/secure]
index = main
sourecetype = secure

[monitor:///var/log/syslog]
index = main
sourcetype = syslog

#Test log
[monitor:///tmp/test.log]
index = main
sourcetype = test"
    ;;
      
    ubuntu)
      OS_MONITORS="
#[default]
#host = Ubuntu18_Web

[monitor:///var/log/apache2/access.log]
index = main
sourcetype = apache

[monitor:///var/log/apache2/error.log]
index = main
sourcetype = apache

[monitor:///var/log/apt/history.log]
index = main
sourcetype = package_manager

[monitor:///var/log/messages]
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
index = main
sourcetype = auth

[monitor:///var/log/syslog]
index = main
sourcetype = syslog

#Test log
[monitor:///tmp/test.log]
index = main
sourcetype = test"
      ;;
      
    debian)
      OS_MONITORS="
#[default]
#host = Debian_Bind9

[monitor:///var/log/dns/queries]
index = main
sourcetype = bind9
recursive = true

[monitor:///var/log/ntpstats/*]
index = main
sourcetype = ntp
recursive = true

[monitor:///var/log]
index = main
sourcetype = syslog

[monitor:///var/log/messages]
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
index = main
sourcetype = auth

[monitor:///var/log/syslog]
index = main
sourcetype = syslog

#Test log
[monitor:///tmp/test.log]
index = main
sourcetype = test"
      ;;
    *)
      OS_MONITORS=""
      ;;
  esac

  # Write the configuration. This is donat using cat and EOL to improve flexibility and customization.
  sudo bash -c "cat > $MONITOR_CONFIG" <<EOL
$OS_MONITORS
EOL

  sudo chown splunk:splunk $MONITOR_CONFIG
  echo "${GREEN}Monitors configured for $ID.${NC}"
}

# Function to configure the forwarder to send logs to the Splunk indexer
configure_forwarder() {
  echo "${BLUE}Configuring Splunk Universal Forwarder to send logs to $INDEXER_IP:$RECEIVER_PORT...${NC}"
  sudo $INSTALL_DIR/bin/splunk add forward-server $INDEXER_IP:$RECEIVER_PORT -auth $ADMIN_USERNAME:$ADMIN_PASSWORD
  echo "${GREEN}Forward-server configuration complete.${NC}"
}

# Function to restart Splunk with timeout and retry handling
restart_splunk() {
  local max_attempts=3
  local attempt=1
  local timeout=30  # 30 seconds per attempt

  echo "${BLUE}Attempting to restart Splunk Forwarder...${NC}"

  while [ $attempt -le $max_attempts ]; do
    # Start Splunk in background and capture PID
    sudo $INSTALL_DIR/bin/splunk restart &>/dev/null &
    local splunk_pid=$!

    # Wait for timeout or process completion
    wait $splunk_pid &>/dev/null &
    local wait_pid=$!
    sleep $timeout
    kill $wait_pid &>/dev/null

    # Check if Splunk is running
    if sudo $INSTALL_DIR/bin/splunk status | grep -q "running"; then
      echo "${GREEN}Splunk Forwarder successfully restarted.${NC}"
      return 0
    fi

    # If we reach here, restart failed
    echo "${YELLOW}Attempt $attempt failed. Trying again...${NC}"
    attempt=$((attempt + 1))
    sleep 5  # Brief pause before retry
  done

  # If we reach here, all attempts failed
  echo "${RED}Failed to restart Splunk after $max_attempts attempts. Please check logs for errors.${NC}"
  return 1
}

# Perform installation
install_splunk

# Set admin credentials before starting the service
set_admin_credentials

# Enable Splunk service and accept license agreement
if [ -d "$INSTALL_DIR/bin" ]; then
  echo "${BLUE}Starting and enabling Splunk Universal Forwarder service...${NC}"
  sudo $INSTALL_DIR/bin/splunk start --accept-license --answer-yes --no-prompt
  sudo $INSTALL_DIR/bin/splunk enable boot-start

  # Add monitors
  setup_monitors

  # Configure forwarder to send logs to the Splunk indexer
  configure_forwarder

  # Restart Splunk using our new function
  if ! restart_splunk; then
    echo "${RED}Splunk Forwarder restart failed. Installation incomplete.${NC}"
    exit 1
  fi
else
  echo "${RED}Installation directory not found. Something went wrong.${NC}"
  exit 1
fi

#Create test log
echo "${BLUE}Creating test log. ${NC}"
echo "Test log entry" > /tmp/test.log
sudo setfacl -m u:splunk:r /tmp/test.log
  
# Verify installation
sudo $INSTALL_DIR/bin/splunk version

echo "${YELLOW}Splunk Universal Forwarder v$SPLUNK_VERSION installation complete with monitors and forwarder configuration!${NC}"

# CentOS-specific fixes
if [[ "$ID" == "centos" || "$ID_LIKE" == *"centos"* ]]; then
  echo "${RED}Applying CentOS-specific fixes...${NC}"

  # Remove AmbientCapabilities line from the systemd service file
  # This needs to be performed on every reboot, because CentOS. This section makes sure it's applied at install, so it can run immediately.
  SERVICE_FILE="/etc/systemd/system/SplunkForwarder.service"
  if [ -f "$SERVICE_FILE" ]; then
    sudo sed -i '/AmbientCapabilities/d' "$SERVICE_FILE"
    echo "${GREEN}Removed AmbientCapabilities line from $SERVICE_FILE ${NC}"
  fi

  # Create a systemd service to handle the fix
  FIX_SERVICE_FILE="/etc/systemd/system/splunk-fix.service"

  # Create the service file
  cat > "$FIX_SERVICE_FILE" <<EOL
[Unit]
Description=Splunk Fix Service
Before=network-online.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/usr/bin/sed -i '/AmbientCapabilities/d' /etc/systemd/system/SplunkForwarder.service"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

  # Enable and start the fix service
  echo "${BLUE}Enabling and starting the fix service${NC}"
  sudo systemctl daemon-reload
  sudo systemctl enable splunk-fix.service
  sudo systemctl start splunk-fix.service

  # Verify the fix service status
  echo "${BLUE}Verifying fix service status: ${NC}"
  sudo systemctl status splunk-fix.service

  # Reload systemd daemon
  echo "${BLUE}Reloading systemctl daemons${NC}"
  sudo systemctl daemon-reload

  # Run Splunk again
  echo "${BLUE}Restarting the Splunk Forwarder${NC}"
  sudo systemctl restart SplunkForwarder

  echo "${YELLOW}Restart complete, forwarder installation on CentOS complete${NC}}"
else
  echo "${GREEN}Operating system not recognized as CentOS. Skipping CentOS fix.${NC}"
fi

# Fedora specific fix. The forwarder doesn't like to work when you install it. For some reason, rebooting just solves this so nicely
# I've looked for logs, tried starting it manually, etc. I couldn't figure it out and am running out of time. Therefore, this beautiful addition.
# This will reboot the machine after a 10 second timer.
if [[ "$ID" == "fedora" ]]; then
  echo "${RED}Fedora system detected, a system reboot is required.${NC}"

  # Reboot with 10 second delay
  # if ! sudo shutdown -r +0 "${GREEN}First reboot attempt failed. System will reattempt in 5 seconds${NC}" & sleep 5; then
  #   echo "${RED}Warning: Graceful reboot failed, attempting forced reboot${NC}"
  #   if ! sudo reboot -f; then
  #     echo "${RED}Error: Unable to initiate reboot. Manual reboot required.${NC}"
  #     exit 1
  #   fi
  # fi
fi