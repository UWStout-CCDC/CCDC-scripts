#!/bin/bash

# Splunk Universal Forwarder installation script for Linux

# TODO:
# - TEST THE SCRIPT IN ENVIRONMENT
# - Add more log files to monitor
#   - Auditd logs primarily

# Define Splunk Forwarder variables
# Splunk UF 9.4.0 download link: https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz
SPLUNK_VERSION="9.4.0"
SPLUNK_BUILD="6b4ebe426ca6"
SPLUNK_PACKAGE_TGZ="splunkforwarder-$SPLUNK_VERSION-$SPLUNK_BUILD-linux-amd64.tgz"
SPLUNK_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/$SPLUNK_VERSION/linux/$SPLUNK_PACKAGE_TGZ"
SPLUNK_HOME="/opt/splunkforwarder"
INDEXER_IP="172.20.241.20"
RECEIVER_PORT="9997"
ADMIN_USERNAME="admin"
echo "Enter new Splunk admin password:"
read -s ADMIN_PASSWORD


RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
BLUE=$'\e[0;34m'
NC=$'\e[0m'  #No Color - resets the color back to default

# Make sure this is being run as root or 
if [[ $EUID -ne 0 ]]; then
    echo "${RED}This script must be run as root or with .${NC}"
    exit 1
fi

if [ ! -d "$SPLUNK_HOME" ]; then
  mkdir -p $SPLUNK_HOME
fi

# Quick function to check if a file exists, and monitor it
monitor() {
  if [ -f $1 ];
  then
    $SPLUNK_HOME/bin/splunk add monitor $1
  fi
}

# Function to create the Splunk user and group
create_splunk_user() {
  useradd -m splunkfwd
  groupadd splunkfwd
  passwd splunkfwd
}

# Function to install Splunk Forwarder
install_splunk() {
  echo "${BLUE}Downloading Splunk Forwarder tarball...${NC}"

  wget $SPLUNK_DOWNLOAD_URL -O $SPLUNK_PACKAGE_TGZ --no-check-certificate

  if [ -f $SPLUNK_PACKAGE_TGZ ]; then
    echo "${BLUE}Extracting Splunk Forwarder tarball...${NC}"
    tar -xvzf $SPLUNK_PACKAGE_TGZ -C /opt

    echo "${BLUE}Setting permissions...${NC}"
    create_splunk_user
    chown -R splunkfwd:splunkfwd $SPLUNK_HOME
  else
    echo "${RED}Failed to download Splunk Forwarder tarball. Installation aborted.${NC}"
    exit 1
  fi
}

# Function to set up OS-specific monitors
setup_monitors() {
  echo "${BLUE}Setting up monitors...${NC}"
  monitor /var/log/secure
  monitor /var/log/messages
  monitor /var/log/audit/audit.log
  monitor /var/log/yum.log
  monitor /var/log/cron
  monitor /var/log/boot.log
  monitor /var/log/spooler
  monitor /var/log/maillog
  monitor /var/log/httpd/access_log
  monitor /var/log/httpd/error_log
  monitor /var/log/mysqld.log
  # Add more log files to monitor here
  echo "${GREEN}Monitor setup complete.${NC}"
}

# Function to configure the forwarder to send logs to the Splunk indexer
configure_forwarder() {
  echo "${BLUE}Configuring Splunk Universal Forwarder to send logs to $INDEXER_IP:$RECEIVER_PORT...${NC}"
   $SPLUNK_HOME/bin/splunk add forward-server $INDEXER_IP:$RECEIVER_PORT -auth $ADMIN_USERNAME:$ADMIN_PASSWORD
  echo "${GREEN}Forward-server configuration complete.${NC}"
}

# Perform installation
install_splunk

# Enable Splunk service and accept license agreement
if [ -d "$SPLUNK_HOME/bin" ]; then
  echo "${BLUE}Starting and enabling Splunk Universal Forwarder service...${NC}"
  $SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt
  $SPLUNK_HOME/bin/splunk enable boot-start

  # Add monitors
  setup_monitors

  # Configure forwarder to send logs to the Splunk indexer
  configure_forwarder

  # Restart Splunk service
  echo "${BLUE}Restarting Splunk Universal Forwarder service...${NC}"
  $SPLUNK_HOME/bin/splunk restart
fi

echo "${YELLOW}Splunk Universal Forwarder v$SPLUNK_VERSION installation complete with monitors and forwarder configuration!${NC}"