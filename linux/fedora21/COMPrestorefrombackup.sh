#!/bin/bash
# Interactive Restore Script
# This script lets you choose which backup to restore from the following options:
#   - Apache (configuration and web files)
#   - Postfix (configuration)
#   - Dovecot (configuration)
#   - Roundcubemail (configuration and web files)
#   - MariaDB (data directory)
#   - Network configurations (network settings)
#   - User and authentication data (e.g. /etc/passwd, /etc/shadow, etc.)
#   - /root/COMPtools (custom tools)
#   - PHP configuration file (/etc/php.ini)
#   - PHP configuration directory (/etc/php.d)
#
# It then restores the selected archive from one of the two backup locations
# (/etc/ftb or /etc/.tarkov) into the root directory (/).
#
# WARNING: Restoring will overwrite existing files in the target directories.
# Ensure you have current backups before proceeding.

set -e

# Prompt for backup to restore
echo "Select the backup to restore:"
echo "a) Apache"
echo "b) Postfix"
echo "c) Dovecot"
echo "d) Roundcubemail"
echo "e) MariaDB"
echo "f) Network Configurations"
echo "g) User and Authentication Data"
echo "h) /root/COMPtools"
echo "i) PHP Configuration File (/etc/php.ini)"
echo "j) PHP Configuration Directory (/etc/php.d)"
read -p "Enter your choice (a-j): " service_choice

case "$service_choice" in
  a|A)
    SERVICE="apache"
    ;;
  b|B)
    SERVICE="postfix"
    ;;
  c|C)
    SERVICE="dovecot"
    ;;
  d|D)
    SERVICE="roundcubemail"
    ;;
  e|E)
    SERVICE="mariadb"
    ;;
  f|F)
    SERVICE="network_configs"
    ;;
  g|G)
    SERVICE="auth_data"
    ;;
  h|H)
    SERVICE="COMPtools"
    ;;
  i|I)
    SERVICE="php_ini"
    ;;
  j|J)
    SERVICE="phpd"
    ;;
  *)
    echo "Invalid selection. Exiting."
    exit 1
    ;;
esac

# Prompt for backup location
echo "Select the backup location to restore from:"
echo "1) /etc/ftb"
echo "2) /etc/.tarkov"
read -p "Enter your choice (1 or 2): " loc_choice

case "$loc_choice" in
  1)
    BACKUP_DIR="/etc/ftb"
    ;;
  2)
    BACKUP_DIR="/etc/.tarkov"
    ;;
  *)
    echo "Invalid selection. Exiting."
    exit 1
    ;;
esac

# Define the backup file
BACKUP_FILE="${BACKUP_DIR}/${SERVICE}.zip"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Backup file $BACKUP_FILE not found! Exiting."
  exit 1
fi

echo "Restoring $SERVICE from $BACKUP_FILE..."

# Change directory to / so that relative paths in the zip are restored correctly.
cd /

# Unzip the backup archive. The -o flag overwrites existing files.
unzip -o "$BACKUP_FILE"

echo "$SERVICE restoration completed successfully."
