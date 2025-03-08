#!/bin/bash
# Interactive Restore Script
# This script lets you choose which service to restore (Apache, Postfix,
# Dovecot, Roundcube, or MariaDB) and from which backup location (/etc/ftb
# or /etc/.tarkov). It then unzips the corresponding archive back into /.
#
# WARNING: Restoring will overwrite existing files in the target directories.
# Ensure you have current backups before proceeding.

set -e

# Prompt for service to restore
echo "Select the service to restore:"
echo "a) Apache"
echo "b) Postfix"
echo "c) Dovecot"
echo "d) Roundcubemail"
echo "e) MariaDB"
read -p "Enter your choice (a-e): " service_choice

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
