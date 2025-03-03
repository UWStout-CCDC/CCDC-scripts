echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     Backups                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1


#!/bin/bash
# Simple Backup Script
# This script zips up the critical service directories and places the resulting
# archives directly into /etc/ftb and /etc/.tarkov.
#
# Services:
#   - Apache: /etc/httpd and /var/www
#   - Postfix: /etc/postfix
#   - Dovecot: /etc/dovecot
#   - Roundcube: /etc/roundcubemail and /usr/share/roundcubemail
#   - MariaDB: /var/lib/mysql
#
# Note: This script uses the system’s 'zip' command. Ensure it is installed.

set -e

# Define backup destination directories
BACKUP_DIR1="/etc/ftb"
BACKUP_DIR2="/etc/.tarkov"

# Create backup directories if they don't already exist.
mkdir -p "$BACKUP_DIR1" "$BACKUP_DIR2"

echo "Starting backup..."

# Backup Apache (configuration and web files)
zip -r "$BACKUP_DIR1/apache.zip" /etc/httpd /var/www
cp "$BACKUP_DIR1/apache.zip" "$BACKUP_DIR2/"
echo "Apache backup complete."

# Backup Postfix (configuration)
zip -r "$BACKUP_DIR1/postfix.zip" /etc/postfix
cp "$BACKUP_DIR1/postfix.zip" "$BACKUP_DIR2/"
echo "Postfix backup complete."

# Backup Dovecot (configuration)
zip -r "$BACKUP_DIR1/dovecot.zip" /etc/dovecot
cp "$BACKUP_DIR1/dovecot.zip" "$BACKUP_DIR2/"
echo "Dovecot backup complete."

# Backup Roundcube (configuration and web files)
zip -r "$BACKUP_DIR1/roundcubemail.zip" /etc/roundcubemail /usr/share/roundcubemail
cp "$BACKUP_DIR1/roundcubemail.zip" "$BACKUP_DIR2/"
echo "Roundcubemail backup complete."

# Backup MariaDB (data directory)
zip -r "$BACKUP_DIR1/mariadb.zip" /var/lib/mysql
cp "$BACKUP_DIR1/mariadb.zip" "$BACKUP_DIR2/"
echo "MariaDB backup complete."

echo "All backups completed successfully."
