#!/bin/bash
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     Backups                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1

# Simple Backup Script


# Define backup destination directories
BACKUP_DIR1="/etc/ftb"
BACKUP_DIR2="/etc/.tarkov"

# Create backup directories if they don't already exist.
mkdir -p "$BACKUP_DIR1" "$BACKUP_DIR2"

echo "Starting backup..."

# Backup Apache (configuration and web files)
zip -r "$BACKUP_DIR1/apache.zip" /etc/httpd /var/www || echo "Warning: Apache backup encountered errors."
cp "$BACKUP_DIR1/apache.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy Apache backup to $BACKUP_DIR2."
echo "Apache backup complete."

# Backup Postfix (configuration)
zip -r "$BACKUP_DIR1/postfix.zip" /etc/postfix || echo "Warning: Postfix backup encountered errors."
cp "$BACKUP_DIR1/postfix.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy Postfix backup to $BACKUP_DIR2."
echo "Postfix backup complete."

# Backup Dovecot (configuration)
zip -r "$BACKUP_DIR1/dovecot.zip" /etc/dovecot || echo "Warning: Dovecot backup encountered errors."
cp "$BACKUP_DIR1/dovecot.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy Dovecot backup to $BACKUP_DIR2."
echo "Dovecot backup complete."

# Backup Roundcube (configuration and web files)
zip -r "$BACKUP_DIR1/roundcubemail.zip" /etc/roundcubemail /usr/share/roundcubemail || echo "Warning: Roundcubemail backup encountered errors."
cp "$BACKUP_DIR1/roundcubemail.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy Roundcubemail backup to $BACKUP_DIR2."
echo "Roundcubemail backup complete."

# Backup MariaDB (data directory)
zip -r "$BACKUP_DIR1/mariadb.zip" /var/lib/mysql || echo "Warning: MariaDB backup encountered errors."
cp "$BACKUP_DIR1/mariadb.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy MariaDB backup to $BACKUP_DIR2."
echo "MariaDB backup complete."

# Backup network configurations
zip -r "$BACKUP_DIR1/network_configs.zip" /etc/sysconfig/network /etc/sysconfig/network-scripts || echo "Warning: Network configurations backup encountered errors."
cp "$BACKUP_DIR1/network_configs.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy network configurations backup to $BACKUP_DIR2."
echo "Network configurations backup complete."

# Backup user and authentication data
zip -r "$BACKUP_DIR1/auth_data.zip" /etc/passwd /etc/shadow /etc/group /etc/gshadow || echo "Warning: Auth data backup encountered errors."
cp "$BACKUP_DIR1/auth_data.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy auth data backup to $BACKUP_DIR2."
echo "User and authentication data backup complete."

# Backup /root/COMPtools directory
zip -r "$BACKUP_DIR1/COMPtools.zip" /root/COMPtools || echo "Warning: /root/COMPtools backup encountered errors."
cp "$BACKUP_DIR1/COMPtools.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy /root/COMPtools backup to $BACKUP_DIR2."
echo "/root/COMPtools backup complete."

# Backup PHP configuration file
zip -r "$BACKUP_DIR1/php_ini.zip" /etc/php.ini || echo "Warning: PHP configuration file backup encountered errors."
cp "$BACKUP_DIR1/php_ini.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy PHP configuration file backup to $BACKUP_DIR2."
echo "/etc/php.ini backup complete."

# Backup PHP configuration directory
zip -r "$BACKUP_DIR1/phpd.zip" /etc/php.d || echo "Warning: PHP configuration directory backup encountered errors."
cp "$BACKUP_DIR1/phpd.zip" "$BACKUP_DIR2/" 2>/dev/null || echo "Warning: Could not copy PHP configuration directory backup to $BACKUP_DIR2."
echo "/etc/php.d backup complete."

echo "All backups completed."
