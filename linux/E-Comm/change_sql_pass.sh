#!/bin/bash

# Variables
MYSQL_ROOT_USER="root"         # MySQL root username
PRESTASHOP_DIR="/var/www/html/prestashop"  # Path to your PrestaShop installation

# Check if MYSQL_ROOT_PASS is passed as an argument or if we need to ask for it
if [ -z "$1" ]; then
    # If no password argument is provided, try to use passwordless login
    MYSQL_COMMAND="mysql -u $MYSQL_ROOT_USER"

    # Test if passwordless login is available by running a simple query
    if ! $MYSQL_COMMAND -e "exit" > /dev/null 2>&1; then
        # If passwordless login fails, prompt for MySQL root password
        read -sp "Enter MySQL root password: " MYSQL_ROOT_PASS
        echo
        MYSQL_COMMAND="mysql -u $MYSQL_ROOT_USER -p$MYSQL_ROOT_PASS"
    fi
else
    # If an argument is passed, use it as the MySQL root password
    MYSQL_ROOT_PASS="$1"
    MYSQL_COMMAND="mysql -u $MYSQL_ROOT_USER -p$MYSQL_ROOT_PASS"
fi

# Read the current PrestaShop database name from the configuration file located in /var/www/html/prestashop/config/settings.inc.php
# it will look like this define('_DB_NAME_', 'prestashop');
# Extract the database name from the define statement

PHP_FILE="$PRESTASHOP_DIR/config/settings.inc.php"
CURRENT_DB_NAME=$(grep -oP "define\('_DB_NAME_', '\K[^']+" "$PHP_FILE")

# If no database name is found in settings.inc.php, ask the user for the database name
if [ -z "$CURRENT_DB_NAME" ]; then
    echo "No database name found in settings.inc.php."
    read -p "Please enter the PrestaShop database name: " CURRENT_DB_NAME
fi

# Generate random password for the new MySQL user
NEW_USER="prestashop_user"
NEW_PASS=$(openssl rand -base64 64)

# Fileter out special characters from the password
NEW_PASS=$(echo "$NEW_PASS" | tr -cd '[:alnum:]')

# Create new MySQL user with random password and grant necessary permissions
echo "Creating MySQL user and granting permissions..."
$MYSQL_COMMAND -e "
CREATE USER '$NEW_USER'@'localhost' IDENTIFIED BY '$NEW_PASS';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER ON $CURRENT_DB_NAME.* TO '$NEW_USER'@'localhost';
FLUSH PRIVILEGES;
"

# Test the new user
echo "Testing new MySQL user..."
$MYSQL_COMMAND -e "exit" -u $NEW_USER -p$NEW_PASS
if [ $? -ne 0 ]; then
    echo "Failed to create or test new MySQL user."
    exit 1
fi

# update the PrestaShop configuration file with the new database user and password
echo "Updating PrestaShop configuration file with the new database user and password..."
sed -i "s/define('_DB_USER_', '.*');/define('_DB_USER_', '$NEW_USER');/" "$PHP_FILE"
sed -i "s/define('_DB_PASSWD_', '.*');/define('_DB_PASSWD_', '$NEW_PASS');/" "$PHP_FILE"

echo "PrestaShop database user updated successfully."
