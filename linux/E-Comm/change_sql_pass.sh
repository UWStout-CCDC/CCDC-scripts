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

# Read the current PrestaShop database name from the configuration file, there are two possible locations, and they have different formats
# The database name can be found in the configuration file located in /var/www/html/prestashop/config/settings.inc.php, or in /var/www/html/prestashop/app/config/parameters.php
# The database name will look like this define('_DB_NAME_', 'prestashop'); or 'database_name' => 'prestashop',
# Extract the database name from the define statement
if [ -f "$PRESTASHOP_DIR/config/settings.inc.php" ]; then
    PHP_FILE="$PRESTASHOP_DIR/config/settings.inc.php"
    CURRENT_DB_NAME=$(grep -oP "define\('_DB_NAME_', '\K[^']+" "$PHP_FILE")
elif [ -f "$PRESTASHOP_DIR/app/config/parameters.php" ]; then
    PHP_FILE="$PRESTASHOP_DIR/app/config/parameters.php"
    CURRENT_DB_NAME=$(grep -oP "'database_name' => '\K[^']+" "$PHP_FILE")
else
    echo "PrestaShop configuration file not found."
    exit 1
fi

# If no database name is found in the configuration file, ask the user for the database name
if [ -z "$CURRENT_DB_NAME" ]; then
    echo "No database name found in the configuration file."
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

# Update the PrestaShop configuration file with the new database user and password
echo "Updating PrestaShop configuration file with the new database user and password..."
if [ -f "$PRESTASHOP_DIR/config/settings.inc.php" ]; then
    sed -i "s/define('_DB_USER_', '.*');/define('_DB_USER_', '$NEW_USER');/" "$PHP_FILE"
    sed -i "s/define('_DB_PASSWD_', '.*');/define('_DB_PASSWD_', '$NEW_PASS');/" "$PHP_FILE"
elif [ -f "$PRESTASHOP_DIR/app/config/parameters.php" ]; then
    sed -i "s/'database_user' => '.*',/'database_user' => '$NEW_USER',/" "$PHP_FILE"
    sed -i "s/'database_password' => '.*',/'database_password' => '$NEW_PASS',/" "$PHP_FILE"
fi

echo "PrestaShop database user updated successfully."
