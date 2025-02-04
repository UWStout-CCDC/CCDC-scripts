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

# Read the current PrestaShop database name from the parameters.php file
PHP_FILE="$PRESTASHOP_DIR/app/config/parameters.php"
CURRENT_DB_NAME=$(grep -oP "'database_name' => '\K[^']+" "$PHP_FILE")

# If no database name is found in parameters.php, search for a database matching 'prestashop*'
if [ -z "$CURRENT_DB_NAME" ]; then
    echo "No database name found in parameters.php."

    echo "Searching for a database that matches 'prestashop*'..."
    CURRENT_DB_NAME=$(mysql -u $MYSQL_ROOT_USER -p$MYSQL_ROOT_PASS -e "SHOW DATABASES LIKE 'prestashop%';" | grep -E '^prestashop' | head -n 1)

    # If no database is found, ask the user for the database name
    if [ -z "$CURRENT_DB_NAME" ]; then
        echo "No matching database found."
        read -p "Please enter the PrestaShop database name: " CURRENT_DB_NAME
    fi
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

# Update the PrestaShop configuration file (parameters.php)
echo "Updating PrestaShop parameters.php with the new username and password..."
sed -i "s/'database_user' => '.*'/'database_user' => '$NEW_USER'/g" "$PHP_FILE"
sed -i "s/'database_password' => '.*'/'database_password' => '$NEW_PASS'/g" "$PHP_FILE"

echo "MySQL user created and PrestaShop configuration updated successfully."

