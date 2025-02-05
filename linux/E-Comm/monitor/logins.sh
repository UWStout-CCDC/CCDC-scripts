#!/bin/bash

# Get credentials from the user for mysql
read -p "Enter MySQL root username: " MYSQL_USER
read -sp "Enter MySQL root password: " MYSQL_PASS

# Check if the user entered the correct credentials
while ! mysql -u $MYSQL_USER -p$MYSQL_PASS -e "exit" > /dev/null 2>&1
do
    echo "Incorrect MySQL root username or password. Please try again."
    read -p "Enter MySQL root username: " MYSQL_USER
    read -sp "Enter MySQL root password: " MYSQL_PASS
done

# Check for current and recent logins
while true
do
    echo "CURRENT LOGIN SESSIONS:"
    echo "-----------------------"
    w | grep -v "load average" 
    echo
    echo "RECENT LOGIN SESSIONS:"
    echo "----------------------"
    last | head -n5
    echo
    echo
    echo "MySQL USERS:"
    echo "------------"
    # Check if MYSQL pass is blank
    if [ -z $MYSQL_PASS ]
    then
        mysql -e "SELECT User, Host FROM mysql.user;" -u $MYSQL_USER
    else
        mysql -e "SELECT User, Host FROM mysql.user;" -u $MYSQL_USER -p$MYSQL_PASS
    fi
    sleep 5
    clear
done