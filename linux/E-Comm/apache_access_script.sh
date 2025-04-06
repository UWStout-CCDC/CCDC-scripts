#!/bin/bash

# create a script that will list out all directories 2 layers deep in /var/www/html, so this would be /var/www/html/directory1/directory2
# Then allow the user to select the directories they want to remove access from, it will also automatically get revoked directories from the apache configuration file
# The script will then remove access from the directories and restart the apache service

if [ $(id -u) -ne 0 ]; then
    echo "You must be root to run this script"
    exit 1
fi

# Check if dialog is installed
if [ ! $(which dialog) ]; then
    echo "The dialog package is not installed"
    if [ $(which apt) ]; then
        apt install -y dialog
    elif [ $(which yum) ]; then
        yum install -y dialog
    else
        echo "Could not install dialog package"
        exit 4
    fi
fi

if [ ! -d /var/www/html ]; then
    echo "The /var/www/html directory does not exist"
    exit 2
fi

if [ -f /etc/apache2/apache2.conf ]; then
    APACHE_CONF="/etc/apache2/apache2.conf"
elif [ -f /etc/httpd/conf/httpd.conf ]; then
    APACHE_CONF="/etc/httpd/conf/httpd.conf"
else
    echo "The apache configuration file could not be found"
    exit 3
fi

# Get the directories 2 layers deep in /var/www/html
DIRECTORIES=$(find /var/www/html -mindepth 2 -maxdepth 2 -type d)

# Create an array of the directories
declare -a DIR_ARRAY
i=0
for DIR in $DIRECTORIES
do
    DIR_ARRAY[$i]=$DIR
    i=$(($i+1))
done

# Get the currently denied directories from the apache configuration file
DENIED_DIRECTORIES=$(grep "RedirectMatch 404" "$APACHE_CONF" | awk '{print $3}' | sed 's/^\^//g')



# Truncate the array to remove the /var/www/html prefix
for ((i=0; i<${#DIR_ARRAY[@]}; i++))
do
    DIR_ARRAY[$i]=${DIR_ARRAY[$i]#/var/www/html/}
done

choices=(
    $(for ((i=0; i<${#DIR_ARRAY[@]}; i++)); do
        if echo "$DENIED_DIRECTORIES" | grep -q "^/${DIR_ARRAY[$i]}$"; then
            echo $i "${DIR_ARRAY[$i]}" on
        else
            echo $i "${DIR_ARRAY[$i]}" off
        fi
    done)
)

# Use dialog to show the checklist
output=$(dialog --checklist "Select items:" 15 40 5 "${choices[@]}" 2>&1 >/dev/tty)
exit_status=$?
clear

# Check if the exit status is 1 (cancel)
if [ $exit_status -eq 1 ] || [ $exit_status -eq 255  ]; then
    echo "User cancelled, changes not saved"
    exit 0
fi

# Set the apache configuration file for each item selected to be denied via RedirectMatch 404 ^/directory
for i in $output
do
    # Only add the RedirectMatch if it's not already present
    if ! grep -q "RedirectMatch 404 ^/${DIR_ARRAY[$i]}" $APACHE_CONF; then
        echo "RedirectMatch 404 ^/${DIR_ARRAY[$i]}" >> $APACHE_CONF
    fi
done


# for the other items that are not in the selected list, remove the RedirectMatch 404 ^/prestashop/classes
for ((i=0; i<${#DIR_ARRAY[@]}; i++))
do
    if ! echo $output | grep -q $i; then
        sed -i "\|RedirectMatch 404 ^/${DIR_ARRAY[$i]}|d" "$APACHE_CONF"
    fi
done

echo "Restarting apache service"
# The service might be called apache2 or httpd
if systemctl is-active --quiet httpd; then
    echo "httpd is running, restarting..."
    systemctl restart httpd
# Check if apache2 is running (alternative name for some systems like Ubuntu)
elif systemctl is-active --quiet apache2; then
    echo "apache2 is running, restarting..."
    systemctl restart apache2
else
    echo "Neither httpd nor apache2 is running."
fi