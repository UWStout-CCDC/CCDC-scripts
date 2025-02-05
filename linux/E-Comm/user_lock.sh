#!/bin/bash
if [[ \$EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Get a list of users from /etc/passwd, and allow the user to select what users to keep with a simple yes/no prompt
while read -r line; do
    # Get the username
    username=$(echo $line | cut -d: -f1)
    # Check if the user is root
    if [ "$username" == "root" ] || [ "$username" == "sysadmin" ]; then
        # Skip the root user and the sysadmin user
        continue
    fi
    # Ask the user if they want to keep the user only if the user can login
    if [ $(echo $line | cut -d: -f7) != "/sbin/nologin" ]; then
        usermod -s /sbin/nologin $username
        passwd -l $username
    fi
done < /etc/passwd