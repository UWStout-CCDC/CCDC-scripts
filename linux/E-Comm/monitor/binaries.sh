#!/bin/bash
# Check for suid binaries
while true
do
    # Finds all UID 0 accounts
    getent passwd | grep '0:0' | cut -d':' -f1 > /ccdc/tmp/uid0.txt

    # Find all users w/ sudo privs
    grep -E '^[^#%@]*\b(ALL|(S|s)udoers)\b' /etc/sudoers > /ccdc/tmp/sudoers.txt

    # SUID binaries
    find /bin /usr/bin -uid 0 -perm -4000 2>/dev/null > /ccdc/tmp/suid.txt

    clear

    echo "UID 0 accounts:"
    cat /ccdc/tmp/uid0.txt

    echo "----------------------"
    echo "Users with sudo privs:"
    cat /ccdc/tmp/sudoers.txt

    echo "----------------------"
    echo "SUID binaries:"
    cat /ccdc/tmp/suid.txt
    sleep 20
    
done