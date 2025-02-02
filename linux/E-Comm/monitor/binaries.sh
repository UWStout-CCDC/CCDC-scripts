#!/bin/bash
# Check for suid binaries
while true
do
    echo "SUID BINARIES:"
    echo "--------------"
    find / -type f -perm -4000 -exec ls -l {} \; | awk '{print $1, $3, $4, $9}'
    sleep 5
    clear
done