#!/bin/bash
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
    sleep 5
    clear
done