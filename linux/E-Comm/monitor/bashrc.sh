#!/bin/bash
# Check for .bashrc locations
while true
do
    echo ".BASHRC LOCATIONS:"
    echo "------------------"
    find / -name .bashrc
    sleep 5
    clear
done