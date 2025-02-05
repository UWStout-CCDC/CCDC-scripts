#!/bin/bash
# Check for changes to important files
while true
do
    aide --check > /ccdc/tmp/aide_output.txt
    if [[ -s aide_output.txt ]];then
        clear
        echo "CHANGES TO IMPORTANT FILES:"
        echo "--------------------------"
        cat /ccdc/tmp/aide_output.txt
    fi
    sleep 20
done