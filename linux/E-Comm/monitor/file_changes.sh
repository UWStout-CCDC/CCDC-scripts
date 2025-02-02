#!/bin/bash
# Check for changes to important files
while true
do
    aide --check > aide_output.txt
    if [[ -s aide_output.txt ]];then
        clear
        echo "CHANGES TO IMPORTANT FILES:"
        echo "--------------------------"
        cat aide_output.txt
    fi
    sleep 20
done