#!/bin/bash
# Check for sleeping processes
while true
do
    clear
    echo "PROCESSES:"
    echo "----------------"
    ps aux
    sleep 5
done