#!/bin/bash
# Check for sleeping processes
while true
do
    sleepingProcs=$(ps aux)
    if [[ ! -z "$sleepingProcs" ]];then
        echo "PROCESSES:"
        echo "----------------"
        sleep 5
        clear
    fi
done