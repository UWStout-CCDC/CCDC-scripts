#!/bin/bash
# Check for sleeping processes
while true
do
    sleepingProcs=$(ps aux | grep sleep)
    if [[ ! -z "$sleepingProcs" ]];then
        echo "SLEEP PROCESSES:"
        echo "----------------"
        sleep 5
        clear
    fi
done