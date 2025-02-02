#!/bin/bash
while true
    do


        echo "Active connections:"
        echo "-------------------"
        netstat -n -A inet | grep ESTABLISHED | grep -vP ":(80|443|53|123)"
        sleep 5
        clear
    done