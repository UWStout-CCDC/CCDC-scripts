#!/bin/bash
# Check for cron jobs, and display them, as well as the cron jobs in cron.d
while true
do
    echo "CRON JOBS:"
    echo "Found Cronjobs in /etc/crontab:"
    echo "---------------------------------------"
    cat /etc/crontab | grep -v "^#" | grep -v "^$" | grep -v "SHELL" | grep -v "PATH" | grep -v "MAILTO"
    echo
    echo "Cronjobs in cron.d:"
    echo "-------------------"
    ls /etc/cron.d/
    echo
    echo "Cronjobs in cron.hourly:"
    echo "------------------------"
    ls /etc/cron.hourly/
    echo
    echo "Cronjobs in cron.daily:"
    echo "------------------------"
    ls /etc/cron.daily/
    echo
    echo "Cronjobs in cron.weekly:"
    echo "------------------------"
    ls /etc/cron.weekly/
    echo
    echo "Cronjobs in cron.monthly:"
    echo "------------------------"
    ls /etc/cron.monthly/
    echo
    sleep 5
    clear
done