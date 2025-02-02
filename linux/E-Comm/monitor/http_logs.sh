#!/bin/bash
# Check httpd logs with teler
while true
do
    tail -f /var/log/httpd/access_log | teler -c /ccdc/etc/teler_config.yaml
    sleep 5
    clear
done