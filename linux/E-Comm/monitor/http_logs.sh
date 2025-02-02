#!/bin/bash
# Check httpd logs with teler
tail -f /var/log/httpd/access_log | teler -c /ccdc/etc/teler_config.yaml