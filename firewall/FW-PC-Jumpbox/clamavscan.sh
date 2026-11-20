#!/bin/bash
#
# clamavscan.sh
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to scan for infected files using ClamAV in the specified directory
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

# Specify the User
USER="sysadmin"

# Define the directory to scan (modify as needed)
SCAN_DIR="/home/$USER"

# Log file for scan results
LOG_FILE="/ccdc/logs/clamav_scan.log"
# LOG_FILE="/var/log/clamav_scan.log" # Alternative log file location

# Run ClamAV scan quietly (no progress, only infected files shown)
clamscan -r --quiet --infected "$SCAN_DIR" >> "$LOG_FILE" 2>&1

# Optional: Notify if infected files are found
if grep -q "FOUND" "$LOG_FILE"; then
    echo "Infected files detected! Check $LOG_FILE"
fi