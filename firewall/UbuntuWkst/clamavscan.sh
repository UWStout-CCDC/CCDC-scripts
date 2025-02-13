#!/bin/bash
#
# clamavscan.sh
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
# 
# Script to scan for infected files using ClamAV in the specified directory

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