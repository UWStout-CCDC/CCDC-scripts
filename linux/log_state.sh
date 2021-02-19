#! /bin/sh
#
# log_state.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
# 
# Script to export the current state of the machine to some files

# All exported info will go here
EXPORT_DIR="/ccdc"

mkdir -p $EXPORT_DIR

# Export Netstat output
netstat -tulnp > $EXPORT_DIR/netstat

# Export user list, including groups

# Export Service status

# Export Ip configuration, DNS servers, NTP

# Export SSH server settings

# Export Password complexity settings

# Export package lists
apt list > $EXPORT_DIR/packages
