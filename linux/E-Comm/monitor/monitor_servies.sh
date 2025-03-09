#!/bin/bash
RED='\033[0;31m'
NC='\033[0m'
while true
do
    printf "${RED}Running services:${NC}"
    echo
    echo
    systemctl --type=service --state=running
    sleep 5
    clear
done