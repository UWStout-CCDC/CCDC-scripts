#!/bin/bash
RED='\033[0;31m'
NC='\033[0m'
while true
do
    printf "${RED}Changed Bash Files:${NC}"
    echo
    echo
    # Get the date the system was installed
    INSTALL_DATE=$(ls -lct --time=ctime / | tail -1 | awk '{ print $6, $7, $8 }')
    # Check if the bash files have been modified since the system was installed
    for FILE in /etc/bashrc /etc/profile /etc/profile.d/* /root/.bashrc /root/.bash_profile /root/.bash_logout /home/*/.bashrc /home/*/.bash_profile /home/*/.bash_logout /etc/bash.bashrc /etc/bash.bash_logout /etc/bash.bash_profile /root/.bash_login /home/*/.bash_login /root/.profile /home/*/.profile /etc/environment
    do
        if [ grep -q "*" $FILE ]; then
            echo "$FILE has been modified since the system was installed"
        fi
    done
    sleep 5
    clear
done