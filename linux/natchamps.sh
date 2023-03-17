#!/bin/bash

LOG_DIR="/ccdc/logs"

if type apt 2&>1 > /dev/null
then
  apt install -y aide fail2ban iptstate
elif type yum 2&>1 > /dev/null
then
  yum install -y aide fail2ban iptstate
else
  echo "Package manager not supported"
fi

# Fail2Ban setup
# TODO

# php.ini fixes
# TODO

# locate setuid
find / -perm /u+s,u+g > "$LOG_DIR/setuid_list" 2> /dev/null &

# generate process list
# TODO

# iptstate
# Likely doesn't need config

# grsec?

# aide
(aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz) &

# Wait for all previous steps to complete
wait
