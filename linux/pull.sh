#! /bin/sh
#
# pull.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Download scirpts from github

# Quck function to grab a script from the repo
get() {
  wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts-2020/master/$1 -O $1
}

get linux/log_state.sh
get linux/iptables.sh
get linux/ssh.sh
get linux/splunk.sh
