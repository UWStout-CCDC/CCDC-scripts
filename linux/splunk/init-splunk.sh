#!/bin/bash

###################################
##    Splunk Specific Configs    ##
###################################

# Changing default admin password
cd /opt/splunk/bin
./splunk edit user <username> -auth admin:<admin_password> -password <password>

# ...
