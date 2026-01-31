#!/usr/bin/env python3
#
# SecureBaseScript.py 
# Copyright (C) 2026 doshowipospf
#
# Distributed under terms of the MIT license.
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

# Version 1.0.0

# Recomended to use curl to get script on VyOS
# Script should be ran prior to competition and added to github
# Documentation on VyOS Firewall: https://docs.vyos.io/en/latest/configuration/firewall/ipv4.html

import textwrap

ethWAN = input("Please enter the WAN Interface (ex.eth0): ")
ethWAN = str(ethWAN)
ethLAN1 = input("Please enter the LAN Interface 1 (ex.eth1): ")
ethLAN1 = str(ethLAN1)
ethLAN2 = input("Please enter the LAN Interface 2 (ex.eth2): ")
ethLAN2 = str(ethLAN2)

with open("vyosconfig.sh", "w") as command_file:
  commands=textwrap.dedent("""#!/bin/vbash
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
source /opt/vyatta/etc/functions/script-template
configure
# Delete services for SSH and Telnet
delete service ssh
delete service telnet
# Create Ingress firewall rules
set firewall name INGRESS default-action 'drop'
set firewall name INGRESS description 'Ingress policy'
# Allow established/related
set firewall name INGRESS rule 10 action 'accept'
set firewall name INGRESS rule 10 state established 'enable'
set firewall name INGRESS rule 10 state related 'enable'
# ICMP
set firewall name INGRESS rule 20 action 'accept'
set firewall name INGRESS rule 20 protocol 'icmp'
# HTTP - Ecom
set firewall name INGRESS rule 30 action 'accept'
set firewall name INGRESS rule 30 protocol 'tcp'
set firewall name INGRESS rule 30 destination port '80'
# HTTPS - Ecom
set firewall name INGRESS rule 40 action 'accept'
set firewall name INGRESS rule 40 protocol 'tcp'
set firewall name INGRESS rule 40 destination port '443'
# POP3 - WebMail
set firewall name INGRESS rule 50 action 'accept'
set firewall name INGRESS rule 50 protocol 'tcp'
set firewall name INGRESS rule 50 destination port '110'
# SMTP - WebMail
set firewall name INGRESS rule 60 action 'accept'
set firewall name INGRESS rule 60 protocol 'tcp'
set firewall name INGRESS rule 60 destination port '25'
# DNS - AD/DNS
set firewall name INGRESS rule 70 action 'accept'
set firewall name INGRESS rule 70 protocol 'tcp_udp'
set firewall name INGRESS rule 70 destination port '53'
# Create Egress Rules
set firewall name EGRESS default-action 'drop'
set firewall name EGRESS description 'Egress policy'
# Allow established/related
set firewall name EGRESS rule 10 action 'accept'
set firewall name EGRESS rule 10 state established 'enable'
set firewall name EGRESS rule 10 state related 'enable'
# ICMP
set firewall name EGRESS rule 20 action 'accept'
set firewall name EGRESS rule 20 protocol 'icmp'
# HTTP
set firewall name EGRESS rule 30 action 'accept'
set firewall name EGRESS rule 30 protocol 'tcp'
set firewall name EGRESS rule 30 destination port '80'
# HTTPS
set firewall name EGRESS rule 40 action 'accept'
set firewall name EGRESS rule 40 protocol 'tcp'
set firewall name EGRESS rule 40 destination port '443'
# DNS
set firewall name EGRESS rule 50 action 'accept'
set firewall name EGRESS rule 50 protocol 'tcp_udp'
set firewall name EGRESS rule 50 destination port '53'
# NTP
set firewall name EGRESS rule 60 action 'accept'
set firewall name EGRESS rule 60 protocol 'udp'
set firewall name EGRESS rule 60 destination port '123'
set interfaces ethernet """+ethWAN+""" firewall in name 'INGRESS'
set interfaces ethernet """+ethLAN1+""" firewall out name 'EGRESS'
set interfaces ethernet """+ethLAN2+""" firewall out name 'EGRESS'
commit
save
""").lstrip()
  command_file.write(commands)
  print("File is written to vyosconfig.sh")
  print("Issue 'curl -Lo vyosconfig.sh https://tinyurl.com/vyosconfig' on VyOS Router\nThen run the script with 'sg vyattacfg -c ./vyosconfig.sh'")