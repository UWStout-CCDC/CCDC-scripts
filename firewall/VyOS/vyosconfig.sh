#!/bin/vbash
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
source /opt/vyatta/etc/functions/script-template
configure
# Delete services for SSH and Telnet
delete service ssh
delete service telnet

# Create firewall rules for WAN to LAN traffic
set firewall ipv4 name WAN-TO-LAN default-action drop
set firewall ipv4 name WAN-TO-LAN description 'WAN to LAN traffic'
# Allow established/related
set firewall ipv4 name WAN-TO-LAN rule 10 action accept
set firewall ipv4 name WAN-TO-LAN rule 10 state established
set firewall ipv4 name WAN-TO-LAN rule 10 state related

# Create firewall rules for LAN to WAN traffic
set firewall ipv4 name LAN-TO-WAN default-action accept
set firewall ipv4 name LAN-TO-WAN description 'LAN to WAN traffic'
# Allow all LAN to WAN for now
set firewall ipv4 name LAN-TO-WAN rule 10 action accept

# Create firewall rules for WAN LOCAL (traffic to router itself)
set firewall ipv4 name WAN-LOCAL default-action drop
set firewall ipv4 name WAN-LOCAL description 'WAN to Router'
# Allow established/related
set firewall ipv4 name WAN-LOCAL rule 10 action accept
set firewall ipv4 name WAN-LOCAL rule 10 state established
set firewall ipv4 name WAN-LOCAL rule 10 state related
# ICMP
set firewall ipv4 name WAN-LOCAL rule 20 action accept
set firewall ipv4 name WAN-LOCAL rule 20 protocol icmp
# HTTP - Ecom
set firewall ipv4 name WAN-LOCAL rule 30 action accept
set firewall ipv4 name WAN-LOCAL rule 30 protocol tcp
set firewall ipv4 name WAN-LOCAL rule 30 destination port 80
# HTTPS - Ecom
set firewall ipv4 name WAN-LOCAL rule 40 action accept
set firewall ipv4 name WAN-LOCAL rule 40 protocol tcp
set firewall ipv4 name WAN-LOCAL rule 40 destination port 443
# POP3 - WebMail
set firewall ipv4 name WAN-LOCAL rule 50 action accept
set firewall ipv4 name WAN-LOCAL rule 50 protocol tcp
set firewall ipv4 name WAN-LOCAL rule 50 destination port 110
# SMTP - WebMail
set firewall ipv4 name WAN-LOCAL rule 60 action accept
set firewall ipv4 name WAN-LOCAL rule 60 protocol tcp
set firewall ipv4 name WAN-LOCAL rule 60 destination port 25
# DNS - AD/DNS
set firewall ipv4 name WAN-LOCAL rule 70 action accept
set firewall ipv4 name WAN-LOCAL rule 70 protocol tcp_udp
set firewall ipv4 name WAN-LOCAL rule 70 destination port 53

# Create firewall rules for LAN LOCAL (LAN to router itself)
set firewall ipv4 name LAN-LOCAL default-action accept
set firewall ipv4 name LAN-LOCAL description 'LAN to Router'

# Define zones
set firewall zone WAN default-action drop
set firewall zone WAN interface eth0
set firewall zone WAN from LAN firewall ipv4 name LAN-TO-WAN

set firewall zone LAN default-action drop
set firewall zone LAN interface eth1
set firewall zone LAN interface eth2
set firewall zone LAN from WAN firewall ipv4 name WAN-TO-LAN

# Local zone (router itself)
set firewall zone LOCAL default-action drop
set firewall zone LOCAL local-zone
set firewall zone LOCAL from WAN firewall ipv4 name WAN-LOCAL
set firewall zone LOCAL from LAN firewall ipv4 name LAN-LOCAL

commit
save
exit
