#!/bin/vbash
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
source /opt/vyatta/etc/functions/script-template
configure
# Delete services for SSH and Telnet
delete service ssh
delete service telnet
# Add System Banner
set system login banner pre-login '

UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED

You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts and actions to access or use this system may result in civil
and/or criminal penalties.

All activities performed on this device are logged and monitored.

'
# Create Ingress firewall rules (IPv4)
set firewall ipv4 name INGRESS default-action drop
set firewall ipv4 name INGRESS description 'Ingress policy'
# Allow established/related
set firewall ipv4 name INGRESS rule 10 action accept
set firewall ipv4 name INGRESS rule 10 state established
set firewall ipv4 name INGRESS rule 10 state related
# ICMP
set firewall ipv4 name INGRESS rule 20 action accept
set firewall ipv4 name INGRESS rule 20 protocol icmp
# HTTP - Ecom
set firewall ipv4 name INGRESS rule 30 action accept
set firewall ipv4 name INGRESS rule 30 protocol tcp
set firewall ipv4 name INGRESS rule 30 destination port 80
# HTTPS - Ecom
set firewall ipv4 name INGRESS rule 40 action accept
set firewall ipv4 name INGRESS rule 40 protocol tcp
set firewall ipv4 name INGRESS rule 40 destination port 443
# POP3 - WebMail
set firewall ipv4 name INGRESS rule 50 action accept
set firewall ipv4 name INGRESS rule 50 protocol tcp
set firewall ipv4 name INGRESS rule 50 destination port 110
# SMTP - WebMail
set firewall ipv4 name INGRESS rule 60 action accept
set firewall ipv4 name INGRESS rule 60 protocol tcp
set firewall ipv4 name INGRESS rule 60 destination port 25
# DNS - AD/DNS
set firewall ipv4 name INGRESS rule 70 action accept
set firewall ipv4 name INGRESS rule 70 protocol tcp_udp
set firewall ipv4 name INGRESS rule 70 destination port 53
# FTP
set firewall ipv4 name INGRESS rule 80 action accept
set firewall ipv4 name INGRESS rule 80 protocol tcp_udp
set firewall ipv4 name INGRESS rule 80 destination port 21
# TFTP
set firewall ipv4 name INGRESS rule 90 action accept
set firewall ipv4 name INGRESS rule 90 protocol udp
set firewall ipv4 name INGRESS rule 90 destination port 69
# SPLUNK
set firewall ipv4 name INGRESS rule 100 action accept
set firewall ipv4 name INGRESS rule 100 protocol udp
set firewall ipv4 name INGRESS rule 100 destination port 8000
# Create Egress Rules
set firewall ipv4 name EGRESS default-action drop
set firewall ipv4 name EGRESS description 'Egress policy'
# Allow established/related
set firewall ipv4 name EGRESS rule 10 action accept
set firewall ipv4 name EGRESS rule 10 state established
set firewall ipv4 name EGRESS rule 10 state related
# ICMP
set firewall ipv4 name EGRESS rule 20 action accept
set firewall ipv4 name EGRESS rule 20 protocol icmp
# HTTP
set firewall ipv4 name EGRESS rule 30 action accept
set firewall ipv4 name EGRESS rule 30 protocol tcp
set firewall ipv4 name EGRESS rule 30 destination port 80
# HTTPS
set firewall ipv4 name EGRESS rule 40 action accept
set firewall ipv4 name EGRESS rule 40 protocol tcp
set firewall ipv4 name EGRESS rule 40 destination port 443
# DNS
set firewall ipv4 name EGRESS rule 50 action accept
set firewall ipv4 name EGRESS rule 50 protocol tcp_udp
set firewall ipv4 name EGRESS rule 50 destination port 53
# NTP
set firewall ipv4 name EGRESS rule 60 action accept
set firewall ipv4 name EGRESS rule 60 protocol udp
set firewall ipv4 name EGRESS rule 60 destination port 123
# Apply firewall to interfaces
# Forward filter: jump to INGRESS for traffic coming in on the WAN Port
set firewall ipv4 forward filter default-action accept
set firewall ipv4 forward filter rule 5 action jump
set firewall ipv4 forward filter rule 5 inbound-interface name eth0
set firewall ipv4 forward filter rule 5 jump-target INGRESS
# Forward filter: jump to EGRESS
set firewall ipv4 forward filter rule 10 action jump
set firewall ipv4 forward filter rule 10 outbound-interface name eth1
set firewall ipv4 forward filter rule 10 jump-target EGRESS
# Forward filter: jump to EGRESS
set firewall ipv4 forward filter rule 15 action jump
set firewall ipv4 forward filter rule 15 outbound-interface name eth2
set firewall ipv4 forward filter rule 15 jump-target EGRESS
commit
save
exit
