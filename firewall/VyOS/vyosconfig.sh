#!/bin/vbash
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
source /opt/vyatta/etc/functions/script-template
configure
# Delete services for SSH and Telnet
delete service ssh
delete service telnet
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
set firewall interface eth0 in name INGRESS
set firewall interface eth1 out name EGRESS
set firewall interface eth2 out name EGRESS
commit
save
exit
