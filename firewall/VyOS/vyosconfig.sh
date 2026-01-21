
#!/bin/vbash
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
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
set interfaces ethernet eth0 firewall in name 'INGRESS'
set interfaces ethernet eth1 firewall out name 'EGRESS'
set interfaces ethernet eth2 firewall out name 'EGRESS'
commit
save
