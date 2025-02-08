#!/bin/sh
#
# iptables.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
# 
# Script to set iptables rules

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  #exit 1
fi

prompt() {
  read -p "$1 [y/N]" ans
  case $ans in
    y|Y) true ;;
    *) false ;;
  esac
}

# Empty all rules
iptables -t filter -F
iptables -t filter -X

# Block everything by default
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# Authorize already established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS (Needed for curl, and updates)
iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk (Server, Forwarder, Palo)
iptables -t filter -A INPUT -p tcp --dport 8000 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 514 -j ACCEPT

# Splunk Forwarder
iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT
  

######## OUTBOUND SERVICES ###############

if prompt "HTTP"
then
  # HTTP/HTTPS (apache)
  iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
fi

if prompt "DNS / NTP"
then
  # DNS (bind)
  iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
  iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT
  iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT
fi

if prompt "Mail"
then
  # SMTP
  iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT

  # POP3
  iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT

  # IMAP
  iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
fi

if prompt "Splunk Server"
then
  # Splunk Ports
  iptables -t filter -A INPUT -p tcp --dport 8000 -j ACCEPT
  # Splunk Forwarder
  iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
  # Palo Syslog
  #iptables -t filter -A INPUT -p tcp --dport 514 -j ACCEPT
fi

if prompt "Splunk Forwarder"
then
  # Splunk Forwarder
  iptables -t filter -A INPUT -p tcp --dport 9997 -j ACCEPT
  iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
fi

if prompt "SSH"
then
  # SSH
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
else
  service ssh stop
fi

# Allow SQL database
#iptables -t filter -A OUTPUT -p tcp --dport 3306 -j ACCEPT
