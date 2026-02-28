#!/bin/bash

# Mail firewall setup backup


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     Firewall                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
sudo yum install iptables-services -y -q
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl enable iptables
sudo systemctl start iptables

# Empty all rules
sudo iptables -t filter -F
sudo iptables -t filter -X

# Block everything by default
sudo iptables -t filter -P INPUT DROP
sudo iptables -t filter -P FORWARD DROP
sudo iptables -t filter -P OUTPUT DROP

# Authorize already established connections
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A INPUT -i lo -j ACCEPT
sudo iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
#sudo iptables -t filter -A INPUT -p icmp -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS (Needed for curl, and updates)
#sudo iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
#sudo iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
#sudo iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk
#sudo iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# SMTP
#sudo iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT

# POP3
#sudo iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p udp --dport 110 -j ACCEPT
#sudo iptables -t filter -A INPUT -p udp --dport 110 -j ACCEPT

# IMAP
#sudo iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
#sudo iptables -t filter -A OUTPUT -p udp --dport 143 -j ACCEPT
#sudo iptables -t filter -A INPUT -p udp --dport 143 -j ACCEPT

# THESE ARE PER THE COMPETITION
#sudo ip6tables -A INPUT -p tcp --dport 25 -j ACCEPT
#sudo ip6tables -A OUTPUT -p tcp --dport 25 -j ACCEPT
#sudo ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
#sudo ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT

sudo iptables-save | sudo tee /etc/sysconfig/iptables

#SPECIFIC TO IPV6
#sudo ip6tables-save | sudo tee /etc/sysconfig/ip6tables
