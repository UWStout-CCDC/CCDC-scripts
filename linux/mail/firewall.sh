#! /bin/bash
# iptables Firewall setup (Fedora Mail)
# By Ella Brech, Fall 2026

# INPUT

# POP3 - 110 TCP
iptables -A INPUT -p tcp --dport 110 -j ACCEPT
# POP3S - 995 TCP
#iptables -A INPUT -p tcp --dport 995 -j ACCEPT

# IMAP - 143 TCP
#iptables -A INPUT -p tcp --dport 143 -j ACCEPT
# IMAPS - 993 TCP
#iptables -A INPUT -p tcp --dport 993 -j ACCEPT

# SMTP - 25 TCP
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
# SMTPS(legacy) - 465 TCP
#iptables -A INPUT -p tcp --dport 465 -j ACCEPT
# SMTP Submission - 587 TCP
iptables -A INPUT -p tcp --dport 587 -j ACCEPT

# Established/Related w/ logging
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j LOG --log-prefix "IPTABLES-I-EST/REL: " --log-level warning
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Deny All
iptables -A INPUT -j REJECT


# FORWARD

# Deny All
iptables -A FORWARD -j REJECT


# OUTPUT
