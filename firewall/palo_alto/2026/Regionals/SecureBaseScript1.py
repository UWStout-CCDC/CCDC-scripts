#!/usr/bin/env python3
#
# SecureBaseScript.py - Firewall 1 (Linux Side)
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
#
#
#                                _   _ ______ _____  _____    /\  
#                               | \ | |  ____|  __ \|  __ \  |/\| 
#                               |  \| | |__  | |__) | |  | |      
#                               | . ` |  __| |  _  /| |  | |      
#                               | |\  | |____| | \ \| |__| |      
#                               |_| \_|______|_|  \_\_____/       
                                   
                                   

# Version 2.2.0
# Run this with your team number and then ssh into the Palo Alto. Enter "set cli scripting-mode on" and then "cofigure"
# Then copy and past the output of the script. The first command increases the winow buffer size and the second command enters configure mode.
# This script should be ran before competition and put the config txt file on GitHub.
# Also Remember to turn off cli scripting after script is ran with "set cli scripting-mode off"
is_not_correct = True
while is_not_correct:
  team_num = input("Please enter the Team Number :")
  team_num = int(team_num) + 20 # Team numbers start at 20, update based on team packet
  team_num = str(team_num)
  print(f"Your Public IP is then : 172.25.{team_num}.0/24?")
  valid = input("(y/n) ")
  if valid == "y":
    is_not_correct = False
# Team number for varaibles

permitted_ip = input("Please enter the Ubuntu Workstation IP : ")
permitted_ip = str(permitted_ip)
# Set Static IP for Ubuntu Workstation
# Permit only the Ubuntu Workstation IP and the Palo Alto IP

print("[*] Okay so lowkey we don't know the zone for each service. You gotta look at it. Maybe they're all external :D.")
print()
splunk_zone = input("Please enter Splunks's zone name : ")
splunk_zone = str(splunk_zone)

ecomm_zone = input("Please enter Ecommerce's zone name : ")
ecomm_zone = str(ecomm_zone)

mail_zone = input("Please enter Mail's zone name : ")
mail_zone = str(mail_zone)

work_zone = input("Please enter Workstation's zone name : ")
work_zone = str(work_zone)

with open("PAConfig.txt", "w") as command_file:
  commands="""
configure
set deviceconfig system permitted-ip """+permitted_ip+"""
set deviceconfig system dns-setting servers primary 9.9.9.9
set deviceconfig system dns-setting servers secondary 149.112.112.112
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no
set deviceconfig system service disable-ssh no
set deviceconfig system service disable-snmp yes
set deviceconfig system login-banner "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED. You must have explicit, authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities performed on this device are logged and monitored."
set deviceconfig system timezone US/Central
set network profiles zone-protection-profile Default discard-overlapping-tcp-segment-mismatch yes discard-unknown-option yes tcp-reject-non-syn yes flood tcp-syn enable yes
set network profiles zone-protection-profile Default flood icmp enable yes
set network profiles zone-protection-profile Default flood udp enable yes
set network profiles zone-protection-profile Default flood other-ip enable yes
set network profiles zone-protection-profile Default flood icmpv6 enable yes
set zone External network zone-protection-profile Default
set zone Internal network zone-protection-profile Default
set network profiles interface-management-profile none
set network interface ethernet ethernet1/3 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 interface-management-profile none
set address PrivIP10 ip-netmask 10.0.0.0/8
set address PrivIP172 ip-netmask 172.16.0.0/12
set address PrivIP192 ip-netmask 192.168.0.0/16

set address UbuntuWrkPriv ip-netmask """+permitted_ip+"""

set address SplunkPriv ip-netmask 172.20.242.20
set address SplunkPub ip-netmask 172.25."""+team_num+""".9

set address EcommPriv ip-netmask 172.20.242.30
set address EcommPub ip-netmask 172.25."""+team_num+""".11

set address FedoraMailPriv ip-netmask 172.20.242.40
set address FedoraMailPub ip-netmask 172.25."""+team_num+""".39

set address ADWindowsPub ip-netmask 172.25."""+team_num+""".155

set address LAN ip-range 172.20.240.0-172.20.242.255
set service WebMail protocol tcp port 25,110
set service SplunkScoring protocol tcp port 8000
set service Splunk protocol tcp port 9997
set service ADWindowsPub protocol tcp port 389,53
delete rulebase security

set rulebase security rules AllowICMP action allow from any to any source any destination any
set rulebase security rules AllowICMP application ping service application-default
set rulebase security rules AllowICMP application icmp service application-default
set rulebase security rules AllowNTP action allow from """+work_zone+""" to External source any destination any
set rulebase security rules AllowNTP action allow from """+splunk_zone+""" to External source any destination any
set rulebase security rules AllowNTP action allow from """+ecomm_zone+""" to External source any destination any
set rulebase security rules AllowNTP action allow from """+mail_zone+""" to External source any destination any
set rulebase security rules AllowNTP application ntp service application-default

# Granular Web Control:
# Enable and disable as needed.
# This is intended to prevent beacons via a zero trust architecture. If packages need install, the admins should communicate with you.

## Splunk
# ======================= Granular Web Control ======================= 
set rulebase security rules SplunkAllowInternet action allow from """+splunk_zone+""" to External source SplunkPriv destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules SplunkAllowInternet application any service service-http
set rulebase security rules SplunkAllowInternet application any service service-https
set rulebase security rules SplunkAllowDNSOutbound action allow from """+splunk_zone+""" to External source SplunkPriv destination any
set rulebase security rules SplunkAllowDNSOutbound application dns service application-default
# ======================= Scoring ======================= 
set rulebase security rules AllowScoringSplunk action allow from External to """+splunk_zone+""" source any destination SplunkPub
set rulebase security rules AllowScoringSplunk application any service SplunkScoring
# ======================= Log Forwarding ======================= 
set rulebase security rules SplunkIntrazone action allow from """+ecomm_zone+""" to """+splunk_zone+""" source SplunkPriv destination any
set rulebase security rules SplunkIntrazone action allow from """+mail_zone+""" to """+splunk_zone+""" source SplunkPriv destination any
set rulebase security rules SplunkIntrazone action allow from """+work_zone+""" to """+splunk_zone+""" source SplunkPriv destination any
set rulebase security rules SplunkIntrazone application any service Splunk

## Ecomm
# ======================= Granular Web Control ======================= 
set rulebase security rules EcommAllowInternet action allow from """+ecomm_zone+""" to External source EcommPriv destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules EcommAllowInternet application any service service-http
set rulebase security rules EcommAllowInternet application any service service-https
set rulebase security rules EcommAllowDNSOutbound action allow from """+ecomm_zone+""" to External source EcommPriv destination any
set rulebase security rules EcommAllowDNSOutbound application dns service application-default
# ======================= Scoring Access ======================= 
set rulebase security rules AllowHTTPSInbound action allow from External to """+ecomm_zone+""" source any destination EcommPub
set rulebase security rules AllowHTTPSInbound application any service service-https
set rulebase security rules AllowHTTPSInbound application any service service-http
# ======================= GUI Access ======================= 
set rulebase security rules EcommWebIntrazone action allow from """+work_zone+""" to """+ecomm_zone+""" source any destination EcommPub
set rulebase security rules EcommWebIntrazone application any service service-https
set rulebase security rules EcommWebIntrazone application any service service-http

## Mail
# ======================= Granular Web Control ======================= 
set rulebase security rules MailAllowInternet action allow from """+mail_zone+""" to External source FedoraMailPriv destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules MailAllowInternet application any service service-http
set rulebase security rules MailAllowInternet application any service service-https
set rulebase security rules MailAllowDNSOutbound action allow from """+mail_zone+""" to External source FedoraMailPriv destination any
set rulebase security rules MailAllowDNSOutbound application dns service application-default
# ======================= Scoring ======================= 
set rulebase security rules AllowMailInbound action allow from External to """+mail_zone+""" source any destination FedoraMailPub
set rulebase security rules AllowMailInbound application pop3 service application-default
set rulebase security rules AllowMailInbound application smtp service application-default
set rulebase security rules AllowMailInbound application imap service application-default
# ======================= I love Deer! ======================= 
set rulebase security rules AllowMailLDAPandDNS action allow from External to """+mail_zone+""" source any destination any
set rulebase security rules AllowMailLDAPandDNS action allow from """+mail_zone+""" to External source any destination any
set rulebase security rules AllowMailLDAPandDNS application ldap service application-default
set rulebase security rules AllowMailLDAPandDNS application dns service application-default
set rulebase security rules AllowMailLDAPandDNS application dns service ADWindowsPub
set rulebase security rules AllowMailLDAPandDNS application ldap service ADWindowsPub


# Deny all
set rulebase security rules DENYOUTBOUND action deny from """+work_zone+""" to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from """+splunk_zone+""" to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from """+ecomm_zone+""" to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from """+mail_zone+""" to External source any destination any
set rulebase security rules DENYOUTBOUND application any service any

set rulebase security rules DENYINBOUND action deny from External to """+work_zone+""" source any destination any
set rulebase security rules DENYINBOUND action deny from External to """+splunk_zone+""" source any destination any
set rulebase security rules DENYINBOUND action deny from External to """+ecomm_zone+""" source any destination any
set rulebase security rules DENYINBOUND action deny from External to """+mail_zone+""" source any destination any
set rulebase security rules DENYINBOUND application any service any

delete rulebase dos


## Slime Zone
set network profiles zone-protection-profile "Slime Zone" flood syn red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood syn red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood syn red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood syn enable yes
set network profiles zone-protection-profile "Slime Zone" flood syn red action random-early-drop

set network profiles zone-protection-profile "Slime Zone" flood icmp red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood icmp red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood icmp red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood icmp enable yes

set network profiles zone-protection-profile "Slime Zone" flood other-ip red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood other-ip red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood other-ip red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood other-ip enable yes

set network profiles zone-protection-profile "Slime Zone" flood udp red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood udp red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood udp red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood udp enable yes

set network profiles zone-protection-profile "Slime Zone" scan threat-id 8001 action block-ip track-by attacker-and-victim interval 300 threshold 5
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8002 action block-ip track-by attacker-and-victim interval 300 threshold 5
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8003 action block-ip track-by attacker-and-victim interval 300 threshold 5
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8006 action block-ip track-by attacker-and-victim interval 300 threshold 5

set network profiles zone-protection-profile "Slime Zone" discard-ip-spoof yes
set network profiles zone-protection-profile "Slime Zone" discard-ip-frag yes
set network profiles zone-protection-profile "Slime Zone" discard-malformed yes

set network profiles zone-protection-profile "Slime Zone" discard-tcp-split-handshake yes
set network profiles zone-protection-profile "Slime Zone" discard-tcp-overlap-segment yes
set network profiles zone-protection-profile "Slime Zone" discard-tcp-syn-with-data yes
set network profiles zone-protection-profile "Slime Zone" discard-tcp-synack-with-data yes

set network profiles zone-protection-profile "Slime Zone" icmp-ping-zero-id yes
set network profiles zone-protection-profile "Slime Zone" icmp-fragment yes
set network profiles zone-protection-profile "Slime Zone" icmp-large-packet yes


commit
set mgt-config users admin password
delete admin-sessions
"""
  command_file.write(commands)
  print("File is written to PAConfig.txt")
print("Copy and paste the output of the script.")

# After Script is done disable CLI Scripting
# Check the group that the user is in and make sure its not a honey pot, disable or remove any other users. IPv6 Addressing scheme can be found in teams or printed off for competition.
# The Reverse Shell Script is disabled by default. Enable when far enough in comp to ensure that it is working and not messing with scoring.

# TODO:
# Implement SSL Decryption to script
# Implement Honey Pot to admin user

# Experimental rules can be disabled:
# Ex: set rulebase security rules KillReverseShells disabled yes

# Code removed from script:
# set mgt-config users """+new_user+""" password
# set mgt-config users """+new_user+""" permissions role-based superuser yes
# set mgt-config users """+new_user+""" password-expiry no

# Change Log:
# 11/10/24 Added IPv6 configuration to script. This script will configure the Palo Alto with the following settings: interfaces and static routes for IPv6 -doshowipospf
# 2/10/25 updated script to work with Pan OS 11, also verified sec rules/NAT.-doshowipospf
# 2/18/25 Added Dos Protection and Services for Splunk, DebianDNS, ADWindowsPub, UbuntuWeb, FedoraMail-doshowipospf
# 3/13/26 Removed IP subnet blocking and Debian DNS references. - Fletcher Meyer
# 3/14/26 Dynamic zone selection, slime zone, validated new script. - Fletcher Meyer
