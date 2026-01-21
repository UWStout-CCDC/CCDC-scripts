#!/usr/bin/env python3
#
# SecureBaseScript.py
# Copyright (C) 2025 doshowipospf
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

# Version 2.1.0
# Run this with your team number and then ssh into the Palo Alto. Enter "set cli scripting-mode on" and then "cofigure"
# Then copy and past the output of the script. The first command increases the winow buffer size and the second command enters configure mode.
# This script should be ran before competition and put the config txt file on GitHub.
# Also Remember to turn off cli scripting after script is ran with "set cli scripting-mode off"

team_num = input("Please enter the Team Number :")
team_num = int(team_num) + 20 # Team numbers start at 20, update based on team packet
team_num = str(team_num)
# Team number for varaibles

permitted_ip = input("Please enter the Ubuntu Workstation IP: ")
permitted_ip = str(permitted_ip)
# Set Static IP for Ubuntu Workstation
# Permit only the Ubuntu Workstation IP and the Palo Alto IP

new_user = input("Please enter the new admin user: ")
new_user = str(new_user)


with open("PAConfig.txt", "w") as command_file:
  commands="""
configure
set deviceconfig system permitted-ip """+permitted_ip+"""
set deviceconfig system dns-setting servers primary 9.9.9.9
set deviceconfig system dns-setting servers secondary 149.112.112.112
delete mgt-config users administrator
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
set zone User network zone-protection-profile Default
set zone Internal network zone-protection-profile Default
set zone Public network zone-protection-profile Default
set network profiles interface-management-profile none
set network interface ethernet ethernet1/3 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 ipv6 enabled yes
set network interface ethernet ethernet1/4 layer3 ipv6 enabled yes
set network interface ethernet ethernet1/1 layer3 ipv6 enabled yes
set network interface ethernet ethernet1/2 layer3 ipv6 address fd00:1::1/64
set network interface ethernet ethernet1/4 layer3 ipv6 address fd00:2::1/64
set network interface ethernet ethernet1/1 layer3 ipv6 address fd00:3::1/64
set network virtual-router RT1 routing-table ipv6 static-route Internal destination fd00:1::/64 interface ethernet1/2
set network virtual-router RT1 routing-table ipv6 static-route User destination fd00:2::/64 interface ethernet1/4
set network virtual-router RT1 routing-table ipv6 static-route Public destination fd00:3::/64 interface ethernet1/1
set address PrivIP10 ip-netmask 10.0.0.0/8
set address SplunkPriv ip-netmask 172.20.241.20
set address SplunkPub ip-netmask 172.25."""+team_num+""".9
set address DockerPriv ip-netmask 172.20.240.10
set address DockerPub ip-netmask 172.25."""+team_num+""".97
set address DebianDNSPriv ip-netmask 172.20.240.20
set address DebianDNSPub ip-netmask 172.25."""+team_num+""".20
set address UbuntuWebPriv ip-netmask 172.20.242.10
set address UbuntuWebPub ip-netmask 172.25."""+team_num+""".23
set address ADWindowsPriv ip-netmask 172.20.242.200
set address ADWindowsPub ip-netmask 172.25."""+team_num+""".27
set address UbuntuPriv ip-netmask """+permitted_ip+"""
set address CentOSWebPriv ip-netmask 172.20.241.30
set address CentOSWebPub ip-netmask 172.25."""+team_num+""".11
set address FedoraMailPriv ip-netmask 172.20.241.40
set address FedoraMailPub ip-netmask 172.25."""+team_num+""".39
set address LAN ip-range 172.20.240.0-172.20.242.255
set service WebMail protocol tcp port 25,110
set service SplunkScoring protocol tcp port 8000
set service Splunk protocol tcp port 8089,9997,514
set service DebianDNS protocol tcp port 53
set service DebianNTP protocol udp port 123
set service ADWindows protocol tcp port 389,53
delete rulebase nat
set rulebase nat rules DebianDNS-Public nat-type ipv4 from Internal to External source DebianDNSPriv destination any service any source-translation static-ip bi-directional yes translated-address DebianDNSPub
set rulebase nat rules Docker-Public nat-type ipv4 from Internal to External source DockerPriv destination any service any source-translation static-ip bi-directional yes translated-address DockerPub
set rulebase nat rules Splunk-Public nat-type ipv4 from Public to External source SplunkPriv destination any service any source-translation static-ip bi-directional yes translated-address SplunkPub
set rulebase nat rules Ecomm-Public nat-type ipv4 from Public to External source CentOSWebPriv destination any service any source-translation static-ip bi-directional yes translated-address CentOSWebPub
set rulebase nat rules FedoraMail-Public nat-type ipv4 from Public to External source FedoraMailPriv destination any service any source-translation static-ip bi-directional yes translated-address FedoraMailPub
set rulebase nat rules UbuntuWeb-Public nat-type ipv4 from User to External source UbuntuWebPriv destination any service any source-translation static-ip bi-directional yes translated-address UbuntuWebPub
set rulebase nat rules WindowsAD-Public nat-type ipv4 from User to External source ADWindowsPriv destination any service any source-translation static-ip bi-directional yes translated-address ADWindowsPub
set rulebase nat rules Inside-OutsidePat nat-type ipv4 from User to External source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/3
set rulebase nat rules Inside-OutsidePat nat-type ipv4 from Public to External source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/3
set rulebase nat rules Inside-OutsidePat nat-type ipv4 from Internal to External source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/3
delete rulebase security
set rulebase security rules KillReverseShells action drop from Public to External source any destination PrivIP10
set rulebase security rules KillReverseShells action drop from User to External source any destination PrivIP10
set rulebase security rules KillReverseShells action drop from Internal to External source any destination PrivIP10
set rulebase security rules KillReverseShells application any service service-https
set rulebase security rules KillReverseShells application any service service-http
set rulebase security rules AllowICMP action allow from any to any source any destination any
set rulebase security rules AllowICMP application ping service application-default
set rulebase security rules AllowICMP application icmp service application-default
set rulebase security rules AllowNTP action allow from Public to External source any destination any
set rulebase security rules AllowNTP action allow from User to External source any destination any
set rulebase security rules AllowNTP action allow from Internal to External source any destination any
set rulebase security rules AllowNTP application ntp service application-default
set rulebase security rules AllowInternet action allow from User to External source any destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules AllowInternet action allow from Public to External source any destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules AllowInternet action allow from Internal to External source any destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules AllowInternet application any service service-http
set rulebase security rules AllowInternet application any service service-https
set rulebase security rules AllowDNSOutbound action allow from Internal to External source any destination any
set rulebase security rules AllowDNSOutbound action allow from User to External source any destination any
set rulebase security rules AllowDNSOutbound action allow from Public to External source any destination any
set rulebase security rules AllowDNSOutbound application dns service application-default
set rulebase security rules AllowDNSInbound action allow from External to Internal source any destination DebianDNSPub
set rulebase security rules AllowDNSInbound action allow from External to User source any destination ADWindowsPub
set rulebase security rules AllowDNSInbound application dns service application-default
set rulebase security rules AllowHTTPSInbound action allow from External to Public source any destination CentOSWebPub
set rulebase security rules AllowHTTPSInbound application any service service-https
set rulebase security rules AllowHTTPSInbound application any service service-http
set rulebase security rules AllowMailInbound action allow from External to Public source any destination FedoraMailPub
set rulebase security rules AllowMailInbound application pop3 service application-default
set rulebase security rules AllowMailInbound application smtp service application-default
set rulebase security rules AllowMailInbound application imap service application-default
set rulebase security rules AllowInboundWindows action allow from External to User source any destination ADWindowsPub
set rulebase security rules AllowInboundWindows application ldap service application-default
set rulebase security rules AllowInboundWindows application dns service application-default
set rulebase security rules AllowScoringSplunk action allow from External to Public source any destination SplunkPub
set rulebase security rules AllowScoringSplunk application any service SplunkScoring
set rulebase security rules DNSDebianIntrazone action allow from Internal to Public source DebianDNSPriv destination any
set rulebase security rules DNSDebianIntrazone action allow from Internal to User source DebianDNSPriv destination any
set rulebase security rules DNSDebianIntrazone application any service DebianDNS
set rulebase security rules NTPDebianIntrazone action allow from Internal to Public source DebianDNSPriv destination any
set rulebase security rules NTPDebianIntrazone action allow from Internal to User source DebianDNSPriv destination any
set rulebase security rules NTPDebianIntrazone application ntp service DebianNTP
set rulebase security rules SplunkIntrazone action allow from Public to Internal source SplunkPriv destination any
set rulebase security rules SplunkIntrazone action allow from Public to User source SplunkPriv destination any
set rulebase security rules SplunkIntrazone application splunk service Splunk
set rulebase security rules ADWindowsIntrazone action allow from User to Internal source ADWindowsPriv destination any
set rulebase security rules ADWindowsIntrazone action allow from User to Public source ADWindowsPriv destination any
set rulebase security rules ADWindowsIntrazone application dns service ADWindows
set rulebase security rules ADWindowsIntrazone application ldap service ADWindows
set rulebase security rules EcommWebIntrazone action allow from Public to User source CentOSWebPriv destination any
set rulebase security rules EcommWebIntrazone action allow from Public to Internal source CentOSWebPriv destination any
set rulebase security rules EcommWebIntrazone application any service service-http
set rulebase security rules EcommWebIntrazone application any service service-https
set rulebase security rules DENYOUTBOUND action deny from Internal to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from User to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from Public to External source any destination any
set rulebase security rules DENYOUTBOUND application any service any
set rulebase security rules DENYINBOUND action deny from External to Internal source any destination any
set rulebase security rules DENYINBOUND action deny from External to User source any destination any
set rulebase security rules DENYINBOUND action deny from External to Public source any destination any
set rulebase security rules DENYINBOUND application any service any
delete rulebase dos
set profiles dos-protection CCDC_Protection type aggregate flood icmp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood udp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood other-ip enable yes
set profiles dos-protection CCDC_Protection type aggregate flood icmpv6 enable yes
set profiles dos-protection CCDC_Protection type aggregate flood tcp-syn enable yes
set rulebase dos rules DebianDNS-DOS action protect from External to Internal source any destination DebianDNSPub
set rulebase dos rules DebianDNS-DOS action protect service DebianDNS protection aggregate profile CCDC_Protection
set rulebase dos rules DebianDNS-DOS action protect service DebianNTP protection aggregate profile CCDC_Protection
set rulebase dos rules Splunk-DOS action protect from External to Public source any destination SplunkPub
set rulebase dos rules Splunk-DOS action protect service SplunkScoring protection aggregate profile CCDC_Protection
set rulebase dos rules ADWindows-DOS action protect from External to User source any destination ADWindowsPub
set rulebase dos rules ADWindows-DOS action protect service ADWindows protection aggregate profile CCDC_Protection
set rulebase dos rules CentOSWeb-DOS action protect from External to Public source any destination CentOSWebPub
set rulebase dos rules CentOSWeb-DOS action protect service http protection aggregate profile CCDC_Protection
set rulebase dos rules CentOSWeb-DOS action protect service https protection aggregate profile CCDC_Protection
set rulebase dos rules FedoraMail-DOS action protect from External to Public source any destination FedoraMailPub
set rulebase dos rules FedoraMail-DOS action protect service WebMail protection aggregate profile CCDC_Protection
set rulebase dos rules ProtectDefault action protect from any to any source any destination any
set rulebase dos rules ProtectDefault action protect service any protection aggregate profile default
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
# 2/18/25 Added Dos Protection and Services for Splunk, DebianDNS, ADWindows, CentOSWeb, FedoraMail-doshowipospf