#!/usr/bin/env python3
#
# SecureBaseScript2.py - Firewall 2 (Windows Side)
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

# Version 1.0.0 - Firewall 2 (Windows Side)
# Zones: External (connects to VyOS), Windows (AD/DNS, Web, FTP, Workstation)
# Run this with your team number and then ssh into Palo Alto Firewall 2.
# Enter "set cli scripting-mode on" and then "configure"
# Then copy and paste the output of this script.
# Also remember to turn off cli scripting after with "set cli scripting-mode off"
#
# Windows-side VMs (172.20.240.0/24):
#   AD/DNS  Server 2019: 172.20.240.102  Public: 172.25.<team>.155
#   Web     Server 2019: 172.20.240.101  Public: 172.25.<team>.140
#   FTP     Server 2022: 172.20.240.104  Public: 172.25.<team>.162
#   Win 11  Workstation: 172.20.240.100  Public: dynamic

team_num = input("Please enter the Team Number: ")
team_num = int(team_num) + 20  # Team numbers start at 20, update based on team packet
team_num = str(team_num)
# Team number for variables

permitted_ip = input("Please enter the Windows Workstation IP: ")
permitted_ip = str(permitted_ip)
# Set static IP for Windows Workstation
# Permit only the Windows Workstation IP to access FW2 management

external_zone = input("Please enter the name of the External Zone: ")
external_zone = str(external_zone)

internal_zone = input("Please enter the name of the Internal Zone: ")
internal_zone = str(internal_zone)


with open("PAConfig2.txt", "w") as command_file:
  commands="""
configure
set deviceconfig system permitted-ip """+permitted_ip+"""
set deviceconfig system dns-setting servers primary 172.20.240.102
set deviceconfig system dns-setting servers secondary 9.9.9.9
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
set zone """+external_zone+""" network zone-protection-profile Default
set zone """+internal_zone+""" network zone-protection-profile Default
set network profiles interface-management-profile none
set network interface ethernet ethernet1/3 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 interface-management-profile none
set address PrivIP10 ip-netmask 10.0.0.0/8
set address PrivIP172 ip-netmask 172.16.0.0/12
set address PrivIP192 ip-netmask 192.168.0.0/16
set address WinWkstPriv ip-netmask """+permitted_ip+"""
set address ADDNSPriv ip-netmask 172.20.240.102/32
set address ADDNSPub ip-netmask 172.25."""+team_num+""".155/32
set address WinWebPriv ip-netmask 172.20.240.101/32
set address WinWebPub ip-netmask 172.25."""+team_num+""".140/32
set address WinFTPPriv ip-netmask 172.20.240.104/32
set address WinFTPPub ip-netmask 172.25."""+team_num+""".162/32
set address SplunkPub ip-netmask 172.25."""+team_num+""".9/32
set address LAN ip-range 172.20.240.0-172.20.242.255
set service WinHTTP protocol tcp port 80
set service WinHTTPS protocol tcp port 443
set service DNS-TCP protocol tcp port 53
set service DNS-UDP protocol udp port 53
set service WinFTP protocol tcp port 21
set service WinTFTP protocol udp port 69
set service WinNTP protocol udp port 123
set service WinLDAP protocol tcp port 389
set service WinKerberos-TCP protocol tcp port 88
set service WinKerberos-UDP protocol udp port 88
set service WinGlobalCat protocol tcp port 3268
set service WinSMB protocol tcp port 445
set service WinRPC protocol tcp port 135
set service Splunk protocol tcp port 8089,9997,514
delete rulebase nat
set rulebase nat rules ADDNS-Public nat-type ipv4 from """+internal_zone+""" to """+external_zone+""" source ADDNSPriv destination any service any source-translation static-ip bi-directional yes translated-address ADDNSPub
set rulebase nat rules WinWeb-Public nat-type ipv4 from """+internal_zone+""" to """+external_zone+""" source WinWebPriv destination any service any source-translation static-ip bi-directional yes translated-address WinWebPub
set rulebase nat rules WinFTP-Public nat-type ipv4 from """+internal_zone+""" to """+external_zone+""" source WinFTPPriv destination any service any source-translation static-ip bi-directional yes translated-address WinFTPPub
set rulebase nat rules Inside-OutsidePAT nat-type ipv4 from """+internal_zone+""" to """+external_zone+""" source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/3
delete rulebase security
set rulebase security rules KillReverseShells action drop from """+internal_zone+""" to """+external_zone+""" source any destination PrivIP10
set rulebase security rules KillReverseShells action drop from """+internal_zone+""" to """+external_zone+""" source any destination PrivIP192
set rulebase security rules KillReverseShells application any service service-https
set rulebase security rules KillReverseShells application any service service-http
set rulebase security rules KillReverseShells application any service DNS-TCP
set rulebase security rules KillReverseShells application any service DNS-UDP
set rulebase security rules AllowICMP action allow from any to any source any destination any
set rulebase security rules AllowICMP application ping service application-default
set rulebase security rules AllowICMP application icmp service application-default
set rulebase security rules AllowNTPOutbound action allow from """+internal_zone+""" to """+external_zone+""" source any destination any
set rulebase security rules AllowNTPOutbound application ntp service application-default
set rulebase security rules AllowDNSOutbound action allow from """+internal_zone+""" to """+external_zone+""" source any destination any
set rulebase security rules AllowDNSOutbound application dns service application-default
set rulebase security rules AllowInternet action allow from """+internal_zone+""" to """+external_zone+""" source any destination any profile-setting profiles spyware strict virus default vulnerability default
set rulebase security rules AllowInternet application any service service-http
set rulebase security rules AllowInternet application any service service-https
set rulebase security rules AllowSplunkForward action allow from """+internal_zone+""" to """+external_zone+""" source any destination SplunkPub
set rulebase security rules AllowSplunkForward application splunk service Splunk
set rulebase security rules AllowWebInbound action allow from """+external_zone+""" to """+internal_zone+""" source any destination WinWebPub
set rulebase security rules AllowWebInbound application web-browsing service WinHTTP
set rulebase security rules AllowWebInbound application ssl service WinHTTPS
set rulebase security rules AllowDNSInbound action allow from """+external_zone+""" to """+internal_zone+""" source any destination ADDNSPub
set rulebase security rules AllowDNSInbound application dns service WinDNS-TCP
set rulebase security rules AllowDNSInbound application dns service WinDNS-UDP
set rulebase security rules AllowFTPInbound action allow from """+external_zone+""" to """+internal_zone+""" source any destination WinFTPPub
set rulebase security rules AllowFTPInbound application ftp service WinFTP
set rulebase security rules AllowTFTPInbound action allow from """+external_zone+""" to """+internal_zone+""" source any destination WinFTPPub
set rulebase security rules AllowTFTPInbound application tftp service WinTFTP
set rulebase security rules AllowNTPInbound action allow from """+external_zone+""" to """+internal_zone+""" source any destination ADDNSPub
set rulebase security rules AllowNTPInbound application ntp service WinNTP
set rulebase security rules AllowADInbound action allow from """+external_zone+""" to """+internal_zone+""" source any destination ADDNSPub
set rulebase security rules AllowADInbound application ldap service WinLDAP
set rulebase security rules AllowADInbound application kerberos service WinKerberos-TCP
set rulebase security rules AllowADInbound application kerberos service WinKerberos-UDP
set rulebase security rules AllowADInbound application msrpc service WinRPC
set rulebase security rules AllowADInbound application ms-ds-replication service WinGlobalCat
set rulebase security rules DENYANYANY action deny from any to any source any destination any
set rulebase security rules DENYANYANY application any service any
delete rulebase dos
set profiles dos-protection CCDC_Protection type aggregate flood icmp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood udp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood other-ip enable yes
set profiles dos-protection CCDC_Protection type aggregate flood icmpv6 enable yes
set profiles dos-protection CCDC_Protection type aggregate flood tcp-syn enable yes
set rulebase dos rules WinWeb-DOS action protect from """+external_zone+""" to """+internal_zone+""" source any destination WinWebPub
set rulebase dos rules WinWeb-DOS action protect service WinHTTP protection aggregate profile CCDC_Protection
set rulebase dos rules WinWeb-DOS action protect service WinHTTPS protection aggregate profile CCDC_Protection
set rulebase dos rules ADDNS-DOS action protect from """+external_zone+""" to """+internal_zone+""" source any destination ADDNSPub
set rulebase dos rules ADDNS-DOS action protect service WinDNS-TCP protection aggregate profile CCDC_Protection
set rulebase dos rules ADDNS-DOS action protect service WinDNS-UDP protection aggregate profile CCDC_Protection
set rulebase dos rules WinFTP-DOS action protect from """+external_zone+""" to """+internal_zone+""" source any destination WinFTPPub
set rulebase dos rules WinFTP-DOS action protect service WinFTP protection aggregate profile CCDC_Protection
set rulebase dos rules WinFTP-DOS action protect service WinTFTP protection aggregate profile CCDC_Protection
set rulebase dos rules ProtectDefault action protect from any to any source any destination any
set rulebase dos rules ProtectDefault action protect service any protection aggregate profile default
commit
set mgt-config users admin password
delete admin-sessions
"""
  command_file.write(commands)
  print("File is written to PAConfig2.txt")
print("Copy and paste the output of the script.")

# After script is done, disable CLI scripting with: set cli scripting-mode off
# Check the admin group and remove any honeypot/extra users.
# The KillReverseShells rule is active by default.
# Disable it if it interferes with scoring: set rulebase security rules KillReverseShells disabled yes

# TODO:
# Implement SSL Decryption
# Implement Honeypot on admin user

# Experimental rules can be disabled:
# Ex: set rulebase security rules KillReverseShells disabled yes

# Change Log:
# 3/12/26 Initial script for FW2 (Windows side). Zones: External, Windows.
#         Named service objects for all scored services (DNS, HTTP/HTTPS, FTP, TFTP, NTP, LDAP, Kerberos).
#         Applications used where applicable per PA app-id.
#         Added Splunk forwarder outbound rule for Windows log shipping.