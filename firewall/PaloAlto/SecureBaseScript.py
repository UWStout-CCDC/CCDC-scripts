#!/usr/bin/env python3

# Version 2.0.2
# Run this with your team number and then Putty into the Palo Alto. Enter "set cli scripting-mode on" and then "cofigure"
# Then copy and past the output of the script. The first command increases the winow buffer size and the second command enters configure mode.
# This script should be ran before competition and put the config txt file on GitHub.
# Remember to put rule in to deny all external to PA NAT IP before removing NothingIn rule
# Also Remember to turn off cli scripting after script is ran with "set cli scripting-mode off"

# 2024 Added IPv6 configuration to script. This script will configure the Palo Alto with the following settings: interfaces and static routes for IPv6
# 2025 updated script to work with Pan OS 11, also verified sec rules.

team_num = input("Please enter the Team Number (+ Internal subnet number if applicable):")
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
set deviceconfig system permitted-ip 127.0.0.1
set deviceconfig system permitted-ip """+permitted_ip+"""
set deviceconfig system dns-setting servers primary 9.9.9.9
set deviceconfig system dns-setting servers secondary 149.112.112.112
delete mgt-config users administrator
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no
set deviceconfig system service disable-ssh no
set deviceconfig system login-banner "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED. You must have explicit, authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities performed on this device are logged and monitored."
set deviceconfig system timezone US/Central
set network profiles zone-protection-profile Default discard-overlapping-tcp-segment-mismatch yes discard-unknown-option yes tcp-reject-non-syn yes flood tcp-syn enable yes
set network profiles zone-protection-profile Default flood icmp enable yes
set network profiles zone-protection-profile Default flood udp enable yes
set network profiles zone-protection-profile Default flood other-ip enable yes
set network profiles zone-protection-profile Default flood icmpv6 enable yes
set network profiles interface-management-profile none
set network interface ethernet ethernet1/3 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 ipv6 enabled yes
set network interface ethernet ethernet1/4 layer3 ipv6 enabled yes
set network interface ethernet ethernet1/1 layer3 ipv6 enabled yes
set network interface ethernet ethernet1/2 layer3 ipv6 address fd00:1::1/64
set network interface ethernet ethernet1/4 layer3 ipv6 address fd00:2::1/64
set network interface ethernet ethernet1/1 layer3 ipv6 address fd00:3::1/64
set network virtual-router default routing-table ipv6 static-route Internal destination fd00:1::/64 interface ethernet1/2
set network virtual-router default routing-table ipv6 static-route User destination fd00:2::/64 interface ethernet1/4
set network virtual-router default routing-table ipv6 static-route Public destination fd00:3::/64 interface ethernet1/1
delete rulebase security
set rulebase security rules KillReverseShells action drop from Internal to External source any destination 172.31."""+(team_num+20)+""".2/29
set rulebase security rules KillReverseShells action drop from User to External source any destination 172.31."""+(team_num+20)+""".2/29
set rulebase security rules KillReverseShells action drop from Public to External source any destination 172.31."""+(team_num+20)+""".2/29
set rulebase security rules KillReverseShells application any service service-https
set rulebase security rules KillReverseShells application any service service-http
set rulebase security rules KillReverseShells disabled yes
set rulebase security rules AllowICMP action allow from any to any source any destination any
set rulebase security rules AllowICMP application ping service application-default
set rulebase security rules AllowICMP application icmp service application-default
set rulebase security rules AllowNTP allow from any to any source any destination any
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
set rulebase security rules AllowDNSInbound action allow from External to Internal source any destination 172.25."""+(team_num+20)+""".20
set rulebase security rules AllowDNSInbound action allow from External to User source any destination 172.25."""+(team_num+20)+""".27
set rulebase security rules AllowDNSInbound application dns service application-default
set rulebase security rules AllowHTTPSInbound action allow from External to Public source any destination 172.25."""+(team_num+20)+""".11
set rulebase security rules AllowHTTPSInbound application any service service-https
set rulebase security rules AllowHTTPSInbound application any service service-http
set rulebase security rules AllowMailInbound action allow from External to Public source any destination 172.25."""+(team_num+20)+""".39
set rulebase security rules AllowMailInbound application pop3 service application-default
set rulebase security rules AllowMailInbound application smtp service application-default
set rulebase security rules AllowMailInbound application imap service application-default
set rulebase security rules AllowMailInbound application smtps service application-default
set rulebase security rules AllowMailInbound application pop3s service application-default
set rulebase security rules AllowInboundWindows action allow from External to User source any destination 172.25."""+(team_num+20)+""".27
set rulebase security rules AllowInboundWindows application ldap service application-default
set rulebase security rules AllowInboundWindows application ssh service application-default
set rulebase security rules AllowScoringSplunk action allow from External to Public source any destination 172.25."""+(team_num+20)+""".9
set rulebase security rules AllowScoringSplunk application splunk service application-default
set rulebase security rules DENYOUTBOUND action deny from Internal to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from User to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from Public to External source any destination any
set rulebase security rules DENYINBOUND action deny from External to Internal source any destination any
set rulebase security rules DENYINBOUND action deny from External to User source any destination any
set rulebase security rules DENYINBOUND action deny from External to Public source any destination any
commit
set mgt-config users admin password
set mgt-config users """+new_user+""" password
set mgt-config users """+new_user+""" permissions role-based superuser yes
set mgt-config users """+new_user+""" password-expiry no
commit
"""
  command_file.write(commands)
  print("File is written to PAConfig.txt")
print("Copy and paste the output of the script.")

# After Script is done disable CLI Scripting
# Check the group that the user is in and make sure its not a honey pot, disable or remove any other users. IPv6 Addressing scheme can be found in teams or printed off for competition.
# The Reverse Shell Script is disabled by default. Enable when far enough in comp to ensure that it is working and not messing with scoring.

# TODO: Implement DOS Protection to script
# Implement SSL Decryption to script
# Implement Honey Pot to admin user
