#!/usr/bin/env python3

# Run this with your team number and then Putty into the Palo Alto. Enter "set cli scripting-mode on" and then "cofigure"
# Then copy and past the output of the script. The first command increases the winow buffer size and the second command enters configure mode.
# This script should be ran before competition and put the config txt file on GitHub.
# Remember to put rule in to deny all external to PA NAT IP before removing NothingIn rule
# Also Remember to turn off cli scripting after script is ran with "set cli scripting-mode off"

# 2024 Added IPv6 configuration to script. This script will configure the Palo Alto with the following settings: interfaces and static routes for IPv6
# Please, Please, Please Read the script and verify IP adressing before bringing this to competition

team_num = input("Please enter the Team Number (+ Internal subnet number if applicable):")
team_num = str(team_num)
# Team number for varaibles

permitted_ip = input("Please enter the Ubuntu Workstation IP: ")
permitted_ip = str(permitted_ip)
# Set Static IP for Ubuntu Workstation
# Permit only the Ubuntu Workstation IP and the Palo Alto IP


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
set network virtual-router default routing-table ipv6 static-route Internal destination fd00:1::/64 interface eth1/2
set network virtual-router default routing-table ipv6 static-route User destination fd00:2::/64 interface eth1/4
set network virtual-router default routing-table ipv6 static-route Public destination fd00:3::/64 interface eth1/1
delete rulebase security
set rulebase security rules AllowICMP action allow from any to any source any destination any
set rulebase security rules AllowICMP application ping
set rulebase security rules AllowICMP application icmp
set rulebase security rules AllowNTP allow from any to any source any destination any
set rulebase security rules AllowNTP application ntp service application-default
set rulebase security rules AllowInternet action allow from User to External source any destination any profile-setting profiles spyware strict virus default vulnerability
set rulebase security rules AllowInternet action allow from Public to External source any destination any profile-setting profiles spyware strict virus default vulnerability
set rulebase security rules AllowInternet action allow from Internal to External source any destination any profile-setting profiles spyware strict virus default vulnerability
set rulebase security rules AllowInternet application any service service-http
set rulebase security rules AllowInternet application any service service-https
set rulebase security rules AllowDNSOutbound action allow from Internal to External source any destination any
set rulebase security rules AllowDNSOutbound action allow from User to External source any destination any
set rulebase security rules AllowDNSOutbound action allow from Public to External source any destination any
set rulebase security rules AllowDNSOutbound application dns service application-default
set rulebase security rules AllowDNSInbound action allow from External to Internal source any destination 172.25."""+team_num+20+""".20
set rulebase security rules AllowDNSInbound application dns service application-default
set rulebase security rules AllowHTTPSInbound action allow from External to Public source any destination 172.25."""+team_num+20+""".11
set rulebase security rules AllowHTTPSInbound application any service service-https
set rulebase security rules AllowHTTPSInbound application any service service-http
set rulebase security rules AllowMailInbound action allow from External to Public source any destination 172.25."""+team_num+20+""".39
set rulebase security rules AllowMailInbound application pop3 service application-default
set rulebase security rules AllowMailInbound application smtp service application-default
set rulebase security rules AllowMailInbound application imap service application-default
set rulebase security rules AllowMailInbound application smtps service application-default
set rulebase security rules AllowMailInbound application pop3s service application-default
set rulebase security rules AllowInboundWindows action allow from External to User source any destination 172.25."""+team_num+20+""".27
set rulebase security rules AllowInboundWindows application ldap service application-default
set rulebase security rules AllowInboundWindows application ssh service application-default
set rulebase security rules AllowScoringSplunk action allow from External to Public source any destination 172.25."""+team_num+20+""".9
set rulebase security rules AllowScoringSplunk application splunk service application-default
set rulebase security rules DENYOUTBOUND action deny from Internal to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from User to External source any destination any
set rulebase security rules DENYOUTBOUND action deny from Public to External source any destination any
set rulebase security rules DENYINBOUND action deny from External to Internal source any destination any
set rulebase security rules DENYINBOUND action deny from External to User source any destination any
set rulebase security rules DENYINBOUND action deny from External to Public source any destination any
commit
set mgt-config users admin password
"""
  command_file.write(commands)
  print("File is written to PAConfig.txt")
print("Copy and paste the output of the script.")


# Old rules from the previous script

# set deviceconfig system permitted-ip 127.0.0.1
# set deviceconfig system permitted-ip """+permitted_ip+"""
# set deviceconfig system dns-setting servers primary 9.9.9.9
# set deviceconfig system dns-setting servers secondary 149.112.112.112
# delete mgt-config users administrator
# set mgt-config users admin password
# set deviceconfig system service disable-telnet yes
# set deviceconfig system service disable-http yes
# set deviceconfig system service disable-https no
# set deviceconfig system login-banner AuthorizedAccessOnly
# set network profiles zone-protection-profile Default discard-overlapping-tcp-segment-mismatch yes discard-unknown-option yes tcp-reject-non-syn yes flood tcp-syn enable yes syn-cookies maximal-rate 500
# set network profiles zone-protection-profile Default flood icmp enable yes
# set network profiles zone-protection-profile Default flood udp enable yes
# set network profiles zone-protection-profile Default flood other-ip enable yes
# set network profiles zone-protection-profile Default flood icmpv6 enable yes
# set network profiles interface-management-profile none
# set network interface ethernet ethernet1/3 layer3 interface-management-profile none
# set network interface ethernet ethernet1/2 layer3 interface-management-profile none
# set network interface ethernet ethernet1/1 layer3 interface-management-profile none
# delete rulebase security
# set rulebase security rules ScoreMail action allow from External to Public source any destination 172.25."""+team_num+""".39 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules ScoreMail application pop3 service application-default
# set rulebase security rules ScoreMail application smtp
# set rulebase security rules ScoreMail disabled yes
# set rulebase security rules ScoreEcomm action allow from External to Public source any destination 172.25."""+team_num+""".11 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules ScoreEcomm application any service service-http
# set rulebase security rules ScoreEcomm service service-https
# set rulebase security rules ScoreEcomm disabled yes
# set rulebase security rules ScoreDNS action allow from External to Internal source any destination 172.25."""+team_num+""".20 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules ScoreDNS application dns service application-default
# set rulebase security rules ScoreDNS disabled yes
# set service splunkweb protocol tcp port 8000
# set rulebase security rules ScoreSplunk action allow from External to Public source any destination 172.25."""+team_num+""".9 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules ScoreSplunk application any service splunkweb
# set rulebase security rules ScoreSplunk disabled yes
# set rulebase security rules NothingIN action deny from External to Internal source any destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules NothingIN to User
# set rulebase security rules NothingIN to Public
# set rulebase security rules NothingIN application any service application-default
# set rulebase security rules Quad9DNS action allow from Internal to External source any destination 9.9.9.9 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules Quad9DNS from User
# set rulebase security rules Quad9DNS from Public
# set rulebase security rules Quad9DNS application dns service application-default
# set rulebase security rules DenyOtherDNS action deny from Internal to External source any destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules DenyOtherDNS from User
# set rulebase security rules DenyOtherDNS from Public
# set rulebase security rules DenyOtherDNS application dns service application-default
# set rulebase security rules AllOut action allow from Internal to External source any destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules AllOut from User
# set rulebase security rules AllOut from Public
# set rulebase security rules AllOut application any service application-default
# set rulebase security rules AllowPublic2UserDNS action allow from Public to User source any destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules AllowPublic2UserDNS application dns service application-default
# set rulebase security rules AllowPublic2InternalDNS action allow from Public to Internal source any destination 172.20.240.20 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules AllowPublic2InternalDNS application dns service application-default
# set rulebase security rules AllowUser2InternalDNS action allow from User to Internal source any destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules AllowUser2InternalDNS application dns service application-default
# set rulebase security rules AllowLDAPFromPublic2User action allow from Public to User source 172.20.242.150 destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules AllowLDAPFromPublic2User application ldap service application-default
# set rulebase security rules AllowSplunkTraffic action allow from Internal to Public source any destination 172.20.242.10 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules AllowSplunkTraffic from User
# set rulebase security rules AllowSplunkTraffic application splunk service application-default
# set network interface ethernet ethernet1/1 link-state up

