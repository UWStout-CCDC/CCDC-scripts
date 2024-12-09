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
set mgt-config users admin password
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no
set deviceconfig system service disable-ssh no
set deviceconfig system login-banner "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED. You must have explicit, authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities performed on this device are logged and monitored."
set deviceconfig system timezone US/Central
set network profiles zone-protection-profile Default discard-overlapping-tcp-segment-mismatch yes discard-unknown-option yes tcp-reject-non-syn yes flood tcp-syn enable yes syn-cookies maximal-rate 500
set network profiles zone-protection-profile Default flood icmp enable yes
set network profiles zone-protection-profile Default flood udp enable yes
set network profiles zone-protection-profile Default flood other-ip enable yes
set network profiles zone-protection-profile Default flood icmpv6 enable yes
set network profiles interface-management-profile none
set network interface ethernet ethernet1/3 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 interface-management-profile none
set network interface ethernet eth1/2 ipv6 enabled yes
set network interface ethernet eth1/4 ipv6 enabled yes
set network interface ethernet eth1/1 ipv6 enabled yes
set network interface ethernet eth1/2 ipv6 address fd00:1::1/64
set network interface ethernet eth1/4 ipv6 address fd00:2::1/64
set network interface ethernet eth1/1 ipv6 address fd00:3::1/64
set network interface ethernet eth1/2 ipv6 ndp-profile default
set network interface ethernet eth1/4 ipv6 ndp-profile default
set network interface ethernet eth1/1 ipv6 ndp-profile default
set network virtual-router default routing-table ipv6 static-route Internal route fd00:1::/64 interface eth1/2 nexthop none
set network virtual-router default routing-table ipv6 static-route User route fd00:2::/64 interface eth1/4 nexthop none
set network virtual-router default routing-table ipv6 static-route Public route fd00:3::/64 interface eth1/1 nexthop none
delete rulebase security rules Any-Any
delete rulebase security rules LAN2DMZ
delete rulebase security rules DMZ2LAN
delete rulebase security rules any2any
set address Private1 ip-range 10.0.0.0-10.255.255.255
set address Private2 ip-range 172.16.0.0-172.16.255.255
set address Private3 ip-range 192.168.0.0-192.168.255.255
set rulebase security rules QuadNine action allow from any to any source any destination 9.9.9.9
set rulebase security rules QuadNine application dns service application-default
set rulebase security rules DNSoutBlock action allow from LAN to EXTERNAL source any destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules DNSoutBlock action allow from DMZ to EXTERNAL source any destination any
set rulebase security rules DNSoutBlock application DNS service application-default
set rulebase security rules NTPandSYSLOGandDNS action allow from LAN to DMZ source any destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules NTPandSYSLOGandDNS action allow from DMZ to LAN source any destination
set rulebase security rules NTPandSYSLOGandDNS application ntp service application-default
set rulebase security rules NTPandSYSLOGandDNS application syslog service application-default
set rulebase security rules NTPandSYSLOGandDNS application dns service application-default
set rulebase security rules NTPandSYSLOGandDNS application ssl service application-default
set rulebase security rules NTPandSYSLOGandDNS application web-browsing service application-default
set rulebase security rules CentOStoUbuntuDB action allow from any to any source 172.20.240.11 destination 172.25."""+team_num+""".23 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules CentOStoUbuntuDB from any source 172.25."""+team_num+""".11
set rulebase security rules CentOStoUbuntuDB application any service any
set rulebase security rules PrivateIPOutNoNo action deny from LAN to External source any destination Private1
set rulebase security rules PrivateIPOutNoNo action deny from LAN to External source any destination Private2
set rulebase security rules PrivateIPOutNoNo action deny from DMZ to External source any destination Private3
set rulebase security rules PrivateIPOutNoNo application any service any
set rulebase security rules PaloAltoOut action allow from LAN to External source 172.20.242.150 destination any
set rulebase security rules PaloAltoOut action allow from LAN to DMZ source 172.20.242.150 destination any
set rulebase security rules PaloAltoOut application paloalto-updates service any
set rulebase security rules PaloAltoOut application dns service any
set rulebase security rules PaloAltoOut application ntp service any
set rulebase security rules Win2019ADExternal action allow from External to External source 172.31."""+team_num+""".27 destination any
set rulebase security rules Win2019ADExternal application any service any
set rulebase security rules CentOSin action allow from External to DMZ source any destination 172.25."""+team_num+""".11 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules CentOSin application ssl service application-default
set rulebase security rules CentOSin application web-browsing service application-default
set rulebase security rules 2019DNStoUbuntuDNS action allow from DMZ to LAN source 172.20.242.200 destination 172.20.240.20 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules 2019DNStoUbuntuDNS application dns service application-default
set rulebase security rules DEBIANtoUBUNTU action allow from LAN to DMZ source 172.20.240.20 destination 172.20.242.10 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules DEBIANtoUBUNTU application mysql service application-default
set rulebase security rules DEBIANtoUBUNTU to External destination 172.25."""+team_num+""".10
set rulebase security rules DEBIANtoUBUNTU to DMZ
set rulebase security rules UbuntuDNSto2019DNS action allow from DMZ to LAN source 172.20.242.10 destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules UbuntuDNSto2019DNS application dns service application-default
set rulebase security rules UbuntuDNSto2019DNS application ntp service application-default
set rulebase security rules UbuntuDNSto2019DNS application active-directory service application-default
set rulebase security rules UbuntuDNSto2019DNS application ldap service application-default
set rulebase security rules UbuntuDNSto2019DNS application ms-ds-smb service application-default
set rulebase security rules UbuntuDNSto2019DNS application msrpc service application-default
set rulebase security rules UbuntuDNSto2019DNS application ms-ds-smb service application-default
set rulebase security rules UbuntuDNSto2019DNS application netbios-ss service application-default
set rulebase security rules UbuntuDNSto2019DNS application netbios-dg service application-default
set rulebase security rules CentOSDNSto2019DNS action allow from DMZ to LAN source 172.20.241.30 destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules CentOSDNSto2019DNS application dns service application-default
set rulebase security rules CentOSDNSto2019DNS application ntp service application-default
set rulebase security rules CentOSDNSto2019DNS application active-directory service application-default
set rulebase security rules CentOSDNSto2019DNS application ldap service application-default
set rulebase security rules CentOSDNSto2019DNS application ms-ds-smb service application-default
set rulebase security rules CentOSDNSto2019DNS application msrpc service application-default
set rulebase security rules CentOSDNSto2019DNS application netbios-ss service application-default
set rulebase security rules CentOSDNSto2019DNS application netbios-dg service application-default
set rulebase security rules UbuntuDNSin action allow from External to DMZ source any destination 172.25."""+team_num+""".23 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules UbuntuDNSin application dns service application-default
set rulebase security rules FedoraWebin action allow from External to LAN source any destination 172.25."""+team_num+""".39 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules FedoraWebin application web-browsing service application-default
set rulebase security rules FedoraWebin application smtp service application-default
set rulebase security rules FedoraWebin application pop3 service application-default
set rulebase security rules FedoraWebin application ssl service application-default
set rulebase security rules FedoraWebin application imap service application-default
set rulebase security rules 2019DNSin action allow from External to LAN source any destination 172.25."""+team_num+""".27 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules 2019DNSin application dns service application-default
set rulebase security rules SERVERout-2019AD action allow from LAN to External source 172.20.242.200 destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules SERVERout-2019AD application ssl service application-default
set rulebase security rules SERVERout-2019AD application ms-update service application-default
set rulebase security rules SERVERout-2019AD application dns service application-default
set rulebase security rules SERVERout-2019AD application web-browsing service application-default
set rulebase security rules SERVERout-Fedora action allow from LAN to External source 172.20.241.39 destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules SERVERout-Fedora application pop3 service application-default
set rulebase security rules SERVERout-Fedora application imap service application-default
set rulebase security rules SERVERout-Fedora application dns service application-default
set rulebase security rules SERVERout-Fedora application ocsp service application-default
set rulebase security rules SERVERout-Fedora application smtp service application-default
set rulebase security rules SERVERout-Fedora application ssh service application-default
set rulebase security rules SERVERout-Fedora application github service application-default
set rulebase security rules SERVERout-Fedora application git-base service application-default
set rulebase security rules SERVERout-Fedora application ssl service application-default
set rulebase security rules SERVERout-Fedora application subversion service application-default
set rulebase security rules SERVERout-Fedora application sourceforge service application-default
set rulebase security rules SERVERout-Fedora application apt-get service application-default
set rulebase security rules SERVERout-Fedora application web-browsing service application-default
set rulebase security rules DMZout-CentOS action allow from DMZ to External source 172.20.241.30 destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules DMZout-CentOS application ssl service application-default
set rulebase security rules DMZout-CentOS application ftp service application-default
set rulebase security rules DMZout-CentOS application yum service application-default
set rulebase security rules DMZout-CentOS application github service application-default
set rulebase security rules DMZout-CentOS application git-base service application-default
set rulebase security rules DMZout-CentOS application ssh service application-default
set rulebase security rules DMZout-CentOS application web-browsing service application-default
set rulebase security rules DMZout-Ubuntu action allow from DMZ to External source 172.20.242.10 destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules DMZout-Ubuntu application dns service application-default
set rulebase security rules DMZout-Ubuntu application web-browsing service application-default
set rulebase security rules DMZout-Ubuntu application ssl service application-default
set rulebase security rules DMZout-Ubuntu application apt-get service application-default
set rulebase security rules INTERZONELAN action allow from LAN to LAN source any destination any
set rulebase security rules INTERZONELAN application any service any
set rulebase security rules INTERZONEDMZ action allow from DMZ to DMZ source any destination any
set rulebase security rules INTERZONEDMZ application any service any
set rulebase security rules AllowPublic2InternalDNS action allow from Public to Internal source any destination 172.20.240.20 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowPublic2InternalDNS application dns service application-default
set rulebase security rules AllowUser2InternalDNS action allow from User to Internal source any destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowUser2InternalDNS application dns service application-default
set rulebase security rules AllowLDAPFromPublic2User action allow from Public to User source 172.20.242.150 destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowLDAPFromPublic2User application ldap service application-default
set rulebase security rules AllowSplunkTraffic action allow from Internal to Public source any destination 172.20.242.10 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowSplunkTraffic from User
set rulebase security rules AllowSplunkTraffic application splunk service application-default
set rulebase security rules DENYALLEXTERNAL action deny from External to any source any destination any
set rulebase security rules DENYALLEXTERNAL application any service any
set rulebase security rules DENYALL action deny from any to any source any destination any
set rulebase security rules DENYALL application any service any
commit
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

