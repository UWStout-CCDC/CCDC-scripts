#!/usr/bin/env python3

#Run this with your team number and then Putty into the Palo Alto. Enter "set cli scripting-mode on" and then "cofigure"
#Then copy and past the output of the script. The first command increases the winow buffer size and the second command enters configure mode.
#Syntax for rule creation
#set rulebase security rules <RuleName> action <allow/deny> from <zone source> to <dest zone> source <source IP> destination <dest ip>

#this will need to go at the begining when done testing configs
#set deviceconfig system permitted-ip 172.20.241.0/24
# Temporary: set deviceconfig system permitted-ip 192.168.1.0/24

#remember to put rule in to deny all external to PA NAT IP before removing NothingIn rule

permitted_ip = "172.20.241.0/24"
team_num = input("Please input a team number (for third octet, add 20 to team#): ")
team_num = str(team_num)

with open("PAConfig.txt", "w") as command_file:
  commands="""
configure
set deviceconfig system permitted-ip """+permitted_ip+"""
set deviceconfig system dns-setting servers primary 9.9.9.9
set deviceconfig system dns-setting servers secondary 149.112.112.112
delete mgt-config users administrator
set mgt-config users admin password
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no
set deviceconfig system login-banner AuthorizedAccessOnly
set network profiles zone-protection-profile Default discard-overlapping-tcp-segment-mismatch yes discard-unknown-option yes tcp-reject-non-syn yes flood tcp-syn enable yes syn-cookies maximal-rate 500
set network profiles zone-protection-profile Default flood icmp enable yes
set network profiles zone-protection-profile Default flood udp enable yes
set network profiles zone-protection-profile Default flood other-ip enable yes
set network profiles zone-protection-profile Default flood icmpv6 enable yes
set network profiles interface-management-profile none
set network interface ethernet ethernet1/3 layer3 interface-management-profile none
set network interface ethernet ethernet1/2 layer3 interface-management-profile none
set network interface ethernet ethernet1/1 layer3 interface-management-profile none

delete rulebase security
set rulebase security rules ScoreMail action allow from External to Public source any destination 172.25."""+team_num+""".39 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules ScoreMail application pop3 service application-default
set rulebase security rules ScoreMail application smtp
set rulebase security rules ScoreMail disabled yes
set rulebase security rules ScoreEcomm action allow from External to Public source any destination 172.25."""+team_num+""".11 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules ScoreEcomm application any service service-http
set rulebase security rules ScoreEcomm service service-https
set rulebase security rules ScoreEcomm disabled yes
set rulebase security rules ScoreDNS action allow from External to Internal source any destination 172.25."""+team_num+""".20 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules ScoreDNS application dns service application-default
set rulebase security rules ScoreDNS disabled yes
set service splunkweb protocol tcp port 8000
set rulebase security rules ScoreSplunk action allow from External to Public source any destination 172.25."""+team_num+""".9 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules ScoreSplunk application any service splunkweb
set rulebase security rules ScoreSplunk disabled yes

set rulebase security rules NothingIN action deny from External to Internal source any destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules NothingIN to User
set rulebase security rules NothingIN to Public
set rulebase security rules NothingIN application any service application-default
set rulebase security rules Quad9DNS action allow from Internal to External source any destination 9.9.9.9 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules Quad9DNS from User
set rulebase security rules Quad9DNS from Public
set rulebase security rules Quad9DNS application dns service application-default
set rulebase security rules DenyOtherDNS action deny from Internal to External source any destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules DenyOtherDNS from User
set rulebase security rules DenyOtherDNS from Public
set rulebase security rules DenyOtherDNS application dns service application-default
set rulebase security rules AllOut action allow from Internal to External source any destination any profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllOut from User
set rulebase security rules AllOut from Public
set rulebase security rules AllOut application any service application-default


set rulebase security rules AllowPublic2UserDNS action allow from Public to User source any destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowPublic2UserDNS application dns service application-default
set rulebase security rules AllowPublic2InternalDNS action allow from Public to Internal source any destination 172.20.240.20 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowPublic2InternalDNS application dns service application-default
set rulebase security rules AllowUser2InternalDNS action allow from User to Internal source any destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowUser2InternalDNS application dns service application-default
set rulebase security rules AllowLDAPFromPublic2User action allow from Public to User source 172.20.242.150 destination 172.20.242.200 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowLDAPFromPublic2User application ldap service application-default
set rulebase security rules AllowSplunkTraffic action allow from Internal to Public source any destination 172.20.242.10 profile-setting profiles spyware strict virus default vulnerability strict
set rulebase security rules AllowSplunkTraffic from User
set rulebase security rules AllowSplunkTraffic application splunk service application-default
commit
"""
  command_file.write(commands)
  print("File is written to PAConfig.txt")
print("Copy and paste the output of the script.")








# set rulebase security rules DNSoutBlock action allow from LAN to EXTERNAL source any destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules DNSoutBlock action allow from DMZ to EXTERNAL source any destination any
# set rulebase security rules DNSoutBlock application DNS service application-default
# set rulebase security rules NTPandSYSLOGandDNS action allow from LAN to DMZ source any destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules NTPandSYSLOGandDNS action allow from DMZ to LAN source any destination
# set rulebase security rules NTPandSYSLOGandDNS application ntp service application-default
# set rulebase security rules NTPandSYSLOGandDNS application syslog service application-default
# set rulebase security rules NTPandSYSLOGandDNS application dns service application-default
# set rulebase security rules NTPandSYSLOGandDNS application ssl service application-default
# set rulebase security rules NTPandSYSLOGandDNS application web-browsing service application-default
# set rulebase security rules CentOStoUbuntuDB action allow from any to any source 172.20.240.11 destination 172.25."""+team_num+""".23 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules CentOStoUbuntuDB from any source 172.25."""+team_num+""".11
# set rulebase security rules CentOStoUbuntuDB application any service any
# set rulebase security rules PrivateIPOutNoNo action deny from LAN to External source any destination Private1
# set rulebase security rules PrivateIPOutNoNo action deny from LAN to External source any destination Private2
# set rulebase security rules PrivateIPOutNoNo action deny from DMZ to External source any destination Private3
# set rulebase security rules PrivateIPOutNoNo application any service any
# set rulebase security rules PaloAltoOut action allow from LAN to External source 172.20.241.100 destination any
# set rulebase security rules PaloAltoOut action allow from LAN to DMZ source 172.20.241.100 destination any
# set rulebase security rules PaloAltoOut application paloalto-updates service any
# set rulebase security rules PaloAltoOut application dns service any
# set rulebase security rules PaloAltoOut application ntp service any
# set rulebase security rules Win7External action allow from External to External source 172.31."""+team_num+""".3 destination any
# set rulebase security rules Win7External application any service any
# set rulebase security rules CentOSin action allow from External to DMZ source any destination 172.25."""+team_num+""".11 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules CentOSin application ssl service application-default
# set rulebase security rules CentOSin application web-browsing service application-default
# set rulebase security rules 2008DNStoUbuntuDNS action allow from LAN to DMZ source 172.20.241.27 destination 172.20.240.23 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules 2008DNStoUbuntuDNS application dns service application-default
# set rulebase security rules DEBIANtoUBUNTU action allow from LAN to DMZ source 172.20.241.39 destination 172.20.240.23 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules DEBIANtoUBUNTU application mysql service application-default
# set rulebase security rules DEBIANtoUBUNTU to External destination 172.25."""+team_num+""".23
# set rulebase security rules DEBIANtoUBUNTU to DMZ
# set rulebase security rules UbuntuDNSto2008DNS action allow from DMZ to LAN source 172.20.240.23 destination 172.20.241.27 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules UbuntuDNSto2008DNS application dns service application-default
# set rulebase security rules UbuntuDNSto2008DNS application ntp service application-default
# set rulebase security rules UbuntuDNSto2008DNS application active-directory service application-default
# set rulebase security rules UbuntuDNSto2008DNS application ldap service application-default
# set rulebase security rules UbuntuDNSto2008DNS application ms-ds-smb service application-default
# set rulebase security rules UbuntuDNSto2008DNS application msrpc service application-default
# set rulebase security rules UbuntuDNSto2008DNS application ms-ds-smb service application-default
# set rulebase security rules UbuntuDNSto2008DNS application netbios-ss service application-default
# set rulebase security rules UbuntuDNSto2008DNS application netbios-dg service application-default
# set rulebase security rules CentOSDNSto2008DNS action allow from DMZ to LAN source 172.20.240.11 destination 172.20.241.27 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules CentOSDNSto2008DNS application dns service application-default
# set rulebase security rules CentOSDNSto2008DNS application ntp service application-default
# set rulebase security rules CentOSDNSto2008DNS application active-directory service application-default
# set rulebase security rules CentOSDNSto2008DNS application ldap service application-default
# set rulebase security rules CentOSDNSto2008DNS application ms-ds-smb service application-default
# set rulebase security rules CentOSDNSto2008DNS application msrpc service application-default
# set rulebase security rules CentOSDNSto2008DNS application netbios-ss service application-default
# set rulebase security rules CentOSDNSto2008DNS application netbios-dg service application-default
# set rulebase security rules UbuntuDNSin action allow from External to DMZ source any destination 172.25."""+team_num+""".23 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules UbuntuDNSin application dns service application-default
# set rulebase security rules DEBIANin action allow from External to LAN source any destination 172.25."""+team_num+""".39 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules DEBIANin application web-browsing service application-default
# set rulebase security rules DEBIANin application smtp service application-default
# set rulebase security rules DEBIANin application pop3 service application-default
# set rulebase security rules DEBIANin application ssl service application-default
# set rulebase security rules DEBIANin application imap service application-default
# set rulebase security rules 2008DNSin action allow from External to LAN source any destination 172.25."""+team_num+""".27 profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules 2008DNSin application dns service application-default
# set rulebase security rules DMZout-CentOS action allow from DMZ to External source 172.20.240.11 destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules DMZout-CentOS application ssl service application-default
# set rulebase security rules DMZout-CentOS application ftp service application-default
# set rulebase security rules DMZout-CentOS application yum service application-default
# set rulebase security rules DMZout-CentOS application github service application-default
# set rulebase security rules DMZout-CentOS application git-base service application-default
# set rulebase security rules DMZout-CentOS application ssh service application-default
# set rulebase security rules DMZout-CentOS application web-browsing service application-default
# set rulebase security rules DMZout-Ubuntu action allow from DMZ to External source 172.20.240.23 destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules DMZout-Ubuntu application dns service application-default
# set rulebase security rules DMZout-Ubuntu application web-browsing service application-default
# set rulebase security rules DMZout-Ubuntu application ssl service application-default
# set rulebase security rules DMZout-Ubuntu application apt-get service application-default
# set rulebase security rules SERVERout-2012WAout action allow from LAN to External source 172.20.241.3 destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules SERVERout-2012WAout application web-browsing service application-default
# set rulebase security rules SERVERout-2012WAout application ssl service application-default
# set rulebase security rules SERVERout-2012WAout application git-base service application-default
# set rulebase security rules SERVERout-2012WAout application ms-update service application-default
# set rulebase security rules SERVERout-2012WAout application github service application-default
# set rulebase security rules SERVERout-2008AD action allow from LAN to External source 172.20.241.27 destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules SERVERout-2008AD application ssl service application-default
# set rulebase security rules SERVERout-2008AD application ms-update service application-default
# set rulebase security rules SERVERout-2008AD application dns service application-default
# set rulebase security rules SERVERout-2008AD application web-browsing service application-default
# set rulebase security rules SERVERout-Debian action allow from LAN to External source 172.20.241.39 destination any profile-setting profiles spyware strict virus default vulnerability strict
# set rulebase security rules SERVERout-Debian application pop3 service application-default
# set rulebase security rules SERVERout-Debian application imap service application-default
# set rulebase security rules SERVERout-Debian application dns service application-default
# set rulebase security rules SERVERout-Debian application ocsp service application-default
# set rulebase security rules SERVERout-Debian application smtp service application-default
# set rulebase security rules SERVERout-Debian application ssh service application-default
# set rulebase security rules SERVERout-Debian application github service application-default
# set rulebase security rules SERVERout-Debian application git-base service application-default
# set rulebase security rules SERVERout-Debian application ssl service application-default
# set rulebase security rules SERVERout-Debian application subversion service application-default
# set rulebase security rules SERVERout-Debian application sourceforge service application-default
# set rulebase security rules SERVERout-Debian application apt-get service application-default
# set rulebase security rules SERVERout-Debian application web-browsing service application-default
# set rulebase security rules INTERZONELAN action allow from LAN to LAN source any destination any
# set rulebase security rules INTERZONELAN application any service any
# set rulebase security rules INTERZONEDMZ action allow from DMZ to DMZ source any destination any
# set rulebase security rules INTERZONEDMZ application any service any
# set rulebase security rules DENYALLEXTERNAL action deny from External to any source any destination any
# set rulebase security rules DENYALLEXTERNAL application any service any
# set rulebase security rules DENYALL action deny from any to any source any destination any
# set rulebase security rules DENYALL application any service any
# commit
