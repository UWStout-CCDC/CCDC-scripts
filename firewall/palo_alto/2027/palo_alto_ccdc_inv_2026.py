#!/usr/bin/env python3
#
# palo_alto_ccdc2026.py - Unified Single Palo Alto Firewall Config Generator
# 2026 Midwest Invitational CCDC (MWCCDC)
# Target: PAN-OS 11.0.2 on Proxmox NETLAB+ VE
#
# Scored Servers:
#   - Rocky Ecom      (Priv: 172.20.240.10   | Pub: 172.25.<team+20>.10)
#   - Ubuntu Email    (Priv: 172.20.240.15   | Pub: 172.25.<team+20>.15)
#   - Debian Splunk   (Priv: 172.20.240.20   | Pub: 172.25.<team+20>.20)
#   - 2022 AD         (Priv: 172.20.240.100  | Pub: 172.25.<team+20>.100)
#   - 2019 MSSQL      (Priv: 172.20.240.120  | Pub: 172.25.<team+20>.120)
#
# Scored Services Covered (22 total):
#   ad-dns, ad-ping, ad-winrm,
#   ecomm-http, ecomm-https, ecomm-ping, ecomm-ssh,
#   mssql-mssql, mssql-ping, mssql-rdp, mssql-smb,
#   splunk-mgmt, splunk-ping, splunk-query, splunk-ssh, splunk-web,
#   webmail-imap, webmail-ping, webmail-pop3, webmail-roundcube, webmail-smtp, webmail-ssh

import sys
import os

def prompt_default(prompt_text, default_val):
    val = input(f"{prompt_text} [{default_val}]: ").strip()
    return val if val else default_val

print("=" * 75)
print(" 2026 MWCCDC - Single Palo Alto Firewall Base Configuration Generator")
print("=" * 75)

# 1. Team Number Validation
while True:
    try:
        raw_team = input("Please enter your Team Number (1-20): ").strip()
        team_int = int(raw_team)
        pub_octet = team_int + 20
        print(f"Calculated Public IP Subnet: 172.25.{pub_octet}.0/24")
        confirm = input("Is this correct? (y/n) [y]: ").strip().lower()
        if confirm in ('', 'y', 'yes'):
            team_num = str(pub_octet)
            break
    except ValueError:
        print("[!] Please enter a valid numerical team number.")

# 2. Permitted Management Workstations
print("\n[*] Management Access Hardening (permitted-ip):")
print("    Specify static IPs for your authorized Ubuntu and Windows workstations.")
ubuntu_mgmt_ip = prompt_default("Enter Ubuntu Workstation Static IP", "172.20.240.50")
windows_mgmt_ip = prompt_default("Enter Windows Workstation Static IP", "172.20.240.60")
include_subnet_fallback = prompt_default("Include internal subnet 172.20.240.0/24 in permitted-ip as safety fallback? (y/n)", "y").lower() == 'y'

permitted_ips = [f"{ubuntu_mgmt_ip}/32", f"{windows_mgmt_ip}/32"]
if include_subnet_fallback:
    permitted_ips.append("172.20.240.0/24")
permitted_ip_cli = "[ " + " ".join(permitted_ips) + " ]"

# 3. Zone Names
print("\n[*] Firewall Security Zones:")
print("    Check your Palo Alto Network -> Zones tab for exact names.  Alternatively, you can run the following command: show zone.")
ext_zone = prompt_default("Enter External (untrust) Zone Name", "External")
int_zone = prompt_default("Enter Internal (trust/LAN) Zone Name", "Internal")

# 4. Interface Names
print("\n[*] Firewall Interfaces:")
print("    Check your Palo Alto Network -> Interfaces tab. Alternatively, you can run the following command: show interface logical.")
ext_interface = prompt_default("Enter External Layer 3 Interface (towards VyOS)", "ethernet1/2")
int_interface = prompt_default("Enter Internal Layer 3 Interface (towards LAN Switch)", "ethernet1/3")

# 5. Security & Enforcement Options
print("\n[*] Security Enforcement & Features:")
enable_custom_fallback = prompt_default("Create dedicated Custom Service rules alongside App-ID rules for scoring resilience? (y/n)", "y").lower() == 'y'
enable_kill_shells = prompt_default("Enable KillReverseShells rule (drops outbound to 10.0.0.0/8 & 192.168.0.0/16)? (y/n)", "y").lower() == 'y'
enable_dos_rules = prompt_default("Enable Aggregate DoS Protection rules on scored public services? (y/n)", "y").lower() == 'y'
enable_threat_profiles = prompt_default("Attach Threat Prevention Profiles (AV, Anti-Spyware, Vuln) to outbound internet? (y/n)", "y").lower() == 'y'

output_filename = "PAConfig_CCDC2026.txt"
script_dir = os.path.dirname(os.path.abspath(__file__))
output_filepath = os.path.join(script_dir, output_filename)

threat_profile_cmd = "profile-setting profiles spyware strict virus default vulnerability default" if enable_threat_profiles else ""

# Build Configuration
commands = f"""# =====================================================================
# 2026 MWCCDC Single Palo Alto Firewall Base Configuration
# Generated for Team Public Subnet: 172.25.{team_num}.0/24
# Zones: {ext_zone} (External) <---> {int_zone} (Internal)
# Interfaces: {ext_interface} (Ext) | {int_interface} (Int)
# Management Workstations: {ubuntu_mgmt_ip} (Ubuntu) | {windows_mgmt_ip} (Windows)
# =====================================================================

configure

# ---------------------------------------------------------------------
# System Settings & Management Hardening
# ---------------------------------------------------------------------
set deviceconfig system permitted-ip {permitted_ip_cli}
set deviceconfig system dns-setting servers primary 172.20.240.100
set deviceconfig system dns-setting servers secondary 9.9.9.9
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no
set deviceconfig system service disable-ssh no
set deviceconfig system service disable-snmp yes
set deviceconfig system login-banner "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED. You must have explicit, authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities performed on this device are logged and monitored."
set deviceconfig system timezone US/Central

# Strip management profiles from data-plane interfaces to prevent interface-based attacks
set network profiles interface-management-profile none
set network interface ethernet {ext_interface} layer3 interface-management-profile none
set network interface ethernet {int_interface} layer3 interface-management-profile none

# ---------------------------------------------------------------------
# Address Objects: RFC1918 & LAN Subnets
# ---------------------------------------------------------------------
set address PrivIP10 ip-netmask 10.0.0.0/8
set address PrivIP172 ip-netmask 172.16.0.0/12
set address PrivIP192 ip-netmask 192.168.0.0/16
set address LAN ip-netmask 172.20.240.0/24

# ---------------------------------------------------------------------
# Address Objects: Management Workstations
# ---------------------------------------------------------------------
set address UbuntuWkstPriv ip-netmask {ubuntu_mgmt_ip}/32
set address WindowsWkstPriv ip-netmask {windows_mgmt_ip}/32
set address-group MgmtWorkstations members [ UbuntuWkstPriv WindowsWkstPriv ]

# ---------------------------------------------------------------------
# Address Objects: Scored Servers (Private & Scored Public)
# ---------------------------------------------------------------------
# Rocky Ecom (Web HTTP/HTTPS, SSH)
set address EcommPriv ip-netmask 172.20.240.10/32
set address EcommPub ip-netmask 172.25.{team_num}.10/32

# Ubuntu Email (SMTP, IMAP, POP3, Roundcube Webmail, SSH)
set address EmailPriv ip-netmask 172.20.240.15/32
set address EmailPub ip-netmask 172.25.{team_num}.15/32

# Debian Splunk (Splunk Web 8000, Splunk Mgmt 8089, SSH)
set address SplunkPriv ip-netmask 172.20.240.20/32
set address SplunkPub ip-netmask 172.25.{team_num}.20/32

# Windows Server 2022 AD (DNS, WinRM, Kerberos, LDAP, SMB)
set address ADPriv ip-netmask 172.20.240.100/32
set address ADPub ip-netmask 172.25.{team_num}.100/32

# Windows Server 2019 MSSQL (MSSQL 1433, RDP 3389, SMB 445)
set address MSSQLPriv ip-netmask 172.20.240.120/32
set address MSSQLPub ip-netmask 172.25.{team_num}.120/32

# Palo Alto Gateways
set address PAInside ip-netmask 172.20.240.254/32
set address PAMgmt ip-netmask 172.20.240.200/32

# ---------------------------------------------------------------------
# Address Objects: Approved DNS Resolvers (Local AD, 1.1.1.1, 9.9.9.9, 8.8.8.8)
# ---------------------------------------------------------------------
set address DNS-Cloudflare-1 ip-netmask 1.1.1.1/32
set address DNS-Cloudflare-2 ip-netmask 1.0.0.1/32
set address DNS-Quad9-1 ip-netmask 9.9.9.9/32
set address DNS-Quad9-2 ip-netmask 149.112.112.112/32
set address DNS-Google-1 ip-netmask 8.8.8.8/32
set address DNS-Google-2 ip-netmask 8.8.4.4/32
set address-group Approved-DNS-Servers members [ ADPriv ADPub DNS-Cloudflare-1 DNS-Cloudflare-2 DNS-Quad9-1 DNS-Quad9-2 DNS-Google-1 DNS-Google-2 ]

# ---------------------------------------------------------------------
# Custom Service Objects (For non-default ports & fallback definitions)
# ---------------------------------------------------------------------
set service svc-http protocol tcp port 80
set service svc-https protocol tcp port 443
set service svc-ssh protocol tcp port 22
set service svc-dns-tcp protocol tcp port 53
set service svc-dns-udp protocol udp port 53
set service svc-smtp protocol tcp port 25,465,587
set service svc-pop3 protocol tcp port 110,995
set service svc-imap protocol tcp port 143,993
set service svc-mssql protocol tcp port 1433
set service svc-rdp protocol tcp port 3389
set service svc-smb protocol tcp port 445,139
set service svc-winrm protocol tcp port 5985,5986
set service svc-splunk-web protocol tcp port 8000
set service svc-splunk-mgmt protocol tcp port 8089
set service svc-splunk-fwd protocol tcp port 9997
set service svc-ldap protocol tcp port 389,636
set service svc-kerberos-tcp protocol tcp port 88
set service svc-kerberos-udp protocol udp port 88
set service svc-rpc protocol tcp port 135
set service svc-ntp protocol udp port 123

# Service Group for Active Directory
set service-group grp-ad-services members [ svc-dns-tcp svc-dns-udp svc-winrm svc-ldap svc-kerberos-tcp svc-kerberos-udp svc-smb svc-rpc svc-ntp ]

# ---------------------------------------------------------------------
# NAT Rules (1:1 Bi-directional Static NAT + Outbound PAT)
# ---------------------------------------------------------------------
delete rulebase nat

# 1:1 Bi-Directional Static NAT for each scored server
set rulebase nat rules Ecomm-StaticNAT nat-type ipv4 from {int_zone} to {ext_zone} source EcommPriv destination any service any source-translation static-ip bi-directional yes translated-address EcommPub
set rulebase nat rules Email-StaticNAT nat-type ipv4 from {int_zone} to {ext_zone} source EmailPriv destination any service any source-translation static-ip bi-directional yes translated-address EmailPub
set rulebase nat rules Splunk-StaticNAT nat-type ipv4 from {int_zone} to {ext_zone} source SplunkPriv destination any service any source-translation static-ip bi-directional yes translated-address SplunkPub
set rulebase nat rules AD-StaticNAT nat-type ipv4 from {int_zone} to {ext_zone} source ADPriv destination any service any source-translation static-ip bi-directional yes translated-address ADPub
set rulebase nat rules MSSQL-StaticNAT nat-type ipv4 from {int_zone} to {ext_zone} source MSSQLPriv destination any service any source-translation static-ip bi-directional yes translated-address MSSQLPub

# General Outbound PAT for Workstations & remaining internal traffic
set rulebase nat rules LAN-OutboundPAT nat-type ipv4 from {int_zone} to {ext_zone} source LAN destination any service any source-translation dynamic-ip-and-port interface-address interface {ext_interface}

# ---------------------------------------------------------------------
# Security Rules (Rulebase)
# Note: In PAN-OS with NAT, destination address matches pre-NAT IP (Public IP),
#       and destination zone matches post-NAT zone ({int_zone}).
#
# Per Architecture Guidelines:
# - App-ID rules specify 'service application-default'.
# - Custom Service rules specify custom port objects and are kept strictly SEPARATE.
# ---------------------------------------------------------------------
delete rulebase security
"""

if enable_kill_shells:
    commands += f"""
# KillReverseShells: Drop outbound connections to common internal ranges used by Red Team
set rulebase security rules KillReverseShells action drop from {int_zone} to {ext_zone} source any destination [ PrivIP10 PrivIP192 ] service any application any
"""

commands += f"""
# Allow ICMP everywhere (Required by CCDC Rule 12 & Scored ping checks)
set rulebase security rules AllowICMP action allow from any to any source any destination any application [ ping icmp ] service application-default

# Outbound Core Infrastructure: NTP
set rulebase security rules AllowNTPOutbound action allow from {int_zone} to {ext_zone} source any destination any application ntp service application-default

# Outbound Core Infrastructure: DNS restricted strictly to Approved Resolvers (Local AD, 1.1.1.1, 9.9.9.9, 8.8.8.8)
# App-ID Rule:
set rulebase security rules AllowDNSOutbound-AppID action allow from {int_zone} to any source any destination Approved-DNS-Servers application dns service application-default

# Custom Service Rule (Fallback UDP/TCP 53 for Approved Resolvers):
set rulebase security rules AllowDNSOutbound-CustomSvc action allow from {int_zone} to any source any destination Approved-DNS-Servers service [ svc-dns-udp svc-dns-tcp ] application any

# Explicitly Block & Drop all Unauthorized Outbound DNS (Kills DNS Tunnels, C2 Beacons, & Rogue Resolvers)
set rulebase security rules BlockUnauthorizedDNS action drop from {int_zone} to {ext_zone} source any destination any service [ svc-dns-udp svc-dns-tcp ] application any

# Outbound Internet Access for Web & Package Managers (App-ID Rule)
# Supports web browsing, apt, dnf/yum, winget/ms-update, git, and OCSP certificate validation
set rulebase security rules AllowInternetOutbound-AppID action allow from {int_zone} to {ext_zone} source any destination any application [ web-browsing ssl apt-get yum ms-update git ocsp ] service application-default {threat_profile_cmd}

# Outbound Internet Access for Package Managers & Web (Custom Service Fallback - TCP 80 & 443)
# Guarantees that any Linux package manager (apt, dnf, yum, pip, curl, wget) and Windows (winget, PowerShell Gallery)
# will never be blocked or dropped mid-download due to App-ID classification shifts or non-standard User-Agents.
set rulebase security rules AllowInternetOutbound-CustomSvc action allow from {int_zone} to {ext_zone} source any destination any service [ svc-http svc-https ] application any {threat_profile_cmd}

# =====================================================================
# INBOUND SCORED SERVICES - APP-ID RULES (service application-default)
# =====================================================================

# 1. Rocky Ecom: Web & SSH (App-ID)
# Covers: ecomm-http (web-browsing:80), ecomm-https (ssl:443), ecomm-ssh (ssh:22)
set rulebase security rules AllowEcomm-AppID action allow from {ext_zone} to {int_zone} source any destination EcommPub application [ web-browsing ssl ssh ] service application-default

# 2. Ubuntu Email: Mail protocols & Roundcube Webmail (App-ID)
# Covers: webmail-smtp (smtp:25, submission:587, smtps:465), webmail-pop3 (pop3:110, pop3s:995),
#         webmail-imap (imap:143, imaps:993), webmail-roundcube (web-browsing:80, ssl:443), webmail-ssh (ssh:22)
set rulebase security rules AllowEmail-AppID action allow from {ext_zone} to {int_zone} source any destination EmailPub application [ smtp submission smtps pop3 pop3s imap imaps web-browsing ssl ssh ] service application-default

# 3. Debian Splunk: SSH (App-ID)
# Covers: splunk-ssh (ssh:22)
# Note: Splunk Web (8000) and Splunk Mgmt (8089) use non-standard ports, defined in Custom Service rule below.
set rulebase security rules AllowSplunk-AppID action allow from {ext_zone} to {int_zone} source any destination SplunkPub application [ ssh ] service application-default

# 4. Windows 2022 AD: Active Directory & Domain Services (App-ID)
# Covers: ad-dns (dns:53), ad-winrm (ms-wman:5985,5986), LDAP/Kerberos/SMB/RPC auth
set rulebase security rules AllowAD-AppID action allow from {ext_zone} to {int_zone} source any destination ADPub application [ dns ms-wman ldap ldaps kerberos ms-ds-smb msrpc ms-ds-replication ] service application-default

# 5. Windows 2019 MSSQL: Database, RDP & SMB (App-ID)
# Covers: mssql-mssql (ms-sql-db:1433), mssql-rdp (ms-rdp:3389), mssql-smb (ms-ds-smb:445, netbios-ssn:139)
set rulebase security rules AllowMSSQL-AppID action allow from {ext_zone} to {int_zone} source any destination MSSQLPub application [ ms-sql-db ms-rdp ms-ds-smb netbios-ssn ] service application-default

# 6. Windows 2022 AD Time Synchronization (App-ID)
# Allows internal LAN systems and external clients to sync NTP time with AD (172.20.240.100)
set rulebase security rules AllowNTP-To-AD-AppID action allow from any to {int_zone} source any destination [ ADPub ADPriv ] application ntp service application-default

# =====================================================================
# INBOUND SCORED SERVICES - SEPARATE CUSTOM SERVICE RULES
# (For non-default ports & scoring engine synthetic traffic resilience)
# =====================================================================

# Splunk Non-Standard Ports: Web GUI (8000) & REST Mgmt API (8089)
# Covers: splunk-web (8000), splunk-mgmt (8089), splunk-query (8000/8089)
set rulebase security rules AllowSplunk-CustomSvc action allow from {ext_zone} to {int_zone} source any destination SplunkPub service [ svc-splunk-web svc-splunk-mgmt ] application any

# AD NTP Time Synchronization (Custom Service Fallback - UDP 123)
set rulebase security rules AllowNTP-To-AD-CustomSvc action allow from any to {int_zone} source any destination [ ADPub ADPriv ] service svc-ntp application any
"""

if enable_custom_fallback:
    commands += f"""
# Resilience Fallback Rules for Scored Services:
# Prevents scoring downtime if synthetic scoring probes do not perform full App-ID handshakes.
set rulebase security rules AllowEcomm-CustomFallback action allow from {ext_zone} to {int_zone} source any destination EcommPub service [ svc-http svc-https svc-ssh ] application any
set rulebase security rules AllowEmail-CustomFallback action allow from {ext_zone} to {int_zone} source any destination EmailPub service [ svc-smtp svc-pop3 svc-imap svc-http svc-https svc-ssh ] application any
set rulebase security rules AllowAD-CustomFallback action allow from {ext_zone} to {int_zone} source any destination ADPub service grp-ad-services application any
set rulebase security rules AllowMSSQL-CustomFallback action allow from {ext_zone} to {int_zone} source any destination MSSQLPub service [ svc-mssql svc-rdp svc-smb ] application any
"""

commands += f"""
# Intrazone LAN Traffic: Full trust within internal network (AD Auth, Log Shipping, Wkst access)
set rulebase security rules AllowIntrazoneLAN action allow from {int_zone} to {int_zone} source LAN destination LAN service any application any

# =====================================================================
# DEFAULT DENY (Strict Zero-Trust Perimeter)
# =====================================================================
set rulebase security rules DENYINBOUND action deny from {ext_zone} to {int_zone} source any destination any service any application any
set rulebase security rules DENYOUTBOUND action deny from {int_zone} to {ext_zone} source any destination any service any application any
set rulebase security rules DENYANYANY action deny from any to any source any destination any service any application any
"""

# Zone Protection Profile ("Slime Zone")
commands += f"""
# ---------------------------------------------------------------------
# Zone Protection Profile ("Slime Zone") - L3/L4 Flood & Anomaly Shield
# ---------------------------------------------------------------------
set network profiles zone-protection-profile "Slime Zone" flood syn red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood syn red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood syn red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood syn enable yes
set network profiles zone-protection-profile "Slime Zone" flood syn red action random-early-drop

set network profiles zone-protection-profile "Slime Zone" flood icmp red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood icmp red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood icmp red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood icmp enable yes

set network profiles zone-protection-profile "Slime Zone" flood udp red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood udp red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood udp red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood udp enable yes

set network profiles zone-protection-profile "Slime Zone" flood other-ip red alarm-rate 100
set network profiles zone-protection-profile "Slime Zone" flood other-ip red activate-rate 100
set network profiles zone-protection-profile "Slime Zone" flood other-ip red maximal-rate 400
set network profiles zone-protection-profile "Slime Zone" flood other-ip enable yes

# Reconnaissance / Port Scan Protection (Automated IP block on aggressive scanners)
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8001 action block-ip track-by attacker-and-victim interval 300 threshold 5
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8002 action block-ip track-by attacker-and-victim interval 300 threshold 5
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8003 action block-ip track-by attacker-and-victim interval 300 threshold 5
set network profiles zone-protection-profile "Slime Zone" scan threat-id 8006 action block-ip track-by attacker-and-victim interval 300 threshold 5

# Packet Discard Checks (Anti-Spoofing & Protocol Anomalies)
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

# Bind Slime Zone profile to External and Internal Zones
set zone {ext_zone} network zone-protection-profile "Slime Zone"
set zone {int_zone} network zone-protection-profile "Slime Zone"
"""

# Optional DoS Protection Rules
if enable_dos_rules:
    commands += f"""
# ---------------------------------------------------------------------
# Aggregate DoS Protection Profile & Rules for Scored Public Services
# ---------------------------------------------------------------------
delete rulebase dos
set profiles dos-protection CCDC_Protection type aggregate flood icmp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood udp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood other-ip enable yes
set profiles dos-protection CCDC_Protection type aggregate flood icmpv6 enable yes
set profiles dos-protection CCDC_Protection type aggregate flood tcp-syn enable yes

set rulebase dos rules Ecomm-DOS action protect from {ext_zone} to {int_zone} source any destination EcommPub service any protection aggregate profile CCDC_Protection
set rulebase dos rules Email-DOS action protect from {ext_zone} to {int_zone} source any destination EmailPub service any protection aggregate profile CCDC_Protection
set rulebase dos rules Splunk-DOS action protect from {ext_zone} to {int_zone} source any destination SplunkPub service any protection aggregate profile CCDC_Protection
set rulebase dos rules AD-DOS action protect from {ext_zone} to {int_zone} source any destination ADPub service any protection aggregate profile CCDC_Protection
set rulebase dos rules MSSQL-DOS action protect from {ext_zone} to {int_zone} source any destination MSSQLPub service any protection aggregate profile CCDC_Protection
set rulebase dos rules ProtectDefault action protect from any to any source any destination any service any protection aggregate profile default
"""

# Post-configuration: Commit and admin credentials
commands += """
# ---------------------------------------------------------------------
# Commit Changes & Terminate Stale Sessions
# ---------------------------------------------------------------------
commit
set mgt-config users admin password
delete admin-sessions
"""

with open(output_filepath, "w") as f:
    f.write(commands)

print(f"\n[+] Configuration file successfully written to: {output_filepath}")
print("[+] Instructions for applying configuration to Palo Alto:")
print("    1. Log in via SSH to Palo Alto at 172.20.240.200 (or console)")
print("    2. Enter command: set cli scripting-mode on")
print("    3. Enter command: configure")
print(f"    4. Copy and paste the contents of '{output_filename}' into the terminal.")
print("    5. When prompted, enter a strong new admin password.")
print("    6. Exit configuration mode and run: set cli scripting-mode off")
print("=" * 75)
