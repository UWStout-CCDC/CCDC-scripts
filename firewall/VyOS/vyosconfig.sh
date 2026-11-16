#!/bin/vbash
# ==============================================================================
# VyOS CCDC Safe Quick-Harden Script (VyOS 1.4+ Default)
# Generated for CCDC Blue Team Operations
#
# IMPORTANT:
#   1. This script secures the ROUTER INPUT (control plane) without dropping
#      scored transit traffic passing through to internal servers.
#   2. It DOES NOT delete SSH. It enforces SSH dynamic brute-force protection.
#   3. It uses 'commit-confirm 5' to automatically roll back if connectivity drops.
# ==============================================================================

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
source /opt/vyatta/etc/functions/script-template
configure

# 1. Security Banner
set system login banner pre-login '
*******************************************************************************
                     AUTHORIZED CCDC BLUE TEAM ACCESS ONLY
 All activities are monitored and recorded. Unauthorized access is prohibited.
*******************************************************************************
'

# 2. Configuration Management & Revisions
set system config-management commit-revisions 100
set system config-management commit-confirm action reload

# 3. Administrative User & SSH Hardening
set system login user blueadmin level admin
set system login user blueadmin authentication plaintext-password 'ChangeMeNowCCDC2026!'

set service ssh port 22
# Note: Adjust management subnet to match your competition jumpbox IP/CIDR
set service ssh dynamic-protection allow-from '192.168.1.0/24'
set service ssh dynamic-protection threshold 15
set service ssh dynamic-protection block-time 600
set service ssh dynamic-protection detect-time 1800

# 4. Attack Surface Reduction
delete service telnet 2>/dev/null || true
delete service https api 2>/dev/null || true
delete system task-scheduler 2>/dev/null || true

# 5. Control Plane (INPUT) Firewall - Protecting VyOS itself
set firewall ipv4 input filter default-action drop

# Rule 10: Allow established/related
set firewall ipv4 input filter rule 10 action accept
set firewall ipv4 input filter rule 10 description 'Allow established/related'
set firewall ipv4 input filter rule 10 state established enable
set firewall ipv4 input filter rule 10 state related enable

# Rule 20: Allow ICMP (vital for network health, Path MTU, scoring pings)
set firewall ipv4 input filter rule 20 action accept
set firewall ipv4 input filter rule 20 description 'Allow ICMP'
set firewall ipv4 input filter rule 20 protocol icmp

# Rule 30: Allow SSH from Blue Team management subnet
set firewall ipv4 input filter rule 30 action accept
set firewall ipv4 input filter rule 30 description 'Allow SSH from Blue Team'
set firewall ipv4 input filter rule 30 protocol tcp
set firewall ipv4 input filter rule 30 destination port 22
set firewall ipv4 input filter rule 30 source address '192.168.1.0/24'

# 6. Transit (FORWARD) Firewall - State-aware & Scoring Safe
# In CCDC, all scored traffic passes through VyOS to the Palo Altos.
# Default forward is kept accept to ensure scored services are NOT black-holed.
set firewall ipv4 forward filter default-action accept
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 description 'Allow established/related transit'
set firewall ipv4 forward filter rule 10 state established enable
set firewall ipv4 forward filter rule 10 state related enable

# 7. Failsafe Commit & Rollback Protection
echo '[*] Applying configuration with 5-minute rollback failsafe...'
commit-confirm 5
echo '[+] SUCCESS: Changes applied with commit-confirm 5!'
echo '[!] Open a NEW SSH session to test credentials:'
echo '    ssh blueadmin@<router-ip>'
echo '[!] If login works, run in VyOS config mode:'
echo '    confirm'
echo '    delete system login user vyos'
echo '    commit'
echo '    save'
echo '    exit'
