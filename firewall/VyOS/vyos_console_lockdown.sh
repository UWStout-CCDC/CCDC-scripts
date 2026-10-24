#!/bin/vbash
# ==============================================================================
# VyOS CCDC Console-Only Lockdown Script (One-Shot Execution)
# Target: Run DIRECTLY from VMware Console / Serial Console
#
# PURPOSE:
#   Eliminates SSH, Telnet, Web API, and Task-Scheduler attack vectors entirely.
#   Forces all management to occur locally through the VMware Console.
#   Protects transit traffic to ensure scored services continue flowing.
# ==============================================================================

if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ] || [ -n "$SSH_CONNECTION" ]; then
    echo "[!] ERROR: Do NOT run this script over SSH! Run it from VMware Console."
    exit 1
fi

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template

echo "======================================================================"
echo "          VyOS CONSOLE-ONLY LOCKDOWN (NUKE SSH MODE)"
echo "======================================================================"

# 1. Clean persistence hooks in filesystem
echo "[*] Quarantining commit hooks and boot scripts..."
mkdir -p /config/quarantine
mv /config/scripts/commit/post-hooks.d/* /config/quarantine/ 2>/dev/null
mv /config/scripts/commit/pre-hooks.d/* /config/quarantine/ 2>/dev/null
echo '#!/bin/bash' > /config/scripts/vyos-postconfig-bootup.script
echo 'exit 0' >> /config/scripts/vyos-postconfig-bootup.script
rm -f /etc/ld.so.preload 2>/dev/null

# 2. Configure VyOS
configure

# Prompt or set new local console password
read -s -p "Enter NEW password for vyos admin: " NEWPASS
echo ""

set system login user vyos authentication plaintext-password "$NEWPASS"
set system config-management commit-revisions 100

# Remove remote management services entirely
echo "[*] Disabling remote management services (SSH, Telnet, HTTPS API)..."
delete service ssh 2>/dev/null || true
delete service telnet 2>/dev/null || true
delete service https api 2>/dev/null || true
delete system task-scheduler 2>/dev/null || true

# Control Plane Firewall: Allow Established/Related and ICMP, drop all remote admin
# Check if 1.4/1.5 or 1.3
if [ -d /opt/vyatta/share/vyatta-cfg/templates/firewall/ipv4 ] || [ -d /usr/share/vyos/templates/firewall/ipv4 ] || [ -n "$(show version | grep -E '1\.4|1\.5|rolling')" ]; then
    echo "[*] Applying VyOS 1.4/1.5 nftables input filter..."
    set firewall ipv4 input filter default-action drop
    set firewall ipv4 input filter rule 10 action accept
    set firewall ipv4 input filter rule 10 description 'Allow established/related'
    set firewall ipv4 input filter rule 10 state established enable
    set firewall ipv4 input filter rule 10 state related enable

    set firewall ipv4 input filter rule 20 action accept
    set firewall ipv4 input filter rule 20 description 'Allow ICMP'
    set firewall ipv4 input filter rule 20 protocol icmp

    # Transit traffic stays open so scored services pass through to Palo Alto
    set firewall ipv4 forward filter default-action accept
else
    echo "[*] Applying VyOS 1.3 iptables input filter..."
    set firewall name VYOS_LOCAL_IN default-action drop
    set firewall name VYOS_LOCAL_IN rule 10 action accept
    set firewall name VYOS_LOCAL_IN rule 10 state established enable
    set firewall name VYOS_LOCAL_IN rule 10 state related enable
    set firewall name VYOS_LOCAL_IN rule 20 action accept
    set firewall name VYOS_LOCAL_IN rule 20 protocol icmp
fi

commit
save
exit

# 3. Terminate any active or rogue SSH daemons
echo "[*] Killing all lingering SSH server processes..."
killall -9 sshd 2>/dev/null || true
killall -9 dropbear 2>/dev/null || true

echo "======================================================================"
echo "[+] SUCCESS: VyOS is now locked down in CONSOLE-ONLY mode."
echo "[+] Remote SSH is deleted and blocked."
echo "[+] Scored transit traffic continues forwarding normally."
echo "======================================================================"
