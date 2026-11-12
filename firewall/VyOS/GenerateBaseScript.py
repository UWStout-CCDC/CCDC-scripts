#!/usr/bin/env python3
#
# GenerateBaseScript.py - Modernized VyOS CCDC Configuration Generator
# Copyright (C) 2026 UW Stout CCDC Team 
# Made with Gemini, doshowipospf's script and AuGust
#
# Generates a safe, production-grade VyOS hardening configuration that:
#   1. Protects router control plane (INPUT) without locking administrators out
#   2. Implements failsafe commit-confirm rollback
#   3. Preserves transit traffic for scored services
#   4. Enables SSH brute-force dynamic-protection and key authentication
#

import sys
import ipaddress

def get_input(prompt, default=None):
    if default:
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default
    while True:
        val = input(f"{prompt}: ").strip()
        if val:
            return val

def main():
    print("=" * 70)
    print("     VyOS CCDC Hardening & Firewall Script Generator (v3.0)")
    print("=" * 70)
    print("WARNING: In CCDC, all scored services pass through VyOS.")
    print("Never blindly drop transit traffic until scoring requirements are mapped!")
    print("-" * 70)

    vyos_ver = get_input("Target VyOS Major Version (1.3 or 1.4)", "1.4")
    eth_wan = get_input("WAN Interface (facing external/internet/red team)", "eth0")
    eth_lan1 = get_input("LAN Interface 1 (e.g., to Palo Alto External / DMZ)", "eth1")
    eth_lan2 = get_input("LAN Interface 2 (optional, press Enter if none)", "eth2")
    
    mgmt_subnet = get_input("Blue Team Management Subnet (CIDR)", "192.168.1.0/24")
    try:
        ipaddress.ip_network(mgmt_subnet, strict=False)
    except ValueError:
        print(f"[!] Warning: '{mgmt_subnet}' is not a standard CIDR format. Proceeding anyway.")

    admin_user = get_input("New Admin Username", "blueadmin")
    admin_pass = get_input("New Admin Password", "ChangeMeNowCCDC2026!")
    ssh_key = get_input("SSH Public Key string (optional, press Enter to skip)", "").strip()

    # Build commands
    cmds = []
    cmds.append("#!/bin/vbash")
    cmds.append("if [ \"$(id -g -n)\" != 'vyattacfg' ] ; then")
    cmds.append("  exec sg vyattacfg -c \"/bin/vbash $(readlink -f $0) $@\"")
    cmds.append("fi")
    cmds.append("source /opt/vyatta/etc/functions/script-template")
    cmds.append("configure\n")

    # Banner
    cmds.append("# 1. Security Banner")
    cmds.append("set system login banner pre-login '\n"
                "*******************************************************************************\n"
                "                     AUTHORIZED CCDC BLUE TEAM ACCESS ONLY\n"
                " All activities are monitored and recorded. Unauthorized access is prohibited.\n"
                "*******************************************************************************\n'")

    # Config revisions
    cmds.append("\n# 2. Configuration Management & Revisions")
    cmds.append("set system config-management commit-revisions 100")
    if vyos_ver == "1.4":
        cmds.append("set system config-management commit-confirm action reload")

    # User & SSH
    cmds.append("\n# 3. Administrative User & SSH Hardening")
    cmds.append(f"set system login user {admin_user} level admin")
    cmds.append(f"set system login user {admin_user} authentication plaintext-password '{admin_pass}'")
    if ssh_key:
        cmds.append(f"set system login user {admin_user} authentication public-keys ccdc_key key '{ssh_key}'")
        cmds.append(f"set system login user {admin_user} authentication public-keys ccdc_key type ssh-ed25519")

    cmds.append("set service ssh port 22")
    cmds.append(f"set service ssh dynamic-protection allow-from '{mgmt_subnet}'")
    cmds.append("set service ssh dynamic-protection threshold 15")
    cmds.append("set service ssh dynamic-protection block-time 600")
    cmds.append("set service ssh dynamic-protection detect-time 1800")

    # Attack surface reduction
    cmds.append("\n# 4. Attack Surface Reduction")
    cmds.append("delete service telnet")
    cmds.append("delete service https api")
    cmds.append("delete system task-scheduler")

    # Firewall
    cmds.append("\n# 5. Control Plane (INPUT) Firewall - Protecting VyOS itself")
    if vyos_ver == "1.4":
        cmds.append("set firewall ipv4 input filter default-action drop")
        cmds.append("set firewall ipv4 input filter rule 10 action accept")
        cmds.append("set firewall ipv4 input filter rule 10 description 'Allow established/related'")
        cmds.append("set firewall ipv4 input filter rule 10 state established enable")
        cmds.append("set firewall ipv4 input filter rule 10 state related enable")
        cmds.append("set firewall ipv4 input filter rule 20 action accept")
        cmds.append("set firewall ipv4 input filter rule 20 description 'Allow ICMP'")
        cmds.append("set firewall ipv4 input filter rule 20 protocol icmp")
        cmds.append("set firewall ipv4 input filter rule 30 action accept")
        cmds.append("set firewall ipv4 input filter rule 30 description 'Allow SSH from Blue Team'")
        cmds.append("set firewall ipv4 input filter rule 30 protocol tcp")
        cmds.append("set firewall ipv4 input filter rule 30 destination port 22")
        cmds.append(f"set firewall ipv4 input filter rule 30 source address '{mgmt_subnet}'")
        
        cmds.append("\n# 6. Transit (FORWARD) Firewall - State-aware & Scoring Safe")
        cmds.append("# Note: Default forward is kept accept to ensure scored services continue passing to Palo Alto")
        cmds.append("set firewall ipv4 forward filter default-action accept")
        cmds.append("set firewall ipv4 forward filter rule 10 action accept")
        cmds.append("set firewall ipv4 forward filter rule 10 description 'Allow established/related transit'")
        cmds.append("set firewall ipv4 forward filter rule 10 state established enable")
        cmds.append("set firewall ipv4 forward filter rule 10 state related enable")
    else: # VyOS 1.3
        cmds.append("set firewall name LOCAL_IN default-action drop")
        cmds.append("set firewall name LOCAL_IN description 'Protect VyOS control plane'")
        cmds.append("set firewall name LOCAL_IN rule 10 action accept")
        cmds.append("set firewall name LOCAL_IN rule 10 state established enable")
        cmds.append("set firewall name LOCAL_IN rule 10 state related enable")
        cmds.append("set firewall name LOCAL_IN rule 20 action accept")
        cmds.append("set firewall name LOCAL_IN rule 20 protocol icmp")
        cmds.append("set firewall name LOCAL_IN rule 30 action accept")
        cmds.append("set firewall name LOCAL_IN rule 30 protocol tcp")
        cmds.append("set firewall name LOCAL_IN rule 30 destination port 22")
        cmds.append(f"set firewall name LOCAL_IN rule 30 source address '{mgmt_subnet}'")
        cmds.append(f"set interfaces ethernet {eth_wan} firewall local name LOCAL_IN")
        if eth_lan1:
            cmds.append(f"set interfaces ethernet {eth_lan1} firewall local name LOCAL_IN")

    # Safe commit-confirm
    cmds.append("\n# 7. Failsafe Commit & Rollback Protection")
    cmds.append("echo '[*] Applying configuration with 5-minute rollback failsafe...'")
    cmds.append("commit-confirm 5")
    cmds.append(f"echo '[+] Success! Verify login as {admin_user} in a second window, then run: confirm && save'")

    output_script = "vyosconfig.sh"
    with open(output_script, "w") as f:
        f.write("\n".join(cmds) + "\n")

    print(f"\n[+] Successfully generated safe configuration script: {output_script}")
    print("[+] Improvements over legacy version:")
    print("    - PREVENTS LOCKOUT: Does NOT delete SSH; binds & protects it.")
    print("    - SCORING SAFE: Protects router INPUT without dropping scored transit traffic.")
    print("    - FAILSAFE ROLLBACK: Uses 'commit-confirm 5' instead of instant save.")
    print("    - DYNAMIC PROTECTION: Enables brute-force banning for non-whitelisted management IPs.")

if __name__ == "__main__":
    main()
