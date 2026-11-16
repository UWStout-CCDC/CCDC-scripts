#!/usr/bin/env bash
# ==============================================================================
# VyOS CCDC Persistence Hunt & Forensic Audit Script (Read-Only)
# Target: VyOS 1.3.x (Equuleus), 1.4.x (Sagitta), 1.5.x (Circinus)
# Usage:
#   ./vyos_audit.sh              # Run full audit and save timestamped baseline
#   ./vyos_audit.sh --diff <log> # Diff current state against previous baseline
# ==============================================================================

set -o pipefail

# Output directory in persistent storage
BASELINE_DIR="/config/baseline"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${BASELINE_DIR}/vyos_audit_${TIMESTAMP}.log"
LATEST_LINK="${BASELINE_DIR}/latest.log"

# Operational command wrapper helper
run_op() {
    if [ -x /opt/vyatta/bin/vyatta-op-cmd-wrapper ]; then
        /opt/vyatta/bin/vyatta-op-cmd-wrapper "$@" 2>/dev/null
    else
        echo "ERR: /opt/vyatta/bin/vyatta-op-cmd-wrapper not found"
    fi
}

# If diff mode requested
if [ "$1" == "--diff" ]; then
    PREV_LOG="$2"
    if [ -z "$PREV_LOG" ]; then
        PREV_LOG="$LATEST_LINK"
    fi
    if [ ! -f "$PREV_LOG" ]; then
        echo "[-] Error: Baseline file '$PREV_LOG' not found!"
        echo "Usage: $0 --diff /path/to/previous_audit.log"
        exit 1
    fi
    TMP_CURRENT=$(mktemp /tmp/vyos_audit_current.XXXXXX)
    echo "[*] Generating temporary fresh audit snapshot..."
    $0 --stdout > "$TMP_CURRENT"
    echo "[*] Comparing current state against: $PREV_LOG"
    echo "======================================================================"
    diff -u --color=always "$PREV_LOG" "$TMP_CURRENT" | less -R
    rm -f "$TMP_CURRENT"
    exit 0
fi

# Determine destination
if [ "$1" == "--stdout" ]; then
    exec 1>&1
else
    mkdir -p "$BASELINE_DIR"
    echo "[+] Running VyOS Forensic & Persistence Audit..."
    echo "[+] Output will be saved to: ${OUTPUT_FILE}"
    exec > >(tee "${OUTPUT_FILE}")
fi

echo "======================================================================"
echo "          VyOS CCDC FORENSIC & PERSISTENCE AUDIT REPORT"
echo "  Timestamp : $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo "  Hostname  : $(hostname)"
echo "  Kernel    : $(uname -a)"
echo "======================================================================"

# ----------------------------------------------------------------------
# 1. VERSION DETECTION & ENVIRONMENT
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 1: VyOS Version & Release Details"
echo "----------------------------------------------------------------------"
run_op show version || cat /etc/os-release

# ----------------------------------------------------------------------
# 2. PERSISTENCE VECTOR: BOOT SCRIPTS & CONFIG SCRIPTS
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 2: /config/scripts/ Directory & Boot Scripts"
echo "----------------------------------------------------------------------"
echo "[-] Recursive listing of /config/scripts/:"
ls -laR /config/scripts/ 2>/dev/null

echo -e "\n[-] Inspecting /config/scripts/vyos-preconfig-bootup.script:"
if [ -f /config/scripts/vyos-preconfig-bootup.script ]; then
    cat /config/scripts/vyos-preconfig-bootup.script
else
    echo "None present."
fi

echo -e "\n[-] Inspecting /config/scripts/vyos-postconfig-bootup.script:"
if [ -f /config/scripts/vyos-postconfig-bootup.script ]; then
    cat /config/scripts/vyos-postconfig-bootup.script
else
    echo "None present."
fi

echo -e "\n[-] Inspecting /config/scripts/post-upgrade:"
if [ -f /config/scripts/post-upgrade ]; then
    cat /config/scripts/post-upgrade
else
    echo "None present."
fi

# ----------------------------------------------------------------------
# 3. PERSISTENCE VECTOR: COMMIT HOOKS (HIGH DANGER)
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 3: Commit Hooks (pre-hooks.d & post-hooks.d)"
echo "----------------------------------------------------------------------"
echo "NOTE: Red teams use post-hooks.d to re-inject persistence on every Blue Team commit!"
echo "[-] /config/scripts/commit/pre-hooks.d/:"
ls -la /config/scripts/commit/pre-hooks.d/ 2>/dev/null || echo "Directory does not exist."
for f in /config/scripts/commit/pre-hooks.d/*; do
    if [ -f "$f" ]; then
        echo -e "\n>>> Content of $f:"
        cat "$f"
    fi
done

echo -e "\n[-] /config/scripts/commit/post-hooks.d/:"
ls -la /config/scripts/commit/post-hooks.d/ 2>/dev/null || echo "Directory does not exist."
for f in /config/scripts/commit/post-hooks.d/*; do
    if [ -f "$f" ]; then
        echo -e "\n>>> Content of $f:"
        cat "$f"
    fi
done

# ----------------------------------------------------------------------
# 4. PERSISTENCE VECTOR: TASK SCHEDULER & CRON
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 4: Task Scheduler (VyOS CLI) & Standard Linux Cron"
echo "----------------------------------------------------------------------"
echo "[-] VyOS Task Scheduler configuration:"
run_op show configuration commands | grep "task-scheduler" || echo "No task-scheduler configured."

echo -e "\n[-] Linux /etc/crontab & cron directories:"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null
for u in /var/spool/cron/crontabs/*; do
    if [ -f "$u" ]; then
        echo ">>> User crontab for $u:"
        cat "$u"
    fi
done

# ----------------------------------------------------------------------
# 5. PERSISTENCE VECTOR: USERS, SUDOERS, & SSH KEYS
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 5: Login Users, Public Keys & Accounts"
echo "----------------------------------------------------------------------"
echo "[-] VyOS Configured Users & Keys:"
run_op show configuration commands | grep "system login"

echo -e "\n[-] /etc/passwd UID 0 and UID >= 1000 accounts:"
awk -F: '($3 == 0 || $3 >= 1000) {print "User: "$1", UID: "$3", Shell: "$7}' /etc/passwd

echo -e "\n[-] SSH Authorized Keys in filesystem:"
for dir in /root/.ssh /home/*/.ssh; do
    if [ -f "${dir}/authorized_keys" ]; then
        echo ">>> File: ${dir}/authorized_keys"
        cat "${dir}/authorized_keys"
    fi
done

echo -e "\n[-] Sudoers configurations (/etc/sudoers.d/):"
ls -la /etc/sudoers.d/ 2>/dev/null
for s in /etc/sudoers.d/*; do
    if [ -f "$s" ]; then
        echo ">>> Content of $s:"
        cat "$s"
    fi
done

# ----------------------------------------------------------------------
# 6. PERSISTENCE VECTOR: ROGUE TUNNELS & INTERFACES
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 6: Tunnels, VPNs & Rogue Network Interfaces"
echo "----------------------------------------------------------------------"
echo "[-] VyOS tunnel/VPN interface configuration:"
run_op show configuration commands | grep -E "interfaces (wireguard|openvpn|vti|tunnel|pseudo-ethernet|vxlan|bridge)" || echo "No rogue interfaces in VyOS config."

echo -e "\n[-] Linux Kernel Network Interfaces (ip link):"
ip -brief link show

# ----------------------------------------------------------------------
# 7. PERSISTENCE VECTOR: CONTAINERS (VyOS 1.4+)
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 7: Containers (Podman / VyOS 1.4+)"
echo "----------------------------------------------------------------------"
echo "[-] VyOS Container Configuration:"
run_op show configuration commands | grep "container" || echo "No container configuration found."

echo -e "\n[-] Podman runtime inspection:"
if command -v podman >/dev/null 2>&1; then
    podman ps -a 2>/dev/null || echo "Podman daemon inactive."
    podman images 2>/dev/null
else
    echo "Podman not installed (likely VyOS 1.3 or container feature unused)."
fi

# ----------------------------------------------------------------------
# 8. PERSISTENCE VECTOR: SYSTEM SERVICES & ATTACK SURFACE
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 8: Configured System Services"
echo "----------------------------------------------------------------------"
run_op show configuration commands | grep "^set service"

# ----------------------------------------------------------------------
# 9. PERSISTENCE VECTOR: ACTIVE PROCESSES & LISTENING PORTS
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 9: Listening Sockets & Established C2 Connections"
echo "----------------------------------------------------------------------"
echo "[-] Listening TCP/UDP Ports (ss -tulpn):"
ss -tulpn

echo -e "\n[-] Established Outbound Connections (possible C2 beacons):"
ss -tan state established '( dport != :22 and sport != :22 )'

echo -e "\n[-] Currently Logged In Users:"
who -a

# ----------------------------------------------------------------------
# 10. PERSISTENCE VECTOR: SYSTEMD UNITS, TIMERS & LD_PRELOAD
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 10: Systemd Services, Timers & Dynamic Linker"
echo "----------------------------------------------------------------------"
echo "[-] Checking /etc/ld.so.preload (Rootkit indicator):"
if [ -f /etc/ld.so.preload ]; then
    echo "[!] WARNING: /etc/ld.so.preload EXISTS! Potential userland rootkit:"
    cat /etc/ld.so.preload
else
    echo "Clean: /etc/ld.so.preload does not exist."
fi

echo -e "\n[-] Custom systemd service units (/etc/systemd/system/):"
ls -la /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null || echo "No custom service/timer overrides."

echo -e "\n[-] Enabled systemd units:"
systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | grep -v -E "getty|systemd|ssh|networking" | head -30

# ----------------------------------------------------------------------
# 11. PERSISTENCE VECTOR: SUID BINARIES & RECENT FILE MODIFICATIONS
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 11: SUID/SGID Binaries & Modified System Files"
echo "----------------------------------------------------------------------"
echo "[-] SUID/SGID files across root filesystem:"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} + 2>/dev/null

echo -e "\n[-] Files modified in /etc, /bin, /sbin, /usr, /config in last 24 hours:"
find /etc /bin /sbin /usr/bin /usr/sbin /config -xdev -mmin -1440 -type f 2>/dev/null | head -50

# ----------------------------------------------------------------------
# 12. CONFIG DRIFT & COMMIT HISTORY
# ----------------------------------------------------------------------
echo -e "\n[+] SECTION 12: Commit History & Config Revisions"
echo "----------------------------------------------------------------------"
run_op show system commit || echo "No commit history found."

echo "======================================================================"
echo "          AUDIT COMPLETE"
echo "======================================================================"

if [ "$1" != "--stdout" ]; then
    ln -sf "${OUTPUT_FILE}" "${LATEST_LINK}"
    echo "[+] Baseline captured: ${OUTPUT_FILE}"
    echo "[+] Symlinked to:      ${LATEST_LINK}"
    echo "[+] Run diff anytime:  $0 --diff ${OUTPUT_FILE}"
fi
