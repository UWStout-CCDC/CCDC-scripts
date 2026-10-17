#!/bin/vbash
# ==============================================================================
# VyOS CCDC Hardening & Remediation Toolkit
# Multi-version support: VyOS 1.3.x (Equuleus) & 1.4.x (Sagitta) / 1.5.x
#
# Features:
#   1. Automatic VyOS version detection
#   2. Script & commit-hook persistence neutralization (quarantine)
#   3. Administrative user creation with SSH key & password
#   4. SSH daemon hardening & dynamic brute-force protection
#   5. Router control plane (INPUT) firewall lockdown (anti-lockout safe)
#   6. Task-scheduler and rogue service attack surface reduction
#   7. Uses commit-confirm failsafe to prevent permanent lockouts
# ==============================================================================

# Ensure script runs inside VyOS config group
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template

# Default Configuration Parameters (Can be overridden via environment or flags)
MGMT_SUBNET="${MGMT_SUBNET:-192.168.1.0/24}"
NEW_ADMIN_USER="${NEW_ADMIN_USER:-blueadmin}"
NEW_ADMIN_PASS="${NEW_ADMIN_PASS:-ChangeMeNowCCDC2026!}"
SSH_PUB_KEY="${SSH_PUB_KEY:-}"
SSH_KEY_TYPE="${SSH_KEY_TYPE:-ssh-ed25519}"
SSH_KEY_ID="${SSH_KEY_ID:-ccdc_admin_key}"
DRY_RUN=false
COMMIT_TIMEOUT=5

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --mgmt-subnet <cidr>    Trusted management subnet (default: $MGMT_SUBNET)"
    echo "  --user <username>       New administrative user (default: $NEW_ADMIN_USER)"
    echo "  --pass <password>       Password for new admin user"
    echo "  --ssh-key '<key>'       SSH public key string (e.g. 'AAAAC3NzaC1...')"
    echo "  --key-type <type>       SSH key type (default: ssh-ed25519)"
    echo "  --dry-run               Display commands without executing configure"
    echo "  -h, --help              Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mgmt-subnet)
            MGMT_SUBNET="$2"
            shift 2
            ;;
        --user)
            NEW_ADMIN_USER="$2"
            shift 2
            ;;
        --pass)
            NEW_ADMIN_PASS="$2"
            shift 2
            ;;
        --ssh-key)
            SSH_PUB_KEY="$2"
            shift 2
            ;;
        --key-type)
            SSH_KEY_TYPE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[-] Unknown parameter: $1"
            usage
            ;;
    esac
done

echo "======================================================================"
echo "          VyOS CCDC HARDENING & PERSISTENCE REMEDIATION"
echo "======================================================================"

# ----------------------------------------------------------------------
# 1. DETECT VYOS VERSION
# ----------------------------------------------------------------------
RAW_VER=$(/opt/vyatta/bin/vyatta-op-cmd-wrapper show version 2>/dev/null | grep -i "Version:" | awk '{print $2}')
if [[ "$RAW_VER" =~ ^1\.3 ]]; then
    VYOS_MAJOR="1.3"
    echo "[+] Detected VyOS version branch: 1.3 (Equuleus) [$RAW_VER]"
elif [[ "$RAW_VER" =~ ^1\.4 ]] || [[ "$RAW_VER" =~ ^1\.5 ]]; then
    VYOS_MAJOR="1.4"
    echo "[+] Detected VyOS version branch: 1.4+ (Sagitta/Circinus) [$RAW_VER]"
else
    # Fallback to checking os-release
    if grep -q "1.3" /etc/os-release 2>/dev/null; then
        VYOS_MAJOR="1.3"
    else
        VYOS_MAJOR="1.4"
    fi
    echo "[*] Inferred VyOS version branch: $VYOS_MAJOR"
fi

echo "[+] Target Management Subnet : $MGMT_SUBNET"
echo "[+] New Administrator User   : $NEW_ADMIN_USER"

# ----------------------------------------------------------------------
# 2. PERSISTENCE NEUTRALIZATION (QUARANTINE FILESYSTEM HOOKS)
# ----------------------------------------------------------------------
echo -e "\n[*] Step 1: Quarantining filesystem persistence hooks..."
BACKUP_DIR="/config/quarantine_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Quarantine commit hooks (Red Team post-commit backdoors)
if [ -d /config/scripts/commit ]; then
    echo "[-] Backing up and cleaning /config/scripts/commit hooks..."
    cp -r /config/scripts/commit "$BACKUP_DIR/"
    rm -rf /config/scripts/commit/pre-hooks.d/* 2>/dev/null
    rm -rf /config/scripts/commit/post-hooks.d/* 2>/dev/null
fi

# Neutralize boot scripts if they contain rogue commands
for script in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script /config/scripts/post-upgrade; do
    if [ -f "$script" ]; then
        echo "[-] Backing up $script to $BACKUP_DIR/"
        cp "$script" "$BACKUP_DIR/"
        # Replace with clean empty template if non-empty
        if [ -s "$script" ]; then
            echo "#!/bin/bash" > "$script"
            echo "# Sanitized by CCDC hardening on $(date)" >> "$script"
            echo "exit 0" >> "$script"
            chmod +x "$script"
            echo "[-] Sanitized $script"
        fi
    fi
done

# Check and warn about /etc/ld.so.preload
if [ -f /etc/ld.so.preload ]; then
    echo "[!] CRITICAL: Found /etc/ld.so.preload! Backing up and removing..."
    cp /etc/ld.so.preload "$BACKUP_DIR/"
    rm -f /etc/ld.so.preload
fi

# ----------------------------------------------------------------------
# 3. APPLY CONFIGURATION HARDENING
# ----------------------------------------------------------------------
if [ "$DRY_RUN" = true ]; then
    echo "[*] Dry run mode enabled. Configuration will not be modified."
    exit 0
fi

echo -e "\n[*] Step 2: Entering VyOS configuration mode..."
configure

# Config management: set 100 revisions
set system config-management commit-revisions 100

# In 1.4+, set commit-confirm action to reload rather than full reboot
if [ "$VYOS_MAJOR" == "1.4" ]; then
    set system config-management commit-confirm action reload
fi

# ----------------------------------------------------------------------
# 4. USER & ACCESS HARDENING
# ----------------------------------------------------------------------
echo "[*] Step 3: Configuring new administrative account..."
set system login user "$NEW_ADMIN_USER" level admin
set system login user "$NEW_ADMIN_USER" authentication plaintext-password "$NEW_ADMIN_PASS"

if [ -n "$SSH_PUB_KEY" ]; then
    echo "[-] Adding public key for $NEW_ADMIN_USER..."
    set system login user "$NEW_ADMIN_USER" authentication public-keys "$SSH_KEY_ID" key "$SSH_PUB_KEY"
    set system login user "$NEW_ADMIN_USER" authentication public-keys "$SSH_KEY_ID" type "$SSH_KEY_TYPE"
fi

# ----------------------------------------------------------------------
# 5. SSH SERVICE HARDENING (WITHOUT LOCKOUT)
# ----------------------------------------------------------------------
echo "[*] Step 4: Hardening SSH service..."
# DO NOT delete service ssh! Configure in-place!
set service ssh port 22

# Dynamic brute-force protection (supported on 1.4+ and 1.3.4+)
set service ssh dynamic-protection allow-from "$MGMT_SUBNET"
set service ssh dynamic-protection threshold 15
set service ssh dynamic-protection block-time 600
set service ssh dynamic-protection detect-time 1800

# Pre-login banner
set system login banner pre-login '
*******************************************************************************
                     AUTHORIZED CCDC BLUE TEAM ACCESS ONLY
 All activities are monitored and recorded. Unauthorized access is prohibited.
*******************************************************************************
'

# ----------------------------------------------------------------------
# 6. ATTACK SURFACE REDUCTION
# ----------------------------------------------------------------------
echo "[*] Step 5: Removing unneeded legacy services & rogue tasks..."
delete service telnet 2>/dev/null || true
delete service https api 2>/dev/null || true
delete system task-scheduler 2>/dev/null || true

# ----------------------------------------------------------------------
# 7. CONTROL-PLANE (INPUT) FIREWALL POLICY
# ----------------------------------------------------------------------
echo "[*] Step 6: Configuring Control Plane (INPUT) firewall..."

if [ "$VYOS_MAJOR" == "1.4" ]; then
    # VyOS 1.4+ nftables-based Input Filter
    set firewall ipv4 input filter default-action drop

    # Established / Related
    set firewall ipv4 input filter rule 10 action accept
    set firewall ipv4 input filter rule 10 description 'Allow established/related'
    set firewall ipv4 input filter rule 10 state established enable
    set firewall ipv4 input filter rule 10 state related enable

    # ICMP (Vital for scoring pings & Path MTU discovery)
    set firewall ipv4 input filter rule 20 action accept
    set firewall ipv4 input filter rule 20 description 'Allow ICMP'
    set firewall ipv4 input filter rule 20 protocol icmp

    # Management SSH
    set firewall ipv4 input filter rule 30 action accept
    set firewall ipv4 input filter rule 30 description 'Allow SSH from Management'
    set firewall ipv4 input filter rule 30 protocol tcp
    set firewall ipv4 input filter rule 30 destination port 22
    set firewall ipv4 input filter rule 30 source address "$MGMT_SUBNET"

    # Routing protocol failsafes (Uncomment if OSPF/BGP terminate on this router)
    # set firewall ipv4 input filter rule 40 action accept
    # set firewall ipv4 input filter rule 40 protocol ospf
    # set firewall ipv4 input filter rule 50 action accept
    # set firewall ipv4 input filter rule 50 protocol tcp
    # set firewall ipv4 input filter rule 50 destination port 179

elif [ "$VYOS_MAJOR" == "1.3" ]; then
    # VyOS 1.3 iptables-based named firewall
    set firewall name VYOS_LOCAL_IN default-action drop
    set firewall name VYOS_LOCAL_IN description 'Protect VyOS control plane'

    set firewall name VYOS_LOCAL_IN rule 10 action accept
    set firewall name VYOS_LOCAL_IN rule 10 description 'Allow established/related'
    set firewall name VYOS_LOCAL_IN rule 10 state established enable
    set firewall name VYOS_LOCAL_IN rule 10 state related enable

    set firewall name VYOS_LOCAL_IN rule 20 action accept
    set firewall name VYOS_LOCAL_IN rule 20 description 'Allow ICMP'
    set firewall name VYOS_LOCAL_IN rule 20 protocol icmp

    set firewall name VYOS_LOCAL_IN rule 30 action accept
    set firewall name VYOS_LOCAL_IN rule 30 description 'Allow SSH from Management'
    set firewall name VYOS_LOCAL_IN rule 30 protocol tcp
    set firewall name VYOS_LOCAL_IN rule 30 destination port 22
    set firewall name VYOS_LOCAL_IN rule 30 source address "$MGMT_SUBNET"

    echo "[!] NOTE: In VyOS 1.3, VYOS_LOCAL_IN must be applied to interfaces:"
    echo "    set interfaces ethernet <ethX> firewall local name VYOS_LOCAL_IN"
fi

# ----------------------------------------------------------------------
# 8. SAFE COMMIT WITH CONFIRMATION
# ----------------------------------------------------------------------
echo -e "\n[*] Step 7: Committing changes with ${COMMIT_TIMEOUT}-minute failsafe..."
echo "======================================================================"
echo "  Executing: commit-confirm ${COMMIT_TIMEOUT}"
echo "  If SSH locks up, VyOS will rollback in ${COMMIT_TIMEOUT} minutes."
echo "======================================================================"

commit-confirm "$COMMIT_TIMEOUT"

echo -e "\n[+] Commit-confirm initiated successfully!"
echo "[+] Verify in a NEW separate terminal:"
echo "    ssh ${NEW_ADMIN_USER}@<vyos_ip>"
echo ""
echo "[+] If login succeeds, run the following in VyOS config mode:"
echo "    confirm"
echo "    delete system login user vyos"
echo "    commit"
echo "    save"
echo "    exit"
echo ""
echo "[+] If something failed, DO NOT TYPE 'confirm'. Wait ${COMMIT_TIMEOUT} min for rollback."
