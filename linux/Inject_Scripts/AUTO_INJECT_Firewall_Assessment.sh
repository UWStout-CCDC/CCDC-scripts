#!/usr/bin/env bash
# MWCCDC FW01 - Host Firewall Assessment (profile-based, iptables)
#
# Interactive: sudo bash fw01-host-firewall-menu.sh
# Apply (advanced): sudo bash fw01-host-firewall-menu.sh <profile> [profile ...] [options]
# Persist:  sudo bash fw01-host-firewall-menu.sh --persist     (only after testing)
#
# Profiles:
#   webserver   TCP 80, 443
#   mail        TCP 25, 110
#   mail-full   TCP 25, 465, 587, 110, 995, 143, 993
#   splunk      TCP 8000, 8089, 9997          (restricted to management networks by default)
#   dnsntp      TCP 53, UDP 53, 123
#   wrkstn      no services (DHCP client replies only)
#
# Options:
#   --mgmt-nets CIDR[,CIDR]     management networks allowed to reach management ports
#   --extra-tcp P[,P]           additional public TCP ports
#   --splunk-open               open Splunk ports to all sources (override)
#   --allow-ping                allow inbound ICMP echo-request (default)
#   --no-ping                   disable inbound ICMP echo-request
#   --dry-run / --preview       print the selected firewall plan without applying it
#   --persist                   save current iptables rules after testing
#
# Examples:
#   sudo bash fw01-host-firewall-menu.sh mail webserver
#   sudo bash fw01-host-firewall-menu.sh mail webserver --extra-tcp 587,993
#   sudo bash fw01-host-firewall-menu.sh splunk --mgmt-nets 172.20.240.0/24,10.10.0.0/16
#   sudo bash fw01-host-firewall-menu.sh splunk --splunk-open
#   sudo bash fw01-host-firewall-menu.sh --persist
#
# Run from the VM console. New inbound IPv4 SSH is blocked by design.
# IPv6 firewall rules are captured but not changed.
# No automatic rollback. Keep console access available for manual recovery.
#
# Safety:
# - Does not flush or replace the whole firewall configuration.
# - Uses a dedicated MWCCDC_HOST chain attached to INPUT.
# - Stops if UFW or firewalld is active.
# - Requires explicit confirmation before applying changes.
# - Does not persist rules unless --persist is used.
# - Uses targeted chain operations to avoid temporary gaps in filtering.
# - Validates state before switchover to prevent corruption.

set -euo pipefail

# ===== CONFIGURATION =====
DEFAULT_MGMT_NETS=("172.20.240.0/24" "172.20.242.0/24")
MGMT_NETS=("${DEFAULT_MGMT_NETS[@]}")
ALLOW_PING=1
MODE="apply"
DRY_RUN=0
SPLUNK_OPEN=0

PROFILES=()
EXTRA_TCP=()

die() { echo "ERROR: $*" >&2; exit 1; }

trim() {
    local s="${1:-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

valid_port() {
    local port
    port="$(trim "$1")"
    # Reject leading zeros (octal interpretation)
    [[ "$port" =~ ^0 ]] && [[ "$port" != "0" ]] && return 1
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    (( 10#$port >= 1 && 10#$port <= 65535 ))
}

valid_cidr() {
    local raw ip mask
    raw="$(trim "$1")"
    [[ "$raw" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1

    ip="${raw%%/*}"
    mask="${raw##*/}"

    # Reject leading zeros in mask
    [[ "$mask" =~ ^0 ]] && [[ "$mask" != "0" ]] && return 1
    (( 10#$mask >= 0 && 10#$mask <= 32 )) || return 1

    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    for octet in "$a" "$b" "$c" "$d"; do
        # Reject leading zeros in octets
        [[ "$octet" =~ ^0 ]] && [[ "$octet" != "0" ]] && return 1
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done

    return 0
}

dedupe() {
    { printf '%s\n' "$@" | grep -E '^[0-9]+$' | sort -nu; } 2>/dev/null || true
}

usage() {
    cat <<'HELP'
MWCCDC FW01 Host Firewall
  sudo bash fw01-host-firewall-menu.sh               # interactive menu
  sudo bash fw01-host-firewall-menu.sh mail webserver
  sudo bash fw01-host-firewall-menu.sh splunk --splunk-open
  sudo bash fw01-host-firewall-menu.sh --dry-run mail webserver --extra-tcp 587
  sudo bash fw01-host-firewall-menu.sh --persist    # after testing
Profiles: webserver, mail, mail-full, splunk, dnsntp, wrkstn
Options:
  --mgmt-nets CIDR[,CIDR]
  --extra-tcp P[,P]
  --splunk-open
  --allow-ping
  --no-ping
  --dry-run / --preview
  --persist
  -h, --help
HELP
}

show_plan() {
    echo
    echo "==============================================="
    echo " MWCCDC FW01 Host Firewall Plan"
    echo "==============================================="
    echo "Profiles: ${PROFILES[*]:-none}"
    echo "Extra TCP: ${EXTRA_TCP[*]:-none}"
    echo "Management networks: ${MGMT_NETS[*]}"
    echo "Ping allowed: ${ALLOW_PING}"
    echo "Splunk open to all sources: ${SPLUNK_OPEN}"
    echo
    echo "Public TCP: ${PUBLIC_TCP[*]:-none}"
    echo "Public UDP: ${PUBLIC_UDP[*]:-none}"
    echo "Mgmt TCP: ${MGMT_TCP[*]:-none}"
    if [[ "$HAS_WRKSTN" -eq 1 ]]; then
        echo "Workstation DHCP client replies: enabled"
    fi
    echo
    echo "Rules:"
    echo "  - New inbound SSH TCP/22: blocked"
    echo "  - Established/related: allowed"
    echo "  - Loopback: allowed"
    echo "  - Outbound: allowed"
    echo "  - Default deny inbound: enforced (IPv4 INPUT only)"
    echo "  - IPv6 and Docker FORWARD/NAT: unchanged"
    echo "  - No automatic rollback"
    echo "==============================================="
}

# Return success when a chain is referenced from a chain other than INPUT.
# Examine actual iptables rule declarations, not chain names or comments.
chain_has_external_references() {
    local target="$1"
    iptables -t filter -S | awk -v target="$target" '
        $1 == "-A" && $2 != "INPUT" {
            for (i = 3; i < NF; i++) {
                if (($i == "-j" || $i == "-g") && $(i+1) == target) found = 1
            }
        }
        END { exit(found ? 0 : 1) }
    '
}

# ===== INTERACTIVE MENU =====
if [[ $# -eq 0 ]]; then
    echo
    echo "==============================================="
    echo "  MWCCDC FW01 - Linux Host Firewall"
    echo "==============================================="
    echo
    echo "Select your assigned Linux system:"
    echo
    echo "  1) Ubuntu Ecom Server"
    echo "  2) Fedora Webmail Server"
    echo "  3) Oracle Linux Splunk Server"
    echo "  4) Ubuntu Desktop Workstation"
    echo
    echo "  0) Exit"
    echo
    read -r -p "Enter your selection: " selection
    case "$selection" in
        1) set -- webserver ;;
        2) set -- mail webserver ;;
        3) set -- splunk ;;
        4) set -- wrkstn ;;
        0) echo "No changes made."; exit 0 ;;
        *) echo "Invalid selection; no changes made."; exit 1 ;;
    esac
fi

# ===== ARGUMENT PARSING =====
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mgmt-nets)
            [[ $# -ge 2 ]] || die "--mgmt-nets needs a value"
            IFS=',' read -ra raw_nets <<< "$(trim "$2")"
            MGMT_NETS=()
            for n in "${raw_nets[@]}"; do
                n="$(trim "$n")"
                [[ -n "$n" ]] || continue
                valid_cidr "$n" || die "Invalid CIDR network: $n"
                MGMT_NETS+=("$n")
            done
            [[ ${#MGMT_NETS[@]} -gt 0 ]] || die "--mgmt-nets requires at least one valid CIDR"
            shift 2
            ;;
        --extra-tcp)
            [[ $# -ge 2 ]] || die "--extra-tcp needs a value"
            IFS=',' read -ra raw_ports <<< "$(trim "$2")"
            EXTRA_TCP=()
            for p in "${raw_ports[@]}"; do
                p="$(trim "$p")"
                [[ -n "$p" ]] || continue
                valid_port "$p" || die "Invalid TCP port: $p"
                EXTRA_TCP+=("$p")
            done
            [[ ${#EXTRA_TCP[@]} -gt 0 ]] || die "--extra-tcp requires at least one valid port"
            shift 2
            ;;
        --splunk-open) SPLUNK_OPEN=1; shift ;;
        --allow-ping) ALLOW_PING=1; shift ;;
        --no-ping) ALLOW_PING=0; shift ;;
        --dry-run|--preview) DRY_RUN=1; shift ;;
        --persist) MODE="persist"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "Unknown option: $1" ;;
        *) PROFILES+=("$1"); shift ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."

# ===== PERSIST MODE =====
if [[ "$MODE" == "persist" ]]; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        die "firewalld is active. Do not persist conflicting iptables rules."
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        die "ufw is active. Do not persist conflicting iptables rules."
    fi
    iptables -C INPUT -j MWCCDC_HOST 2>/dev/null || die "MWCCDC_HOST is not attached to INPUT. Re-apply before persisting."

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
        echo "Rules saved with netfilter-persistent."
        if systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
            echo "netfilter-persistent is enabled at boot."
        else
            echo "WARNING: netfilter-persistent is not enabled at boot."
            echo "To enable: sudo systemctl enable netfilter-persistent"
        fi
    elif [[ -d /etc/sysconfig ]]; then
        iptables-save > /etc/sysconfig/iptables
        echo "Saved to /etc/sysconfig/iptables."
        if systemctl is-enabled iptables >/dev/null 2>&1; then
            echo "iptables service is enabled at boot."
        else
            echo "WARNING: iptables service is not enabled at boot."
            echo "To enable: sudo systemctl enable iptables"
        fi
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        echo "Saved to /etc/iptables/rules.v4."
        echo "WARNING: No standard persistence service found."
        echo "To load at boot, add to /etc/rc.local or a systemd service:"
        echo "  iptables-restore < /etc/iptables/rules.v4"
    fi
    exit 0
fi

# ===== VALIDATION =====
# This script manages IPv4 INPUT only. IPv6 and Docker FORWARD/NAT are unchanged.
[[ ${#PROFILES[@]} -gt 0 ]] || { usage; exit 1; }

for cmd in iptables iptables-save ss; do
    command -v "$cmd" >/dev/null 2>&1 || die "Missing command: $cmd"
done

for p in "${EXTRA_TCP[@]}"; do
    valid_port "$p" || die "Invalid port: $p"
done

for n in "${MGMT_NETS[@]}"; do
    valid_cidr "$n" || die "Invalid network: $n"
done

# ===== BUILD PORT LISTS FROM PROFILES =====
PUBLIC_TCP=()
PUBLIC_UDP=()
MGMT_TCP=()
HAS_WRKSTN=0

for P in "${PROFILES[@]}"; do
    case "$P" in
        webserver) PUBLIC_TCP+=(80 443) ;;
        mail)      PUBLIC_TCP+=(25 110) ;;
        mail-full) PUBLIC_TCP+=(25 465 587 110 995 143 993) ;;
        splunk)
            if [[ "$SPLUNK_OPEN" -eq 1 ]]; then
                PUBLIC_TCP+=(8000 8089 9997)
            else
                MGMT_TCP+=(8000 8089 9997)
            fi
            ;;
        dnsntp)    PUBLIC_TCP+=(53); PUBLIC_UDP+=(53 123) ;;
        wrkstn)    HAS_WRKSTN=1 ;;
        *) die "Unknown profile: $P" ;;
    esac
done

PUBLIC_TCP+=("${EXTRA_TCP[@]}")

# dedupe
mapfile -t PUBLIC_TCP < <(dedupe "${PUBLIC_TCP[@]}")
mapfile -t PUBLIC_UDP < <(dedupe "${PUBLIC_UDP[@]}")
mapfile -t MGMT_TCP   < <(dedupe "${MGMT_TCP[@]}")

# ===== REPORT DIRECTORY =====
PROFILE_TAG="$(IFS=_; echo "${PROFILES[*]}")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="/root/FW01_${PROFILE_TAG}_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

SUMMARY="$REPORT_DIR/summary.txt"
note() { printf '%-6s %-7s %s\n' "$1" "$2" "$3" >> "$SUMMARY"; }

echo "======================================"
echo "MWCCDC FW01 Host Firewall Assessment"
echo "Profiles: ${PROFILES[*]}"
echo "Report:   $REPORT_DIR"
echo "======================================"

# ===== CAPTURE (BEFORE / AFTER) =====
capture() {
    local stage="$1"
    iptables -L INPUT  -n -v --line-numbers > "$REPORT_DIR/${stage}-input.txt"
    iptables -L OUTPUT -n -v --line-numbers > "$REPORT_DIR/${stage}-output.txt"
    iptables-save                           > "$REPORT_DIR/${stage}-iptables.rules"
    ss -tulnp                               > "$REPORT_DIR/${stage}-listening.txt"
    command -v ufw >/dev/null 2>&1 &&
        ufw status verbose > "$REPORT_DIR/${stage}-ufw.txt" 2>&1 || true
    command -v firewall-cmd >/dev/null 2>&1 &&
        firewall-cmd --list-all > "$REPORT_DIR/${stage}-firewalld.txt" 2>&1 || true
    command -v nft >/dev/null 2>&1 &&
        nft list ruleset > "$REPORT_DIR/${stage}-nftables.txt" 2>&1 || true
    command -v ip6tables-save >/dev/null 2>&1 &&
        ip6tables-save > "$REPORT_DIR/${stage}-ip6tables.rules" 2>&1 || true
}

# ===== DRY RUN =====
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[1/2] Capturing current listening services..."
    ss -tulnp > "$REPORT_DIR/dry-run-listening.txt"

    {
        echo "Host firewall plan - profiles: ${PROFILES[*]}"
        echo "Default: inbound denied; established/related allowed; new SSH blocked."
        printf '%-6s %-7s %s\n' "PROTO" "PORT" "ALLOWED SOURCES"
    } > "$SUMMARY"

    if command -v git >/dev/null 2>&1; then
        SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
        COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || true)"
        if [[ -n "$COMMIT" ]]; then
            echo "Git commit: $COMMIT" >> "$SUMMARY"
        else
            echo "Git commit: unavailable (not a Git checkout)" >> "$SUMMARY"
        fi
    else
        echo "Git commit: unavailable (git not installed)" >> "$SUMMARY"
    fi

    if [[ "$ALLOW_PING" -eq 1 ]]; then
        note icmp echo "any source"
    fi

    for p in "${PUBLIC_TCP[@]}"; do
        note tcp "$p" "any source"
    done
    for p in "${PUBLIC_UDP[@]}"; do
        note udp "$p" "any source"
    done
    for p in "${MGMT_TCP[@]}"; do
        for n in "${MGMT_NETS[@]}"; do
            note tcp "$p" "$n only"
        done
    done

    if [[ "$HAS_WRKSTN" -eq 1 ]]; then
        note udp 68 "DHCP server replies (client)"
    fi

    echo "[2/2] Generating dry-run report..."
    echo
    echo "DRY RUN: No firewall changes were applied."
    show_plan
    echo
    echo "===== CURRENTLY LISTENING SERVICES ====="
    cat "$REPORT_DIR/dry-run-listening.txt"
    echo
    echo "Summary saved to: $SUMMARY"
    exit 0
fi

# ===== BEFORE STATE CAPTURE =====
echo "[1/5] Capturing BEFORE state..."
capture before

# Stop before applying changes if another firewall manager is active.
MANAGER_ACTIVE=0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "ERROR: firewalld is active. Review $REPORT_DIR/before-firewalld.txt and before-nftables.txt."
    MANAGER_ACTIVE=1
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    echo "ERROR: ufw is active. Review $REPORT_DIR/before-ufw.txt."
    MANAGER_ACTIVE=1
fi
if [[ "$MANAGER_ACTIVE" -eq 1 ]]; then
    echo "No firewall changes made. Coordinate with the admin to use one firewall manager."
    exit 1
fi

# ===== PREPARE SUMMARY =====
{
    echo "Host firewall plan - profiles: ${PROFILES[*]}"
    echo "Default: inbound denied; established/related allowed; new SSH blocked."
    printf '%-6s %-7s %s\n' "PROTO" "PORT" "ALLOWED SOURCES"
} > "$SUMMARY"

if command -v git >/dev/null 2>&1; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -n "$COMMIT" ]]; then
        echo "Git commit: $COMMIT" >> "$SUMMARY"
    else
        echo "Git commit: unavailable (not a Git checkout)" >> "$SUMMARY"
    fi
else
    echo "Git commit: unavailable (git not installed)" >> "$SUMMARY"
fi

if [[ "$ALLOW_PING" -eq 1 ]]; then
    note icmp echo "any source"
fi

for p in "${PUBLIC_TCP[@]}"; do
    note tcp "$p" "any source"
done
for p in "${PUBLIC_UDP[@]}"; do
    note udp "$p" "any source"
done
for p in "${MGMT_TCP[@]}"; do
    for n in "${MGMT_NETS[@]}"; do
        note tcp "$p" "$n only"
    done
done

if [[ "$HAS_WRKSTN" -eq 1 ]]; then
    note udp 68 "DHCP server replies (client)"
fi

# ===== DISPLAY PLAN AND CONFIRM (SINGLE PROMPT) =====
show_plan
echo
read -r -p "Apply these host firewall rules? [y/N]: " confirm
[[ "$confirm" =~ ^[Yy]([Ee][Ss])?$ ]] || { echo "No changes made."; exit 0; }

# ===== PRE-SWITCHOVER VALIDATION =====
echo "[2/5] Pre-flight validation..."

TEMP_CHAIN="MWCCDC_HOST_NEW"

# Refuse to reuse an existing temporary chain.
# It may be active after an interrupted run.
if iptables -t filter -L "$TEMP_CHAIN" -n >/dev/null 2>&1; then
    die "Temporary chain $TEMP_CHAIN already exists. Inspect INPUT and the chain before retrying; do not flush an active chain."
fi

# Check any existing production chain before touching firewall state.
if iptables -t filter -L MWCCDC_HOST -n >/dev/null 2>&1; then
    if ! iptables -t filter -C INPUT -j MWCCDC_HOST 2>/dev/null; then
        die "MWCCDC_HOST exists but is not attached to INPUT. Inspect it manually."
    fi
    if chain_has_external_references MWCCDC_HOST; then
        die "MWCCDC_HOST is referenced outside INPUT. Inspect: sudo iptables -t filter -S"
    fi
    echo "Existing MWCCDC_HOST chain is attached to INPUT and can be replaced."
fi

# ===== SAFE CHAIN REPLACEMENT =====
echo "[3/5] Building and switching to replacement firewall chain..."

# Create new temporary chain
iptables -t filter -N "$TEMP_CHAIN" || die "Failed to create temporary chain"

# Build all rules in the temporary chain
iptables -A "$TEMP_CHAIN" -i lo -j ACCEPT
iptables -A "$TEMP_CHAIN" -m conntrack --ctstate INVALID -j DROP
iptables -A "$TEMP_CHAIN" -p tcp --dport 22 -m conntrack --ctstate NEW -j DROP
iptables -A "$TEMP_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if [[ "$ALLOW_PING" -eq 1 ]]; then
    iptables -A "$TEMP_CHAIN" -p icmp --icmp-type echo-request -j ACCEPT
fi

for p in "${PUBLIC_TCP[@]}"; do
    iptables -A "$TEMP_CHAIN" -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done
for p in "${PUBLIC_UDP[@]}"; do
    iptables -A "$TEMP_CHAIN" -p udp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done
for p in "${MGMT_TCP[@]}"; do
    for n in "${MGMT_NETS[@]}"; do
        iptables -A "$TEMP_CHAIN" -p tcp -s "$n" --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
    done
done

if [[ "$HAS_WRKSTN" -eq 1 ]]; then
    iptables -A "$TEMP_CHAIN" -p udp --sport 67 --dport 68 -j ACCEPT
fi

iptables -A "$TEMP_CHAIN" -j DROP

echo "  Temporary chain built. Inserting into INPUT (filtering active immediately)..."

# Insert temporary chain at the top of INPUT (new chain is now active, filtering traffic)
if ! iptables -I INPUT 1 -j "$TEMP_CHAIN"; then
    iptables -F "$TEMP_CHAIN" 2>/dev/null || true
    iptables -X "$TEMP_CHAIN" 2>/dev/null || true
    die "Failed to insert temporary chain into INPUT"
fi

echo "  New chain is active. Removing old references..."

# Remove old INPUT references only after the new chain is attached.
while iptables -t filter -C INPUT -j MWCCDC_HOST 2>/dev/null; do
    iptables -t filter -D INPUT -j MWCCDC_HOST ||
        die "Failed to remove old INPUT reference. New chain remains active."
done

echo "  Old chain removed from INPUT. Cleaning old chain resources..."

# Delete the old production chain only if it exists and has no references.
if iptables -t filter -L MWCCDC_HOST -n >/dev/null 2>&1; then
    if chain_has_external_references MWCCDC_HOST; then
        die "Old chain acquired a reference outside INPUT. New chain remains active."
    fi
    iptables -t filter -F MWCCDC_HOST || die "Failed to flush old chain."
    iptables -t filter -X MWCCDC_HOST || die "Failed to delete old chain. New chain remains active."
fi

echo "  Renaming temporary chain to production name..."

# Rename temporary chain to production name
if ! iptables -E "$TEMP_CHAIN" MWCCDC_HOST; then
    die "Failed to rename $TEMP_CHAIN to MWCCDC_HOST. Firewall is in unexpected state. Active filtering chain: $TEMP_CHAIN. Manual recovery: sudo iptables -E $TEMP_CHAIN MWCCDC_HOST"
fi

echo "  Chain renamed. Verifying active configuration..."

# Verify the chain is active in INPUT
if ! iptables -C INPUT -j MWCCDC_HOST 2>/dev/null; then
    die "MWCCDC_HOST chain is not in INPUT. Firewall may be in an inconsistent state. Investigate with: sudo iptables -L INPUT -n"
fi

echo "[4/5] Capturing AFTER state..."
capture after
iptables -L MWCCDC_HOST -n -v --line-numbers > "$REPORT_DIR/after-host-rules.txt"

normalize_rules() {
    sed -E \
        -e '/^# Generated by /d' \
        -e '/^# Completed on /d' \
        -e 's/\[[0-9]+:[0-9]+\]//g' \
        "$1"
}

echo "[5/5] Generating diff..."
diff -u \
    <(normalize_rules "$REPORT_DIR/before-iptables.rules") \
    <(normalize_rules "$REPORT_DIR/after-iptables.rules") \
    > "$REPORT_DIR/firewall-changes.txt" || true

echo
echo "===== BEFORE INPUT RULES ====="
cat "$REPORT_DIR/before-input.txt"
echo
echo "===== AFTER INPUT RULES ====="
cat "$REPORT_DIR/after-input.txt"
echo
echo "===== HOST FIREWALL CHAIN ====="
cat "$REPORT_DIR/after-host-rules.txt"
echo
echo "===== PLAN SUMMARY ====="
cat "$SUMMARY"
echo
echo "Reports: $REPORT_DIR"
echo "Next: verify scored services in NISE."
echo
echo "===== MANUAL RECOVERY COMMANDS ====="
echo "Verify the active chain:"
echo "  sudo iptables -L INPUT -n | grep MWCCDC_HOST"
echo
echo "If you need to remove the firewall rules:"
echo "  sudo iptables -D INPUT -j MWCCDC_HOST  # repeat if multiple jumps exist"
echo "  sudo iptables -F MWCCDC_HOST"
echo "  sudo iptables -X MWCCDC_HOST"
echo
echo "If you need to save current state before removal:"
echo "  sudo iptables-save > /root/fw01-before-recovery.rules"
echo
echo "Saved pre-change snapshot: $REPORT_DIR/before-iptables.rules"
echo "Changed rules: $REPORT_DIR/firewall-changes.txt"
