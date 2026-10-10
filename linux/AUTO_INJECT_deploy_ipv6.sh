#!/usr/bin/env bash
# deploy_ipv6.sh — Interactive IPv6 deployment for Ubuntu, Debian, CentOS, Fedora
# Run as root: sudo bash deploy_ipv6.sh

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERR ]${RESET}  $*" >&2; }

die() { log_error "$*"; exit 1; }

# ─── Root check ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (use: sudo bash $0)"

# ─── Global state ────────────────────────────────────────────────────────────
OS_FAMILY=""   # ubuntu | debian | centos | fedora
OS_VERSION=""
IFACE=""
IPV6_ADDR=""
IPV6_PREFIX="64"
IPV6_GW=""
DNS_PRIMARY=""
DNS_SECONDARY=""

# ─── Helpers ─────────────────────────────────────────────────────────────────
backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
        log_info "Backed up $f"
    fi
}

validate_ipv6() {
    # Returns 0 (true) if the argument looks like a valid IPv6 address (no prefix)
    local addr="$1"
    python3 -c "import ipaddress; ipaddress.IPv6Address('$addr')" 2>/dev/null
}

prompt_yn() {
    # Usage: prompt_yn "Question?" && echo yes || echo no
    local msg="$1" ans
    while true; do
        read -rp "$(echo -e "${BOLD}${msg}${RESET} [y/n]: ")" ans
        case "$ans" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# ─── 1. OS Detection ─────────────────────────────────────────────────────────
detect_os() {
    echo
    echo -e "${BOLD}━━━ Step 1: Detecting OS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    [[ -f /etc/os-release ]] || die "/etc/os-release not found — cannot detect OS."
    # shellcheck source=/dev/null
    source /etc/os-release

    OS_VERSION="${VERSION_ID:-unknown}"

    case "${ID,,}" in
        ubuntu)  OS_FAMILY="ubuntu"  ;;
        debian)  OS_FAMILY="debian"  ;;
        centos|rhel|rocky|almalinux) OS_FAMILY="centos" ;;
        fedora)  OS_FAMILY="fedora"  ;;
        *)
            log_warn "Unrecognized OS ID: ${ID}. Attempting generic configuration."
            OS_FAMILY="generic"
            ;;
    esac

    log_ok "Detected: ${PRETTY_NAME:-$ID $OS_VERSION} → family=${OS_FAMILY}"
}

# ─── 2. Interface Detection ───────────────────────────────────────────────────
detect_interface() {
    echo
    echo -e "${BOLD}━━━ Step 2: Network Interface ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    local detected
    detected=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

    if [[ -n "$detected" ]]; then
        log_info "Auto-detected default interface: ${BOLD}${detected}${RESET}"
        if prompt_yn "Use interface '$detected'?"; then
            IFACE="$detected"
        fi
    fi

    if [[ -z "$IFACE" ]]; then
        echo
        echo "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  " $2}' | grep -v lo
        echo
        while true; do
            read -rp "$(echo -e "${BOLD}Enter interface name:${RESET} ")" IFACE
            [[ -n "$IFACE" ]] && break
            echo "Interface name cannot be empty."
        done
    fi

    ip link show "$IFACE" &>/dev/null || die "Interface '$IFACE' does not exist."
    log_ok "Using interface: ${BOLD}${IFACE}${RESET}"
}

# ─── 3. IPv6 Address ─────────────────────────────────────────────────────────
prompt_ipv6_address() {
    echo
    echo -e "${BOLD}━━━ Step 3: IPv6 Address ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "  ${BOLD}Recommended addresses (ULA — Unique Local, /64):${RESET}"
    echo -e "  ┌─────────┬──────────────────────────────────────┐"
    echo -e "  │ Label   │ IPv6 Address                         │"
    echo -e "  ├─────────┼──────────────────────────────────────┤"
    echo -e "  │ (user1) │ fd00::1                              │"
    echo -e "  │ (user2) │ fd00::2                              │"
    echo -e "  │ (user3) │ fd00::3                              │"
    echo -e "  │ (user4) │ fd00::4                              │"
    echo -e "  │ (user5) │ fd00::5                              │"
    echo -e "  │ (user6) │ fd00::6                              │"
    echo -e "  │ (user7) │ fd00::7                              │"
    echo -e "  │ (user8) │ fd00::8                              │"
    echo -e "  └─────────┴──────────────────────────────────────┘"
    echo
    echo -e "  Enter a label (user1–user8) to use a recommendation,"
    echo -e "  or type a full IPv6 address manually (with optional /prefix)."
    echo

    while true; do
        read -rp "$(echo -e "${BOLD}IPv6 address or label:${RESET} ")" input
        input="${input,,}"  # lowercase

        case "$input" in
            user1) IPV6_ADDR="fd00::1" ;;
            user2) IPV6_ADDR="fd00::2" ;;
            user3) IPV6_ADDR="fd00::3" ;;
            user4) IPV6_ADDR="fd00::4" ;;
            user5) IPV6_ADDR="fd00::5" ;;
            user6) IPV6_ADDR="fd00::6" ;;
            user7) IPV6_ADDR="fd00::7" ;;
            user8) IPV6_ADDR="fd00::8" ;;
            *)
                # Strip optional /prefix for validation
                local bare="${input%%/*}"
                local pfx="${input##*/}"
                if [[ "$input" == */* ]] && [[ "$pfx" =~ ^[0-9]+$ ]]; then
                    IPV6_PREFIX="$pfx"
                fi
                if validate_ipv6 "$bare"; then
                    IPV6_ADDR="$bare"
                else
                    log_warn "'$input' is not a valid IPv6 address or label. Try again."
                    continue
                fi
                ;;
        esac
        break
    done

    read -rp "$(echo -e "${BOLD}Prefix length [${IPV6_PREFIX}]:${RESET} ")" pfx_input
    if [[ -n "$pfx_input" && "$pfx_input" =~ ^[0-9]+$ ]]; then
        IPV6_PREFIX="$pfx_input"
    fi

    log_ok "IPv6 address: ${BOLD}${IPV6_ADDR}/${IPV6_PREFIX}${RESET}"
}

# ─── 4. Gateway ───────────────────────────────────────────────────────────────
prompt_gateway() {
    echo
    echo -e "${BOLD}━━━ Step 4: Default Gateway ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    while true; do
        read -rp "$(echo -e "${BOLD}Enter IPv6 default gateway (e.g. fd00::fffe):${RESET} ")" IPV6_GW
        [[ -z "$IPV6_GW" ]] && { echo "Gateway cannot be empty."; continue; }
        validate_ipv6 "$IPV6_GW" && break || log_warn "'$IPV6_GW' is not a valid IPv6 address. Try again."
    done

    log_ok "Gateway: ${BOLD}${IPV6_GW}${RESET}"
}

# ─── 5. DNS ───────────────────────────────────────────────────────────────────
_pick_public_dns() {
    echo
    echo -e "  ${BOLD}Public IPv6 DNS Options:${RESET}"
    echo -e "  1) Google      → 2001:4860:4860::8888"
    echo -e "  2) Cloudflare  → 2606:4700:4700::1111"
    echo -e "  3) OpenDNS     → 2620:119:35::35"
    echo -e "  4) Custom      → enter manually"
    echo

    local choice addr
    while true; do
        read -rp "$(echo -e "${BOLD}Select public DNS [1-4]:${RESET} ")" choice
        case "$choice" in
            1) addr="2001:4860:4860::8888"; break ;;
            2) addr="2606:4700:4700::1111"; break ;;
            3) addr="2620:119:35::35"; break ;;
            4)
                while true; do
                    read -rp "$(echo -e "${BOLD}Enter DNS address:${RESET} ")" addr
                    validate_ipv6 "$addr" && break || log_warn "Invalid IPv6 address."
                done
                break
                ;;
            *) echo "Enter 1, 2, 3, or 4." ;;
        esac
    done
    echo "$addr"
}

prompt_dns() {
    echo
    echo -e "${BOLD}━━━ Step 5: DNS Configuration ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  Leave blank to choose from public IPv6 DNS providers."
    echo

    read -rp "$(echo -e "${BOLD}Primary DNS (or Enter for public options):${RESET} ")" DNS_PRIMARY

    if [[ -z "$DNS_PRIMARY" ]]; then
        DNS_PRIMARY="$(_pick_public_dns)"
    else
        validate_ipv6 "$DNS_PRIMARY" || die "'$DNS_PRIMARY' is not a valid IPv6 address."
    fi

    log_ok "Primary DNS: ${BOLD}${DNS_PRIMARY}${RESET}"

    if prompt_yn "Configure a secondary DNS server?"; then
        read -rp "$(echo -e "${BOLD}Secondary DNS (or Enter for public options):${RESET} ")" DNS_SECONDARY
        if [[ -z "$DNS_SECONDARY" ]]; then
            DNS_SECONDARY="$(_pick_public_dns)"
        else
            validate_ipv6 "$DNS_SECONDARY" || { log_warn "Invalid secondary DNS — skipping."; DNS_SECONDARY=""; }
        fi
        [[ -n "$DNS_SECONDARY" ]] && log_ok "Secondary DNS: ${BOLD}${DNS_SECONDARY}${RESET}"
    fi
}

# ─── 6. OS-Specific Configuration ────────────────────────────────────────────

_configure_nmcli() {
    log_info "Configuring via NetworkManager (nmcli)…"

    local conn
    conn=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null \
           | awk -F: -v iface="$IFACE" '$2==iface {print $1; exit}')

    if [[ -z "$conn" ]]; then
        # No active connection on this interface — find any connection tied to it
        conn=$(nmcli -t -f NAME,DEVICE con show 2>/dev/null \
               | awk -F: -v iface="$IFACE" '$2==iface {print $1; exit}')
    fi

    if [[ -z "$conn" ]]; then
        log_warn "No NetworkManager connection found for $IFACE — creating one."
        conn="ipv6-${IFACE}"
        nmcli con add type ethernet ifname "$IFACE" con-name "$conn"
    fi

    local dns_str="$DNS_PRIMARY"
    [[ -n "$DNS_SECONDARY" ]] && dns_str="${DNS_PRIMARY} ${DNS_SECONDARY}"

    nmcli con mod "$conn" \
        ipv6.method manual \
        ipv6.addresses "${IPV6_ADDR}/${IPV6_PREFIX}" \
        ipv6.gateway   "$IPV6_GW" \
        ipv6.dns       "$dns_str"

    nmcli con up "$conn"
    log_ok "nmcli connection '$conn' updated and brought up."
}

_configure_netplan() {
    log_info "Configuring via netplan…"

    local yaml_file
    yaml_file=$(ls /etc/netplan/*.yaml 2>/dev/null | head -1)

    if [[ -z "$yaml_file" ]]; then
        yaml_file="/etc/netplan/01-netcfg.yaml"
        log_warn "No netplan file found — creating $yaml_file"
    fi

    backup_file "$yaml_file"

    local dns_block="            addresses: [${DNS_PRIMARY}"
    [[ -n "$DNS_SECONDARY" ]] && dns_block="${dns_block}, ${DNS_SECONDARY}"
    dns_block="${dns_block}]"

    cat > "$yaml_file" <<NETPLAN
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: true
      dhcp6: false
      addresses:
        - ${IPV6_ADDR}/${IPV6_PREFIX}
      routes:
        - to: ::/0
          via: ${IPV6_GW}
      nameservers:
${dns_block}
NETPLAN

    netplan apply
    log_ok "Netplan configuration applied."
}

_configure_interfaces() {
    log_info "Configuring via /etc/network/interfaces…"

    local ifaces_file="/etc/network/interfaces"
    backup_file "$ifaces_file"

    # Remove any existing IPv6 stanza for this interface
    sed -i "/^iface ${IFACE} inet6/,/^$/d" "$ifaces_file" 2>/dev/null || true

    local dns_line="dns-nameservers ${DNS_PRIMARY}"
    [[ -n "$DNS_SECONDARY" ]] && dns_line="${dns_line} ${DNS_SECONDARY}"

    cat >> "$ifaces_file" <<INTERFACES

iface ${IFACE} inet6 static
    address ${IPV6_ADDR}/${IPV6_PREFIX}
    gateway ${IPV6_GW}
    ${dns_line}
INTERFACES

    if command -v ifdown &>/dev/null; then
        ifdown "$IFACE" 2>/dev/null || true
        ifup   "$IFACE" 2>/dev/null || log_warn "ifup failed — you may need to restart networking manually."
    else
        systemctl restart networking 2>/dev/null || log_warn "Could not restart networking — reboot may be required."
    fi

    log_ok "/etc/network/interfaces updated."
}

_configure_sysconfig() {
    log_info "Configuring via /etc/sysconfig/network-scripts…"

    local cfg="/etc/sysconfig/network-scripts/ifcfg-${IFACE}"
    backup_file "$cfg"

    # Remove existing IPv6 keys
    sed -i '/^IPV6/d' "$cfg" 2>/dev/null || true

    cat >> "$cfg" <<SYSCONFIG
IPV6INIT=yes
IPV6_AUTOCONF=no
IPV6ADDR=${IPV6_ADDR}/${IPV6_PREFIX}
IPV6_DEFAULTGW=${IPV6_GW}
DNS6_1=${DNS_PRIMARY}
SYSCONFIG

    if [[ -n "$DNS_SECONDARY" ]]; then
        echo "DNS6_2=${DNS_SECONDARY}" >> "$cfg"
    fi

    # CentOS 7 uses 'network' service; CentOS 8+ / Fedora use NetworkManager
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        nmcli con reload
        nmcli con up "$IFACE" 2>/dev/null || true
    elif systemctl is-active --quiet network 2>/dev/null; then
        systemctl restart network
    else
        log_warn "Could not restart network service — reboot may be required."
    fi

    log_ok "/etc/sysconfig/network-scripts/ifcfg-${IFACE} updated."
}

configure_ipv6() {
    echo
    echo -e "${BOLD}━━━ Step 6: Applying Configuration ━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    # Prefer nmcli when NetworkManager is actively running
    if command -v nmcli &>/dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        _configure_nmcli
        return
    fi

    # Netplan (Ubuntu 18.04+)
    if command -v netplan &>/dev/null; then
        _configure_netplan
        return
    fi

    # Debian / older Ubuntu
    if [[ -f /etc/network/interfaces ]]; then
        _configure_interfaces
        return
    fi

    # CentOS 7 / RHEL 7
    if [[ -d /etc/sysconfig/network-scripts ]]; then
        _configure_sysconfig
        return
    fi

    die "No supported network configuration method found on this system."
}

# ─── 7. Status Report ─────────────────────────────────────────────────────────
status_report() {
    echo
    echo -e "${BOLD}━━━ Step 7: Status Report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    # Give the network stack a moment to settle
    sleep 2

    local pass=0 fail=0

    _check() {
        local label="$1" result="$2"
        if [[ "$result" == "ok" ]]; then
            printf "  ${GREEN}✓${RESET}  %-40s ${GREEN}PASS${RESET}\n" "$label"
            ((pass++))
        else
            printf "  ${RED}✗${RESET}  %-40s ${RED}FAIL${RESET}\n" "$label"
            ((fail++))
        fi
    }

    # 1. IPv6 address assigned on interface
    if ip -6 addr show dev "$IFACE" 2>/dev/null | grep -q "${IPV6_ADDR}"; then
        _check "IPv6 address assigned ($IPV6_ADDR)" "ok"
    else
        _check "IPv6 address assigned ($IPV6_ADDR)" "fail"
    fi

    # 2. Link-local address present
    if ip -6 addr show dev "$IFACE" 2>/dev/null | grep -q "fe80::"; then
        _check "Link-local address (fe80::) present" "ok"
    else
        _check "Link-local address (fe80::) present" "fail"
    fi

    # 3. Default IPv6 route present
    if ip -6 route show default 2>/dev/null | grep -q "via"; then
        _check "Default IPv6 route configured" "ok"
    else
        _check "Default IPv6 route configured" "fail"
    fi

    # 4. Gateway reachable
    if ping6 -c 2 -W 3 "$IPV6_GW" &>/dev/null 2>&1; then
        _check "Gateway reachable ($IPV6_GW)" "ok"
    else
        _check "Gateway reachable ($IPV6_GW)" "fail"
    fi

    # 5. DNS resolution
    if command -v dig &>/dev/null; then
        if dig AAAA google.com "@${DNS_PRIMARY}" +short +time=3 2>/dev/null | grep -q ':'; then
            _check "DNS resolution via $DNS_PRIMARY" "ok"
        else
            _check "DNS resolution via $DNS_PRIMARY" "fail"
        fi
    else
        printf "  ${YELLOW}~${RESET}  %-40s ${YELLOW}SKIP${RESET} (dig not installed)\n" "DNS resolution"
    fi

    # 6. Internet connectivity (Google Public DNS as beacon)
    if ping6 -c 2 -W 5 2001:4860:4860::8888 &>/dev/null 2>&1; then
        _check "Internet connectivity (ping6 Google DNS)" "ok"
    else
        _check "Internet connectivity (ping6 Google DNS)" "fail"
    fi

    echo
    echo -e "  ─────────────────────────────────────────────────────────"
    if [[ $fail -eq 0 ]]; then
        echo -e "  ${BOLD}${GREEN}IPv6 deployment SUCCESSFUL${RESET}  (${pass} checks passed, 0 failed)"
    else
        echo -e "  ${BOLD}${RED}IPv6 deployment FAILED${RESET}      (${pass} passed, ${fail} failed — see above)"
        echo
        echo -e "  ${YELLOW}Troubleshooting tips:${RESET}"
        echo -e "    • Verify the gateway address is reachable on your network segment"
        echo -e "    • Check 'journalctl -u NetworkManager' or 'dmesg | grep ipv6'"
        echo -e "    • Ensure your router/upstream supports IPv6"
        echo -e "    • A reboot may be needed for sysconfig/interfaces changes to fully apply"
    fi
    echo
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║          IPv6 Deployment Script — CCDC Team              ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"

    detect_os
    detect_interface
    prompt_ipv6_address
    prompt_gateway
    prompt_dns

    echo
    echo -e "${BOLD}━━━ Configuration Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  Interface : ${BOLD}${IFACE}${RESET}"
    echo -e "  Address   : ${BOLD}${IPV6_ADDR}/${IPV6_PREFIX}${RESET}"
    echo -e "  Gateway   : ${BOLD}${IPV6_GW}${RESET}"
    echo -e "  DNS (pri) : ${BOLD}${DNS_PRIMARY}${RESET}"
    [[ -n "$DNS_SECONDARY" ]] && echo -e "  DNS (sec) : ${BOLD}${DNS_SECONDARY}${RESET}"
    echo

    prompt_yn "Apply this configuration now?" || { echo "Aborted."; exit 0; }

    configure_ipv6
    status_report
}

main "$@"
