#!/usr/bin/env bash
# ============================================================
# Inject: 35 - Firewall_Assessment (FW01)
#
# Supported:
#   - Ubuntu: iptables / iptables-nft
#   - Fedora: firewalld
#
# Menu:
#   1. Assess current IPv4 firewall rules
#   2. Generate and apply hardening plan
#   3. Verify firewall and display evidence
#   4. Exit
#
# IPv6 is outside the scope of FW01.
# No IPv6 rules are modified.
#
# Runtime-only firewall changes.
# No evidence files are created.
#
# WARNING:
# Use direct VM console access when applying firewall rules.
# ============================================================

set -Eeuo pipefail

BACKEND=""
PROFILES=""
TCP_PORTS=()
UDP_PORTS=()

# ============================================================
# HELPER FUNCTIONS
# ============================================================

has() {
    command -v "$1" >/dev/null 2>&1
}

heading() {
    echo
    echo "========================================"
    echo " $1"
    echo "========================================"
}

info() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*"
}

error() {
    echo "[ERROR] $*" >&2
}

exit_script() {
    echo
    echo "[INFO] Exiting MWCCDC Firewall Assessment."
    exit 0
}

# Read user input without automatically treating 4 or q
# as an exit. Each menu handles those choices separately.
read_input() {
    local variable="$1"
    local prompt="$2"
    local user_response=""

    if ! IFS= read -r -p "$prompt" user_response; then
        exit_script
    fi

    printf -v "$variable" '%s' "$user_response"
}

# Return to main menu after Option 2.
pause_menu() {
    local user_response=""

    while true; do
        echo
        IFS= read -r -p \
            "Press 'q' or Enter to return to the main menu: " \
            user_response || exit_script

        case "${user_response,,}" in
            q|"")
                return
                ;;
            exit|4)
                exit_script
                ;;
            *)
                echo "Invalid selection. Enter 'q' or press Enter."
                ;;
        esac
    done
}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Run this script using sudo."
        exit 1
    fi
}

# ============================================================
# FIREWALL BACKEND DETECTION
# ============================================================

detect_backend() {
    BACKEND="unsupported"

    # Prefer firewalld when it is running.
    if has firewall-cmd &&
       firewall-cmd --state 2>/dev/null |
       grep -qx running; then
        BACKEND="firewalld"
        return
    fi

    # Check for active UFW.
    if has ufw &&
       ufw status 2>/dev/null |
       grep -qi '^Status: active'; then
        BACKEND="ufw"
        return
    fi

    # Recognize iptables, including iptables-nft.
    if has iptables; then
        if iptables -V 2>/dev/null | grep -q nf_tables; then
            BACKEND="iptables (nf_tables)"
        else
            BACKEND="iptables"
        fi
        return
    fi

    if has nft; then
        BACKEND="nftables"
    fi
}

# ============================================================
# SCROLLABLE OUTPUT
# ============================================================

show_scrollable() {
    local output
    output="$(mktemp)"

    {
        "$@"

        echo
        echo "========================================"
        echo " Press 'q' to return to the main menu"
        echo "========================================"
    } > "$output" 2>&1

    if has less; then
        # -S: Do not wrap long lines
        # -R: Preserve terminal formatting
        # -+F: Disable automatic exit for short output
        less -S -R -+F "$output"
    else
        cat "$output"
        pause_menu
    fi

    rm -f "$output"
}

# ============================================================
# HOST INFORMATION
# ============================================================

host_info() {
    detect_backend

    echo "Hostname : $(hostname)"
    echo "OS       : $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "Firewall : $BACKEND"
    echo "Scope    : IPv4 only"
}

# ============================================================
# OPTION 1 - ASSESS CURRENT FIREWALL
# ============================================================

assess_firewall() {
    heading "FW01 CURRENT FIREWALL ASSESSMENT"

    host_info

    echo
    echo "--- Current IPv4 Firewall Rules ---"

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)")
            echo
            echo "[IPv4 INPUT]"
            iptables -S INPUT
            ;;

        firewalld)
            echo
            echo "[Active Zones]"
            firewall-cmd --get-active-zones

            echo
            echo "[Zone Configurations]"

            while IFS= read -r zone; do
                [[ -n "$zone" ]] || continue

                echo
                echo "Zone: $zone"
                firewall-cmd --zone="$zone" --list-all

            done < <(
                firewall-cmd --get-active-zones |
                awk '/^[^[:space:]]/ {print $1}'
            )
            ;;

        ufw)
            ufw status verbose
            ;;

        nftables)
            nft -4 list ruleset
            ;;

        *)
            echo "Unsupported firewall backend."
            ;;
    esac

    echo
    echo "--- Listening IPv4 Services ---"
    ss -4 -tuln
}

# ============================================================
# SERVICE PROFILES
# ============================================================

choose_profiles() {
    echo
    echo "Available profiles:"
    echo
    echo " webserver : TCP 80,443"
    echo " mail      : TCP 25,465,587,110,995,143,993"
    echo " splunk    : TCP 8000,8089,9997"
    echo " dnsntp    : TCP 53 / UDP 53,123"
    echo " wrkstn    : No additional inbound ports"
    echo
    echo "Combine profiles using commas."
    echo "Example: mail,webserver"
    echo
    echo "Enter 'q' to return to the main menu."
    echo

    local answer
    read_input answer "Profiles: "

    case "${answer,,}" in
        q)
            info "Returning to main menu."
            return 1
            ;;
        exit)
            exit_script
            ;;
    esac

    PROFILES="${answer// /}"
    PROFILES="${PROFILES,,}"

    [[ -n "$PROFILES" ]] || {
        error "No profile selected."
        return 1
    }

    TCP_PORTS=()
    UDP_PORTS=()

    local profile
    local -a selected

    IFS=',' read -r -a selected <<< "$PROFILES"

    for profile in "${selected[@]}"; do
        case "$profile" in
            webserver)
                TCP_PORTS+=(80 443)
                ;;
            mail)
                TCP_PORTS+=(25 465 587 110 995 143 993)
                ;;
            splunk)
                TCP_PORTS+=(8000 8089 9997)
                ;;
            dnsntp)
                TCP_PORTS+=(53)
                UDP_PORTS+=(53 123)
                ;;
            wrkstn)
                ;;
            *)
                error "Unknown profile: $profile"
                return 1
                ;;
        esac
    done

    # Remove duplicate ports.
    if ((${#TCP_PORTS[@]})); then
        mapfile -t TCP_PORTS < <(
            printf '%s\n' "${TCP_PORTS[@]}" | sort -nu
        )
    fi

    if ((${#UDP_PORTS[@]})); then
        mapfile -t UDP_PORTS < <(
            printf '%s\n' "${UDP_PORTS[@]}" | sort -nu
        )
    fi
}

# ============================================================
# IPTABLES - DIRECT IPv4 INPUT RULES
# ============================================================

apply_iptables() {
    local port

    # Set permissive policy before rebuilding rules.
    iptables -P INPUT ACCEPT

    # Remove existing IPv4 INPUT rules.
    iptables -F INPUT

    # Allow loopback traffic.
    iptables -A INPUT -i lo -j ACCEPT

    # Allow established and related connections.
    iptables -A INPUT -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Explicitly block new inbound SSH on TCP 22.
    iptables -A INPUT -p tcp \
        --dport 22 -j DROP

    # Allow selected TCP ports.
    for port in "${TCP_PORTS[@]}"; do
        iptables -A INPUT -p tcp \
            --dport "$port" -j ACCEPT
    done

    # Allow selected UDP ports.
    for port in "${UDP_PORTS[@]}"; do
        iptables -A INPUT -p udp \
            --dport "$port" -j ACCEPT
    done

    # Allow IPv4 ICMP.
    iptables -A INPUT -p icmp -j ACCEPT

    # Default deny for remaining inbound IPv4 traffic.
    iptables -P INPUT DROP

    info "IPv4 INPUT firewall rules applied."
}

# ============================================================
# FIREWALLD - ACTIVE ZONES
# ============================================================

apply_firewalld() {
    local zone port
    local -a zones=()

    mapfile -t zones < <(
        firewall-cmd --get-active-zones |
        awk '/^[^[:space:]]/ {print $1}'
    )

    if ((${#zones[@]} == 0)); then
        error "No active firewalld zones found."
        return 1
    fi

    for zone in "${zones[@]}"; do
        info "Configuring zone: $zone"

        # Remove standard SSH service allowance.
        firewall-cmd --zone="$zone" \
            --remove-service=ssh 2>/dev/null || true

        # Remove explicit TCP 22 allowance.
        firewall-cmd --zone="$zone" \
            --remove-port=22/tcp 2>/dev/null || true

        # Allow required TCP ports.
        for port in "${TCP_PORTS[@]}"; do
            firewall-cmd --zone="$zone" \
                --add-port="$port/tcp"
        done

        # Allow required UDP ports.
        for port in "${UDP_PORTS[@]}"; do
            firewall-cmd --zone="$zone" \
                --add-port="$port/udp"
        done

        # Block IPv4 SSH explicitly.
        firewall-cmd --zone="$zone" \
            --add-rich-rule='rule family="ipv4" port port="22" protocol="tcp" drop'
    done

    info "firewalld runtime rules updated."
    warn "Existing non-SSH allowances remain unchanged."
}

# ============================================================
# OPTION 2 - APPLY HARDENING
# ============================================================

apply_hardening() {
    detect_backend

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)"|firewalld)
            ;;
        *)
            error "Automatic enforcement unsupported for $BACKEND."
            return
            ;;
    esac

    choose_profiles || return

    heading "FW01 IPv4 FIREWALL HARDENING PLAN"

    echo "Hostname : $(hostname)"
    echo "Firewall : $BACKEND"
    echo "Profiles : $PROFILES"
    echo
    echo "Required inbound TCP: ${TCP_PORTS[*]:-None}"
    echo "Required inbound UDP: ${UDP_PORTS[*]:-None}"
    echo
    echo "Planned controls:"
    echo " - Allow loopback traffic"
    echo " - Allow established/related connections"
    echo " - Block inbound SSH (TCP 22)"
    echo " - Allow required service ports"
    echo " - Restrict unnecessary inbound IPv4 traffic"
    echo " - Preserve outbound firewall policy"
    echo
    echo "IPv6 is outside the scope of this script."
    echo
    warn "Active IPv4 firewall rules will change."
    warn "Use direct VM console access."
    echo

    local confirm
    read_input confirm "Type APPLY to continue (q = menu): "

    case "${confirm,,}" in
        q)
            info "Returning to main menu."
            return
            ;;
        exit)
            exit_script
            ;;
    esac

    if [[ "$confirm" != "APPLY" ]]; then
        info "Hardening cancelled."
        return
    fi

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)")
            apply_iptables
            ;;
        firewalld)
            apply_firewalld
            ;;
    esac

    echo
    info "Use Option 3 to verify the configuration."
}

# ============================================================
# OPTION 3 - VERIFICATION AND EVIDENCE
# ============================================================

verify_firewall() {
    heading "FW01 IPv4 FIREWALL VERIFICATION"

    host_info

    echo
    echo "Selected Profile: ${PROFILES:-Not selected in this session}"

    echo
    echo "--- Applied IPv4 Firewall Rules ---"

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)")
            echo
            echo "[IPv4 INPUT]"
            iptables -S INPUT
            ;;

        firewalld)
            echo
            echo "[Active Zones]"
            firewall-cmd --get-active-zones

            while IFS= read -r zone; do
                [[ -n "$zone" ]] || continue

                echo
                echo "[Zone: $zone]"
                firewall-cmd --zone="$zone" --list-all

            done < <(
                firewall-cmd --get-active-zones |
                awk '/^[^[:space:]]/ {print $1}'
            )
            ;;

        ufw)
            ufw status verbose
            ;;

        nftables)
            nft -4 list ruleset
            ;;

        *)
            echo "Unsupported verification backend."
            ;;
    esac

    echo
    echo "----------------------------------------"
    echo "IPv4 firewall rules displayed for review."
    echo "External connectivity testing is required"
    echo "to confirm allowed and blocked traffic."
    echo "----------------------------------------"
}

# ============================================================
# MAIN MENU
# ============================================================

main() {
    need_root

    while true; do
        clear
        detect_backend

        echo "========================================"
        echo "      MWCCDC FIREWALL ASSESSMENT"
        echo "========================================"
        echo
        echo "Hostname : $(hostname)"
        echo "Firewall : $BACKEND"
        echo "Scope    : IPv4 only"
        echo
        echo "1) Assess current firewall rules"
        echo "2) Generate and apply hardening plan"
        echo "3) Verify firewall and display evidence"
        echo "4) Exit"
        echo
        echo "Enter '4', 'q', or 'exit' to quit."
        echo

        local choice
        read_input choice "Select option: "

        case "${choice,,}" in
            1)
                show_scrollable assess_firewall
                ;;
            2)
                apply_hardening
                pause_menu
                ;;
            3)
                show_scrollable verify_firewall
                ;;
            4|q|exit)
                exit_script
                ;;
            *)
                error "Invalid selection."
                pause_menu
                ;;
        esac
    done
}

main "$@"
