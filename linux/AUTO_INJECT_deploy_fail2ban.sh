#!/usr/bin/env bash
# deploy_fail2ban.sh — Interactive fail2ban deployment for Ubuntu, Debian, CentOS, Fedora
# Run as root: sudo bash deploy_fail2ban.sh

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERR ]${RESET}  $*" >&2; }
die()       { log_error "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root (use: sudo bash $0)"

# ─── Global state ─────────────────────────────────────────────────────────────
OS_FAMILY=""
OS_VERSION_MAJOR=0
PKG_MGR=""

declare -a CONFIGURED_JAILS=()
declare -A JAIL_CONFIGS

JAIL_CONF_FILE="/etc/fail2ban/jail.d/ccdc-custom.conf"
SERVICES_ENABLED=()

# ─── 1. OS Detection ──────────────────────────────────────────────────────────
detect_os() {
    echo
    echo -e "${BOLD}━━━ Step 1: Detecting OS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    [[ -f /etc/os-release ]] || die "/etc/os-release not found."
    # shellcheck source=/dev/null
    source /etc/os-release

    local ver_id="${VERSION_ID:-0}"
    OS_VERSION_MAJOR="${ver_id%%.*}"

    case "${ID,,}" in
        ubuntu)
            OS_FAMILY="ubuntu"; PKG_MGR="apt"
            ;;
        debian)
            OS_FAMILY="debian"; PKG_MGR="apt"
            ;;
        centos|rhel|rocky|almalinux)
            OS_FAMILY="centos"
            [[ "$OS_VERSION_MAJOR" -ge 8 ]] && PKG_MGR="dnf" || PKG_MGR="yum"
            ;;
        fedora)
            OS_FAMILY="fedora"; PKG_MGR="dnf"
            ;;
        *)
            log_warn "Unknown OS '${ID}' — attempting auto-detection."
            if   command -v dnf    &>/dev/null; then PKG_MGR="dnf"; OS_FAMILY="fedora"
            elif command -v yum    &>/dev/null; then PKG_MGR="yum"; OS_FAMILY="centos"
            elif command -v apt-get &>/dev/null; then PKG_MGR="apt"; OS_FAMILY="debian"
            else die "No supported package manager found."
            fi
            ;;
    esac

    log_ok "OS: ${PRETTY_NAME:-$ID $OS_VERSION_MAJOR} | Package manager: $PKG_MGR"
}

# ─── 2. Install fail2ban ──────────────────────────────────────────────────────
install_fail2ban() {
    echo
    echo -e "${BOLD}━━━ Step 2: Installing fail2ban ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    if command -v fail2ban-client &>/dev/null; then
        log_ok "Already installed: $(fail2ban-client version 2>/dev/null | head -1)"
        return
    fi

    case "$PKG_MGR" in
        apt)
            log_info "Updating apt cache…"
            apt-get update -qq
            log_info "Installing fail2ban…"
            DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
            ;;
        yum)
            if ! rpm -q epel-release &>/dev/null; then
                log_info "Installing EPEL repository…"
                yum install -y epel-release
            fi
            log_info "Installing fail2ban…"
            yum install -y fail2ban fail2ban-systemd
            ;;
        dnf)
            if [[ "$OS_FAMILY" == "centos" ]] && ! rpm -q epel-release &>/dev/null; then
                log_info "Installing EPEL repository…"
                dnf install -y epel-release
                # Enable CRB/PowerTools for dependencies
                dnf config-manager --set-enabled crb       2>/dev/null || \
                dnf config-manager --set-enabled powertools 2>/dev/null || true
            fi
            log_info "Installing fail2ban…"
            dnf install -y fail2ban fail2ban-systemd 2>/dev/null || dnf install -y fail2ban
            ;;
    esac

    command -v fail2ban-client &>/dev/null || die "Installation failed."
    log_ok "Installed: $(fail2ban-client version 2>/dev/null | head -1)"
}

# ─── Timing helpers ───────────────────────────────────────────────────────────
_prompt_bantime() {
    local default="${1:-1h}"
    echo -e "\n  ${BOLD}Ban duration:${RESET}"
    echo -e "    1) 10 minutes    2) 1 hour (rec)  3) 12 hours"
    echo -e "    4) 24 hours      5) 1 week         6) Permanent (-1)"
    echo -e "    7) Custom"
    local choice
    while true; do
        read -rp "  Choice [1-7, default=${default}]: " choice
        case "$choice" in
            1) printf "10m"; return ;;
            2) printf "1h";  return ;;
            3) printf "12h"; return ;;
            4) printf "24h"; return ;;
            5) printf "1w";  return ;;
            6) printf "%s" "-1"; return ;;
            7)
                local v
                read -rp "  Custom bantime (e.g. 30m, 2h, 3d): " v
                printf "%s" "$v"; return
                ;;
            "") printf "%s" "$default"; return ;;
            *)  log_warn "Enter 1-7." ;;
        esac
    done
}

_prompt_maxretry() {
    local default="${1:-5}"
    echo -e "\n  ${BOLD}Max failures before ban:${RESET}"
    echo -e "    1) 3 (strict)   2) 5 (default)   3) 10 (lenient)   4) Custom"
    local choice
    while true; do
        read -rp "  Choice [1-4, default=${default}]: " choice
        case "$choice" in
            1) printf "3";  return ;;
            2) printf "5";  return ;;
            3) printf "10"; return ;;
            4)
                local v
                read -rp "  Custom maxretry: " v
                printf "%s" "$v"; return
                ;;
            "") printf "%s" "$default"; return ;;
            *)  log_warn "Enter 1-4." ;;
        esac
    done
}

_prompt_findtime() {
    local default="${1:-10m}"
    echo -e "\n  ${BOLD}Detection window (failures within this window = ban):${RESET}"
    echo -e "    1) 5 minutes    2) 10 minutes (rec)   3) 30 minutes"
    echo -e "    4) 1 hour       5) Custom"
    local choice
    while true; do
        read -rp "  Choice [1-5, default=${default}]: " choice
        case "$choice" in
            1) printf "5m";  return ;;
            2) printf "10m"; return ;;
            3) printf "30m"; return ;;
            4) printf "1h";  return ;;
            5)
                local v
                read -rp "  Custom findtime (e.g. 15m, 2h): " v
                printf "%s" "$v"; return
                ;;
            "") printf "%s" "$default"; return ;;
            *)  log_warn "Enter 1-5." ;;
        esac
    done
}

_add_jail() {
    local name="$1"
    local content="$2"
    JAIL_CONFIGS["$name"]="$content"
    CONFIGURED_JAILS+=("$name")
    log_ok "Jail queued: ${BOLD}${name}${RESET}"
}

# ─── 3. Service Selection Menu ────────────────────────────────────────────────
select_services() {
    echo
    echo -e "${BOLD}━━━ Step 3: Select Services to Protect ━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "  Toggle with a number, ${BOLD}A${RESET} to select all, ${BOLD}D${RESET} when done."
    echo

    local -a svc_keys=("ssh" "apache" "opencart" "dovecot" "postfix" "splunk")
    local -a svc_labels=("SSH" "Apache" "OpenCart" "Dovecot" "Postfix" "Splunk")
    local -a enabled=(0 0 0 0 0 0)

    while true; do
        echo -e "  ${BOLD}Services:${RESET}"
        local i
        for i in "${!svc_keys[@]}"; do
            local tag
            if [[ "${enabled[$i]}" -eq 1 ]]; then
                tag="${GREEN}[ENABLED] ${RESET}"
            else
                tag="${RED}[DISABLED]${RESET}"
            fi
            printf "    %d) %-12s  %b\n" "$((i+1))" "${svc_labels[$i]}" "$tag"
        done
        echo -e "    A) Select all    D) Done"
        echo

        local inp
        read -rp "  [1-6 / A / D]: " inp
        inp="${inp,,}"

        case "$inp" in
            d) break ;;
            a)
                for i in "${!enabled[@]}"; do enabled[$i]=1; done
                ;;
            [1-6])
                local idx=$((inp - 1))
                if [[ "${enabled[$idx]}" -eq 1 ]]; then
                    enabled[$idx]=0
                else
                    enabled[$idx]=1
                fi
                ;;
            *) log_warn "Enter a number 1-6, A, or D." ;;
        esac
        echo
    done

    for i in "${!svc_keys[@]}"; do
        [[ "${enabled[$i]}" -eq 1 ]] && SERVICES_ENABLED+=("${svc_keys[$i]}")
    done

    if [[ ${#SERVICES_ENABLED[@]} -eq 0 ]]; then
        die "No services selected."
    fi

    echo
    log_ok "Selected: ${SERVICES_ENABLED[*]}"
}

# ─── Service: SSH ─────────────────────────────────────────────────────────────
configure_ssh() {
    echo
    echo -e "  ${BOLD}── SSH ─────────────────────────────────────────────────────────${RESET}"
    echo -e "    Available SSH jail options:"
    echo -e "      1) sshd       — Standard SSH daemon protection"
    echo -e "      2) sshd-ddos  — High-rate DDoS detection (aggressive thresholds)"
    echo -e "      3) Both"
    echo

    local choice
    read -rp "    Selection [1-3, default=1]: " choice
    [[ -z "$choice" ]] && choice="1"

    local ssh_port
    read -rp "    SSH port [default: 22]: " ssh_port
    [[ -z "$ssh_port" ]] && ssh_port="22"

    if [[ "$choice" == "1" || "$choice" == "3" ]]; then
        echo -e "\n    ${BOLD}sshd jail settings:${RESET}"
        local bt mr ft
        bt=$(_prompt_bantime  "1h")
        mr=$(_prompt_maxretry "5")
        ft=$(_prompt_findtime "10m")
        _add_jail "sshd" "[sshd]
enabled  = true
port     = ${ssh_port}
filter   = sshd
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi

    if [[ "$choice" == "2" || "$choice" == "3" ]]; then
        echo -e "\n    ${BOLD}sshd-ddos jail settings:${RESET}"
        local bt mr ft
        bt=$(_prompt_bantime  "10m")
        mr=$(_prompt_maxretry "10")
        ft=$(_prompt_findtime "5m")
        _add_jail "sshd-ddos" "[sshd-ddos]
enabled  = true
port     = ${ssh_port}
filter   = sshd
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi
}

# ─── Service: Apache ──────────────────────────────────────────────────────────
configure_apache() {
    echo
    echo -e "  ${BOLD}── Apache ──────────────────────────────────────────────────────${RESET}"
    echo -e "    Available Apache jail options:"
    echo -e "      1) apache-auth       — HTTP authentication failures"
    echo -e "      2) apache-badbots    — Known malicious crawler/bot signatures"
    echo -e "      3) apache-noscript   — PHP/CGI script injection attempts"
    echo -e "      4) apache-overflows  — Buffer overflow exploit attempts"
    echo -e "      5) apache-shellshock — Shellshock (CVE-2014-6271) exploit attempts"
    echo -e "      A) All of the above"
    echo -e ""
    echo -e "    Enter numbers separated by spaces (e.g. \"1 2\") or A for all:"
    echo

    local input
    read -rp "    Selection [default=1]: " input
    [[ -z "$input" ]] && input="1"
    [[ "${input,,}" == "a" ]] && input="1 2 3 4 5"

    # Detect Apache error/access log paths
    local err_log acc_log
    if [[ -d /var/log/apache2 ]]; then
        err_log="/var/log/apache2/error.log"
        acc_log="/var/log/apache2/access.log"
    elif [[ -d /var/log/httpd ]]; then
        err_log="/var/log/httpd/error_log"
        acc_log="/var/log/httpd/access_log"
    else
        read -rp "    Apache error log path: " err_log
        read -rp "    Apache access log path: " acc_log
    fi
    log_info "Apache logs: error=$err_log  access=$acc_log"

    echo -e "\n    ${BOLD}Shared timing settings for all selected Apache jails:${RESET}"
    local bt mr ft
    bt=$(_prompt_bantime  "1h")
    mr=$(_prompt_maxretry "5")
    ft=$(_prompt_findtime "10m")

    local choices
    read -ra choices <<< "$input"
    for c in "${choices[@]}"; do
        case "$c" in
            1) _add_jail "apache-auth" "[apache-auth]
enabled  = true
filter   = apache-auth
logpath  = ${err_log}
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
            ;;
            2) _add_jail "apache-badbots" "[apache-badbots]
enabled  = true
filter   = apache-badbots
logpath  = ${acc_log}
maxretry = 1
bantime  = ${bt}
findtime = ${ft}"
            ;;
            3) _add_jail "apache-noscript" "[apache-noscript]
enabled  = true
filter   = apache-noscript
logpath  = ${err_log}
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
            ;;
            4) _add_jail "apache-overflows" "[apache-overflows]
enabled  = true
filter   = apache-overflows
logpath  = ${err_log}
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
            ;;
            5) _add_jail "apache-shellshock" "[apache-shellshock]
enabled  = true
filter   = apache-shellshock
logpath  = ${err_log}
maxretry = 1
bantime  = ${bt}
findtime = ${ft}"
            ;;
            *) log_warn "Unknown option '$c' — skipped." ;;
        esac
    done
}

# ─── Service: OpenCart ────────────────────────────────────────────────────────
configure_opencart() {
    echo
    echo -e "  ${BOLD}── OpenCart ────────────────────────────────────────────────────${RESET}"
    echo -e "    Custom fail2ban filters will be written to /etc/fail2ban/filter.d/"
    echo
    echo -e "    Available OpenCart protection options:"
    echo -e "      1) opencart-admin  — Admin panel brute-force (POST /admin/)"
    echo -e "      2) opencart-login  — Customer login brute-force (?route=account/login)"
    echo -e "      3) Both"
    echo

    local choice
    read -rp "    Selection [1-3, default=3]: " choice
    [[ -z "$choice" ]] && choice="3"

    # Detect web server access log
    local acc_log
    if   [[ -f /var/log/apache2/access.log ]];  then acc_log="/var/log/apache2/access.log"
    elif [[ -f /var/log/httpd/access_log ]];     then acc_log="/var/log/httpd/access_log"
    elif [[ -f /var/log/nginx/access.log ]];     then acc_log="/var/log/nginx/access.log"
    else acc_log="/var/log/apache2/access.log"
    fi
    read -rp "    Web server access log [${acc_log}]: " custom
    [[ -n "$custom" ]] && acc_log="$custom"
    log_info "Access log: $acc_log"

    echo -e "\n    ${BOLD}Timing settings for OpenCart jails:${RESET}"
    local bt mr ft
    bt=$(_prompt_bantime  "1h")
    mr=$(_prompt_maxretry "5")
    ft=$(_prompt_findtime "10m")

    if [[ "$choice" == "1" || "$choice" == "3" ]]; then
        cat > /etc/fail2ban/filter.d/opencart-admin.conf << 'FILTER'
[Definition]
# Brute-force attempts on the OpenCart admin panel
failregex = ^<HOST> .* "POST /.*admin[/]?(index\.php)?.* HTTP.*" \d{3} .*$
ignoreregex =
FILTER
        log_ok "Filter written: /etc/fail2ban/filter.d/opencart-admin.conf"
        _add_jail "opencart-admin" "[opencart-admin]
enabled  = true
filter   = opencart-admin
logpath  = ${acc_log}
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi

    if [[ "$choice" == "2" || "$choice" == "3" ]]; then
        cat > /etc/fail2ban/filter.d/opencart-login.conf << 'FILTER'
[Definition]
# Brute-force attempts on the OpenCart customer login
failregex = ^<HOST> .* "POST /index\.php\?route=account/login.* HTTP.*" \d{3} .*$
            ^<HOST> .* "POST /.*login.* HTTP.*" \d{3} .*$
ignoreregex =
FILTER
        log_ok "Filter written: /etc/fail2ban/filter.d/opencart-login.conf"
        _add_jail "opencart-login" "[opencart-login]
enabled  = true
filter   = opencart-login
logpath  = ${acc_log}
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi
}

# ─── Service: Dovecot ─────────────────────────────────────────────────────────
configure_dovecot() {
    echo
    echo -e "  ${BOLD}── Dovecot ─────────────────────────────────────────────────────${RESET}"
    echo -e "    Available Dovecot jail options:"
    echo -e "      1) dovecot       — All auth failures (IMAP, POP3, LMTP)"
    echo -e "      2) dovecot-pop3d — POP3-specific authentication failures"
    echo -e "      3) Both"
    echo

    local choice
    read -rp "    Selection [1-3, default=1]: " choice
    [[ -z "$choice" ]] && choice="1"

    echo -e "\n    ${BOLD}Timing settings for Dovecot jails:${RESET}"
    local bt mr ft
    bt=$(_prompt_bantime  "1h")
    mr=$(_prompt_maxretry "5")
    ft=$(_prompt_findtime "10m")

    if [[ "$choice" == "1" || "$choice" == "3" ]]; then
        _add_jail "dovecot" "[dovecot]
enabled  = true
filter   = dovecot
logpath  = %(dovecot_log)s
backend  = %(dovecot_backend)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi

    if [[ "$choice" == "2" || "$choice" == "3" ]]; then
        _add_jail "dovecot-pop3d" "[dovecot-pop3d]
enabled  = true
filter   = dovecot
port     = pop3,pop3s
logpath  = %(dovecot_log)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi
}

# ─── Service: Postfix ─────────────────────────────────────────────────────────
configure_postfix() {
    echo
    echo -e "  ${BOLD}── Postfix ─────────────────────────────────────────────────────${RESET}"
    echo -e "    Available Postfix jail options:"
    echo -e "      1) postfix       — General delivery/relay failures"
    echo -e "      2) postfix-sasl  — SASL authentication failures"
    echo -e "      3) postfix-rbl   — DNS real-time blacklist violations"
    echo -e "      A) All of the above"
    echo -e ""
    echo -e "    Enter numbers separated by spaces or A for all:"
    echo

    local input
    read -rp "    Selection [default=1 2]: " input
    [[ -z "$input" ]] && input="1 2"
    [[ "${input,,}" == "a" ]] && input="1 2 3"

    echo -e "\n    ${BOLD}Shared timing settings for all selected Postfix jails:${RESET}"
    local bt mr ft
    bt=$(_prompt_bantime  "1h")
    mr=$(_prompt_maxretry "5")
    ft=$(_prompt_findtime "10m")

    local choices
    read -ra choices <<< "$input"
    for c in "${choices[@]}"; do
        case "$c" in
            1) _add_jail "postfix" "[postfix]
enabled  = true
filter   = postfix
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
            ;;
            2) _add_jail "postfix-sasl" "[postfix-sasl]
enabled  = true
filter   = postfix-sasl
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
            ;;
            3) _add_jail "postfix-rbl" "[postfix-rbl]
enabled  = true
filter   = postfix-rbl
logpath  = %(postfix_log)s
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
            ;;
            *) log_warn "Unknown option '$c' — skipped." ;;
        esac
    done
}

# ─── Service: Splunk ──────────────────────────────────────────────────────────
configure_splunk() {
    echo
    echo -e "  ${BOLD}── Splunk ──────────────────────────────────────────────────────${RESET}"
    echo -e "    Custom fail2ban filters will be written to /etc/fail2ban/filter.d/"
    echo
    echo -e "    Available Splunk protection options:"
    echo -e "      1) splunk-web  — Web UI login brute-force (:8000)"
    echo -e "      2) splunk-api  — REST API authentication failures (:8089)"
    echo -e "      3) Both"
    echo

    local choice
    read -rp "    Selection [1-3, default=3]: " choice
    [[ -z "$choice" ]] && choice="3"

    local splunk_log_dir="/opt/splunk/var/log/splunk"
    read -rp "    Splunk log directory [${splunk_log_dir}]: " custom
    [[ -n "$custom" ]] && splunk_log_dir="$custom"
    log_info "Splunk log dir: $splunk_log_dir"

    echo -e "\n    ${BOLD}Timing settings for Splunk jails:${RESET}"
    local bt mr ft
    bt=$(_prompt_bantime  "1h")
    mr=$(_prompt_maxretry "5")
    ft=$(_prompt_findtime "10m")

    if [[ "$choice" == "1" || "$choice" == "3" ]]; then
        cat > /etc/fail2ban/filter.d/splunk-web.conf << 'FILTER'
[Definition]
# Failed Splunk Web UI authentication (splunkd.log)
failregex = .*- - - \[.*\] "POST /en-US/account/login HTTP.* 200.*
            .*AuditLogger.*action=login.*status=failure.*clientip=<HOST>
            .*Invalid username or password.*
ignoreregex =
FILTER
        log_ok "Filter written: /etc/fail2ban/filter.d/splunk-web.conf"
        _add_jail "splunk-web" "[splunk-web]
enabled  = true
filter   = splunk-web
logpath  = ${splunk_log_dir}/splunkd.log
           ${splunk_log_dir}/web_access.log
port     = 8000
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi

    if [[ "$choice" == "2" || "$choice" == "3" ]]; then
        cat > /etc/fail2ban/filter.d/splunk-api.conf << 'FILTER'
[Definition]
# Failed Splunk REST API authentication
failregex = .*AuditLogger.*action=login.*status=failure.*clientip=<HOST>
            .*Failed password.*<HOST>
            .*Unauthorized.*<HOST>
ignoreregex =
FILTER
        log_ok "Filter written: /etc/fail2ban/filter.d/splunk-api.conf"
        _add_jail "splunk-api" "[splunk-api]
enabled  = true
filter   = splunk-api
logpath  = ${splunk_log_dir}/splunkd.log
port     = 8089
maxretry = ${mr}
bantime  = ${bt}
findtime = ${ft}"
    fi
}

# ─── 5. Write config and restart fail2ban ────────────────────────────────────
write_and_apply() {
    echo
    echo -e "${BOLD}━━━ Step 5: Writing Configuration & Starting fail2ban ━━━━━━━━━━${RESET}"
    echo

    mkdir -p /etc/fail2ban/jail.d

    {
        printf "# CCDC fail2ban configuration — generated %s\n" "$(date)"
        printf "# Re-run deploy_fail2ban.sh to regenerate\n\n"

        # Detect and set the correct banaction for the active firewall
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            printf "[DEFAULT]\nbanaction = firewallcmd-ipset\nbanaction_allports = firewallcmd-allports\n\n"
        elif command -v nft &>/dev/null && nft list ruleset &>/dev/null 2>&1; then
            printf "[DEFAULT]\nbanaction = nftables-multiport\nbanaction_allports = nftables-allports\n\n"
        else
            printf "[DEFAULT]\nbanaction = iptables-multiport\nbanaction_allports = iptables-allports\n\n"
        fi

        local jail
        for jail in "${CONFIGURED_JAILS[@]}"; do
            printf "%s\n\n" "${JAIL_CONFIGS[$jail]}"
        done
    } > "$JAIL_CONF_FILE"

    log_ok "Config written: $JAIL_CONF_FILE"

    log_info "Testing fail2ban configuration…"
    if fail2ban-client -t 2>&1 | grep -qi "error"; then
        log_warn "fail2ban config test reported issues — check $JAIL_CONF_FILE"
    else
        log_ok "Configuration test passed."
    fi

    log_info "Enabling fail2ban at boot…"
    systemctl enable fail2ban

    log_info "Restarting fail2ban…"
    systemctl restart fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        log_ok "fail2ban service is running."
    else
        log_error "fail2ban failed to start."
        log_warn "Run: journalctl -u fail2ban --no-pager -n 30"
    fi
}

# ─── 6. Status Report ─────────────────────────────────────────────────────────
status_report() {
    echo
    echo -e "${BOLD}━━━ Status Report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo

    local pass=0 fail=0

    _chk() {
        local label="$1" ok="$2"
        if [[ "$ok" == "1" ]]; then
            printf "  ${GREEN}✓${RESET}  %-50s ${GREEN}PASS${RESET}\n" "$label"
            pass=$((pass + 1))
        else
            printf "  ${RED}✗${RESET}  %-50s ${RED}FAIL${RESET}\n" "$label"
            fail=$((fail + 1))
        fi
    }

    # Service state checks
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        _chk "fail2ban service running" 1
    else
        _chk "fail2ban service running" 0
    fi

    if systemctl is-enabled --quiet fail2ban 2>/dev/null; then
        _chk "fail2ban enabled at boot" 1
    else
        _chk "fail2ban enabled at boot" 0
    fi

    if [[ -f "$JAIL_CONF_FILE" ]]; then
        _chk "Config file present  ($JAIL_CONF_FILE)" 1
    else
        _chk "Config file present  ($JAIL_CONF_FILE)" 0
    fi

    # Per-jail checks
    echo
    echo -e "  ${BOLD}Jail Status:${RESET}"
    printf "  %-32s  %-10s  %-16s  %s\n" "Jail" "Active" "Currently Banned" "Total Banned"
    echo -e "  ─────────────────────────────────────────────────────────────────────"

    local jail
    for jail in "${CONFIGURED_JAILS[@]}"; do
        local jail_status
        jail_status=$(fail2ban-client status "$jail" 2>/dev/null) && r=0 || r=1
        if [[ $r -eq 0 ]]; then
            local cur tot
            cur=$(printf "%s" "$jail_status" | grep "Currently banned:" | awk '{print $NF}')
            tot=$(printf "%s" "$jail_status" | grep "Total banned:"     | awk '{print $NF}')
            printf "  ${GREEN}✓${RESET}  %-30s  %-10s  %-16s  %s\n" \
                "[$jail]" "yes" "${cur:-0}" "${tot:-0}"
            pass=$((pass + 1))
        else
            printf "  ${RED}✗${RESET}  %-30s  %-10s\n" "[$jail]" "NO"
            fail=$((fail + 1))
        fi
    done

    echo
    echo -e "  ─────────────────────────────────────────────────────────────────────"
    echo -e "  ${BOLD}Summary${RESET}"
    echo -e "    fail2ban version  : $(fail2ban-client version 2>/dev/null | head -1)"
    echo -e "    Config file       : $JAIL_CONF_FILE"
    echo -e "    Jails configured  : ${#CONFIGURED_JAILS[@]}"
    echo -e "    Checks passed     : $pass"
    echo -e "    Checks failed     : $fail"
    echo

    if [[ $fail -eq 0 ]]; then
        echo -e "  ${BOLD}${GREEN}fail2ban deployment SUCCESSFUL${RESET}"
    else
        echo -e "  ${BOLD}${RED}fail2ban deployment FAILED${RESET} — see above"
        echo
        echo -e "  ${YELLOW}Troubleshooting tips:${RESET}"
        echo -e "    • journalctl -u fail2ban --no-pager -n 50"
        echo -e "    • fail2ban-client -t                  (test config syntax)"
        echo -e "    • fail2ban-client status              (list active jails)"
        echo -e "    • cat /var/log/fail2ban.log            (detailed log)"
        echo -e "    • Review filter regex patterns in /etc/fail2ban/filter.d/"
    fi
    echo
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║      fail2ban Deployment Script — CCDC Team              ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"

    detect_os
    install_fail2ban
    select_services

    echo
    echo -e "${BOLD}━━━ Step 4: Configure Each Service ━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    local svc
    for svc in "${SERVICES_ENABLED[@]}"; do
        case "$svc" in
            ssh)      configure_ssh      ;;
            apache)   configure_apache   ;;
            opencart) configure_opencart ;;
            dovecot)  configure_dovecot  ;;
            postfix)  configure_postfix  ;;
            splunk)   configure_splunk   ;;
        esac
    done

    echo
    echo -e "${BOLD}━━━ Configuration Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  Services  : ${SERVICES_ENABLED[*]}"
    echo -e "  Jails     : ${CONFIGURED_JAILS[*]}"
    echo -e "  Output    : $JAIL_CONF_FILE"
    echo

    local confirm
    read -rp "$(echo -e "${BOLD}Apply this configuration now? [y/n]:${RESET} ")" confirm
    [[ "${confirm,,}" =~ ^y ]] || { echo "Aborted."; exit 0; }

    write_and_apply
    status_report
}

main "$@"
