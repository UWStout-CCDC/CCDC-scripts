#!/bin/bash

set -euo pipefail

# --- Set Colors ----------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

# --- Ensure Run as Root --------------------------------------------
if (( EUID != 0 )); then
    echo "Error: This script must be run as root or with sudo." >&2
    exit 1
fi

# --- Log Hardening Script -------------------------------------------
LOG_FILE="/var/log/harden_jumpbox_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
info "Logging to $LOG_FILE"

# --- Package Installer Func -----------------------------------------
install_packages() {
    local retries=3
    for ((i=1; i<=retries; i++)); do
        if apt-get install -y "$@"; then
            return 0
        fi
        warn "Install attempt $i/$retries failed, retrying..."
        sleep 2
    done
    error "Failed to install packages after $retries attempts: $*"
    return 1
}

# --- Create Backup --------------------------------------------------
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "${file}.bak.$(date +%Y%m%d_%H%M%S)"
        info "Backed up $file"
    fi
}

main () {
    info "Starting jumpbox hardening"

    # Change user passwords
    read -rp "Enter your main workstation username: " wrkstn_username
    if ! id "$wrkstn_username" &>/dev/null; then
        error "User '$wrkstn_username' does not exist."
        exit 1
    fi

    read -rsp "Enter a new password for $wrkstn_username: " wrkstn_password; echo
    read -rsp "Confirm password for $wrkstn_username: " wrkstn_password_confirm; echo
    if [[ "$wrkstn_password" != "$wrkstn_password_confirm" ]]; then
        error "Passwords do not match."; exit 1
    fi
    echo "$wrkstn_username:$wrkstn_password" | chpasswd
    info "Password changed for $wrkstn_username"

    # Change root password
    read -rsp "Enter a new root password: " root_password; echo
    read -rsp "Confirm root password: " root_password_confirm; echo
    if [[ "$root_password" != "$root_password_confirm" ]]; then
        error "Passwords do not match."; exit 1
    fi
    echo "root:$root_password" | chpasswd
    info "Password changed for root"

    # Clear password variables from memory
    unset wrkstn_password wrkstn_password_confirm root_password root_password_confirm

    info "Disabling non-essential user accounts"
    declare -A PRESERVE_USERS=( ["root"]=1 ["$wrkstn_username"]=1 ["nobody"]=1 )

    while IFS=: read -r username _ uid _ _ _ shell; do
        if [[ $uid -ge 1000 ]] && [[ -z "${PRESERVE_USERS[$username]+_}" ]]; then
            info "Disabling login and locking account: $username (shell: $shell)"
            usermod -s /usr/sbin/nologin "$username"
            passwd -l "$username"   # Lock the password too
        fi
    done < /etc/passwd

    # Update packages
    apt-get update -y

    # Make backup dir
    mkdir -p /opt/snap/packages/

    # Clone down packages and install packages
    info "Installing essential packages"
    install_packages \
        git wget curl \
        auditd audispd-plugins \
        apt-listchanges \
        rkhunter \
        acl \
        apparmor apparmor-utils

    wget -P /opt/snap/packages/ https://github.com/UWStout-CCDC/CCDC-scripts/blob/master/firewall/host_firewall/nftbuild
    chmod +x /opt/snap/packages/nftbuild
    ./nftbuild -sys wrkstn -ssh

    # Setup Auditd
    info "Setting up auditd"
    if wget -q -O /opt/snap/packages/audit.rules \
        "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/CustomAudit.rules" 2>/dev/null; then
        backup_file /etc/audit/audit.rules
        cp /opt/snap/packages/audit.rules /etc/audit/audit.rules
    else
        warn "Could not download custom audit rules — using defaults"
    fi
    systemctl enable --now auditd
    info "Auditd enabled"

    # Run Palo alto Ansible
    # cd /opt/snap/packages/Firewall-Automation/
    # echo "Enter the palo alto API key:"
    # read palo_api
    # # Replace 'old_string' with the variable value
    # sed -i "s/{{ palo_api_key }}/$palo_api/g" "/opt/snap/packages/Firewall-Automation/group_vars/palo.yml"
    # python3 -m venv venv
    # source venv/bin/activate
    # pip install ansible
    # ansible-galaxy collection install -r requirements.yml
    # ansible-playbook playbook.yml

    # Kernel Hardening
    info "Applying sysctl hardening"
    cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# ── Network hardening ──
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ── Kernel hardening ──
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
fs.suid_dumpable = 0
EOF
    sysctl --system > /dev/null 2>&1
    info "Sysctl hardening applied"

    # Set File perms
    info "Hardening sensitive file permissions"
    chmod 600 /etc/shadow /etc/gshadow
    chmod 644 /etc/passwd /etc/group
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

    # Restrict cron
    if [[ ! -f /etc/cron.allow ]]; then
        echo "root" > /etc/cron.allow
        echo "$wrkstn_username" >> /etc/cron.allow
        chmod 600 /etc/cron.allow
    fi
    [[ -f /etc/cron.deny ]] && rm -f /etc/cron.deny

    # Disable Unused services
    info "Disabling unnecessary services"
    DISABLE_SERVICES=(
        avahi-daemon
        cups
        bluetooth
        rpcbind
        telnet
        vsftpd
    )
    for svc in "${DISABLE_SERVICES[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            systemctl disable --now "$svc" && info "Disabled $svc"
        fi
    done

    # Remove unnessary packages
    info "Removing unnecessary packages"
    REMOVE_PACKAGES=(
        perl
        telnet
        rsh-client
        rsh-redone-client
        talk
        inetutils-telnet
    )
    for pkg in "${REMOVE_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            apt-get purge -y "$pkg"
        fi
    done
    apt-get autoremove --purge -y

    # AppArmor
    info "Ensuring AppArmor is active"
    systemctl enable --now apparmor
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true

    # Use rkhunter
    info "Updating rkhunter database"
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true

    # Upgrade All other packages
    info "Upgrading All Packages"
    apt upgrade -y

    echo ""
    info "============================================"
    info "  Hardening complete — summary of actions"
    info "============================================"
    info "  - User passwords changed"
    info "  - Non-essential accounts locked"
    info "  - Firewall configured"
    info "  - Auditd enabled"
    info "  - Kernel / network sysctl hardening applied"
    info "  - Sensitive file permissions tightened"
    info "  - Unnecessary services disabled"
    info "  - Unnecessary packages removed"
    info "  - AppArmor enforced"
    info "  - rkhunter initialized"
    info "============================================"
    warn "Log saved to: $LOG_FILE"
    warn ""
    warn "Please reboot to apply all changes."
}

# Run main method
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi