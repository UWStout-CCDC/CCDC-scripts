#!/bin/fish
#
#  _____ _             ____                      
# |  ___| | __ _  __ _|  _ \ _ __ ___  _ __   ||‾‾‾\ 
# | |_  | |/ _` |/ _` | | | | '__/ _ \| '_ \  ||___/
# |  _| | | (_| | (_| | |_| | | | (_) | |_) | ||
# |_|   |_|\__,_|\__, |____/|_|  \___/| .__/  ||    
#                |___/                |_|     ||     
#
# A CCDC Mail Setup Script That Smells Kind of Fishy

# Ensure it is run as root
if not fish_is_root_user
    echo >&2 "This script must be run as root (or with sudo)."
    exit 1
end

# Logging
# Log file
set -l LOG_TIME (date "+%Y%m%d-%H:%M:%S")
mkdir ~/script_logs
set -g LOG_FILE "$HOME/script_logs/flagdrop_$LOG_TIME.log"
echo "
  _____ _             ____                      
 |  ___| | __ _  __ _|  _ \ _ __ ___  _ __   ||‾‾‾\ 
 | |_  | |/ _` |/ _` | | | | '__/ _ \| '_ \  ||___/
 |  _| | | (_| | (_| | |_| | | | (_) | |_) | ||
 |_|   |_|\__,_|\__, |____/|_|  \___/| .__/  ||    
                |___/                |_|     ||     

A CCDC Mail Setup Script That Smells Kind of Fishy
Log $LOG_TIME
" >$LOG_FILE

# Color codes
set -l c_reset (set_color normal)
set -l c_time (set_color 555)
set -l c_info (set_color cyan)
set -l c_warn (set_color yellow)
set -l c_error (set_color red --bold)

# Custom log function
function log --argument level --description "Print formatted log messages"
    # Get current timestamp (Format: YYYY-MM-DD HH:MM:SS)
    set -l timestamp (date "+%Y-%m-%d %H:%M:%S")

    # Extract the message (everything after the first argument)
    set -l message $argv[2..-1]

    # Format output based on the log level
    switch $level
        case header
            set term_output "$c_reset
=======================================
  $message
======================================="
            echo $term_output | tee -a $LOG_FILE
        case info
            set term_output "[$c_time$timestamp$c_reset] [$c_info\INFO$c_reset]  $message"
            echo $term_output | tee -a $LOG_FILE
        case warn
            set term_output "[$c_time$timestamp$c_reset] [$c_warn\WARN$c_reset]  $message"
            echo $term_output | tee -a $LOG_FILE
        case error
            set term_output "[$c_time$timestamp$c_reset] [$c_error\ERROR$c_reset] $message"
            echo $file_output >>$LOG_FILE
            echo $term_output >&2
        case '*'
            # Fallback if no level is provided
            echo "[$c_time$timestamp$c_reset] $argv" | tee -a $LOG_FILE
    end
end

# Install pre-reqs
log header "Install Prerequisites"
log info "Installing..."
dnf install -y fish nyancat wget2-wget 2>/dev/null &

# Cron
set cron-dirs \
    /etc/cron.d/ \
    /etc/cron.hourly/ \
    /etc/cron.daily/ \
    /etc/cron.weekly/ \
    /etc/cron.monthly/ \
    /var/spool/cron
for dir in "$cron_dirs"
    for file in "$dir*"
        rm -rf $file
        log warn "Removed cron job: $dir$file"
    end
end

# Firewall
log header Firewall
# This just fetched the nftbuild firewall script and runs it for mail
echo "wget -O nftbuild.sh https://tinyurl.com/nftbuild && chmod +x nftbuild.sh && ./nftbuild.sh -sys mail" | fish &
if [ "$status" != 0 ]
    log error "nftbuild.sh: $status: Firewall script failed"
else
    log info "Firewall configuration successful"
end

# Exterminator
log header "Exterminate Malicious packages"
log info "Uninstalling packages..."
set mal_packs \
    sshd \
    openssh \
    xinetd \
    nfsutils \
    cockpit \
    nginx \
    apache2 \
    telnet-server \
    rsh-server \
    telnet \
    rsh \
    ypbind \
    ypserv \
    tftp-server \
    cronie-anacron \
    at \
    atq \
    bind \
    vsftpd \
    squid \
    net-snmpd \
    ttyd \
    snapd

set error_count 0
for package in $mal_packs
    dnf remove -y $package
    if [ "$status" != 0 ]
        $error_count+=1
        log error "dnf: $status: Failed to uninstall $package"
    else
        log info "- $package removed"
    end
end
log info "Malicious Packages Exterminated"
if $error_count >1
    log error "Encountered errors: $error_count"
end

# SystemD reload to banish the uninstalled shit
log header "systemd Reload"
log info "Reloading system daemon..."
systemctl daemon-reload
if [ "$status" != 0 ]
    log error "systemctl: $status: Error reloading system daemon"
else
    log info "System daemon reload successful"
end

# Users
log header "User Neuter 6000"
# Root protections
echo tty1 >/etc/securetty
chmod 700 /root
# Sudoers hardening
log info "Hardening sudoers..."
set is_immutable [ (lsattr /etc/sudoers) == *"i"* ]
if $is_immutable
    chattr -i /etc/sudoers
end
echo "root ALL=(ALL:ALL) ALL" >/etc/sudoers
chattr -i /etc/sudoers
for file in (ls /etc/sudoers.d)
    rm -rf $file
    log warn "Removed file from sudoers.d: $file"
end
log info "Sudoers hardening successful"
# User permissions fixing
# Loop through each user in the system (excluding root)
for user in (getent passwd | awk -F: '$3 >= 1000 {print $1}')
    if [ "$user" != "root" ]
        log info "Modifying permissions for user: $user"

        # Set home directory permissions to read-only
        chmod -R 755 /home/"$user"

        # Remove sudo/wheel access
        gpasswd -d "$user" wheel 2>/dev/null
        gpasswd -d "$user" sudo 2>/dev/null

        # Set user shell to nyancat
        usermod -s /bin/nyancat "$user"
    end
end

# Installing Tools
dnf install -y htop lynis
