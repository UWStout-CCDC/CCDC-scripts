#!/bin/bash
# __ __       _  _   ___        _            
#|  \  \ ___ <_>| | / __> ___ _| |_ _ _  ___ 
#|     |<_> || || | \__ \/ ._> | | | | || . \
#|_|_|_|<___||_||_| <___/\___. |_| `___||  _/
#                                       |_|  
# Written By Kayne


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m             General Security Measures                \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Only allow root login from console
echo "tty1" > /etc/securetty
chmod 700 /root
echo "DONE"

# DENY ALL TCP WRAPPERS
echo "ALL:ALL" > /etc/hosts.deny

echo "Removing all users from the wheel group except root..."

# Get a list of all users in the wheel group
wheel_users=$(grep '^wheel:' /etc/group | cut -d: -f4 | tr ',' '\n')

# Loop through each user and remove them if they are not root
for user in $wheel_users; do
    if [[ "$user" != "root" ]]; then
        echo "Removing $user from wheel group..."
        gpasswd -d "$user" wheel
    fi
done

echo "Cleanup complete. Only root has sudo permissions now."

#!/bin/bash

# Ensure only root can run this script
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

######################################THIS COULD BREAK IT ALL################################################################################
echo "Restricting permissions: Only root will have full privileges."

# Loop through each user in the system (excluding root)
for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
    if [[ "$user" != "root" ]]; then
        echo "Modifying permissions for user: $user"

        # Set home directory permissions to read-only
        chmod -R 755 /home/"$user"
        
        # Remove sudo/wheel access
        gpasswd -d "$user" wheel 2>/dev/null
        gpasswd -d "$user" sudo 2>/dev/null

        # Set user shell to /bin/false to prevent login if needed
        usermod -s /bin/false "$user"
    fi
done


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                Implementing Fail2Ban                 \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Install fail2ban
echo "Installing fail2ban..."
sudo yum install -y -q fail2ban
# Create fail2ban log file
echo "Creating fail2ban log file..."
sudo touch /var/log/fail2ban.log
# Backup and configure fail2ban
echo "Configuring fail2ban..."
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.BACKUP
sed -i '/^\s*\[dovecot\]/,/^\[/{/logpath\s*=/d;/enabled\s*=/d;/bantime\s*=/d;/maxretry\s*=/d}' /etc/fail2ban/jail.conf
sed -i '/\[dovecot\]/a enabled = true\nbantime = 1800\nmaxretry = 5\nlogpath = /var/log/fail2ban.log' /etc/fail2ban/jail.conf
sed -i '/^\s*\[postfix\]/,/^\[/{/logpath\s*=/d;/enabled\s*=/d;/bantime\s*=/d;/maxretry\s*=/d}' /etc/fail2ban/jail.conf
sed -i '/\[postfix\]/a enabled = true\nbantime = 1800\nmaxretry = 5\nlogpath = /var/log/fail2ban.log' /etc/fail2ban/jail.conf
sed -i '/^\s*\[apache-auth\]/,/^\[/{/logpath\s*=/d;/enabled\s*=/d;/bantime\s*=/d;/maxretry\s*=/d}' /etc/fail2ban/jail.conf
sed -i '/\[apache-auth\]/a enabled = true\nbantime = 1800\nmaxretry = 5\nlogpath = /var/log/fail2ban.log' /etc/fail2ban/jail.conf
sed -i '/^\s*\[roundcube-auth\]/,/^\[/{/logpath\s*=/d;/enabled\s*=/d;/bantime\s*=/d;/maxretry\s*=/d}' /etc/fail2ban/jail.conf
sed -i '/\[roundcube-auth\]/a enabled = true\nbantime = 1800\nmaxretry = 5\nlogpath = /var/log/fail2ban.log' /etc/fail2ban/jail.conf
echo "Restarting fail2ban service..."
systemctl enable fail2ban
systemctl restart fail2ban


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m         Installing Comp Tools from Github            \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Create the directory if it doesn't exist
mkdir -p COMPtools

# Base URL for the files
base_url="https://raw.githubusercontent.com/Whitneyk7878/Kayne/refs/heads/main/"

# List of files to download
files=(
    "COMPMailBoxClear.sh"
    "COMPInstallBroZEEK.sh"
    "COMPBackupFIREWALL.sh"
    "COMPcreatebackups.sh"
    "COMPrestorefrombackup.sh"
)

# Loop over each file and download it into the COMPtools directory
for file in "${files[@]}"; do
    echo "Downloading ${file}..."
    wget -P COMPtools "${base_url}${file}"
done

echo "All files have been downloaded to the COMPtools directory."



echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     Firewall                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
sudo yum install iptables-services -y -q
echo "stopping alternate firewall services.."
# More like firewall-mid
sudo systemctl stop firewalld && sudo systemctl disable firewalld && sudo systemctl mask firewalld
sudo dnf remove firewalld -y -q
# More like nf-mid
sudo systemctl stop nftables && sudo systemctl disable nftables && sudo systemctl mask nftables
sudo systemctl mask nftables -y -q
# Install and setup IPTABLES
echo "Starting IPTABLES..."
sudo yum install iptables iptables-services -y -q
# Enable and start IPTABLES
sudo systemctl enable iptables && sudo systemctl start iptables

# Empty all rules
sudo iptables -t filter -F
sudo iptables -t filter -X

# Block everything by default
sudo iptables -t filter -P INPUT DROP
sudo iptables -t filter -P FORWARD DROP
sudo iptables -t filter -P OUTPUT DROP

# Authorize already established connections
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A INPUT -i lo -j ACCEPT
sudo iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
sudo iptables -t filter -A INPUT -p icmp -j ACCEPT
sudo iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS (Needed for curl, and updates)
sudo iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
sudo iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
sudo iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk
sudo iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# SMTP
sudo iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 587 -j ACCEPT
sudo iptables -t filter -A OUPUT -p tcp --dport 465 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 587 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 465 -j ACCEPT

# POP3
sudo iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp --dport 110 -j ACCEPT
sudo iptables -t filter -A INPUT -p udp --dport 110 -j ACCEPT

# IMAP
sudo iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp --dport 143 -j ACCEPT
sudo iptables -t filter -A INPUT -p udp --dport 143 -j ACCEPT

# LDAP traffic
sudo iptables -t filter -A INPUT -p tcp --dport 389 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 636 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 389 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 636 -j ACCEPT


# THESE ARE PER THE COMPETITION
#sudo ip6tables -A INPUT -p tcp --dport 25 -j ACCEPT
#sudo ip6tables -A OUTPUT -p tcp --dport 25 -j ACCEPT
#sudo ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
#sudo ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT

sudo iptables-save | sudo tee /etc/sysconfig/iptables

#SPECIFIC TO IPV6
#sudo ip6tables-save | sudo tee /etc/sysconfig/ip6tables




echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                Stuff Removal                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
#Remove Stuff I Dont like
sudo yum remove sshd xinetd telnet-server rsh-server telnet rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd squid net-snmpd -y -q
sudo systemctl stop xinetd && sudo systemctl disable xinetd
sudo systemctl stop rexec && sudo systemctl disable rexec
sudo systemctl stop rsh && sudo systemctl disable rsh
sudo systemctl stop rlogin && sudo systemctl disable rlogin
sudo systemctl stop ypbind && sudo systemctl disable ypbind
sudo systemctl stop tftp && sudo systemctl disable tftp
sudo systemctl stop certmonger && sudo systemctl disable certmonger
sudo systemctl stop cgconfig && sudo systemctl disable cgconfig
sudo systemctl stop cgred && sudo systemctl disable cgred
# sudo systemctl stop cpuspeed && sudo systemctl disable cpuspeed
# sudo systemctl stop irqbalance && sudo systemctl disable irqbalance
sudo systemctl stop kdump && sudo systemctl disable kdump
sudo systemctl stop mdmonitor && sudo systemctl disable mdmonitor
# sudo systemctl stop messagebus && sudo systemctl disable messagebus
sudo systemctl stop netconsole && sudo systemctl disable netconsole
# sudo systemctl stop ntpdate && sudo systemctl disable ntpdate
sudo systemctl stop oddjobd && sudo systemctl disable oddjobd
sudo systemctl stop portreserve && sudo systemctl disable portreserve
sudo systemctl stop qpidd && sudo systemctl disable qpidd
sudo systemctl stop quota_nld && sudo systemctl disable quota_nld
sudo systemctl stop rdisc && sudo systemctl disable rdisc
sudo systemctl stop rhnsd && sudo systemctl disable rhnsd
sudo systemctl stop rhsmcertd && sudo systemctl disable rhsmcertd
sudo systemctl stop saslauthd && sudo systemctl disable saslauthd
sudo systemctl stop smartd && sudo systemctl disable smartd
sudo systemctl stop sysstat && sudo systemctl disable sysstat
sudo systemctl stop atd && sudo systemctl disable atd
sudo systemctl stop nfslock && sudo systemctl disable nfslock
sudo systemctl stop named && sudo systemctl disable named
sudo systemctl stop squid && sudo systemctl disable squid
sudo systemctl stop snmpd && sudo systemctl disable snmpd
#sudo systemctl stop mariadb && sudo systemctl disable mariadb
#sudo systemctl stop mysql && sudo systemctl disable mysql
sudo systemctl stop postgresql && sudo systemctl disable postgresql
#sudo systemctl stop httpd && sudo systemctl disable httpd
sudo systemctl stop nginx && sudo systemctl disable nginx
#sudo systemctl stop php-fpm && sudo systemctl disable php-fpm
#THESE ARE SPECIFIC TO THE COMP ENVIRONMENT 2/12/2025
sudo systemctl stop cockpit.s && sudo systemctl disable cockpit.s
sudo systemctl stop rpcgssd && sudo systemctl disable rpcgssd
sudo systemctl stop rpcsvcgssd && sudo systemctl disable rpcsvcgssd
sudo systemctl stop rpcidmapd && sudo systemctl disable rpcidmapd

# Disable Network File Systems (netfs)
systemctl disable netfs

# Disable Network File System (nfs)
systemctl disable nfs

#Remove hacker coding languages
#sudo yum remove -q -y ruby* java* perl* mysql* python* nodejs* php*
#THIS IS FOR COMP
sudo yum remove -q -y ruby* java* perl* python* nodejs*


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m               Kernel Hardening                       \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Disable core dumps for users
echo -e "Disabling core dumps for users"
echo "* hard core 0" >> /etc/security/limits.conf
# Secure sysctl.conf
echo -e "Securing sysctl.conf"
cat <<-EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0
kernel.exec_shield = 1
kernel.randomize_va_space = 2
# CHANGED THIS TEST THIS BEFORE LOCKING IT IN -----------------------------------------------------------------------
net.ipv4.ip_forward = 1
# ---------------------------------------------------------------------
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_max_syn_backlog = 1280
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.log_martians = 1
net.core.bpf_jit_harden = 2
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 3
EOF
sudo sysctl -p


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m               Update + Upgrade                       \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Update system
echo "Updating and upgrading system packages. This may take a while..."
#sudo yum update -y -q && yum upgrade -y -q


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m               Securing APACHE                        \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# 2. Secure HTTPD Configuration
echo "Hardening Apache HTTPD..."
sed -i 's/ServerTokens OS/ServerTokens Prod/' /etc/httpd/conf/httpd.conf
sed -i 's/ServerSignature On/ServerSignature Off/' /etc/httpd/conf/httpd.conf
systemctl restart httpd

echo "Apache HTTPD secured."

# Prevent remote command execution in Apache
echo "Securing Apache against remote command execution..."
sed -i '/Options/d' /etc/httpd/conf/httpd.conf
sed -i 's/AllowOverride All/AllowOverride None/' /etc/httpd/conf/httpd.conf
sed -i 's/Require all granted/Require all denied/' /etc/httpd/conf/httpd.conf
systemctl restart httpd


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m               Securing Roundcube                      \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
sudo systemctl start httpd
sudo systemctl enable httpd

# 5. Secure RoundcubeMail Configuration
echo "Hardening RoundcubeMail..."
sed -i "s/\$config\['enable_installer'\] = true;/\$config['enable_installer'] = false;/" /etc/roundcubemail/config.inc.php
sed -i "s/\$config\['default_host'\] = '';/\$config['default_host'] = 'ssl:\/\/localhost';/" /etc/roundcubemail/config.inc.php
echo "RoundcubeMail secured."
systemctl restart httpd

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     Securing PHP                     \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Prevent PHP remote execution
echo "Disabling dangerous PHP functions..."
sed -i 's/^disable_functions =.*/disable_functions = exec,system,shell_exec,passthru,popen,proc_open/' /etc/php.ini

# Turn Expose PHP off
echo -e "Turning off expose_php.."
sudo sed -i 's/^expose_php\s*=\s*On/expose_php = Off/' /etc/php.ini

# Disable functions in PHP
sudo sed -i '/^\s*disable_functions\s*=/d' /etc/php.ini && sudo sh -c 'echo "disable_functions = exec,shell_exec,system,passthru,popen,proc_open,phpinfo,eval" >> /etc/php.ini'

# Disabling allow_url_fopen and allow_url_include helps prevent remote file inclusion attacks and arbitrary code execution from external sources.
sed -i -e '/^[;\s]*allow_url_fopen\s*=/d' -e '/^[;\s]*allow_url_include\s*=/d' -e '$ a allow_url_fopen = Off\nallow_url_include = Off' /etc/php.ini

systemctl restart httpd

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                  Securing Dovecot                    \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Enable and start Dovecot and Postfix
echo "Enabling and starting Dovecot and Postfix..."
systemctl enable dovecot
systemctl enable postfix
systemctl start dovecot
systemctl start postfix
#Installing and configuring TLS
#sudo yum install openssl -y -q
#sudo mkdir -p /etc/dovecot/ssl
#echo -e "ENTER INFORMATION FOR TLS CERTIFICATE"
#sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/dovecot/ssl/dovecot.pem -out /etc/dovecot/ssl/dovecot.crt -days 365 -nodes
#sudo chmod 600 /etc/dovecot/ssl/dovecot.pem
#sudo chmod 600 /etc/dovecot/ssl/dovecot.crt
#sed -i 's|ssl_cert = </etc/pki/dovecot/certs/dovecot.pem|ssl_cert = </etc/dovecot/ssl/dovecot.crt|' /etc/dovecot/conf.d/10-ssl.conf
#sed -i 's|ssl_key = </etc/pki/dovecot/private/dovecot.pem|ssl_key = </etc/dovecot/ssl/dovecot.pem|' /etc/dovecot/conf.d/10-ssl.conf
#sed -i 's|#ssl_protocols = !SSLv2|ssl_protocols = !SSLv3 !TLSv1 !TLSv1.1|' /etc/dovecot/conf.d/10-ssl.conf


sudo systemctl restart dovecot

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                  Securing Postfix                    \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

#echo "Installing OpenSSL and configuring it..."
#sudo mkdir -p /etc/postfix/ssl
#Name doesnt matter on this one for the keys
#sudo openssl genpkey -algorithm RSA -out ccdc.key -pkeyopt rsa_keygen_bits:4096
#sudo mv *.key /etc/postfix/ssl/
# THE KEY SHOULD BE THE KEY GENERATED EARLIER
#sudo openssl req -new -key /etc/postfix/ssl/ccdc.key -out ccdc.csr
#sudo mv *.csr /etc/postfix/ssl/
#postconf -e 'smtpd_use_tls = yes'
#postconf -e 'smtpd_tls_auth_only = yes'
#postconf -e 'smtpd_tls_key_file = /etc/postfix/ssl/ccdc.key'
#postconf -e 'smtpd_tls_cert_file = /etc/postfix/ssl/mail.ccdclab.net.crt'
#postconf -e 'smtpd_tls_loglevel = 1'
#sudo systemctl restart postfix

echo "Configuring Postfix..."
POSTFIX_CONFIG="/etc/postfix/main.cf"

declare -A POSTFIX_SETTINGS=(
    ["smtpd_client_connection_count_limit"]="10"
    ["smtpd_client_connection_rate_limit"]="60"
    ["smtpd_error_sleep_time"]="5s"
    ["smtpd_soft_error_limit"]="10"
    ["smtpd_hard_error_limit"]="20"
    ["message_size_limit"]="10485760"
    ["smtpd_recipient_restrictions"]="reject_unauth_destination"
)

for key in "${!POSTFIX_SETTINGS[@]}"; do
    if ! grep -q "^$key" "$POSTFIX_CONFIG"; then
        echo "$key = ${POSTFIX_SETTINGS[$key]}" >> "$POSTFIX_CONFIG"
    fi
done

sudo systemctl restart postfix


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m              Downloading Security Tools              \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Update and install necessary packages
echo "Installing required packages..."
sudo yum install -y -q chkrootkit aide rkhunter clamav clamd clamav-update
# Download and set up monitoring script
echo "Downloading monitoring script..."
sudo wget https://raw.githubusercontent.com/UWStout-CCDC/kronos/master/Linux/General/monitor.sh
echo "Insalling Lynis..."
sudo yum install lynis -y -q


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     AuditD                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Enable and start auditd
echo "Configuring auditd..."
sudo systemctl enable auditd
sudo systemctl start auditd
# Download audit rules and apply them
echo "Setting up audit rules..."
# MAKE SURE TO CHANGE THIS BEFORE YOU GO INTO COMPETITION
sudo wget https://raw.githubusercontent.com/Whitneyk7878/Kayne/refs/heads/main/CustomAudit.rules
sudo rm /etc/audit/rules.d/audit.rules
sudo mv CustomAudit.rules /etc/audit/rules.d/
sudo dos2unix /etc/audit/rules.d/CustomAudit.rules
sudo auditctl -R /etc/audit/rules.d/audit.rules


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     CLAMAV                           \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Configure ClamAV
echo "Configuring ClamAV..."
sudo sed -i '8s/^/#/' /etc/freshclam.conf
sudo freshclam


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     SE LINUX                           \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
# This makes it so that se linux is enforcing policies, not just logging violations
echo "Setting SE to enforce mode and turning off permissive.."
sudo sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
#THESE ARE FOR POSTFIX TO WORK BECAUSE SE LINUX CAN BREAK IT
sudo setsebool -P allow_postfix_local_write_mail_spool on
sudo setsebool -P httpd_can_sendmail on
sudo setsebool -P allow_postfix_local_write_mail_spool=1
sudo systemctl restart postfix


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m            I HATE THE ANTICHRIST (compilers)         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Remove Compilers
sudo yum remove libgcc clang make cmake automake autoconf -y -q


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m        IPv6 is for Microsoft Engineers not me        \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
if grep -q "udp6" /etc/netconfig
then
    echo "Support for RPC IPv6 already disabled"
else
    echo "Disabling Support for RPC IPv6..."
    sed -i 's/udp6       tpi_clts      v     inet6    udp     -       -/#udp6       tpi_clts      v     inet6    udp     -       -/g' /etc/netconfig
    sed -i 's/tcp6       tpi_cots_ord  v     inet6    tcp     -       -/#tcp6       tpi_cots_ord  v     inet6    tcp     -       -/g' /etc/netconfig
fi


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                   Cron Lockdown                      \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Secure cron
echo "Locking down Cron"
sudo systemctl start crond && sudo systemctl enable crond
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny
chmod 600 /etc/cron.deny
chmod 600 /etc/at.deny
chmod 600 /etc/crontab



echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     NTP                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
sudo yum install ntpdate -y -q
ntpdate pool.ntp.org


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m             Diffing for Baselines                    \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Create DIFFING directory
echo "Creating DIFFING directory..."
sudo mkdir DIFFING
# Generate baseline system information
echo "Generating baseline data..."
sudo lsof -i -n | grep "LISTEN" > DIFFING/portdiffingBASELINE.txt
sudo ss -t state established > DIFFING/connectiondiffingBASELINE.txt
sudo cat /root/.bashrc > DIFFING/alias_diffingBASELINE.txt
sudo find / -type f -executable 2>/dev/null > DIFFING/executables_diffingBASELINE.txt
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done > DIFFING/cron_diffingBASELINE.txt
sudo cat /etc/shadow > DIFFING/users_diffingBASELINE.txt


#Running auditctl rules again because it doesnt like it the first time
sudo auditctl -R /etc/audit/rules.d/audit.rules


#echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
#echo -e "\e[38;5;46m                 Installing RITA                      \e[0m"
#echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

#echo "Installing RITA for C2 detection (this may take a while).."
#sudo wget https://github.com/activecm/rita/releases/download/v5.0.8/install-rita-zeek-here.sh
#sudo bash install-rita-zeek-here.sh
#sudo touch rita-roll
#sudo echo -e "#!/bin/bash\nscreen -S ritaimport -d -m /usr/local/bin/rita import --rolling -l /opt/zeek/logs/ -d rolling\n" > rita-roll
#sudo chmod +x rita-roll
#sudo touch rita /etc/cron.d
# THIS CRON JOB IMPORTS ZEEK STUFF EVERY 2 MINUTES
#sudo echo "*/2 * * * * root /opt/rita/rita-roll" > /etc/cron.d/rita
# RESOURCE: https://www.youtube.com/watch?v=oP5xYq0_44E&pp=ygURcml0YSBpbnN0YWxsYXRpb24%3D
# RESOURCE: https://www.youtube.com/watch?v=tRlzVNG2sGQ
# COMMAND to run: zeek start && rita view rolling



echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m              Installing Suricata IDS                 \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

# echo "installing suricata.."
# sudo yum install suricata -y -q
# sudo yum install jq -y -q
# echo "Installing the latest emerging threats rules.."
# I HAVE THIS COMMENTED OUT because it breaks my poor little old fedora box to have so many rules that arent compatible
# So i have to use the default ruleset
# Uncomment it if you are on a better distro than me
# sudo wget https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz -O /tmp/emerging.rules.tar.gz
# sudo tar -xvzf /tmp/emerging.rules.tar.gz -C /etc/suricata/
# sudo systemctl enable suricata
# sudo systemctl start suricata
# Go into the /etc/suricata/suricata.yaml file and set af-packet (around page 13) to your ens32
# resource: https://www.youtube.com/watch?v=UXKbh0jPPpg
# Commands: jq '.' /var/log/suricata/eve.json | less
# tail -f /var/log/fast.log
# cat /var/log/suricata/stats.log



#echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
#echo -e "\e[38;5;46m                    TripWire                          \e[0m"
#echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

#echo "installing tripwire"
#sudo yum install tripwire -y -q
#echo "fill out the information to sign policies and configurations.."
#sudo tripwire-setup-keyfiles
#echo "initialize the database..."
#sudo tripwire --init


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                  Install XFCE                        \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

sudo yum groupinstall "XFCE" "X Window System" -y -q

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m              Carpet Bombing Binaries                 \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

echo "Making the secret location.."
sudo mkdir /etc/stb
sudo mv /usr/bin/curl /etc/stb/1
sudo mv /usr/bin/wget /etc/stb/2
sudo mv /usr/bin/ftp  /etc/stb/3
sudo mv /usr/bin/sftp /etc/stb/4
sudo mv /usr/bin/aria2c /etc/stb/5
sudo mv /usr/bin/nc /etc/stb/6
sudo mv /usr/bin/socat /etc/stb/7
sudo mv /usr/bin/telnet /etc/stb/8
sudo mv /usr/bin/tftp /etc/stb/9
sudo mv /usr/bin/ncat    /etc/stb/10
sudo mv /usr/bin/gdb     /etc/stb/11  
sudo mv /usr/bin/strace  /etc/stb/12 
sudo mv /usr/bin/ltrace  /etc/stb/13

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m              Locking Down Critical Files             \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
#!/bin/bash
# List of critical files to protect
FILES=(
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/gshadow
    /etc/sudoers
    /etc/ssh/sshd_config
    /etc/ssh/ssh_config
    /etc/crontab
    /etc/fstab
    /etc/hosts
    /etc/resolv.conf
    /etc/sysctl.conf
    /etc/selinux/config
)

# Loop through each file and set it immutable if it exists
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        chattr +i "$file"
        echo "Set immutable on $file"
    else
        echo "File not found: $file"
    fi
done

# A helper function to apply ownership, perms, and immutability.
set_permissions_and_immutable() {
  local dir="$1"

  echo "Applying ownership root:root to $dir ..."
  sudo chown -R root:root "$dir"

  echo "Setting directory permissions to 755 in $dir ..."
  sudo find "$dir" -type d -exec chmod 755 {} \;

  echo "Setting file permissions to 644 in $dir ..."
  sudo find "$dir" -type f -exec chmod 644 {} \;

  echo "Applying immutable attribute (+i) to $dir ..."
  sudo chattr -R +i "$dir"

  echo "Finished securing $dir."
  echo
}

# List of directories we want to process
CONFIG_DIRS=(
  "/etc/roundcubemail"
  "/etc/httpd"
  "/etc/dovecot"
  "/etc/postfix"
)

# Loop through each directory, prompt user, and apply changes if "y"
for dir in "${CONFIG_DIRS[@]}"; do
  echo "Directory: $dir"
  read -r -p "Is this the correct directory to secure? (y/n): " answer

  if [[ "$answer" =~ ^[Yy]$ ]]; then
    if [[ -d "$dir" ]]; then
      set_permissions_and_immutable "$dir"
    else
      echo "Warning: $dir does not exist on this system. Skipping."
      echo
    fi
  else
    echo "Skipping $dir."
    echo
  fi
done


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m            Initializing AIDE Database                \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

echo "Initializing AIDE database (this may take a while).."
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo " "
echo -e "\e[45mSCRIPT HAS FINISHED RUNNING... REBOOTING..\e[0m"
sleep 3
sudo reboot
