#!/bin/bash
# __ __       _  _   ___        _            
#|  \  \ ___ <_>| | / __> ___ _| |_ _ _  ___ 
#|     |<_> || || | \__ \/ ._> | | | | || . \
#|_|_|_|<___||_||_| <___/\___. |_| `___||  _/
#                                       |_|  
# Written By Kayne

echo -e "starting script"


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m             General Security Measures                      \e[0m"
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
echo -e "\e[38;5;46m                     Firewall                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
sudo yum install iptables-services -y
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl enable iptables
sudo systemctl start iptables

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

# NTP (server time)
sudo iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk
sudo iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# SMTP
sudo iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT

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

sudo iptables-save | sudo tee /etc/sysconfig/iptables

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                Stuff Removal                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
#Remove Stuff I Dont like
yum remove sshd xinetd telnet-server rsh-server telnet rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd squid net-snmpd -y
sudo systemctl stop xinetd && sudo systemctl disable xinetd
sudo systemctl stop rexec && sudo systemctl disable rexec
sudo systemctl stop rsh && sudo systemctl disable rsh
sudo systemctl stop rlogin && sudo systemctl disable rlogin
sudo systemctl stop ypbind && sudo systemctl disable ypbind
sudo systemctl stop tftp && sudo systemctl disable tftp
sudo systemctl stop certmonger && sudo systemctl disable certmonger
sudo systemctl stop cgconfig && sudo systemctl disable cgconfig
sudo systemctl stop cgred && sudo systemctl disable cgred
sudo systemctl stop cpuspeed && sudo systemctl disable cpuspeed
sudo systemctl start irqbalance && sudo systemctl enable irqbalance
sudo systemctl stop kdump && sudo systemctl disable kdump
sudo systemctl stop mdmonitor && sudo systemctl disable mdmonitor
sudo systemctl stop messagebus && sudo systemctl disable messagebus
sudo systemctl stop netconsole && sudo systemctl disable netconsole
sudo systemctl stop ntpdate && sudo systemctl disable ntpdate
sudo systemctl stop oddjobd && sudo systemctl disable oddjobd
sudo systemctl stop portreserve && sudo systemctl disable portreserve
sudo systemctl start psacct && sudo systemctl enable psacct
sudo systemctl stop qpidd && sudo systemctl disable qpidd
sudo systemctl stop quota_nld && sudo systemctl disable quota_nld
sudo systemctl stop rdisc && sudo systemctl disable rdisc
sudo systemctl stop rhnsd && sudo systemctl disable rhnsd
sudo systemctl stop rhsmcertd && sudo systemctl disable rhsmcertd
sudo systemctl stop saslauthd && sudo systemctl disable saslauthd
sudo systemctl stop smartd && sudo systemctl disable smartd
sudo systemctl stop sysstat && sudo systemctl disable sysstat
sudo systemctl start crond && sudo systemctl enable crond
sudo systemctl stop atd && sudo systemctl disable atd
sudo systemctl stop nfslock && sudo systemctl disable nfslock
sudo systemctl stop named && sudo systemctl disable named
sudo systemctl stop squid && sudo systemctl disable squid
sudo systemctl stop snmpd && sudo systemctl disable snmpd
sudo systemctl stop mariadb && sudo systemctl disable mariadb
sudo systemctl stop mysql && sudo systemctl disable mysql
sudo systemctl stop postgresql && sudo systemctl disable postgresql
sudo systemctl stop httpd && sudo systemctl disable httpd
sudo systemctl stop nginx && sudo systemctl disable nginx
sudo systemctl stop php-fpm && sudo systemctl disable php-fpm

# Disable rpc
systemctl disable rpcgssd
systemctl disable rpcsvcgssd
systemctl disable rpcidmapd

# Disable Network File Systems (netfs)
systemctl disable netfs

# Disable Network File System (nfs)
systemctl disable nfs

#Remove hacker coding languages
sudo yum remove -y ruby* java* perl* mysql* mariadb* python* nodejs* php*


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m               Kernel Hardening                       \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Disable core dumps for users
echo -e "Disabling core dumps for users"
echo "* hard core 0" >> /etc/security/limits.conf

# Secure sysctl.conf
echo -e "\e[33mSecuring sysctl.conf\e[0m"
cat <<-EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0
kernel.exec_shield = 1
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
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
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 3
EOF
sudo sysctl -p


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m               Update + Upgrade                       \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Update system
echo "Updating and upgrading system packages..."
sudo yum update -y && yum upgrade -y




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
sudo yum install openssl -y
sudo mkdir -p /etc/dovecot/ssl
echo -e "ENTER INFORMATION FOR TLS CERTIFICATE"
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/dovecot/ssl/dovecot.pem -out /etc/dovecot/ssl/dovecot.crt -days 365 -nodes
sudo chmod 600 /etc/dovecot/ssl/dovecot.pem
sudo chmod 600 /etc/dovecot/ssl/dovecot.crt
sed -i 's|ssl_cert = </etc/pki/dovecot/certs/dovecot.pem|ssl_cert = </etc/dovecot/ssl/dovecot.crt|' /etc/dovecot/conf.d/10-ssl.conf
sed -i 's|ssl_key = </etc/pki/dovecot/private/dovecot.pem|ssl_key = </etc/dovecot/ssl/dovecot.pem|' /etc/dovecot/conf.d/10-ssl.conf
sed -i 's|#ssl_protocols = !SSLv2|ssl_protocols = !SSLv3 !TLSv1 !TLSv1.1|' /etc/dovecot/conf.d/10-ssl.conf
sed -i 's|#disable_plaintext_auth = yes|disable_plaintext_auth = yes|' /etc/dovecot/conf.d/10-auth.conf
sed -i 's|#auth_verbose = no|auth_verbose = yes|' /etc/dovecot/conf.d/10-logging.conf
sudo systemctl restart dovecot


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                Implementing Fail2Ban                 \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Install fail2ban
echo "Installing fail2ban..."
yum install -y fail2ban
# Create fail2ban log file
echo "Creating fail2ban log file..."
touch /var/log/fail2banlog
# Backup and configure fail2ban
echo "Configuring fail2ban..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
# Putting in the contents to the jail file
sed -i '/\[dovecot\]/a enabled = true\nmaxretry = 5\nbantime = 3600' /etc/fail2ban/jail.local
sed -i 's|logpath = %(dovecot_log)s|logpath = /var/log/fail2banlog|g' /etc/fail2ban/jail.local
# Restart fail2ban service
echo "Restarting fail2ban service..."
systemctl enable fail2ban
systemctl restart fail2ban


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m              Downloading Security Tools              \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Update and install necessary packages
echo "Installing required packages..."
sudo yum install -y aide rkhunter clamav clamd clamav-update
# Download and set up monitoring script
echo "Downloading monitoring script..."
sudo wget https://raw.githubusercontent.com/UWStout-CCDC/kronos/master/Linux/General/monitor.sh
echo "Insalling Lynis..."
sudo yum install lynis -y


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
sudo wget https://raw.githubusercontent.com/Neo23x0/auditd/refs/heads/master/audit.rules
sudo rm /etc/audit/rules.d/audit.rules
sudo mv audit.rules /etc/audit/rules.d/
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
echo -e "\e[38;5;46m                     Backups                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
# Create hidden directory for compressed files
echo "Creating hidden directory..."
sudo mkdir /lib/.tarkov
# Archive and store system files
echo "Compressing and storing system files individually..."
sudo tar -czf /lib/.tarkov/shadow_backup.tar.gz /etc/shadow
sudo tar -czf /lib/.tarkov/passwd_backup.tar.gz /etc/passwd
sudo tar -czf /lib/.tarkov/fail2ban_backup.tar.gz /etc/fail2ban/
sudo tar -czf /lib/.tarkov/hosts_backup.tar.gz /etc/hosts
sudo tar -czf /lib/.tarkov/log_backup.tar.gz /var/log
sudo tar -czf /lib/.tarkov/mail_backup.tar.gz /var/mail
sudo tar -czf /lib/.tarkov/postfix_spool_backup.tar.gz /var/spool/postfix/
sudo tar -czf /lib/.tarkov/postfix_backup.tar.gz /etc/postfix/
sudo tar -czf /lib/.tarkov/dovecot_backup.tar.gz /etc/dovecot

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m            I HATE THE ANTICHRIST (compilers)         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
#Remove Compilers
sudo yum remove libgcc clang make cmake automake autoconf -y


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


#Running auditctl rules again because it doesnt like it the first time
sudo auditctl -R /etc/audit/rules.d/audit.rules


echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m                     NTP                         \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
sleep 1
sudo yum install ntpdate -y
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

echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"
echo -e "\e[38;5;46m            Initializing AIDE Database                \e[0m"
echo -e "\e[38;5;46m//////////////////////////////////////////////////////\e[0m"

sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "FINISHED MAKE SURE YOU REBOOT"
