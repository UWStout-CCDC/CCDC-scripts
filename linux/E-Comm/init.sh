#!/bin/bash
# https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master/linux/E-Comm/init.sh
BASEURL=https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master
read -p "Enter the default password for the PrestaShop database: " -s DEFAULT_PRESTA_PASS

# Test if the password is correct
while ! mysql -u root -p$DEFAULT_PRESTA_PASS -e "exit" > /dev/null 2>&1
do
    echo "Incorrect MySQL root password. Please try again."
    read -p "Enter the default password for the PrestaShop database: " -s DEFAULT_PRESTA_PASS
done

CCDC_DIR="/ccdc"
CCDC_ETC="$CCDC_DIR/etc"
SCRIPT_DIR="/ccdc/scripts"


if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# check if the script dir exists, if it does not, create it
if [ ! -d "$SCRIPT_DIR" ]; then
    mkdir -p $SCRIPT_DIR
fi

# Check if the linux directory exists within the script directory, if it does not, create it
if [ ! -d "$SCRIPT_DIR/linux" ]; then
    mkdir -p $SCRIPT_DIR/linux
fi

# Download and install new repos
wget -O /etc/yum.repos.d/CentOS-Base.repo $BASEURL/linux/E-Comm/CentOS-Base.repo --no-check-certificate

# Clean the yum cache
yum -v clean expire-cache

# update the certificates on the system
yum update -y ca-certificates

get() {
  # only download if the file doesn't exist
  if [[ ! -f "$SCRIPT_DIR/$1" ]]
  then
    mkdir -p $(dirname "$SCRIPT_DIR/$1") 1>&2
    BASE_URL="https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/master"
    wget --no-check-certificate "$BASE_URL/$1" -O "$SCRIPT_DIR/$1" 1>&2
  fi
  echo "$SCRIPT_DIR/$1"
}

# replace <dir> <file> <new file>
replace() {
  mkdir -p $CCDC_ETC/$(dirname $2)
  cp $1/$2 $CCDC_ETC/$2.old
  mkdir -p $(dirname $1/$2)
  cp $(get $3) $1/$2
}

prompt() {
  case "$2" in 
    y) def="[Y/n]" ;;
    n) def="[y/N]" ;;
    *) echo "INVALID PARAMETER!!!!"; exit ;;
  esac
  read -p "$1 $def" ans
  case $ans in
    y|Y) true ;;
    n|N) false ;;
    *) [[ "$def" != "[y/N]" ]] ;;
  esac
}


# change DNS in network config file by replacing the DNS1 and DNS2 values
echo "Setting up DNS..."
INTERFACE=$(ip route | grep default | awk '{print $5}')
sed -i 's/DNS1='.*'/DNS1=1.1.1.1/g' /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
sed -i 's/DNS2='.*'/DNS2=9.9.9.9/g' /etc/sysconfig/network-scripts/ifcfg-$INTERFACE

# Restart the network service
systemctl restart network

# Lock all users except root and sysadmin
USER_LOCK_SCRIPT="$SCRIPT_DIR/linux/user_lock.sh"
wget -O $USER_LOCK_SCRIPT $BASEURL/linux/E-Comm/user_lock.sh
chmod +x $USER_LOCK_SCRIPT
bash $USER_LOCK_SCRIPT

# Grab script so it's guarnteed to be in /ccdc/scripts/linux
get linux/init.sh


# Get PrestaShop sql password change script
wget -O $SCRIPT_DIR/linux/change_sql_pass.sh $BASEURL/linux/E-Comm/change_sql_pass.sh
chmod +x $SCRIPT_DIR/linux/change_sql_pass.sh

# Run mysql_secure_installation to secure the MySQL installation and auto answer the questions, leaving password as blank
# This is done to ensure that the MySQL installation is secure
echo -e "$DEFAULT_PRESTA_PASS\nn\n\n\n\n\n" | mysql_secure_installation

# Disable ssh
systemctl stop sshd
systemctl disable sshd

# Set firewall rules
IPTABLES_SCRIPT="$SCRIPT_DIR/linux/iptables.sh"
cat <<EOF > $IPTABLES_SCRIPT
#!/bin/bash
if [[ \$EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

# Empty all rules
iptables -t filter -F
iptables -t filter -X

# Block everything by default
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# Authorize already established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# Deny outbound traffic to RFC 1918 addresses (do not need to communicate with private IP addresses)
iptables -t filter -A OUTPUT -d 10.0.0.0/8 -j REJECT
iptables -t filter -A OUTPUT -d 172.16.0.0/12 -j REJECT
iptables -t filter -A OUTPUT -d 192.168.0.0/16 -j REJECT

# DNS (Needed for curl, and updates)
iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# # Splunk
# iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
# iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
# iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

######## OUTBOUND SERVICES ###############
# HTTP/HTTPS (apache)
iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
EOF

# Make the script executable
chmod +x $IPTABLES_SCRIPT

bash $IPTABLES_SCRIPT

# Create systemd unit for the firewall
mkdir -p /etc/systemd/system/
cat <<-EOF > /etc/systemd/system/ccdc_firewall.service
[Unit]
Description=ZDSFirewall
After=syslog.target network.target

[Service]
Type=oneshot
ExecStart=$IPTABLES_SCRIPT
ExecStop=/sbin/iptables -F
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Automatically apply IPTABLES_SCRIPT on boot
systemctl enable --now ccdc_firewall.service

#######################################
#
#          PRESTASHOP_CONFIG
#
#######################################



# Zip up the /var/www/html directory and move it to /bkp
# Check if the /bkp directory exists, if it does not, create it
if [ ! -d "/bkp/original" ]; then
    mkdir -p /bkp/original
fi
echo "Zipping up /var/www/html..."
tar -czf /bkp/original/html.tar.gz /var/www/html


# zip up the /etc/httpd directory and move it to /bkp
echo "Zipping up /etc/httpd..."
tar -czf /bkp/original/httpd.tar.gz /etc/httpd

# backup the mysql database
if [ -z "$DEFAULT_PRESTA_PASS" ]; then
  mysqldump -u root --all-databases > /bkp/original/ecomm.sql
else
  mysqldump -u root -p$DEFAULT_PRESTA_PASS --all-databases > /bkp/original/ecomm.sql
fi

# Remove prestashop admin directory, its in /var/www/html/prestashop and it will have random characters after admin
rm -rf /var/www/html/prestashop/admin*

# Remove the unneeded directories from prestashop
rm -rf /var/www/html/prestashop/install*
rm -rf /var/www/html/prestashop/docs
rm -f /var/www/html/prestashop/README.md

rm -f /var/www/html/prestashop/CONTRIBUTING.md
rm -f /var/www/html/prestashop/CONTRIBUTORS.md
rm -f /var/www/html/prestashop/init.php

rm -f /var/www/html/prestashop/INSTALL.txt
rm -f /var/www/html/prestashop/Install_PrestaShop.html
rm -f /var/www/html/prestashop/LICENSES
rm -f /var/www/html/prestashop/XMLFeed.cache

# remove index.php from /upload and /download directories
rm -f /var/www/html/prestashop/upload/index.php
rm -f /var/www/html/prestashop/download/index.php

# remove more unneeded files, such as the composer.lock files
rm -f /var/www/html/prestashop/composer.lock
rm -f /var/www/html/prestashop/Makefile
rm -f /var/www/html/prestashop/phpstan.neon.dist

# edit the /etc/httpd/conf/httpd.conf file and add hardening options for prestashop
# Add the following to the end of the file

# Check if the changes have already been made
if grep -q "Disable config folder access" /etc/httpd/conf/httpd.conf
then
    echo "Config folder access already disabled"
else
    echo "Disabling config folder access..."
    cat <<EOF >> /etc/httpd/conf/httpd.conf
# Disable config folder access
<Directory "/var/www/html/prestashop/config">
    Order Deny,Allow
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/app>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/var>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/translations>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/cache>
    Order deny,allow
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/src>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/vendor>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/install>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/cache>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/mails>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/pdf>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/log>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/controllers>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/classes>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/override>
    Order Allow,Deny
    Deny from all
</Directory>

<Directory /var/www/html/prestashop/img>
    <FilesMatch "\.(jpg|jpeg|png|gif|svg|webp|ico)$">
        Order allow,deny
        Allow from all
    </FilesMatch>
    <FilesMatch "\.php$">
        Deny from all
    </FilesMatch>
</Directory>

# Prevent access to sensitive files
<FilesMatch "\.(env|ini|log|bak|swp|sql|git)">
    Order Allow,Deny
    Deny from all
</FilesMatch>
<FilesMatch "^(settings.inc.php|config.inc.php|parameters.php|parameters.yml)$">
    Order deny,allow
    Deny from all
</FilesMatch>
<FilesMatch "\.(sql|tpl|twig|md|yml|yaml|log|ini|sh|bak|inc)$">
    Order deny,allow
    Deny from all
</FilesMatch>

# Disable directory listing
<IfModule autoindex_module>
    Options -Indexes
</IfModule>

# Disable TRACE and TRACK HTTP methods
TraceEnable off

EOF
fi



# Edit the /etc/httpd/conf.d/php.conf file and add the following to the end of the file
# Check if the changes have already been made
if grep -q "Disable PHP engine in the uploads directory" /etc/httpd/conf.d/php.conf
then
    echo "PHP engine already disabled in uploads directory"
else
    echo "Disabling PHP engine in uploads directory..."
    cat <<EOF >> /etc/httpd/conf.d/php.conf
# Disable PHP engine in the uploads directory
<Directory "/var/www/html/prestashop/upload">
    php_flag engine off
</Directory>

# Disable PHP engine in the download directory
<Directory "/var/www/html/prestashop/download">
    php_flag engine off
</Directory>

<Directory "/var/www/html/prestashop/img">
    php_flag engine off
</Directory>

EOF
fi

# Disable expose_php in the php.ini file, this is done by setting expose_php = Off
if grep -q "expose_php = Off" /etc/php.ini
then
    echo "expose_php already set to Off"
else
    echo "Setting expose_php to Off..."
    sed -i 's/expose_php = On/expose_php = Off/g' /etc/php.ini
fi


# Disable allow_url_fopen in the php.ini file, this is done by setting allow_url_fopen = Off
if grep -q "allow_url_fopen = Off" /etc/php.ini
then
    echo "allow_url_fopen already set to Off"
else
    echo "Setting allow_url_fopen to Off..."
    sed -i 's/allow_url_fopen = On/allow_url_fopen = Off/g' /etc/php.ini
fi


# Check if the change_sql_pass.sh script exists, if it is then run it
if [ -f "$SCRIPT_DIR/linux/change_sql_pass.sh" ]; then
    bash $SCRIPT_DIR/linux/change_sql_pass.sh $DEFAULT_PRESTA_PASS
fi

# set db to disable smarty cache in the ps_configuration table
# check if they are using empty password for mysql
if [ -z "$DEFAULT_PRESTA_PASS" ]; then
  mysql -u root -e "use prestashop; update ps_configuration set value='0' where name='PS_SMARTY_CACHE';"
else
  mysql -u root -p$DEFAULT_PRESTA_PASS -e "use prestashop; update ps_configuration set value='0' where name='PS_SMARTY_CACHE';"
fi

# fix permissions on the /var/www/html/prestashop directory
TARGET_DIR="/var/www/html/prestashop"
# Set directories to 755
find "$TARGET_DIR" -type d -exec chmod 755 {} \;
# Set files to 644
find "$TARGET_DIR" -type f -exec chmod 644 {} \;
echo "Permissions set: Directories (755), Files (644) in $TARGET_DIR"

# Restart the httpd service
systemctl restart httpd


if [ ! -d "/bkp/new" ]; then
    mkdir -p /bkp/new
fi

echo "Zipping up edited /var/www/html..."
tar -czf /bkp/new/html.tar.gz /var/www/html

# zip up the /etc/httpd directory and move it to /bkp
echo "Zipping up edited /etc/httpd..."
tar -czf /bkp/new/httpd.tar.gz /etc/httpd

# backup the mysql database
if [ -z "$DEFAULT_PRESTA_PASS" ]; then
  mysqldump -u root --all-databases > /bkp/new/ecomm.sql
else
  mysqldump -u root -p$DEFAULT_PRESTA_PASS --all-databases > /bkp/new/ecomm.sql
fi

#########################################
#
#         END PRESTASHOP_CONFIG
#
#########################################


# Replace the legal banners
replace /etc motd general/legal_banner.txt
replace /etc issue general/legal_banner.txt
replace /etc issue.net general/legal_banner.txt

# Disable other firewalls
# (--now also runs a start/stop with the enable/disable)
systemctl disable --now firewalld
systemctl disable --now ufw


##################################################
#
#           CENTOS HARDENING
#
##################################################

# Ensure NTP is installed and running
yum install ntpdate -y
ntpdate pool.ntp.org

# Disable prelinking altogether for aide
#
if grep -q ^PRELINKING /etc/sysconfig/prelink
then
  sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
else
  echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
  echo "PRELINKING=no" >> /etc/sysconfig/prelink
fi

# Enable SHA512 password hashing
authconfig --passalgo=sha512 —update

# Set Last Login/Access Notification
# Edit /etc/pam.d/system-auth, and add following line imeediatley after session required pam_limits.so: session       required     pam_lastlog.so showfailed

if grep -q pam_lastlog.so /etc/pam.d/system-auth
then
    echo "pam_lastlog.so already in system-auth"
else
    echo "Adding pam_lastlog.so to system-auth..."
    sed -i '/pam_limits.so/a session required pam_lastlog.so showfailed' /etc/pam.d/system-auth
fi

# Disable Ctrl-Alt-Del Reboot Activation
# change 'exec /sbin/shutdown -r now "Control-Alt-Delete pressed"' to 'exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"' in /etc/init/control-alt-delete.conf

if grep -q "exec /usr/bin/logger -p security.info" /etc/init/control-alt-delete.conf
then
    echo "Control-Alt-Delete already disabled"
else
    echo "Disabling Control-Alt-Delete..."
    sed -i 's/exec \/sbin\/shutdown -r now "Control-Alt-Delete pressed"/exec \/usr\/bin\/logger -p security.info "Control-Alt-Delete pressed"/g' /etc/init/control-alt-delete.conf
fi

# secure grub by ensuring the permissions are set to 600
chmod 600 /boot/grub2/grub.cfg

# Ensure SELinux is enabled and enforcing
# Check if SELINUX is already set to enforcing
if grep -q SELINUX=enforcing /etc/selinux/config
then
    echo "SELINUX already set to enforcing"
else
    echo "Setting SELINUX to enforcing..."
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
fi

# REMOVE ALLL COMPILERS
yum remove libgcc -y

# Disable Support for RPC IPv6
# comment the following lines in /etc/netconfig
# udp6       tpi_clts      v     inet6    udp     -       -
# tcp6       tpi_cots_ord  v     inet6    tcp     -       -

if grep -q "udp6" /etc/netconfig
then
    echo "Support for RPC IPv6 already disabled"
else
    echo "Disabling Support for RPC IPv6..."
    sed -i 's/udp6       tpi_clts      v     inet6    udp     -       -/#udp6       tpi_clts      v     inet6    udp     -       -/g' /etc/netconfig
    sed -i 's/tcp6       tpi_cots_ord  v     inet6    tcp     -       -/#tcp6       tpi_cots_ord  v     inet6    tcp     -       -/g' /etc/netconfig
fi

# Only allow root login from console
echo "tty1" > /etc/securetty
chmod 700 /root

# Enable UMASK 077
echo "umask 077" >> /etc/bashrc
umask 077

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
rm -f /var/spool/cron/*

# Sysctl Security 
cat <<-EOF > /etc/sysctl.conf
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
kernel.exec_shield = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF

#kernel.modules_disabled = 1

# kernel.yama.ptrace_scope = 2

# DENY ALL TCP WRAPPERS
echo "ALL:ALL" > /etc/hosts.deny

# Disable Uncommon Protocols
echo "install dccp /bin/false" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/false" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/false" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/false" > /etc/modprobe.d/tipc.conf

# Install and Configure Auditd
yum install auditd
systemctl enable auditd
systemctl start auditd
wget raw.githubusercontent.com/Neo23x0/auditd/refs/heads/master/audit.rules
rm /etc/audit/rules.d/audit.rules
mv audit.rules audit.rules /etc/audit/rules.d/
# CHANGE VALUE TO RefuseManualStop=no
if grep -q "RefuseManualStop=no" /usr/lib/systemd/system/auditd.service
then
    echo "RefuseManualStop already set to no"
else
    echo "Setting RefuseManualStop to no..."
    sed -i 's/RefuseManualStop=yes/RefuseManualStop=no/g' /usr/lib/systemd/system/auditd.service
fi

Auditctl -R /etc/audit/rules.d/audit.rules
systemctl restart auditd
Service auditd restart
Systemctl daemon-reload


# Bulk remove services
yum remove xinetd telnet-server rsh-server telnet rsh ypbind ypserv tftp-server cronie-anacron bind vsftpd dovecot squid net-snmpd postfix vim httpd-manual -y

# Bulk disable services
systemctl disable xinetd
systemctl disable rexec
systemctl disable rsh
systemctl disable rlogin
systemctl disable ypbind
systemctl disable tftp
systemctl disable certmonger
systemctl disable cgconfig
systemctl disable cgred
systemctl disable cpuspeed
systemctl enable irqbalance
systemctl disable kdump
systemctl disable mdmonitor
systemctl disable messagebus
systemctl disable netconsole
systemctl disable ntpdate
systemctl disable oddjobd
systemctl disable portreserve
systemctl enable psacct
systemctl disable qpidd
systemctl disable quota_nld
systemctl disable rdisc
systemctl disable rhnsd
systemctl disable rhsmcertd
systemctl disable saslauthd
systemctl disable smartd
systemctl disable sysstat
systemctl enable crond
systemctl disable atd
systemctl disable nfslock
systemctl disable named
systemctl disable dovecot
systemctl disable squid
systemctl disable snmpd
systemctl disable postfix

# Disable rpc
systemctl disable rpcgssd
systemctl disable rpcsvcgssd
systemctl disable rpcidmapd

# Disable Network File Systems (netfs)
systemctl disable netfs

# Disable Network File System (nfs)
systemctl disable nfs

##################################################
#
#           END CENTOS HARDENING
#
##################################################

yum update -y && yum upgrade -y
yum install -y screen netcat aide clamav tmux lynis

# Set up AIDE
echo "Initializing AIDE..."
# add /var/www/html to the aide.conf file
# Check if the changes have already been made
if grep -q "/var/www/html" /etc/aide.conf
then
    echo "/var/www/html already in aide.conf"
else
    echo "/var/www/html CONTENT_EX" >> /etc/aide.conf
fi

# check if /ccdc is in the aide.conf file
if grep -q "/ccdc" /etc/aide.conf
then
    echo "/ccdc already in aide.conf"
else
    echo "/ccdc CONTENT_EX" >> /etc/aide.conf
fi

aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

echo "Setting up AIDE cron job..."
# Set up cron job for AIDE
# Check if the cron job already exists
if [ -f "/etc/cron.d/aide" ]; then
    echo "AIDE cron job already exists"
else
    echo "Setting up AIDE cron job..."
    # echo "*/5 * * * * /usr/sbin/aide --check > /tmp/aide.log && mv /tmp/aide.log /root/aide.log" > /etc/cron.d/aide
fi

# Check if changes were already made to the network config file
if grep -q "IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
then
    echo "Network config file already has IPv6 settings"
else
    echo "Setting up IPv6..."
    # get the interface name
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    echo "IPV6INIT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6ADDR=fd00:3::70/64" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    echo "IPV6_DEFAULTGW=fd00:3::1" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACE
    systemctl restart network
fi

# Set up ClamAV
echo "Initializing ClamAV..."
freshclam

# Install monitor script
wget $BASEURL/linux/E-Comm/monitor.sh -O /ccdc/scripts/monitor.sh
chmod +x /ccdc/scripts/monitor.sh

wget $BASEURL/linux/E-Comm/update_apache.sh -O /ccdc/scripts/update_apache.sh
chmod +x /ccdc/scripts/update_apache.sh

cp -R /bkp /etc/frr

echo "Finished running init.sh, please reboot the system to apply changes"
