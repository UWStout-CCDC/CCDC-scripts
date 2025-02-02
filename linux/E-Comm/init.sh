#!/bin/bash
BASEURL=https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/fix/ecomm-init #TODO: Update this URL to the correct branch
read -p "Enter the default password for the PrestaShop database: " -s DEFAULT_PRESTA_PASS

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
wget -O /etc/yum.repos.d/CentOS-Base.repo $BASEURL/linux/E-Comm/CentOS-Base.repo

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

# Lock all users except root and sysadmin
USER_LOCK_SCRIPT="$SCRIPT_DIR/linux/user_lock.sh"
wget -O $USER_LOCK_SCRIPT $BASEURL/linux/E-Comm/user_lock.sh
chmod +x $USER_LOCK_SCRIPT
bash $USER_LOCK_SCRIPT

# Grab script so it's guarnteed to be in /ccdc/scripts/linux
wget -O $SCRIPT_DIR/linux/init.sh $BASEURL/linux/E-Comm/init.sh
chmod +x $SCRIPT_DIR/linux/init.sh

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
  mysqldump -u root --all-databases > /bkp/ecomm.sql
else
  mysqldump -u root -p$DEFAULT_PRESTA_PASS --all-databases > /bkp/ecomm.sql
fi

# Remove prestashop admin directory, its in /var/www/html/prestashop and it will have random characters after admin
rm -rf /var/www/html/prestashop/admin*

# Remove the unneeded directories from prestashop
rm -rf /var/www/html/prestashop/install
rm -rf /var/www/html/prestashop/docs
rm -f /var/www/html/prestashop/README.md

# edit the /etc/httpd/conf/httpd.conf file and add hardening options for prestashop
# Add the following to the end of the file
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

# Prevent access to sensitive files
<FilesMatch "\.(env|ini|log|bak|swp|sql|git)">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Disable directory listing
<IfModule autoindex_module>
    Options -Indexes
</IfModule>

EOF

# Edit the /etc/httpd/conf.d/php.conf file and add the following to the end of the file
cat <<EOF >> /etc/httpd/conf.d/php.conf
# Disable PHP engine in the uploads directory
<Directory "/var/www/html/prestashop/upload">
    php_flag engine off
</Directory>

# Disable PHP engine in the download directory
<Directory "/var/www/html/prestashop/download">
    php_flag engine off
</Directory>
EOF

# Check if the change_sql_pass.sh script exists, if it is then run it
if [ -f "$SCRIPT_DIR/linux/change_sql_pass.sh" ]; then
    bash $SCRIPT_DIR/linux/change_sql_pass.sh $DEFAULT_PRESTA_PASS
fi


# Restart the httpd service
systemctl restart httpd


if [ ! -d "/bkp/new" ]; then
    mkdir -p /bkp/new
fi


echo "Zipping up edited /var/www/html..."
tar -czf /bkp/new/html-changed.tar.gz /var/www/html

# zip up the /etc/httpd directory and move it to /bkp
echo "Zipping up edited /etc/httpd..."
tar -czf /bkp/new/httpd-changed.tar.gz /etc/httpd

# backup the mysql database
if [ -z "$DEFAULT_PRESTA_PASS" ]; then
  mysqldump -u root --all-databases > /bkp/ecomm-changed.sql
else
  mysqldump -u root -p$DEFAULT_PRESTA_PASS --all-databases > /bkp/ecomm-changed.sql
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

# Automatically apply IPTABLES_SCRIPT on boot
systemctl enable --now ccdc_firewall.service

yum update -y && yum upgrade -y
yum install -y screen netcat aide clamav tmux

# Set up AIDE
echo "Initializing AIDE..."
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

echo "Setting up AIDE cron job..."
# Set up cron job for AIDE
echo "*/5 * * * * /usr/sbin/aide --check > /tmp/aide.log && mv /tmp/aide.log /root/aide.log" > /etc/cron.d/aide


# Set up ClamAV
echo "Initializing ClamAV..."
freshclam

# Install monitor script
wget $BASEURL/linux/E-Comm/monitor.sh -O /ccdc/scripts/monitor.sh
chmod +x /ccdc/scripts/monitor.sh

echo "Finished running init.sh, please reboot the system to apply changes"