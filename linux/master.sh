#! /bin/bash
#
# master.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#


# Master script
if [[ $EUID -ne 0 ]]; then
	printf 'Must be run as root, exiting!\n'
	exit 1
fi

# Definitions
CCDC_DIR="/ccdc"
DOWNLOAD_DIR="$CCDC_DIR/downloads"
SCRIPT_DIR="$CCDC_DIR/scripts"

mkdir -p $CCDC_DIR
cd $CCDC_DIR
mkdir -p $DOWNLOAD_DIR
mkdir -p $SCRIPT_DIR

# Useful functions
confirm() {
	read -r -p "$1 [Y/n]:" RES
	[[ !("$RES" =~ ^([nN]).*$) ]]
}

get() {
	mkdir -p $(dirname "$DOWNLOAD_DIR/$1")
	curl "https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts-2020/master/$1" > "$DOWNLOAD_DIR/$1"
}

if false;then
#create user ccdc with home dir '/ccdc'

# Pull suplemental resources
#get linux/iptables.sh

# Reporting
get linux/log_state.sh
bash $DOWNLOAD_DIR/linux/log_state.sh

# Passwords
# force user to change password, maybe figure out how?
read -r -p "Username:" $USER
passwd $USER

fi

# Packages/Repos
# Fix CentOS 6 repos

# Iptables
IPTABLES_SCRIPT="$SCRIPT_DIR/iptables.sh"
cat <<- EOF > $IPTABLES_SCRIPT
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
	iptables -t filter -a output -p udp --dport 123 -j accept

	# Splunk
	iptables -t filter -a output -p tcp --dport 8000 -j accept
	iptables -t filter -a output -p tcp --dport 8089 -j accept
	iptables -t filter -a output -p tcp --dport 9997 -j accept

	######## OUTBOUND SERVICES ###############

	# SSH
	iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

	EOF

confirm "HTTP(S) Server?" && cat <<- EOF >> $IPTABLES_SCRIPT
	# HTTP/HTTPS (apache) iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
	iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

	EOF

confirm "DNS Server?" && cat <<- EOF >> $IPTABLES_SCRIPT
	# DNS (bind)
	iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
	iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT

	EOF

confirm "MAIL Server?" && cat <<- EOF >> $IPTABLES_SCRIPT
	# SMTP
	iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
	iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT

	# POP3
	iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
	iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT

	# IMAP
	iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
	iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT

	EOF

confirm "NTP Server?" && cat <<- EOF >> $IPTABLES_SCRIPT
	# DNS (bind)
	iptables -t filter -A INPUT -p tcp --dport 123 -j ACCEPT
	iptables -t filter -A INPUT -p udp --dport 123 -j ACCEPT

	EOF

bash $IPTABLES_SCRIPT

# Splunk forwarder
get linux/splunk.sh
read -r -p "Splunk Server IP: " SPLUNK_SERVER
bash $DOWNLOAD_DIR/linux/splunk.sh $SPLUNK_SERVER

# SSH Server config
get linux/sshd_config

mkdir -p $CCDC_DIR/ssh/
cp /etc/ssh/sshd_config $CCDC_DIR/ssh/sshd_config.old
cp $DOWNLOAD_DIR/linux/sshd_config /etc/ssh/sshd_config

# Disable all keys - sshd_config will set the server to check this file
touch /ccdc/ssh/authorized_keys

# Restart service
if type systemctl
then
	systemctl restart sshd
else
	service sshd restart
fi

# set NTP server
read -r -p "NTP Server IP: " NTP_SERVER

######## Services ########

# NTP config

# Bind config

# Mail server config

# Apache/NginX

# Splunk Server
# Enable SSL for the webserver? - probably breaks the scoring engine

# FTP Server for firewall backups
# SSH servers?
# 
# Spiceworks?
# SNMP

# Upgrade distrobution
