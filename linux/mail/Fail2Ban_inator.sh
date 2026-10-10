#!/bin/bash
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
