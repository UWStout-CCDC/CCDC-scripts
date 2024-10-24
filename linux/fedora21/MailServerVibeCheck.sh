#!/bin/bash
#Created by Kayne Whitney for vibe checking the Mail Server

echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Updating the system packages..."
dnf update postfix dovecot

echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Configuring firewall rules for mail server..."
firewall-cmd --permanent --add-service=smtp
firewall-cmd --permanent --add-service=imap
firewall-cmd --permanent --add-service=imaps
firewall-cmd --reload

# THIS IS SUBJECT TO CHANGE DEPENDING ON ENVIRONMENT
# I HAVE THIS LINE FOR MY OWN ENVIRONMENT THAT I MADE TO FAMILIARIZE MYSELF WITH MAIL SERVER
#echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
#echo "Restricting Postfix to listen on localhost..."
#postconf -e 'inet_interfaces = localhost'

#ALSO SUBJECT TO ENVIRONMENT AND ITS NEEDS
#echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
#echo "Disabling open relay in Postfix..."
#postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination'

echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Enabling and starting Postfix and Dovecot services..."
systemctl enable postfix
systemctl start postfix
systemctl enable dovecot
systemctl start dovecot

echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Securing mail logs..."
chmod 640 /var/log/maillog
chown root:adm /var/log/maillog

echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Restarting Postfix and Dovecot to apply changes..."
systemctl restart postfix
systemctl restart dovecot

echo -e "\n//////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Checking status of Postfix and Dovecot services..."
systemctl status postfix
systemctl status dovecot

echo -e "\n"
echo "Mail server script completed."

