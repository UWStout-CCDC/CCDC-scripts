#!/bin/bash

echo "Clearing mail logs and mailboxes for all users..."

#MAIL_LOG="/var/log/maillog"
MAIL_BASE="/home"

# Ensure only root can run the script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!"
   exit 1
fi

# Iterate over users and clear mailboxes
for user in $(ls $MAIL_BASE); do
    MAILDIR="$MAIL_BASE/$user/Maildir"
    
    if [[ -d "$MAILDIR" ]]; then
        echo "Clearing emails for user: $user"

        # Delete all emails in cur, new, and tmp
        rm -rf "$MAILDIR/cur/"* "$MAILDIR/new/"* "$MAILDIR/tmp/"*

        # Reset ownership (to avoid permission issues)
        chown -R "$user:$user" "$MAILDIR"
    fi
done

# Properly clear mail logs
#echo "Clearing mail logs..."
#if [[ -f "$MAIL_LOG" ]]; then
#    systemctl stop rsyslog
#    systemctl stop postfix
#    systemctl stop dovecot

#    echo "" > "$MAIL_LOG"  # Truncate the log file
#    rm -f "$MAIL_LOG"       # Delete the file
#    touch "$MAIL_LOG"       # Recreate an empty log file
#    chmod 640 "$MAIL_LOG"   # Set correct permissions

#    systemctl start rsyslog
    systemctl start postfix
    systemctl start dovecot
    echo "Mail logs cleared successfully."
#else
#    echo "Mail log file not found!"
#fi

echo "All mailboxes and logs have been cleared!"
