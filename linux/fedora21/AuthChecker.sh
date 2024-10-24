#!/bin/bash
# Created by Kayne to identify important mail logs and print them to screen

# Define the log file location
MAIL_LOG="/var/log/maillog"

# Check if the log file exists
if [[ ! -f "$MAIL_LOG" ]]; then
    echo "Log file not found: $MAIL_LOG"
    exit 1
fi
echo -e "\n"
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Checking for logins and logouts in Dovecot..."
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo -e "\n"
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Dovecot Logins:"
grep -E 'dovecot.*Login' "$MAIL_LOG" | grep --color=always -E 'user=<[^>]+'
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo -e "\n"
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Dovecot Logouts:"
grep -E 'Disconnected' "$MAIL_LOG" | grep --color=always -E 'imap[^<]+'
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo -e "\n"
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
echo "Authentication Attempts:"
grep -E 'Authentication' "$MAIL_LOG" | grep --color=always -E 'Authentication[^)]+'
echo "////////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"

echo -e "\nLog check complete."
