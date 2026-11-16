#!/bin/bash
# cron_check.sh - CCDC cron persistence check (Ubuntu)
# Usage: sudo ./cron_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo) or you'll miss user crontabs."
    exit 1
fi

# Patterns that usually mean trouble in a cron job
SUS='curl|wget|nc |ncat|netcat|/dev/tcp|/dev/udp|bash -i|sh -i|base64|python|perl|php -r|ruby|socat|mkfifo|/tmp/|/dev/shm|/var/tmp|chmod \+s|useradd|passwd|\.sh'

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'

header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }

# Print active (non-comment, non-blank) lines and flag suspicious ones
show_file() {
    local f="$1"
    [ -f "$f" ] || return
    echo -e "${YEL}--- $f${NC}  ($(stat -c '%U:%G %a modified %y' "$f" | cut -d. -f1))"
    grep -vE '^\s*#|^\s*$' "$f" | while IFS= read -r line; do
        if echo "$line" | grep -qiE "$SUS"; then
            echo -e "  ${RED}[SUS] $line${NC}"
        else
            echo "        $line"
        fi
    done
}

# Script dirs (cron.hourly etc.) run whole files, so check file contents too
show_dir() {
    local d="$1"
    header "$d"
    if [ ! -d "$d" ]; then echo "  (does not exist)"; return; fi
    ls -la "$d"
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        [ "$(basename "$f")" = ".placeholder" ] && continue
        show_file "$f"
    done
}

# 1. /etc/crontab
header "/etc/crontab"
[ -f /etc/crontab ] && show_file /etc/crontab || echo "  (does not exist)"

# 2. /etc/cron.d and periodic dirs
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    show_dir "$d"
done

# 3. User crontabs (Ubuntu stores them in /var/spool/cron/crontabs)
show_dir /var/spool/cron/crontabs

# 4. Anything else in /var/spool/cron (atjobs, stray files)
header "/var/spool/cron (full tree)"
if [ -d /var/spool/cron ]; then
    ls -laR /var/spool/cron
    find /var/spool/cron -type f ! -path '*/crontabs/*' | while read -r f; do show_file "$f"; done
else
    echo "  (does not exist)"
fi

# 5. Per-user crontab -l (catches anything the spool listing missed)
header "crontab -l for every user"
cut -d: -f1 /etc/passwd | while read -r u; do
    out=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*#|^\s*$')
    if [ -n "$out" ]; then
        echo -e "${YEL}--- user: $u${NC}"
        echo "$out" | while IFS= read -r line; do
            if echo "$line" | grep -qiE "$SUS"; then
                echo -e "  ${RED}[SUS] $line${NC}"
            else
                echo "        $line"
            fi
        done
    fi
done

# 6. anacrontab
header "/etc/anacrontab"
[ -f /etc/anacrontab ] && show_file /etc/anacrontab || echo "  (does not exist)"

# 7. cron.allow / cron.deny
for f in /etc/cron.allow /etc/cron.deny; do
    header "$f"
    if [ -f "$f" ]; then
        stat -c '%U:%G %a modified %y' "$f" | cut -d. -f1
        cat "$f"
        [ "$f" = /etc/cron.allow ] && echo -e "${YEL}  NOTE: only users listed above can use crontab${NC}"
    else
        echo "  (does not exist)"
        [ "$f" = /etc/cron.allow ] && echo "  NOTE: no cron.allow -> any user not in cron.deny can use crontab"
    fi
done

# 8. Recently modified cron files (last 7 days) - quick triage
header "Cron files modified in last 7 days"
find /etc/crontab /etc/cron.* /etc/anacrontab /var/spool/cron -type f -mtime -7 2>/dev/null -exec ls -la {} \;

echo -e "\n${GRN}[*] Done. Review anything marked ${RED}[SUS]${GRN} and any unexpected files.${NC}"
