#!/bin/bash
# first5.sh - CCDC first 5 minutes (Ubuntu)
# Snapshot -> backup -> passwords -> kick sessions -> baseline scans
# Asks before changing anything. Usage: sudo ./first5.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
step() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
ask()  { local a; read -r -p "$(echo -e "${YEL}$1 [y/N]: ${NC}")" a; [[ "$a" =~ ^[Yy] ]]; }

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="/root/ccdc/$(date +%H%M)"
mkdir -p "$OUT"/{snapshot,backup,baseline}
chmod 700 /root/ccdc
echo "Saving everything to $OUT"
START=$(date +%s)

# ---------------------------------------------------------------
step "1. Snapshot (what the box looks like before we touch it)"
# Good for your incident report: proves what was there at start
S="$OUT/snapshot"
{ date; hostname; ip -br a; ip r; } > "$S/host.txt" 2>&1
who -a        > "$S/who.txt" 2>&1
w             > "$S/w.txt" 2>&1
last -n 30    > "$S/last.txt" 2>&1
ps auxf       > "$S/ps.txt" 2>&1
ss -tunap     > "$S/ss.txt" 2>&1
systemctl list-units --type=service --state=running --no-pager > "$S/services.txt" 2>&1
cp /etc/passwd /etc/group "$S/" 2>/dev/null
echo "  saved to $S"

echo -e "\n${YEL}Who is logged in right now:${NC}"
w -h 2>/dev/null | sed 's/^/        /'
echo -e "\n${YEL}Listening ports (these are probably your scored services - don't firewall them off):${NC}"
ss -tulnp 2>/dev/null | awk 'NR>1 {print "        "$1, $5, $7}' | sort -u

# ---------------------------------------------------------------
step "2. Backup (so you can undo anything)"
B="$OUT/backup"
tar czf "$B/etc.tgz" /etc 2>/dev/null && echo "  /etc         -> $B/etc.tgz"
[ -d /var/www ] && tar czf "$B/www.tgz" /var/www 2>/dev/null && echo "  /var/www     -> $B/www.tgz"
tar czf "$B/ssh_keys.tgz" /root/.ssh /home/*/.ssh 2>/dev/null && echo "  ssh keys     -> $B/ssh_keys.tgz"
crontab -l > "$B/root_crontab.txt" 2>/dev/null
cp -a /var/spool/cron "$B/spool_cron" 2>/dev/null

# Database (OpenCart uses MySQL/MariaDB). Ubuntu root usually logs in via socket, no password needed.
if command -v mysqldump >/dev/null; then
    if timeout 60 mysqldump --all-databases --single-transaction > "$B/all_databases.sql" 2>/dev/null; then
        echo "  MySQL        -> $B/all_databases.sql ($(du -h "$B/all_databases.sql" | cut -f1))"
    else
        rm -f "$B/all_databases.sql"
        echo -e "  ${RED}MySQL dump failed (needs a password?). Run by hand:${NC} mysqldump -u root -p --all-databases > $B/all_databases.sql"
    fi
fi
# Second copy in a less obvious place in case red team wipes /root/ccdc
HIDE="/var/lib/.cache-$(hostname | md5sum | cut -c1-6)"
mkdir -p "$HIDE" && cp -a "$B"/. "$HIDE"/ && chmod -R 700 "$HIDE"
echo "  second copy  -> $HIDE   (also scp backups OFF the box when you can)"

# ---------------------------------------------------------------
step "3. Passwords"

# Red team trick: chattr +i on /etc/shadow (or /etc itself) makes passwd fail with
# "Authentication token manipulation error". Check + fix before changing anything.
echo "Checking if account files are locked (immutable/append-only)..."
LOCKFILES="/etc /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d \
/etc/.pwd.lock /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- /etc/nshadow /etc/npasswd \
/etc/pam.d /etc/pam.d/common-password /etc/ssh/sshd_config /root/.ssh /root/.ssh/authorized_keys"

if ! command -v lsattr >/dev/null || ! command -v chattr >/dev/null; then
    echo -e "  ${RED}[SUS] lsattr/chattr missing - red team may have deleted them so you can't remove +i${NC}"
    echo "        fix: apt-get install --reinstall e2fsprogs   (or: busybox chattr -i /etc/shadow)"
else
    LOCKED=""
    for f in $LOCKFILES /home/*/.ssh /home/*/.ssh/authorized_keys; do
        [ -e "$f" ] || continue
        attrs=$(lsattr -d "$f" 2>/dev/null | awk '{print $1}')
        if [[ "$attrs" == *i* || "$attrs" == *a* ]]; then
            echo -e "  ${RED}[SUS] $attrs $f${NC}"
            LOCKED="$LOCKED $f"
        fi
    done
    if [ -z "$LOCKED" ]; then
        echo -e "  ${GRN}none locked${NC}"
    elif ask "Remove immutable/append-only flags from these?"; then
        for f in $LOCKED; do
            chattr -i -a "$f" && echo "$(date +%H:%M) chattr -i -a $f" >> "$OUT/actions.log"
        done
        echo "  unlocked. (red team may re-lock - if passwd fails later, re-check: lsattr /etc/shadow)"
    fi
fi
# Other reasons passwd fails with the same error
ROOTFS=$(findmnt -no OPTIONS / 2>/dev/null)
[[ "$ROOTFS" == ro,* || "$ROOTFS" == ro ]] && echo -e "  ${RED}[SUS] / is mounted READ-ONLY. fix: mount -o remount,rw /${NC}"
USE=$(df --output=pcent /etc 2>/dev/null | tail -1 | tr -dc 0-9)
[ -n "$USE" ] && [ "$USE" -ge 98 ] && echo -e "  ${RED}[SUS] disk is ${USE}% full - passwd can't write. Free space (check /tmp, /var/log)${NC}"
echo

echo -e "${RED}CHECK YOUR PACKET: changing a scored account's password can break scoring.${NC}"
echo "Accounts that can log in:"
mapfile -t USERS < <(awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd)
for u in "${USERS[@]}"; do
    echo "        $u (uid $(id -u "$u"), groups: $(id -nG "$u" | tr ' ' ','))"
done
echo
for u in "${USERS[@]}"; do
    if ask "Change password for $u?"; then
        if passwd "$u"; then
            echo "$(date +%H:%M) changed password: $u" >> "$OUT/actions.log"
        else
            echo -e "  ${RED}passwd FAILED for $u. Check: lsattr /etc/shadow /etc ; findmnt / ; df -h /etc${NC}"
        fi
    fi
done

# ---------------------------------------------------------------
step "4. Kick other sessions"
MYTTY=$(tty 2>/dev/null | sed 's|/dev/||')
echo "You are on: ${MYTTY:-unknown} (this one is never killed)"
who | while read -r u t _; do echo "        $u on $t"; done
for t in $(who | awk '{print $2}' | sort -u); do
    [ "$t" = "$MYTTY" ] && continue
    if ask "Kill session on $t ($(who | awk -v t="$t" '$2==t {print $1; exit}'))?"; then
        pkill -KILL -t "$t" && echo "$(date +%H:%M) killed session $t" >> "$OUT/actions.log"
    fi
done
echo -e "\n${YEL}Established remote connections (look for shells/reverse connections):${NC}"
ss -tnp state established 2>/dev/null | awk 'NR>1 {print "        "$3" -> "$4"  "$5}'

# ---------------------------------------------------------------
step "5. Baseline scans (read-only)"
B2="$OUT/baseline"
for s in users_check ssh_check webshell_check systemd_check cron_check shell_check; do
    if [ -f "$HERE/$s.sh" ]; then
        echo -n "  running $s ... "
        bash "$HERE/$s.sh" > "$B2/$s.txt" 2>&1
        echo "$(grep -c '\[SUS\]' "$B2/$s.txt") flagged"
    else
        echo -e "  ${YEL}$s.sh not found next to this script - skipped${NC}"
    fi
done

echo -e "\n${YEL}Everything flagged:${NC}"
grep -h '\[SUS\]' "$B2"/*.txt 2>/dev/null | grep -v 'Review anything marked' | sed 's/\x1b\[[0-9;]*m//g' | head -60

# ---------------------------------------------------------------
step "Done in $(( $(date +%s) - START ))s"
cat <<EOF
  Snapshot:  $OUT/snapshot
  Backups:   $OUT/backup   (+ copy in $HIDE)
  Baseline:  $OUT/baseline
  Actions:   $OUT/actions.log

  Next:
   - Fix flagged items (screenshot first for the incident report)
   - Firewall: allow ONLY the listening ports above, e.g.
       ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw enable
   - Re-check later and diff:  diff $B2/users_check.txt <(sudo bash $HERE/users_check.sh 2>&1)
EOF
