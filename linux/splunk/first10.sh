#!/usr/bin/env bash
# First-10-minutes baseline: read-only inventory + state snapshot + root-only backups.
# Safe to re-run. Output: /root/ccdc/base-<UTC>/ (base-latest symlink)
. "$(dirname "$(readlink -f "$0")")/common.sh"
need_root; mkcc
B="$CC/base-$TS"; mkdir -p "$B"; ln -sfn "$B" "$CC/base-latest"
exec > >(tee "$B/first10.txt") 2>&1
log "first10 started"
SH=$(splunk_home); UNIT=$(splunk_unit)

hdr "Who is on this box right now"; w; echo; last -n 10 -a 2>/dev/null
hdr "Time / IPs"; date -u; timedatectl 2>/dev/null | grep -E 'System clock|NTP' ; ip -br a
hdr "Splunk unit"
echo "unit=${UNIT:-NOT FOUND}  home=$SH  user=$(splunk_user)"
if [ -n "$UNIT" ]; then
  systemctl is-active "$UNIT"; systemctl is-enabled "$UNIT" 2>&1
  [ "$(systemctl is-enabled "$UNIT" 2>&1)" = masked ] && red "!! $UNIT IS MASKED -> run splunk-recover.sh"
fi
hdr "Listeners"; ss -lntup
hdr "UID 0 / login shells / sudo-capable"
awk -F: '$3==0 && $1!="root"{print "!! extra UID0: "$1}' /etc/passwd
getent passwd | awk -F: '($3<1000 && $3!=0 && $7 !~ /(nologin|false|sync)$/){print "!! system acct w/ shell: "$1" "$7}'
getent passwd | awk -F: '$3>=1000 && $1!="nobody"{print "user: "$1" uid="$3" shell="$7" home="$6}'
getent group sudo adm wheel docker 2>/dev/null
grep -RnE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/!! /'
hdr "Preload / masked units"
[ -e /etc/ld.so.preload ] && { red "!! /etc/ld.so.preload EXISTS:"; cat /etc/ld.so.preload; } || grn "no ld.so.preload"
find /etc/systemd/system -type l -lname /dev/null -exec ls -l {} \; 2>/dev/null | sed 's/^/!! masked: /'
hdr "Timers + cron (quick look)"; systemctl list-timers --all --no-pager | head -25
cat /etc/crontab 2>/dev/null | grep -vE '^#|^$'; ls -la /etc/cron.d 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^#|^$'); [ -n "$c" ] && { echo "[crontab $u]"; echo "$c"; }; done
atq 2>/dev/null

hdr "Saving state snapshot for watch.sh"
state_snapshot "$B" nosuid
( nice -n 10 find / -xdev -perm /6000 -type f 2>/dev/null | sort > "$B/suid.txt" ) &
echo "(SUID sweep running in background -> $B/suid.txt)"
tar --acls --xattrs -czpf "$B/sysconf.tgz" /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d \
  /etc/ssh /etc/pam.d /etc/systemd/system /etc/cron* /var/spool/cron /etc/profile /etc/profile.d \
  /etc/bash.bashrc /etc/environment /etc/hosts /etc/resolv.conf /etc/nftables.conf /etc/rc.local 2>/dev/null
sha256sum "$B/sysconf.tgz" | tee "$B/sysconf.tgz.sha256"
hdr "Splunk config backup (evidence copy, NOT yet known-good)"
"$(dirname "$(readlink -f "$0")")/splunk-backup.sh" first10 > "$B/backup.log" 2>&1 &
echo "(Splunk backup running in background -> tail $B/backup.log)"
echo; grn "Done. Baseline: $B"
hdr "Immutable files in key dirs (attackers use chattr +i to protect persistence)"
lsattr -R /etc /root /usr/lib/systemd /usr/local /opt 2>/dev/null | awk '$1 ~ /^[-a-zA-Z]*i/ && $2 !~ /:$/ {print "!! immutable: "$2}' | grep -v '^!! immutable: /opt/splunk/var' | head -20
echo "Next: ./splunk-check.sh   then   ./accounts.sh   then   ./hunt.sh"
log "first10 finished ($B)"
