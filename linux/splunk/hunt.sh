#!/usr/bin/env bash
# hunt.sh [--deep]  Read-only persistence sweep for Debian 12 + Splunk. Output saved to /root/ccdc/hunt-<UTC>.txt
# Findings starting with "!!" deserve a look. Nothing here changes the system.
# --deep adds a full 'dpkg --verify' (slow) and a 60-min recent-file sweep.
. "$(dirname "$(readlink -f "$0")")/common.sh"
need_root; mkcc
DEEP=0; [ "${1:-}" = --deep ] && DEEP=1
exec > >(tee "$CC/hunt-$TS.txt") 2>&1
SH=$(splunk_home); UNIT=$(splunk_unit); SU=$(splunk_user)
SUS='curl[^|]*\|[^|]*(sh|bash)|wget[^|]*\|[^|]*(sh|bash)|base64 +-d|/dev/tcp/|nc +-e|ncat|socat|python[0-9.]* +-c|perl +-e|mkfifo|LD_PRELOAD|LD_LIBRARY_PATH|bash +-i|chattr|/dev/shm|/var/tmp|/tmp/\.'
scan(){ grep -nEH "$SUS" "$@" 2>/dev/null | sed 's/^/!! /'; }
log "hunt started"

hdr "1 accounts / sudo / ssh"
awk -F: '$3==0 && $1!="root"{print "!! extra UID0: "$1}' /etc/passwd
getent passwd | awk -F: '$3<1000 && $3!=0 && $7 !~ /(nologin|false|sync)$/{print "!! sys acct w/ shell: "$1" "$7}'
grep -RnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/!! /'
ls -la /etc/sudoers.d
sshd -T 2>/dev/null | grep -E '^(authorizedkeyscommand|forcecommand|permitemptypasswords|permitrootlogin) ' 
find /root /home -maxdepth 4 -name 'authorized_keys*' -type f 2>/dev/null | sed 's/^/!! key file: /'
grep -RnE 'pam_exec|pam_script|pam_permit' /etc/pam.d 2>/dev/null | sed 's/^/!! pam: /'
find /etc/pam.d /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security -type f -mtime -3 2>/dev/null | sed 's/^/!! recent pam: /'

sshd -T 2>/dev/null | grep -E '^port ' | sed 's/^/sshd /'
echo "-- immutable/append-only files (chattr +i hides persistence from rm):"
lsattr -R /etc /root /usr/lib/systemd /usr/local /opt/splunk/etc /var/spool 2>/dev/null | awk '$1 ~ /^[-a-zA-Z]*[ia]/ && $2 !~ /:$/ {print "!! immutable: "$2}' | head -30
echo "-- established connections (look for odd remote IPs/ports, shells):"; ss -tnp state established 2>/dev/null | head -20

hdr "2 shell/profile/env hooks"
scan /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/environment /etc/skel/.* /etc/skel/* /root/.bashrc /root/.profile /root/.bash_profile
for h in /home/*; do scan "$h"/.bashrc "$h"/.profile "$h"/.bash_profile "$h"/.zshrc; done
grep -RnE '^\s*alias (ls|ps|ss|netstat|ssh|sudo|cat|systemctl|top)=' /etc/profile.d /etc/bash.bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null | sed 's/^/!! alias: /'
ls -la /etc/profile.d

hdr "3 cron / at / timers"
scan /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/anacrontab /var/spool/cron/crontabs/*
find /etc/cron* /var/spool/cron -type f -mtime -3 -ls 2>/dev/null | sed 's/^/recent: /'
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -vE '^#|^$' | sed "s/^/[cron $u] /"; done
atq 2>/dev/null; ls /var/spool/cron/atjobs 2>/dev/null
for j in $(atq 2>/dev/null | awk '{print $1}'); do echo "[at job $j body]"; at -c "$j" 2>/dev/null | tail -6; done
grep -RnE '/dev/tcp/|bash +-i|nc +-e|mkfifo' /etc/cron* /var/spool/cron /var/spool/at* /usr/local 2>/dev/null | sed 's/^/!! REVERSE SHELL: /'
echo "-- cron.d files not owned by a package (stock Debian: e2scrub_all, .placeholder, sysstat etc):"
for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do [ -f "$f" ] && ! dpkg -S "$f" >/dev/null 2>&1 && echo "!! non-package cron file: $f"; done
systemctl list-timers --all --no-pager

hdr "4 systemd: local (non-package) units, masks, drop-ins, linger"
find /etc/systemd/system -type l -lname /dev/null -exec ls -l {} \; 2>/dev/null | sed 's/^/!! MASKED: /'
find /etc/systemd/system /usr/local/lib/systemd /run/systemd/system -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) 2>/dev/null | while read -r f; do
  echo "unit file: $f ($(stat -c '%y %U' "$f" | cut -c1-19))"; grep -HE '^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload|Environment|EnvironmentFile)=' "$f" | sed 's/^/     /'
done
scan /etc/systemd/system/*.service /etc/systemd/system/*/*.conf /etc/systemd/system/*.timer
ls /var/lib/systemd/linger 2>/dev/null | sed 's/^/!! linger enabled: /'
for h in /root /home/*; do find "$h"/.config/systemd -type f 2>/dev/null | sed 's/^/!! user unit: /'; done
systemctl --failed --no-pager | head -10

hdr "5 boot hooks / loader / modules"
for f in /etc/rc.local /etc/ld.so.preload; do [ -e "$f" ] && { red "!! $f exists:"; cat "$f"; }; done
ls /etc/rc?.d 2>/dev/null | grep -vE '^[SK][0-9]{2}' | head -3
find /etc/init.d /etc/rc*.d -type f -mtime -3 2>/dev/null | sed 's/^/recent: /'
ls -la /etc/ld.so.conf.d; cat /etc/ld.so.conf.d/* 2>/dev/null | grep -vE '^#' | grep -vE 'lib' | sed 's/^/!! ld path: /'
grep -RnE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc /root /home 2>/dev/null | grep -v '^Binary' | head -10 | sed 's/^/!! /'
lsmod | head -40; ls /etc/modules-load.d /etc/modprobe.d 2>/dev/null; scan /etc/modules-load.d/* /etc/modprobe.d/*
scan /etc/udev/rules.d/* /etc/NetworkManager/dispatcher.d/* /etc/acpi/events/* 2>/dev/null
grep -nE 'init=|rdinit=' /etc/default/grub /boot/grub/grub.cfg 2>/dev/null | sed 's/^/!! grub: /'

hdr "6 binaries / PATH hijack / SUID"
for b in ssh sshd sudo su login ps top ss netstat ls cat systemctl bash sh journalctl find grep curl; do
  p=$(command -v "$b" 2>/dev/null) || continue
  file -L "$p" | grep -qv ELF && echo "!! not an ELF: $p ($(file -L "$p" | cut -d: -f2))"
done
ls -la /usr/local/bin /usr/local/sbin 2>/dev/null
echo "PATH=$PATH"; echo "$PATH" | tr ':' '\n' | grep -E '^(/tmp|/dev/shm|/var/tmp|\.|$)' | sed 's/^/!! odd PATH entry: /'
if [ -f "$CC/base-latest/suid.txt" ]; then
  find / -xdev -perm /6000 -type f 2>/dev/null | sort | diff "$CC/base-latest/suid.txt" - | sed 's/^/!! SUID change vs baseline: /'
else find / -xdev -perm /6000 -type f 2>/dev/null | grep -vE '^/(usr/(bin|sbin|lib|libexec)|bin|sbin)/' | sed 's/^/!! SUID outside std dirs: /'; fi
echo "-- package verify (key packages; changed files shown)"
dpkg --verify coreutils procps openssh-server openssh-client sudo libc6 libpam-modules libpam-runtime login util-linux systemd bash iproute2 2>&1 | grep -v ' c ' | head -20
[ "$DEEP" = 1 ] && { echo "-- FULL dpkg --verify (conffile changes filtered)"; dpkg --verify 2>&1 | grep -v ' c ' | head -60; }

hdr "7 staging dirs / hidden / recent"
find /tmp /var/tmp /dev/shm /run/user -maxdepth 3 -type f \( -perm /111 -o -name '.*' \) -ls 2>/dev/null | sed 's/^/!! /' | head -30
find / -xdev -maxdepth 4 -name '.*' -type f \( -perm /111 -o -name '*.sh' -o -name '*.so' \) -not -path '/home/*/.*' -not -path '/root/.*' -not -path '/proc/*' -not -path '/opt/splunk/*' 2>/dev/null | head -20 | sed 's/^/!! hidden exec: /'
echo "-- changed in last 120 min (excluding splunk data, proc, sys):"
find / -xdev -type f -mmin -120 -not -path '/proc/*' -not -path '/sys/*' -not -path "$SH/var/*" -not -path '/var/log/*' -not -path '/root/ccdc/*' -not -path '/var/lib/*' 2>/dev/null | head -40
[ "$DEEP" = 1 ] && find / -xdev -type f -executable -mmin -60 -not -path '/proc/*' -not -path "$SH/var/*" 2>/dev/null | head -40

hdr "8 who ran what"
journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -E 'COMMAND=|useradd|usermod|chpasswd|passwd\[|systemctl.*(mask|disable|stop)|Accepted |session opened for user root' | tail -40
lastb -n 10 2>/dev/null; last -n 15 -a
for h in /root /home/*; do [ -f "$h/.bash_history" ] && { echo "[$h/.bash_history tail]"; tail -15 "$h/.bash_history"; }; done

hdr "9 SPLUNK-specific"
echo "unit=${UNIT:-none} home=$SH svcuser=$SU"
[ -n "$UNIT" ] && { systemctl cat "$UNIT" 2>&1 | grep -E '^(#|\[|Exec|User|Environment)'; journalctl -u "$UNIT" --since "24 hours ago" --no-pager 2>/dev/null | tail -12; }
cat "$SH/etc/splunk-launch.conf" 2>/dev/null | grep -vE '^#|^$' | sed 's/^/launch.conf: /'
ls -la "$SH/etc/apps" 2>/dev/null | awk '{print $NF}' | tr '\n' ' '; echo
echo "-- script/monitor/network inputs in LOCAL config:"
grep -RnE '^\[(script|monitor|tcp|udp|splunktcp|http|fifo)[:/]' "$SH"/etc/system/local "$SH"/etc/apps/*/local "$SH"/etc/users 2>/dev/null | sed 's/^/!! /'
echo "-- alert actions / scripted auth / custom commands:"
grep -RnEi 'action\.script|^\s*command\s*=|authType\s*=\s*Scripted|scriptPath|^\[script:|alert\.execute|\bexternal\s*=\s*true' "$SH"/etc/system/local "$SH"/etc/apps/*/local "$SH"/etc/users 2>/dev/null | sed 's/^/!! /'
echo "-- non-default executables under apps/*/bin (name, mtime):"
find "$SH"/etc/apps -path '*/bin/*' -type f -mtime -30 -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | head -25
echo "-- Splunk local users file:"; cut -d: -f2 "$SH/etc/passwd" 2>/dev/null | tr '\n' ' '; echo
echo "-- local conf changed in last 3 days:"; find "$SH"/etc/system/local "$SH"/etc/apps/*/local -type f -mtime -3 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null
echo "-- cert/key paths that do not exist:"
grep -rhE '^\s*(serverCert|privKeyPath|caCertFile|sslRootCAPath|caPath|sslKeysfile|certPath)\s*=' "$SH"/etc/system/local "$SH"/etc/apps/*/local 2>/dev/null | sed -E 's/^[^=]*=\s*//; s|\$SPLUNK_HOME|'"$SH"'|g' | sort -u | while read -r p; do [ -e "$p" ] || red "!! MISSING $p"; done
echo "-- effective web/mgmt settings:"
as_splunk "$SH/bin/splunk" btool web list settings 2>/dev/null | grep -E '^(httpport|enableSplunkWebSSL|startwebserver|mgmtHostPort|server\.socket_host)' 
as_splunk "$SH/bin/splunk" btool server list sslConfig 2>/dev/null | grep -E '^(enableSplunkdSSL|serverCert|sslVersions)'
echo "-- ownership of splunk tree (should all be $SU):"; find "$SH" -xdev \( -not -user "$SU" \) -not -path "$SH/var/run/*" 2>/dev/null | head -10 | sed 's/^/!! not owned by splunk user: /'
echo; grn "hunt complete -> $CC/hunt-$TS.txt"; log "hunt finished"
