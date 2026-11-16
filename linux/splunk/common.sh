# shellcheck shell=bash
# Shared helpers. Sourced by the other scripts. Debian 12 target.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
CC="${CCDC_DIR:-/root/ccdc}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }
hdr(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
fail(){ red "ERROR: $*"; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || fail "run as root (sudo -i first)"; }
mkcc(){ ( umask 077; mkdir -p "$CC" ); chmod 700 "$CC"; }
log(){ mkcc; echo "$(date -u +%FT%TZ) $*" >> "$CC/timeline.log"; }
confirm(){ [ "${YES:-0}" = 1 ] && return 0; read -r -p "$1 [y/N] " _a; [ "$_a" = y ] || [ "$_a" = Y ]; }

splunk_home(){
  for d in "${SPLUNK_HOME:-}" /opt/splunk; do
    [ -n "$d" ] && [ -x "$d/bin/splunk" ] && { echo "$d"; return; }
  done
  echo /opt/splunk
}
splunk_unit(){
  systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' \
    | grep -iE '^splunk.*\.service$' | grep -vi forwarder | head -1
}
splunk_user(){ stat -c %U "$(splunk_home)/bin/splunk" 2>/dev/null || echo splunk; }
as_splunk(){ runuser -u "$(splunk_user)" -- "$@"; }

# state_snapshot DIR [full]  -> small text files the watcher diffs
state_snapshot(){
  local d=$1 full=${2:-}
  mkdir -p "$d"
  getent passwd | awk -F: '{print $1":"$3":"$7}' | sort > "$d/users.txt"
  ss -H -lntu 2>/dev/null | awk '{print $1,$5}' | sort -u > "$d/listen.txt"
  systemctl list-unit-files --no-legend --type=service,timer,socket,path 2>/dev/null \
    | awk '{print $1,$2}' | sort > "$d/units.txt"
  { find /etc/cron* /var/spool/cron /var/spool/at* -type f 2>/dev/null | sort | xargs -r sha256sum; atq 2>/dev/null; } > "$d/cron.txt"
  find /root /home /opt /var -xdev -maxdepth 5 -name 'authorized_keys*' -type f 2>/dev/null | sort | xargs -r sha256sum > "$d/keys.txt"
  { sha256sum /etc/sudoers /etc/sudoers.d/* 2>/dev/null; } > "$d/sudo.txt"
  { find /etc/pam.d /etc/ssh -type f 2>/dev/null | sort | xargs -r sha256sum; } > "$d/pam_ssh.txt"
  { for f in /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/environment /etc/ld.so.preload /etc/rc.local; do [ -e "$f" ] && sha256sum "$f"; done; } > "$d/profile.txt" 2>/dev/null
  { find /etc/systemd/system /usr/local/lib/systemd /etc/udev/rules.d /etc/NetworkManager/dispatcher.d -type f 2>/dev/null | sort | xargs -r sha256sum; find /etc/systemd/system -type l -lname /dev/null 2>/dev/null | sort; } > "$d/localunits.txt"
  if [ "$full" = full ] || { [ "$full" != nosuid ] && [ ! -f "$d/suid.txt" ]; }; then
    find / -xdev -perm /6000 -type f 2>/dev/null | sort > "$d/suid.txt"
  fi
}

# rmforce PATH : clear immutable/append-only flags, remove, and VERIFY it is really gone (returns 0 only if gone)
rmforce(){
  local f=$1
  [ -e "$f" ] || [ -L "$f" ] || return 0
  lsattr -d "$f" 2>/dev/null | awk '{print $1}' | grep -qE '[ia]' && chattr -ia "$f" 2>/dev/null
  rm -f -- "$f" 2>/dev/null
  if [ -e "$f" ] || [ -L "$f" ]; then red "FAILED to remove $f (flags: $(lsattr -d "$f" 2>&1 | awk '{print $1}'))"; return 1; fi
  return 0
}
# refs STRING : where else is this name/path referenced? (finds the thing that REBUILDS it)
refs(){
  grep -rIl --exclude-dir=quarantine --exclude-dir=ccdc -- "$1" /etc /usr/local /usr/lib/systemd /var/spool /root /opt/splunk/etc/apps 2>/dev/null | head -10
  for j in $(atq 2>/dev/null | awk '{print $1}'); do at -c "$j" 2>/dev/null | grep -qF -- "$1" && echo "at job $j"; done
}
