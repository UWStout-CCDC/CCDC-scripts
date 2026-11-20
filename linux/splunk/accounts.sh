#!/usr/bin/env bash
# Account review. DRY RUN by default. Locks unexpected login accounts with --apply.
# ALLOW="sysadmin splunk" ./accounts.sh [--apply] [--keys]
#  - NEVER change the password of a scored account with passwd; use the Quotient PCR tab
#    (otherwise the scoring engine's stored password goes stale and SSH/Splunk checks fail).
#  --keys also quarantines every authorized_keys file (scoring uses password auth).
. "$(dirname "$(readlink -f "$0")")/common.sh"
need_root; mkcc
ALLOW="${ALLOW:-root sysadmin splunk}"
APPLY=0; KEYS=0
for a in "$@"; do [ "$a" = --apply ] && APPLY=1; [ "$a" = --keys ] && KEYS=1; done
allowed(){ for x in $ALLOW; do [ "$x" = "$1" ] && return 0; done; return 1; }

hdr "Flagged accounts (allow-list: $ALLOW)"
FLAG=()
while IFS=: read -r n _ uid _ _ home shell; do
  [ "$n" = root ] && continue
  why=""
  [ "$uid" = 0 ] && why="UID0"
  case "$shell" in */nologin|*/false|*/sync|"") ;; *) why="${why:+$why,}login-shell";; esac
  case "$home" in /tmp*|/var/tmp*|/dev/shm*|/var/www*) why="${why:+$why,}odd-home";; esac
  [ -n "$why" ] && ! allowed "$n" && { echo "FLAG $n uid=$uid shell=$shell home=$home ($why)"; FLAG+=("$n"); }
done < <(getent passwd)
[ ${#FLAG[@]} -eq 0 ] && grn "none"

hdr "Privileged group members"; getent group sudo adm wheel docker root 2>/dev/null
hdr "Password state (P=has pw, L=locked, NP=none)"; passwd -Sa 2>/dev/null | awk '$2!="L"{print}' | head -30
hdr "authorized_keys files"
find /root /home /opt /var -xdev -maxdepth 5 -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do echo "$f"; ssh-keygen -lf "$f" 2>&1 | sed 's/^/   /'; done
hdr "sshd effective (look for AuthorizedKeysCommand / ForceCommand / PermitRoot / empty pw)"
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeyscommand|authorizedkeysfile|forcecommand|usepam|allowusers|allowgroups) '

if [ "$APPLY" = 1 ] && [ ${#FLAG[@]} -gt 0 ]; then
  hdr "APPLY"
  for n in "${FLAG[@]}"; do
    confirm "Lock $n (usermod -L, shell nologin, kill sessions)?" || continue
    usermod -L -s /usr/sbin/nologin "$n" && pkill -KILL -u "$n" 2>/dev/null
    log "locked account $n via accounts.sh"; grn "locked $n"
  done
fi
if [ "$KEYS" = 1 ]; then
  Q="$CC/quarantine/keys-$TS"; mkdir -p "$Q"
  find /root /home /opt /var -xdev -maxdepth 5 -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do
    confirm "Quarantine $f?" || continue
    d="$Q/$(echo "$f" | tr / _)"; cp -a "$f" "$d" && : > "$f" && log "quarantined $f -> $d"; grn "emptied $f"
  done
fi
[ "$APPLY" = 0 ] && ylw "Dry run. Re-run with --apply to lock flagged accounts (confirm per account)."
