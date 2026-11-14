#!/bin/bash
# users_check.sh - CCDC user / group / sudo persistence check (Ubuntu)
# Usage: sudo ./users_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
sus()    { echo -e "  ${RED}[SUS] $1${NC}"; }

TODAY=$(( $(date +%s) / 86400 ))   # shadow stores dates as days since 1970

# ---------------- /etc/passwd ----------------
header "/etc/passwd"
echo "  ($(stat -c '%U:%G %a modified %y' /etc/passwd | cut -d. -f1), should be root:root 644)"

# UID 0 = root. Only root should have it.
awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | while read -r u; do
    sus "$u has UID 0 (this is a second root account)"
done

# Password hash stored in passwd instead of shadow (or empty = no password)
awk -F: '$2!="x" {print $1":"$2}' /etc/passwd | while read -r l; do
    sus "password field not 'x' (bypasses shadow): $l"
done

# Duplicate UIDs
cut -d: -f3 /etc/passwd | sort | uniq -d | while read -r id; do
    sus "UID $id shared by: $(awk -F: -v i="$id" '$3==i {printf $1" "}' /etc/passwd)"
done

# System accounts (UID < 1000) that can log in
awk -F: '$3<1000 && $3!=0 && $7!~/(nologin|false|sync|shutdown|halt)$/ {print $1" (uid "$3") shell="$7}' /etc/passwd | while read -r l; do
    sus "system account with login shell: $l"
done

# Weird home dirs
awk -F: '$6~/^\/(tmp|dev\/shm|var\/tmp)/ {print $1" home="$6}' /etc/passwd | while read -r l; do
    sus "home dir in temp location: $l"
done

echo -e "\n  ${YEL}Accounts that can log in (verify every one is supposed to exist):${NC}"
awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ {printf "        %-15s uid=%-6s home=%-20s shell=%s\n",$1,$3,$6,$7}' /etc/passwd

# ---------------- /etc/shadow ----------------
header "/etc/shadow"
echo "  ($(stat -c '%U:%G %a modified %y' /etc/shadow | cut -d. -f1), should be root:shadow 640)"
while IFS=: read -r u hash lastchg _; do
    case "$hash" in
        "")       sus "$u has an EMPTY password (anyone can log in as them)" ;;
        "!"*|"*") ;;  # locked / no password - normal
        *)
            uid=$(id -u "$u" 2>/dev/null)
            if [ -n "$uid" ] && [ "$uid" -lt 1000 ] && [ "$u" != root ]; then
                sus "system account $u has a password set"
            fi
            if [ -n "$lastchg" ] && [ $((TODAY - lastchg)) -le 7 ]; then
                echo -e "        ${YEL}$u password changed $((TODAY - lastchg)) day(s) ago${NC}"
            fi
            ;;
    esac
done < /etc/shadow
echo -e "\n  ${YEL}Accounts with a usable password:${NC}"
awk -F: '$2!~/^[!*]/ && $2!="" {print "        "$1}' /etc/shadow

# ---------------- /etc/group ----------------
header "/etc/group - privileged groups"
echo "  ($(stat -c '%U:%G %a modified %y' /etc/group | cut -d. -f1), should be root:root 644)"
# These groups = root or an easy path to root
for g in sudo admin wheel root adm shadow disk docker lxd lxc libvirt; do
    line=$(getent group "$g") || continue
    members=$(echo "$line" | cut -d: -f4)
    gid=$(echo "$line" | cut -d: -f3)
    # Also users whose PRIMARY group is this one
    primary=$(awk -F: -v id="$gid" '$4==id {printf $1" "}' /etc/passwd)
    all=$(echo "$members ${primary}" | tr ', ' '\n\n' | grep -v '^$' | sort -u | tr '\n' ' ')
    [ -z "$all" ] && continue
    case "$g" in
        sudo|admin|wheel|root|docker|lxd|lxc|disk) echo -e "  ${RED}$g${NC}: $all" ;;
        *) echo -e "  ${YEL}$g${NC}: $all" ;;
    esac
done
echo "  (sudo/admin/wheel = full root. docker/lxd/disk = root in one command. Check every name.)"

# Duplicate GIDs / GID 0 groups
cut -d: -f3 /etc/group | sort | uniq -d | while read -r id; do
    sus "GID $id shared by groups: $(awk -F: -v i="$id" '$3==i {printf $1" "}' /etc/group)"
done

# ---------------- /etc/gshadow ----------------
header "/etc/gshadow"
echo "  ($(stat -c '%U:%G %a modified %y' /etc/gshadow | cut -d. -f1), should be root:shadow 640)"
while IFS=: read -r g pw admins members; do
    if [ -n "$pw" ] && [[ "$pw" != "!"* ]] && [ "$pw" != "*" ]; then
        sus "group $g has a password (anyone with it can join via newgrp)"
    fi
    [ -n "$admins" ] && sus "group $g has group admins: $admins"
done < /etc/gshadow

# ---------------- sudoers ----------------
header "sudoers"
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    [ "$(basename "$f")" = README ] && continue
    perms=$(stat -c '%U:%G %a' "$f")
    echo -e "${YEL}--- $f${NC}  ($perms, modified $(stat -c %y "$f" | cut -d. -f1))"
    [ "$perms" != "root:root 440" ] && sus "permissions should be root:root 440"
    grep -vE '^\s*#|^\s*$|^\s*Defaults\s+(env_reset|mail_badpass|secure_path|use_pty)' "$f" | while IFS= read -r line; do
        if echo "$line" | grep -qE '^\s*(root|%admin|%sudo)\s+ALL=\(ALL(:ALL)?\)\s+ALL\s*$|^\s*[@#]includedir\s+/etc/sudoers\.d\s*$'; then
            echo "        $line"   # stock Ubuntu lines
        elif echo "$line" | grep -qE 'NOPASSWD|!authenticate|^\s*ALL\s|@include|#include|Defaults.*(env_keep|LD_PRELOAD|!env_reset|setenv)'; then
            sus "$line"
        else
            echo -e "  ${YEL}[CHECK] $line${NC}"
        fi
    done
done
echo -e "\n  Syntax check:"; visudo -c 2>&1 | sed 's/^/        /'

# What every user is actually allowed to run
header "Effective sudo rights per login user"
awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd | while read -r u; do
    out=$(sudo -l -U "$u" 2>/dev/null | sed -n '/may run/,$p' | tail -n +2)
    [ -n "$out" ] && { echo -e "${YEL}--- $u${NC}"; echo "$out" | sed 's/^/      /'; }
done

# ---------------- processes by user ----------------
header "Processes by user"
echo "  (regular users: every process listed. root/service accounts: only suspicious ones)"
SHELLS='^-?(ba|da|z|k|c|tc|fi)?sh$|^(nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|php[0-9.]*|lua|telnet|busybox)$'

# Network sockets per PID (listening ports + live connections)
declare -A NET
while read -r st local peer procs; do
    for pid in $(echo "$procs" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
        if [ "$st" = LISTEN ] || [ "$st" = UNCONN ]; then NET[$pid]+="listening ${local} "
        else NET[$pid]+="connected ${peer} "; fi
    done
done < <(ss -tunapH 2>/dev/null | awk '{print $2, $5, $6, $7}')

declare -A SEEN_USER
ME=$$
while read -r pid user uid ppid etime comm args; do
    [ "$pid" = "$ME" ] || [ "$ppid" = "$ME" ] && continue          # this script
    [[ "$args" == \[*\] ]] && continue                              # kernel threads
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    why=""
    # owner doesn't exist anymore (ps shows a number instead of a name)
    getent passwd "$uid" >/dev/null || why+="owner uid $uid has NO account (deleted user still running?); "
    [[ "$exe" == *"(deleted)"* ]] && why+="its program file was deleted; "
    [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm)/ || "$exe" =~ /\.[^/]+$ || "$exe" =~ ^/usr/local/lib/ ]] && why+="runs from $exe; "
    if [[ "$comm" =~ $SHELLS ]]; then
        [ "$uid" -ne 0 ] && [ "$uid" -lt 1000 ] && why+="service account running a shell/interpreter; "
        [ -n "${NET[$pid]}" ] && why+="shell with network: ${NET[$pid]}; "
    fi
    echo "$args" | grep -qE '/dev/tcp/|/dev/udp/|(^|[ /])(ba)?sh -i( |$)|php -S|(^|[ /])(nc|ncat|netcat) [^|;&]*-[ec] |mkfifo [^ ]*;|import socket|pty\.spawn' && why+="backdoor-style command; "

    # Decide what to print: regular users = everything; others = only flagged
    if [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] || [ -n "$why" ]; then
        if [ -z "${SEEN_USER[$user]}" ]; then
            SEEN_USER[$user]=1
            sh=$(getent passwd "$uid" | cut -d: -f7); total=$(ps -o pid= -u "$uid" 2>/dev/null | wc -l)
            echo -e "\n${YEL}--- user: $user (uid $uid, shell ${sh:-none}, $total processes)${NC}"
        fi
        net=""; [ -n "${NET[$pid]}" ] && net="  [${NET[$pid]% }]"
        line=$(printf "pid %-7s ppid %-7s up %-9s %s" "$pid" "$ppid" "$(printf '%dh%02dm' $((etime/3600)) $((etime%3600/60)))" "$(echo "$args" | cut -c1-110)")
        if [ -n "$why" ]; then
            sus "$line$net"
            echo -e "        ${RED}-> ${why%; }${NC}"
        else
            echo "        $line$net"
        fi
    fi
done < <(ps -eo pid=,user:32=,uid=,ppid=,etimes=,comm=,args= --sort=uid,pid 2>/dev/null)
[ ${#SEEN_USER[@]} -eq 0 ] && echo "        nothing flagged, no regular-user processes"
echo -e "\n  ${YEL}Process count per user:${NC}"
ps -eo user:32= | sort | uniq -c | sort -rn | head -15 | sed 's/^/        /'
echo "  Kill one: kill -9 PID   |   everything a user runs: pkill -9 -u USER   |   tree: ps -ef --forest"

# ---------------- locked files ----------------
header "Immutable / append-only account files (breaks passwd, blocks your fixes)"
if ! command -v lsattr >/dev/null; then
    sus "lsattr missing - reinstall: apt-get install --reinstall e2fsprogs"
else
    found=0
    for f in /etc /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d \
             /etc/sudoers.d/* /etc/.pwd.lock /etc/pam.d /etc/ssh/sshd_config /root/.ssh /root/.ssh/authorized_keys \
             /home/*/.ssh /home/*/.ssh/authorized_keys; do
        [ -e "$f" ] || continue
        a=$(lsattr -d "$f" 2>/dev/null | awk '{print $1}')
        [[ "$a" == *i* || "$a" == *a* ]] && { sus "$a $f   (fix: chattr -i -a $f)"; found=1; }
    done
    [ $found -eq 0 ] && echo "        none"
fi

# ---------------- recent changes ----------------
header "Modified in last 7 days"
find /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d -type f -mtime -7 -exec ls -la {} \; 2>/dev/null
echo "  (backup copies like /etc/passwd- show the PREVIOUS version: diff /etc/passwd- /etc/passwd)"
for f in passwd shadow group gshadow; do
    if [ -f "/etc/$f-" ] && ! cmp -s "/etc/$f-" "/etc/$f"; then
        echo -e "${YEL}--- diff /etc/$f- /etc/$f${NC}"
        # hide password hashes so they don't end up on screen / in screenshots
        diff "/etc/$f-" "/etc/$f" | grep '^[<>]' | { [[ $f == *shadow ]] && sed -E 's/^([<>] [^:]*):[^:!*][^:]*:/\1:[hash]:/' || cat; } | sed 's/^/        /'
    fi
done

echo -e "\n${GRN}[*] Done.${NC}"
