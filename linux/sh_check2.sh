#!/bin/bash
# shell_check.sh - CCDC shell startup file persistence check (Ubuntu + Fedora/RHEL)
# Checks: /etc/profile, /etc/profile.d/*.sh, /etc/bash.bashrc, /etc/bashrc, /etc/environment,
#         and every user's ~/.bash_profile ~/.bash_login ~/.profile ~/.bashrc ~/.bash_logout
# Compares each file to the real distro default, shows only what was ADDED, flags bad lines,
# and follows hooks (lines that run/source another file) to show what that file does.
# Read-only. Usage: sudo ./shell_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; touch "$TMP/hooks"
if command -v dpkg >/dev/null; then DISTRO=deb; else DISTRO=rpm; fi

# What makes a line suspicious in a shell startup file
SUS='curl|wget|nc |ncat|netcat|socat|/dev/tcp|/dev/udp|bash -i|sh -i|base64|mkfifo|python[0-9.]* -c|perl -e|php -r|ruby -e'\
'|/tmp/|/dev/shm|/var/tmp|/usr/local/(s?bin|lib)/|/(usr|etc|var|opt|lib)/[^ ]*/\.[A-Za-z0-9]'\
'|PROMPT_COMMAND|trap .*(DEBUG|EXIT|RETURN|ERR)|LD_PRELOAD|LD_LIBRARY_PATH'\
'|HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|HISTFILESIZE=0|history -c'\
'|alias +(sudo|su|ssh|passwd|ls|ps|cd|cat|netstat|ss|who|w|top|kill|systemctl|grep|find|lsattr|chattr|crontab|id|whoami)='\
'|^[[:space:]]*(function[[:space:]]+)?(sudo|su|ssh|passwd|ps|ls|ss|netstat|who|kill|systemctl|lsattr|cd)[[:space:]]*\(\)'\
'|nohup|disown|setsid|[^&]&[[:space:]]*$|chmod \+s|useradd|usermod'\
'|PATH=["]?(\.|/tmp|/dev/shm|/var/tmp)|PATH=.*:\.(:|"|$)'
# Stock lines that would otherwise trip the pattern
OK='alias (ls|dir|vdir|grep|fgrep|egrep)=.(ls|dir|vdir|grep|fgrep|egrep) --color=auto|alias (ll|la|l)='

# ---------------------------------------------------------------
# Package helpers
declare -A CONFMD5
if [ "$DISTRO" = deb ]; then
    while read -r f sum _; do [ -n "$f" ] && CONFMD5["$f"]="$sum"; done \
        < <(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | grep '^ /')
fi
from_pkg() {
    if [ "$DISTRO" = deb ]; then
        local r; r=$(readlink -f "$1")
        for p in "$1" "$r" "${r#/usr}" "/usr$r"; do dpkg -S "$p" >/dev/null 2>&1 && return 0; done; return 1
    else rpm -qf "$1" >/dev/null 2>&1; fi
}
# -> "ok", "MODIFIED", or "nopkg"
pkg_status() {
    local f="$1"
    if [ "$DISTRO" = deb ]; then
        if [ "$f" = /etc/profile ] && [ -f /usr/share/base-files/profile ]; then
            cmp -s "$f" /usr/share/base-files/profile && echo ok || echo MODIFIED; return
        fi
        if [ -n "${CONFMD5[$f]}" ]; then
            [ "$(md5sum "$f" | cut -d' ' -f1)" = "${CONFMD5[$f]}" ] && echo ok || echo MODIFIED; return
        fi
        from_pkg "$f" && echo ok || echo nopkg
    else
        rpm -qf "$f" >/dev/null 2>&1 || { echo nopkg; return; }
        rpm -Vf "$f" 2>/dev/null | grep -qE "^..5.* $f\$" && echo MODIFIED || echo ok
    fi
}

# Print lines with flags. Reads lines on stdin as "NUM:text"
flag_print() {
    while IFS= read -r l; do
        num="${l%%:*}"; txt="${l#*:}"
        if echo "$txt" | grep -qE "$SUS" && ! echo "$txt" | grep -qE "$OK"; then
            echo -e "    ${RED}[SUS] line $num: $txt${NC}"
            # remember any file this line runs/sources, to inspect later
            echo "$txt" | grep -oE '(/[A-Za-z0-9._+-]+)+' | while read -r p; do [ -f "$p" ] && echo "$p" >> "$TMP/hooks"; done
        else
            echo "          line $num: $txt"
        fi
    done
}
# Real (non-comment, non-blank) lines of a file as NUM:text
real_lines() { grep -nvE '^\s*#|^\s*$' "$1" 2>/dev/null; }
# Lines in $2 that are NOT in $1 (what was added vs the default), as NUM:text
added_lines() {
    awk 'NR==FNR {seen[$0]=1; next} !($0 in seen) && $0 !~ /^[[:space:]]*(#|$)/ {print FNR":"$0}' "$1" "$2"
}
info() { stat -c '%U %a, changed %z' "$1" | sed 's/\.[0-9]* / /'; }

# ---------------------------------------------------------------
header "1. System-wide startup files"
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/profile.d/*; do
    [ -f "$f" ] || continue
    st=$(pkg_status "$f")
    case "$st" in
        ok)
            # unchanged from the package - trust it, but still catch the odd planted line
            hits=$(real_lines "$f" | grep -E "$SUS" | grep -vE "$OK" | grep -E '/usr/local/|/tmp/|/dev/shm|/dev/tcp|/\.[A-Za-z]|curl|wget|nc ')
            if [ -n "$hits" ]; then echo -e "${YEL}--- $f${NC}  (from package, but has odd lines)"; echo "$hits" | flag_print
            else echo -e "${GRN}    ok${NC}  $f  (unchanged from package)"; fi ;;
        MODIFIED)
            echo -e "${YEL}--- $f${NC}  ($(info "$f"))  ${RED}MODIFIED from package version${NC}"
            if [ "$f" = /etc/profile ] && [ -f /usr/share/base-files/profile ]; then
                added_lines /usr/share/base-files/profile "$f" | flag_print
            else
                # no clean copy on disk - show only flagged lines
                out=$(real_lines "$f" | grep -E "$SUS" | grep -vE "$OK")
                if [ -n "$out" ]; then echo "$out" | flag_print; else echo "          (no flagged lines - compare with a clean box: diff)"; fi
            fi ;;
        nopkg)
            if [ "$f" = /etc/environment ] || { [ "$DISTRO" = rpm ] && [ "$f" = /etc/bashrc ]; }; then
                note="${YEL}no package owns it (normal for this file)${NC}"
            else
                note="${RED}NO PACKAGE OWNS THIS FILE - someone added it${NC}"
            fi
            echo -e "${YEL}--- $f${NC}  ($(info "$f"))  $note"
            real_lines "$f" | head -40 | flag_print ;;
    esac
done
[ "$DISTRO" = deb ] && [ ! -f /etc/bashrc ] && echo "    (/etc/bashrc does not exist - normal on Ubuntu)"

# ---------------------------------------------------------------
header "2. /etc/skel (template copied into every NEW user)"
for f in /etc/skel/.[!.]*; do
    [ -f "$f" ] || continue
    st=$(pkg_status "$f")
    if [ "$st" = ok ]; then echo -e "${GRN}    ok${NC}  $f"
    else echo -e "${YEL}--- $f${NC}  ${RED}$st${NC}"; real_lines "$f" | grep -E "$SUS" | grep -vE "$OK" | flag_print; fi
done

# ---------------------------------------------------------------
header "3. Each user's startup files (only lines ADDED vs the default are shown)"
while IFS=: read -r user _ uid _ _ home shell; do
    [ -d "$home" ] || continue
    for name in .bash_profile .bash_login .profile .bashrc .bash_logout; do
        f="$home/$name"; [ -f "$f" ] || continue
        skel="/etc/skel/$name"
        [ "$user" = root ] && [ -f "/usr/share/base-files/dot$name" ] && skel="/usr/share/base-files/dot$name"
        if [ -f "$skel" ] && cmp -s "$f" "$skel"; then
            echo -e "${GRN}    ok${NC}  $f  (same as default)"; continue
        fi
        if [ -f "$skel" ]; then
            echo -e "${YEL}--- $f${NC}  (user: $user, $(info "$f"))  ${RED}DIFFERENT from default${NC}"
            out=$(added_lines "$skel" "$f")
            if [ -n "$out" ]; then echo "$out" | flag_print; else echo "          (only lines removed, nothing added)"; fi
        else
            echo -e "${YEL}--- $f${NC}  (user: $user, $(info "$f"))  ${YEL}not created by default - who made it?${NC}"
            real_lines "$f" | head -30 | flag_print
        fi
    done
done < /etc/passwd

# ---------------------------------------------------------------
header "4. Hooks: files that the flagged lines run or load"
if [ -s "$TMP/hooks" ]; then
    sort -u "$TMP/hooks" | while read -r h; do
        [ -f "$h" ] || continue
        from_pkg "$h" && continue                                  # e.g. /usr/bin/curl itself - fine
        kind=$(file -b "$(readlink -f "$h")" 2>/dev/null | cut -c1-55)
        echo -e "${RED}--- $h${NC}  (NOT from a package; $kind; $(info "$h"))"
        if [[ "$kind" == *text* || "$kind" == *script* ]]; then
            real_lines "$h" | head -20 | flag_print
        elif [[ "$kind" == *ELF* ]]; then
            strings "$h" 2>/dev/null | grep -E '/dev/tcp|/dev/udp|bash -i|sh -i|/bin/sh|curl |wget |0\.0\.0\.0|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?' \
                | head -6 | while IFS= read -r s; do echo -e "    ${RED}[SUS] inside program: $s${NC}"; done
            echo -e "    ${YEL}(compiled program - copy to /root/evidence, then delete)${NC}"
        fi
    done
else
    echo "        none"
fi

# ---------------------------------------------------------------
header "5. Startup files changed in last 7 days"
{ find /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /etc/environment /etc/skel -maxdepth 1 -type f -mtime -7 2>/dev/null
  while IFS=: read -r _ _ _ _ _ home _; do
      for n in .bash_profile .bash_login .profile .bashrc .bash_logout; do
          [ -f "$home/$n" ] && find "$home/$n" -mtime -7 2>/dev/null
      done
  done < /etc/passwd; } | sort -u | while read -r f; do echo "        $(stat -c '%y' "$f" | cut -d. -f1)  $f"; done

echo -e "\n${GRN}[*] Done. To clean:${NC}"
echo "    user file   -> cp /etc/skel/.bashrc /home/USER/.bashrc && chown USER:USER /home/USER/.bashrc"
echo "    system file -> delete just the bad lines (sudo nano FILE), or rm a profile.d file NO package owns"
echo "    hook files  -> copy to /root/evidence, then delete. Open a NEW terminal afterwards (old ones keep the hook)."
