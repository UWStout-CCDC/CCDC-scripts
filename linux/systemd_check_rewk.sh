#!/bin/bash
# systemd_check.sh - CCDC systemd persistence check (Ubuntu + Fedora/RHEL)
# Shows the contents of every suspicious service/timer, flags bad lines, and
# follows ExecStart= into the script/program it runs.
# Read-only. Usage: sudo ./systemd_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }

# What makes a line suspicious (same idea as cron_check)
SUS='curl|wget|nc |ncat|netcat|socat|/dev/tcp|/dev/udp|bash -i|sh -i|base64|mkfifo|php -S|php -r|python[0-9.]* -c|perl -e|ruby -e|/tmp/|/dev/shm|/var/tmp|/home/|/\.[A-Za-z0-9]|/usr/local/(s?bin|lib)/|systemctl +(stop|mask|disable|kill)|chmod \+s|chattr|useradd|usermod|passwd|iptables +-F|ufw +disable|0\.0\.0\.0|nohup|setsid|>/dev/null 2>&1 *&'

if command -v dpkg >/dev/null; then DISTRO=deb; else DISTRO=rpm; fi

# ---------------------------------------------------------------
# Known-good list: every file a package installed, with its original md5 (deb)
declare -A PKGMD5 PKGOWNED
norm() { local p="$1"; p="${p/#\/lib\//\/usr\/lib\/}"; echo "$p"; }
if [ "$DISTRO" = deb ]; then
    while read -r sum path; do
        p=$(norm "/$path"); PKGMD5["$p"]="$sum"; PKGOWNED["$p"]=1
    done < <(cat /var/lib/dpkg/info/*.md5sums 2>/dev/null | grep -E 'systemd/(system|user)/')
    while read -r path; do PKGOWNED["$(norm "$path")"]=1; done \
        < <(cat /var/lib/dpkg/info/*.list 2>/dev/null | grep -E 'systemd/(system|user)/')
else
    while read -r path; do PKGOWNED["$(norm "$path")"]=1; done \
        < <(rpm -qa --qf '[%{FILENAMES}\n]' 2>/dev/null | grep -E 'systemd/(system|user)/')
fi

# Returns: "pkg-ok", "pkg-MODIFIED", or "no-pkg"
pkg_status() {
    local f; f=$(norm "$1")
    [ -z "${PKGOWNED[$f]}" ] && { echo no-pkg; return; }
    if [ "$DISTRO" = deb ] && [ -n "${PKGMD5[$f]}" ]; then
        [ "$(md5sum "$1" | cut -d' ' -f1)" = "${PKGMD5[$f]}" ] && echo pkg-ok || echo pkg-MODIFIED
    elif [ "$DISTRO" = rpm ]; then
        rpm -Vf "$1" 2>/dev/null | grep -q "^..5.* $1\$" && echo pkg-MODIFIED || echo pkg-ok
    else
        echo pkg-ok
    fi
}

# Print a file's real lines, red-flagging suspicious ones
show_lines() {   # $1=file  $2=max lines
    grep -vE '^\s*[#;]|^\s*$' "$1" 2>/dev/null | head -"${2:-40}" | while IFS= read -r l; do
        if echo "$l" | grep -qE "$SUS"; then echo -e "    ${RED}[SUS] $l${NC}"
        else echo "          $l"; fi
    done
}

# Is a file installed by a package? (resolves symlinks like /bin/sh -> dash first)
from_pkg() {
    local r; r=$(readlink -f "$1")
    if [ "$DISTRO" = deb ]; then
        for p in "$1" "$r" "${r#/usr}" "/usr$r"; do dpkg -S "$p" >/dev/null 2>&1 && return 0; done
        return 1
    else
        rpm -qf "$r" >/dev/null 2>&1 || rpm -qf "$1" >/dev/null 2>&1
    fi
}

# Strong signs inside a compiled program (keeps gnu.org links etc. out)
BIN_SUS='/dev/tcp|/dev/udp|bash -i|sh -i|/bin/sh -c|nc -e|mkfifo|curl |wget |0\.0\.0\.0|/dev/shm|/tmp/\.|https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+'

# Follow Exec*= lines: check EVERY file path in the command (catches sh -c "... /hidden/file ...")
# Only files NOT installed by a package are opened and shown.
follow_exec() {  # $1=unit file
    grep -E '^\s*Exec[A-Za-z]*=' "$1" 2>/dev/null | grep -oE '/[A-Za-z0-9._/+-]+' | sort -u | while read -r target; do
        [ -f "$target" ] || continue
        from_pkg "$target" && continue                       # stock program, nothing to see
        kind=$(file -b "$(readlink -f "$target")" 2>/dev/null | cut -c1-60)
        echo -e "    ${RED}runs -> $target  (NOT from a package; $kind)${NC}"
        if [[ "$kind" == *text* || "$kind" == *script* ]]; then
            show_lines "$target" 25 | sed 's/^/  /'
        elif [[ "$kind" == *ELF* ]]; then
            strings "$target" 2>/dev/null | grep -E "$BIN_SUS" | head -8 | while IFS= read -r s; do
                echo -e "      ${RED}[SUS] inside program: $s${NC}"
            done
            echo -e "      ${YEL}(compiled program - copy to /root/evidence, then delete)${NC}"
        fi
    done
}

# Explain a timer's schedule in plain words
timer_info() {   # $1=timer file
    local t="$1" unit
    unit=$(grep -E '^\s*Unit=' "$t" | head -1 | cut -d= -f2)
    [ -z "$unit" ] && unit="$(basename "${t%.timer}").service"
    sched=$(grep -E '^\s*On(Calendar|BootSec|StartupSec|UnitActiveSec|UnitInactiveSec|ActiveSec)=' "$t" | xargs)
    echo -e "    ${YEL}timer fires: ${sched:-?}  ->  starts $unit${NC}"
    # Fires very often? (every few seconds/minutes)
    if echo "$sched" | grep -qE 'Sec=([0-9]+s?|[0-9]+ ?(s|sec|m|min))( |$)|OnCalendar=(\*:\*|minutely|\*-\*-\* \*:\*:\*|.*\*:0?/[0-9]+)'; then
        echo -e "    ${RED}[SUS] runs every few minutes or faster${NC}"
    fi
}

# ---------------------------------------------------------------
# Where unit files live (system + user + every user's ~/.config)
DIRS="/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system \
/usr/local/lib/systemd/system /etc/systemd/user /run/systemd/user /usr/lib/systemd/user /usr/local/lib/systemd/user"
for h in /root /home/*; do [ -d "$h/.config/systemd/user" ] && DIRS="$DIRS $h/.config/systemd/user"; done
DIRS=$(for d in $DIRS; do [ -d "$d" ] && readlink -f "$d"; done | sort -u)

# ---------------------------------------------------------------
header "1. Services RUNNING but their file was deleted (live in memory)"
echo "  (killing these doesn't work - systemd restarts them. Use: systemctl stop NAME && systemctl mask NAME)"
found=0
if systemctl list-units --all --no-legend --plain >/dev/null 2>&1; then
    while read -r unit load active sub _; do
        [ "$load" = not-found ] && [ "$active" = active ] || continue
        found=1
        pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
        cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120)
        echo -e "  ${RED}[SUS] $unit is $sub, file is GONE  (pid $pid: $cmd)${NC}"
    done < <(systemctl list-units --all --no-legend --plain 2>/dev/null)
    [ $found -eq 0 ] && echo "        none"
else
    echo "        (systemctl not available - skipped)"
fi

# ---------------------------------------------------------------
header "2. Suspicious or non-package units (full contents)"
echo "  (stock units unchanged from their package are skipped)"
for d in $DIRS; do
    while IFS= read -r f; do
        st=$(pkg_status "$f")
        sushits=$(grep -vE '^\s*[#;]' "$f" 2>/dev/null | grep -cE "$SUS")
        [ "$st" = pkg-ok ] && continue                        # untouched stock unit
        case "$st" in
            no-pkg)       tag="${RED}NO PACKAGE OWNS THIS FILE${NC}";;
            pkg-MODIFIED) tag="${RED}MODIFIED from package version${NC}";;
        esac
        echo -e "\n${YEL}--- $f${NC}  ($(stat -c '%U %a modified %y' "$f" | cut -d. -f1))  $tag"
        state=$(systemctl is-enabled "$(basename "$f")" 2>/dev/null); act=$(systemctl is-active "$(basename "$f")" 2>/dev/null)
        [ -n "$state$act" ] && echo "    status: ${state:-?} / ${act:-?}"
        show_lines "$f" 40
        grep -qE '^\s*Restart=(always|on-failure)' "$f" && \
            echo -e "    ${YEL}note: auto-restarts if killed -> use 'systemctl stop' then 'mask', not kill${NC}"
        [[ "$f" == *.timer ]] && timer_info "$f"
        follow_exec "$f"
    done < <(find "$d" -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null | sort)
done

# ---------------------------------------------------------------
header "3. Drop-in overrides (*.d/*.conf) - can hijack legit services"
find $DIRS -path '*.d/*.conf' -type f 2>/dev/null | while read -r f; do
    st=$(pkg_status "$f"); [ "$st" = pkg-ok ] && continue
    case "$f" in /run/systemd/system/*netplan*) continue;; esac        # netplan generates these at boot
    echo -e "${YEL}--- $f${NC}  ($(stat -c '%y' "$f" | cut -d. -f1))"
    show_lines "$f" 20
    follow_exec "$f"
done

# ---------------------------------------------------------------
header "4. Symlinks in /etc/systemd/system pointing outside normal dirs"
find /etc/systemd/system -type l 2>/dev/null | while read -r l; do
    t=$(readlink -f "$l")
    case "$t" in
        /usr/lib/systemd/*|/lib/systemd/*|/etc/systemd/*|/dev/null|/run/systemd/*) ;;
        *) echo -e "  ${RED}[SUS] $l -> $t${NC}" ;;
    esac
done

# ---------------------------------------------------------------
header "5. Timers (systemd's version of cron)"
systemctl list-timers --all --no-pager 2>/dev/null | head -40 || echo "        (systemctl not available)"
echo -e "\n  Timers NOT from a package:"
for d in $DIRS; do
    find "$d" -maxdepth 1 -name '*.timer' -type f 2>/dev/null | while read -r t; do
        [ "$(pkg_status "$t")" = no-pkg ] && { echo -e "  ${RED}[SUS] $t${NC}"; timer_info "$t"; }
    done
done

# ---------------------------------------------------------------
header "6. Unit files modified in last 7 days"
for d in $DIRS; do
    find "$d" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) \
        -mtime -7 -printf '        %TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null
done | sort -r

echo -e "\n${GRN}[*] Done. To remove a bad unit:${NC}"
echo "    systemctl stop NAME.timer NAME.service; systemctl disable NAME.timer NAME.service; systemctl mask NAME.service"
echo "    rm /etc/systemd/system/NAME.*; systemctl daemon-reload   (and delete the file its ExecStart ran)"
