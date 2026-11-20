#!/bin/bash
# boot_check.sh - CCDC pre-OS / early-boot persistence check (Ubuntu + Fedora/RHEL)
# GRUB, kernel cmdline, kernel + initramfs, initramfs hooks, kernel modules,
# modprobe hooks, rc.local / init.d, systemd generators, udev RUN rules,
# ld.so.preload, UEFI boot entries, Secure Boot.
# Read-only. Usage: sudo ./boot_check.sh

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
sus()    { echo -e "  ${RED}[SUS] $1${NC}"; }
chk()    { echo -e "  ${YEL}[CHECK] $1${NC}"; }
ok()     { echo -e "  ${GRN}ok${NC}  $1"; }
if command -v dpkg >/dev/null; then DISTRO=deb; else DISTRO=rpm; fi

# Same "bad command" idea as the other scripts
SUS='curl|wget|nc |ncat|netcat|socat|/dev/tcp|/dev/udp|bash -i|sh -i|base64|mkfifo|python[0-9.]* -c|perl -e|/tmp/|/dev/shm|/var/tmp|/usr/local/(s?bin|lib)/|/\.[A-Za-z0-9]|chmod \+s|useradd|usermod|passwd|chattr|insmod|nohup|setsid'
# Kernel boot options that give a root shell / disable security
BADARGS='(^| )(init|rdinit)=|rd\.break|rd\.shell|(^| )single( |$)|(^| )emergency( |$)|systemd\.unit=(rescue|emergency)|(^| )[sS]( |$)|selinux=0|enforcing=0|apparmor=0|security=none|module\.sig_enforce=0|lockdown=none|systemd\.debug-shell'

from_pkg() {
    local r; r=$(readlink -f "$1")
    if [ "$DISTRO" = deb ]; then
        for p in "$1" "$r" "${r#/usr}" "/usr$r"; do dpkg -S "$p" >/dev/null 2>&1 && return 0; done; return 1
    else rpm -qf "$1" >/dev/null 2>&1 || rpm -qf "$r" >/dev/null 2>&1; fi
}
# Has a package file been changed since install?
pkg_modified() {
    if [ "$DISTRO" = deb ]; then
        local pkg; pkg=$(dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1) || return 1
        [ -n "$pkg" ] && dpkg --verify "$pkg" 2>/dev/null | grep -qE "^..5.* $1\$"
    else
        rpm -Vf "$1" 2>/dev/null | grep -qE "^..5.* $1\$"
    fi
}
flag_file() {   # show non-comment lines, red-flag suspicious ones
    grep -nvE '^\s*#|^\s*$' "$1" 2>/dev/null | head -"${2:-25}" | while IFS= read -r l; do
        if echo "$l" | grep -qE "$SUS"; then echo -e "    ${RED}[SUS] line $l${NC}"; else echo "          line $l"; fi
    done
}
info() { stat -c '%U %a, changed %z' "$1" 2>/dev/null | sed 's/\.[0-9]* / /'; }

# ---------------------------------------------------------------
header "1. Kernel boot options (what this boot actually used + what next boot will use)"
echo -e "  Running now: $(cat /proc/cmdline)"
grep -oE "($BADARGS)[^ ]*" /proc/cmdline | while read -r a; do sus "current boot has: $a"; done

for f in /etc/default/grub /etc/default/grub.d/*.cfg; do
    [ -f "$f" ] || continue
    grep -nE '^\s*GRUB_CMDLINE_LINUX(_DEFAULT)?=' "$f" | while IFS= read -r l; do
        if echo "$l" | grep -qE "$BADARGS|$SUS"; then sus "$f:$l"; else echo "        $f:$l"; fi
    done
    grep -nE '^\s*GRUB_(INIT_TUNE|DISABLE_RECOVERY|TIMEOUT)=' "$f" | sed "s|^|        $f:|"
    [ "$f" != /etc/default/grub ] && ! from_pkg "$f" && chk "$f is not from a package (normal: cloud/vendor tweaks) - read it"
done
# Fedora / BLS boot entries
for f in /boot/loader/entries/*.conf; do
    [ -f "$f" ] || continue
    opts=$(grep -E '^\s*options' "$f")
    if echo "$opts" | grep -qE "$BADARGS|$SUS"; then sus "$f: $opts"; else echo "        $(basename "$f"): $opts" | cut -c1-160; fi
    grep -E '^\s*(linux|initrd)\s' "$f" | awk '{print $2}' | while read -r p; do
        [ -e "/boot$p" ] || [ -e "$p" ] || chk "$f points to missing file $p"
    done
done
command -v grubby >/dev/null && grubby --info=ALL 2>/dev/null | grep -E '^args=' | grep -E "$BADARGS" | while read -r l; do sus "grubby: $l"; done

# ---------------------------------------------------------------
header "2. GRUB scripts and menu"
for d in /etc/grub.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        case "$(basename "$f")" in README) continue;; esac
        if ! from_pkg "$f"; then
            sus "$f is NOT from a package ($(info "$f"))"; flag_file "$f" 20
        elif pkg_modified "$f"; then
            sus "$f MODIFIED from package version"; flag_file "$f" 40 | grep SUS
        fi
    done
    # 40_custom / 41_custom ship nearly empty - anything real in them is worth reading
    for f in "$d"/40_custom "$d"/41_custom; do
        [ -f "$f" ] || continue
        extra=$(grep -vE '^\s*#|^\s*$|^exec tail|^\s*if \[ -f|^\s*source|^\s*fi$' "$f")
        [ -n "$extra" ] && { chk "$f has custom menu entries:"; echo "$extra" | head -15 | sed 's/^/          /'; }
    done
done
GCFG=$(ls /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg 2>/dev/null | head -1)
if [ -n "$GCFG" ]; then
    echo "  Menu file: $GCFG ($(info "$GCFG"))"
    grep -nE '^\s*(linux|linuxefi|kernel)\s' $GCFG | grep -E "$BADARGS|$SUS" | while IFS= read -r l; do sus "$GCFG:$l"; done
    grep -nE 'init=|rd\.break|/tmp/|/\.[a-z]' $GCFG | grep -vE '^\s*[0-9]+:\s*#' | grep -vE 'initrd|init_' | head -5 | while IFS= read -r l; do chk "$GCFG:$l"; done
fi
# GRUB password: without one, anyone at the console can edit boot options (rd.break / init=/bin/bash)
if grep -rqsE '^\s*set superusers|password_pbkdf2' /etc/grub.d /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/grub2/user.cfg 2>/dev/null || [ -s /boot/grub2/user.cfg ]; then
    ok "GRUB has a password set"
else
    chk "GRUB has NO password - anyone at the console can get a root shell via boot options"
fi

# ---------------------------------------------------------------
header "3. Kernel and initramfs files in /boot"
for f in /boot/vmlinuz* /boot/initrd* /boot/initramfs* /boot/System.map* /boot/config-*; do
    [ -f "$f" ] || continue
    case "$f" in
        */initrd*|*/initramfs*) echo "        $(basename "$f")  ($(info "$f"))  - built locally, so no package owns it";;
        *) if from_pkg "$f"; then
               if pkg_modified "$f"; then sus "$f MODIFIED from package (replaced kernel?)"; else echo "        $(basename "$f")  ok (from package)"; fi
           else sus "$f is NOT from a package ($(info "$f"))"; fi;;
    esac
done
find /boot -maxdepth 2 -type f -newermt "-7 days" 2>/dev/null | while read -r f; do chk "changed in last 7 days: $f ($(info "$f"))"; done
find /boot -name '.*' -not -name '.' 2>/dev/null | while read -r f; do sus "hidden file in /boot: $f"; done

# ---------------------------------------------------------------
header "4. Initramfs hooks (code baked into the early-boot image)"
for d in /etc/initramfs-tools/hooks /etc/initramfs-tools/scripts /usr/share/initramfs-tools/hooks /usr/share/initramfs-tools/scripts \
         /etc/dracut.conf.d /usr/lib/dracut/modules.d /usr/lib/dracut/dracut.conf.d; do
    [ -d "$d" ] || continue
    find "$d" -type f 2>/dev/null | while read -r f; do
        if ! from_pkg "$f"; then sus "$f is NOT from a package ($(info "$f"))"; flag_file "$f" 15
        elif pkg_modified "$f"; then sus "$f MODIFIED from package version"; flag_file "$f" 40 | grep SUS; fi
    done
done
for f in /etc/initramfs-tools/initramfs.conf /etc/initramfs-tools/modules /etc/dracut.conf; do
    [ -f "$f" ] && grep -nvE '^\s*#|^\s*$' "$f" | grep -E "$SUS|install_items|add_dracutmodules|include" | while IFS= read -r l; do chk "$f:$l"; done
done
# Quick look inside the current initramfs for files that don't belong
INITRD=$(ls -t /boot/initrd.img-"$(uname -r)" /boot/initramfs-"$(uname -r)".img 2>/dev/null | head -1)
if [ -n "$INITRD" ]; then
    if command -v lsinitramfs >/dev/null; then LIST=$(lsinitramfs "$INITRD" 2>/dev/null)
    elif command -v lsinitrd >/dev/null; then LIST=$(lsinitrd "$INITRD" 2>/dev/null | awk '{print $NF}'); fi
    echo "$LIST" | grep -E '(^|/)\.[A-Za-z0-9][^/]*$|/tmp/|/usr/local/|/root/|/home/' | grep -vE '\.build-id|\.hmac$|/\.git' | head -10 \
        | while read -r f; do sus "inside $INITRD: $f"; done
fi

# ---------------------------------------------------------------
header "5. Kernel modules (rootkits load as modules)"
t=$(cat /proc/sys/kernel/tainted 2>/dev/null)
if [ -n "$t" ] && [ "$t" != 0 ]; then
    why=""
    (( t & 1 ))    && why+="proprietary module; "
    (( t & 2 ))    && why+="module force-loaded; "
    (( t & 4096 )) && why+="out-of-tree module; "
    (( t & 8192 )) && why+="UNSIGNED module; "
    (( t & 32768 )) && why+="kernel live-patched; "
    chk "kernel is tainted ($t): ${why:-other reason}(VMware/VirtualBox tools can cause this - check the list below)"
else
    ok "kernel not tainted"
fi
lsmod 2>/dev/null | awk 'NR>1 {print $1}' | while read -r m; do
    p=$(modinfo -n "$m" 2>/dev/null)
    if [ -z "$p" ] || [ "$p" = "(builtin)" ]; then
        [ -z "$p" ] && sus "module $m is loaded but has no file on disk (hidden or deleted)"
        continue
    fi
    from_pkg "$p" || sus "module $m loaded from $p - NOT from a package"
done
for f in /etc/modules /etc/modules-load.d/*.conf /usr/lib/modules-load.d/*.conf /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf; do
    [ -f "$f" ] || continue
    # 'install X <command>' runs a command whenever module X loads
    grep -nE '^\s*install\s' "$f" | while IFS= read -r l; do
        if echo "$l" | grep -qE '/bin/(true|false)|^\s*[0-9]+:\s*install\s+\S+\s+/bin/(true|false)'; then echo "        $f:$l  (blocks the module - normal)"
        else sus "$f:$l  (runs a command when module loads)"; fi
    done
    from_pkg "$f" || { [ "$f" = /etc/modules ] || chk "$f not from a package:"; grep -vE '^\s*#|^\s*$' "$f" | head -5 | sed 's/^/          /'; }
done
# Modules set to load at boot: does each one really exist? is it a known rootkit?
ROOTKITS='diamorphine|reptile|suterusu|adore|knark|kovid|rkduck|khook|nuk3gh0st|singularity|vlany|beurk|puszek|sutekh|kbeast|azazel|jynx|bdvl|enyelkm|phalanx'
for f in /etc/modules /etc/modules-load.d/*.conf /usr/lib/modules-load.d/*.conf; do
    [ -f "$f" ] || continue
    grep -vE '^\s*[#;]|^\s*$' "$f" | awk '{print $1}' | while read -r m; do
        if echo "$m" | grep -qiE "^($ROOTKITS)"; then
            sus "$f loads '$m' at boot - KNOWN LINUX ROOTKIT NAME"
        elif ! modinfo "$m" >/dev/null 2>&1; then
            sus "$f loads '$m' at boot - no such module in this kernel (custom/rootkit?)"
        fi
    done
done
lsmod 2>/dev/null | awk 'NR>1 {print $1}' | grep -iE "^($ROOTKITS)" | while read -r m; do sus "LOADED module '$m' matches a known rootkit name"; done

# ---------------------------------------------------------------
header "6. Early-boot hooks (run before or as the system comes up)"
# rc.local
for f in /etc/rc.local /etc/rc.d/rc.local; do
    [ -f "$f" ] || continue
    real=$(grep -vE '^\s*#|^\s*$|^exit 0' "$f")
    if [ -n "$real" ]; then sus "$f has commands (runs as root at boot):"; flag_file "$f" 20; else echo "        $f empty"; fi
done
# SysV init scripts nobody installed
for f in /etc/init.d/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in README|skeleton|functions) continue;; esac
    from_pkg "$f" || { sus "$f is NOT from a package ($(info "$f"))"; flag_file "$f" 15; }
done
# systemd generators run very early at every boot / daemon-reload
for d in /etc/systemd/system-generators /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators /lib/systemd/system-generators; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
        [ -f "$f" ] || continue
        from_pkg "$f" || { sus "generator $f is NOT from a package ($(info "$f"))"; file -b "$f" | grep -q text && flag_file "$f" 15; }
    done
done
# udev rules: RUN+= runs a program on device events (including every boot)
for f in /etc/udev/rules.d/*.rules /usr/lib/udev/rules.d/*.rules /lib/udev/rules.d/*.rules; do
    [ -f "$f" ] || continue
    pkg=yes; from_pkg "$f" || pkg=no
    grep -nE 'RUN\+?=|PROGRAM=|IMPORT\{program\}' "$f" | while IFS= read -r l; do
        if [ "$pkg" = no ] || echo "$l" | grep -qE "$SUS"; then sus "$f:$(echo "$l" | cut -c1-140)"; fi
    done
    [ "$pkg" = no ] && ! grep -qE 'RUN|PROGRAM' "$f" && chk "$f not from a package (no RUN lines)"
done
# ld.so.preload: library injected into EVERY program
if [ -s /etc/ld.so.preload ]; then
    sus "/etc/ld.so.preload is not empty - this injects a library into every program (rootkit trick):"
    sed 's/^/          /' /etc/ld.so.preload
else
    ok "/etc/ld.so.preload empty or absent"
fi

# ---------------------------------------------------------------
header "7. UEFI firmware boot entries and EFI partition"
if [ -d /sys/firmware/efi ]; then
    if command -v mokutil >/dev/null; then echo "  $(mokutil --sb-state 2>/dev/null | head -1)"; fi
    if command -v efibootmgr >/dev/null; then
        efibootmgr -v 2>/dev/null | grep -E '^Boot[0-9A-F]{4}' | while IFS= read -r l; do
            if echo "$l" | grep -qiE 'shim|grub|ubuntu|fedora|redhat|rhel|centos|rocky|alma|debian|windows|bootmgfw|PXE|IPv4|IPv6|UEFI Shell|EFI (Hard|DVD|Network|USB)|CD-?ROM|Floppy|HD\('; then
                echo "        $(echo "$l" | cut -c1-140)"
            else
                chk "unusual boot entry: $(echo "$l" | cut -c1-140)"
            fi
        done
        echo "  $(efibootmgr 2>/dev/null | grep -E '^(BootCurrent|BootOrder)' | tr '\n' ' ')"
    fi
    for f in $(find /boot/efi -type f \( -iname '*.efi' -o -iname 'grub.cfg' \) 2>/dev/null); do
        from_pkg "$f" || chk "$f not from a package ($(info "$f")) - normal for some installs, but compare with a clean box"
    done
else
    echo "        legacy BIOS boot (no UEFI) - nothing to check here"
fi

echo -e "\n${GRN}[*] Done.${NC} Fixing boot stuff can stop the box from booting - keep a console open and fix ONE thing at a time:"
echo "    bad kernel options  -> edit /etc/default/grub (or grubby --update-kernel=ALL --remove-args=\"init=...\" on Fedora)"
echo "                           then: Ubuntu 'update-grub'   Fedora 'grub2-mkconfig -o /boot/grub2/grub.cfg'"
echo "    bad initramfs hook  -> evidence + delete it, then rebuild: Ubuntu 'update-initramfs -u'   Fedora 'dracut -f'"
echo "    bad module          -> 'modprobe -r NAME', delete its .ko + config line, 'depmod -a'"
echo "    rc.local / udev / generator / ld.so.preload -> evidence + delete the line or file"
