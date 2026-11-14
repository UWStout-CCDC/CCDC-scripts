#!/bin/bash
# webshell_check.sh - CCDC PHP web shell hunt (Ubuntu + Fedora/RHEL, Apache/nginx/OpenCart)
# Finds web shells INSIDE the webroot and ANYWHERE else on disk, PHP running as its own
# server (php -S), and PHP config backdoors (auto_prepend_file).
# Read-only. Usage: sudo ./webshell_check.sh [webroot] [logdir]
#   defaults: webroot=/var/www   logdir=auto (/var/log/apache2, /var/log/httpd or /var/log/nginx)

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root (sudo)."
    exit 1
fi

WEB="${1:-/var/www}"
LOGDIR="$2"
if [ -z "$LOGDIR" ]; then
    for d in /var/log/apache2 /var/log/httpd /var/log/nginx; do [ -d "$d" ] && { LOGDIR="$d"; break; }; done
fi
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
header() { echo -e "\n${GRN}========== $1 ==========${NC}"; }
sus()    { echo -e "  ${RED}[SUS] $1${NC}"; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
if command -v dpkg >/dev/null; then DISTRO=deb; else DISTRO=rpm; fi

[ -d "$WEB" ] || echo -e "${YEL}[!] $WEB not found - webroot checks skipped, rest still runs. Pass webroot: sudo $0 /path${NC}"
echo "Webroot: $WEB    Logs: ${LOGDIR:-none found}"

EXT='php|php[0-9]|phtml|pht|phar|inc'
# ---- Patterns -----------------------------------------------------------------
EXEC='(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|call_user_func(_array)?)\s*\('
INPUT='\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|\$\{"_(GET|POST|REQUEST)"\}|php://input|getallheaders'
OBFUS='(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev|convert_uudecode)\s*\('
# Known shell kits / signatures (WSO, c99, r57, b374k, weevely, p0wny, China Chopper...)
KITS='FilesMan|c99shell|c99_|r57shell|b374k|WSOsetcookie|wso_version|p0wny|Weevely|\$kh=|\$kf=|uname -a.*\$_|<\?php @eval\(\$_POST\[|Chopper|IndoXploit|Sh3ll|shell_exec\(\$_'

cut200() { cut -c1-200; }

# HIGH checks for one file -> prints hits (empty = clean)
high_hits() {
    local f="$1"
    {
      grep -nE "$EXEC" "$f" | grep -E "$INPUT"                                        # system($_GET[..])
      grep -nE "(eval|assert)\s*\(\s*@?$OBFUS" "$f"                                  # eval(base64_decode(..))
      grep -nE '`[^`]*\$_(GET|POST|REQUEST|COOKIE)' "$f"                              # `$_GET[c]`
      grep -nE "preg_replace\s*\(\s*['\"].*/[a-z]*e[a-z]*['\"]" "$f"                  # /e modifier
      grep -nE '\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\]\s*\(' "$f"                      # $_GET['f']($_GET['c'])
      grep -nE '(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)' "$f"  # include($_GET['p'])
      grep -nE '(fsockopen|stream_socket_client|socket_connect)\s*\(.*' "$f" | grep -E '/bin/(ba)?sh|proc_open|\$_' # reverse shell
      grep -nE "$KITS" "$f"                                                          # known shell kits
    } 2>/dev/null | sort -u | cut200
}
medium_hits() {
    grep -nE "$EXEC|$OBFUS|move_uploaded_file|file_put_contents\s*\(.*\\\$_" "$1" 2>/dev/null \
        | grep -vE '^\s*[0-9]+:\s*(//|\*|#)' | cut200
}
from_pkg() {
    if [ "$DISTRO" = deb ]; then dpkg -S "$1" >/dev/null 2>&1 || dpkg -S "${1#/usr}" >/dev/null 2>&1
    else rpm -qf "$1" >/dev/null 2>&1; fi
}

# ---- Collect files ------------------------------------------------------------
# Webroot: every executable script
[ -d "$WEB" ] && find "$WEB" -type f -regextype posix-extended -iregex ".*\.($EXT|cgi|pl|py|jsp|aspx?|shtml)$" 2>/dev/null > "$TMP/web"
touch "$TMP/web"
# Outside webroot: PHP files anywhere on disk that NO package installed
find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path "$WEB" -o -path /root/evidence -o -path /snap \) -prune -o \
     -type f -regextype posix-extended -iregex ".*\.($EXT)$" -print 2>/dev/null | while read -r f; do
    case "$f" in */node_modules/*|/var/lib/dpkg/*|/var/cache/dictionaries-common/*) continue;; esac
    grep -qE '<\?php|<\?=' "$f" 2>/dev/null || continue          # must actually contain PHP code
    from_pkg "$f" || echo "$f"
done > "$TMP/outside"
# Places a real site never keeps PHP
HOT='^/(tmp|var/tmp|dev/shm|run|usr/local/(s?bin|lib)|var/lib/php|home|root|etc|boot|var/spool|var/mail|opt/\.)|/\.[^/]+$'

# ---------------------------------------------------------------
header "1. PHP running as its own server / from the command line (not through Apache)"
echo "  (php -S = built-in web server. Red team uses it to run a shell on its own port.)"
found=0
for pid in $(pgrep -x 'php|php[0-9.]*' ; pgrep -f '^/usr/bin/php|^php[0-9.]* '); do
    cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null); [ -z "$cmd" ] && continue
    [[ "$cmd" == *php-fpm* ]] && continue
    found=1
    user=$(ps -o user= -p "$pid"); cwd=$(readlink /proc/$pid/cwd)
    unit=$(cat /proc/$pid/cgroup 2>/dev/null | grep -oE '[^/]+\.service' | head -1)
    sus "pid $pid ($user): $cmd"
    echo "        folder: $cwd   ${unit:+started by: $unit (use: systemctl stop $unit && systemctl mask $unit)}"
    ports=$(ss -tlnpH 2>/dev/null | grep "pid=$pid," | awk '{print $4}' | tr '\n' ' ')
    [ -n "$ports" ] && echo -e "        ${RED}listening on: $ports${NC}"
    # router/script it serves
    for a in $cmd; do [[ "$a" == *.php ]] && { [[ "$a" == /* ]] && p="$a" || p="$cwd/$a"; echo "        serves: $p"; echo "$p" >> "$TMP/outside"; }; done
done | sort -u
[ "$(pgrep -fc 'php -S|php[0-9.]* -S|php -r')" = 0 ] && echo "        none"

# ---------------------------------------------------------------
header "2. HIGH: web shell code (request input -> code execution, known shell kits)"
HIGHLIST=""
sort -u "$TMP/web" "$TMP/outside" | while read -r f; do
    [ -f "$f" ] || continue
    h=$(high_hits "$f")
    [ -z "$h" ] && continue
    loc="webroot"; grep -qxF "$f" "$TMP/web" || loc="${RED}OUTSIDE webroot${NC}"
    echo -e "${YEL}--- $f${NC}  ($loc, $(stat -c '%U %a changed %z' "$f" | cut -d. -f1))"
    echo "$h" | while IFS= read -r l; do echo -e "    ${RED}[SUS] line $l${NC}"; done
    echo "$f" >> "$TMP/highfiles"
done
touch "$TMP/highfiles"
[ -s "$TMP/highfiles" ] || echo "        none"

# ---------------------------------------------------------------
header "3. PHP files OUTSIDE the webroot that no package installed"
echo "  ([SUS] = in a place real sites never use, or a hidden file. [CHECK] = probably some tool's file)"
if [ -s "$TMP/outside" ]; then
    sort -u "$TMP/outside" | while read -r f; do
        [ -f "$f" ] || continue
        grep -qxF "$f" "$TMP/highfiles" && tag="${RED}(web shell - see section 2)${NC}" || tag=""
        if [ -n "$tag" ] || echo "$f" | grep -qE "$HOT"; then
            echo -e "  ${RED}[SUS]${NC} $f  ($(stat -c '%U %a changed %z' "$f" | cut -d. -f1)) $tag"
        else
            echo -e "  ${YEL}[CHECK]${NC} $f  (probably part of some tool - glance at it)"
        fi
    done
else
    echo "        none"
fi

# ---------------------------------------------------------------
header "4. MEDIUM: exec / decode / upload functions in the webroot (apps use some legitimately - read these)"
while read -r f; do
    grep -qxF "$f" "$TMP/highfiles" && continue
    hits=$(medium_hits "$f"); [ -z "$hits" ] && continue
    echo -e "${YEL}--- $f${NC}"
    echo "$hits" | head -5 | sed 's/^/        /'
    n=$(echo "$hits" | wc -l); [ "$n" -gt 5 ] && echo "        ... ($n total)"
done < "$TMP/web"

# ---------------------------------------------------------------
header "5. Obfuscated code (lines >1000 chars)"
sort -u "$TMP/web" "$TMP/outside" | while read -r f; do
    awk -v f="$f" 'length($0)>1000 {printf "  \033[0;31m[SUS] %s:%d (%d chars)\033[0m\n", f, NR, length($0)}' "$f" 2>/dev/null | head -2
done

# ---------------------------------------------------------------
header "6. PHP config backdoors (auto_prepend_file runs a file before EVERY page)"
OUT6=$(
for f in $(find /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.d /usr/local/etc/php -type f \( -name '*.ini' -o -name '*.conf' \) 2>/dev/null) \
         $(find / -xdev -name '.user.ini' -not -path '/proc/*' 2>/dev/null); do
    grep -nE '^\s*(php_value\[)?(auto_prepend_file|auto_append_file)\]?\s*=\s*[^ ;]+' "$f" 2>/dev/null | grep -vE '=\s*("")?\s*$' \
        | while IFS= read -r l; do sus "$f:$l"; done
done
find / -xdev -name '.user.ini' -not -path '/proc/*' 2>/dev/null | while read -r f; do sus ".user.ini found (per-folder PHP settings): $f"; done
# Apache/nginx: extra extensions run as PHP, or php_value prepend in vhost/.htaccess
for f in $(find /etc/apache2 /etc/httpd /etc/nginx -type f 2>/dev/null) $( [ -d "$WEB" ] && find "$WEB" -name '.htaccess' 2>/dev/null); do
    grep -inE 'AddType\s+application/x-httpd-php\s|AddHandler\s+.*php|SetHandler\s+.*php|php_value\s+auto_(prepend|append)_file|ForceType' "$f" 2>/dev/null \
        | grep -viE '\.(php|phar|phtml)[0-9]*\$?["]?\s*>?\s*$|<FilesMatch' | while IFS= read -r l; do sus "$f:$l"; done
done
)
[ -n "$OUT6" ] && echo "$OUT6" || echo "        none"

# ---------------------------------------------------------------
if [ -d "$WEB" ]; then
header "7. Webroot: scripts where they don't belong / odd extensions"
while read -r f; do
    rel="${f#$WEB}"
    echo "$rel" | grep -qiE '/(uploads?|images?|img|media|cache|tmp|temp|files|download)/' && sus "script in data folder: $f"
done < "$TMP/web"
find "$WEB" -type f \( -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' -o -iname '*.*.php' -o -iname '*.php.*' \) 2>/dev/null \
    | while read -r f; do sus "odd/double extension: $f"; done
find "$WEB" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.ico' -o -iname '*.txt' -o -iname '*.css' -o -iname '*.js' \) \
     -exec grep -lE '<\?php|<\?=' {} + 2>/dev/null | while read -r f; do sus "PHP hidden inside non-PHP file: $f"; done
find "$WEB" -name '.*' -type f ! -name '.htaccess' ! -name '.user.ini' ! -path '*/.git/*' 2>/dev/null | while read -r f; do echo -e "  ${YEL}[CHECK] hidden file: $f${NC}"; done

header "8. Webroot files changed in last 2 days (newest first)"
echo "  (ctime - can't be faked with 'touch'. Catches lines appended to real files.)"
find "$WEB" -type f -ctime -2 ! -path '*/cache/*' -printf '%CY-%Cm-%Cd %CH:%CM  %-9u %p\n' 2>/dev/null | sort -r | head -30 | sed 's/^/        /'

header "9. Scripts owned by the web server user (it wrote them - why?)"
while read -r f; do
    o=$(stat -c %U "$f"); [[ "$o" == www-data || "$o" == apache || "$o" == nginx ]] && echo "        $f ($o)"
done < "$TMP/web" | head -30
fi

# ---------------------------------------------------------------
header "10. Is someone using a web shell RIGHT NOW?"
OUT10=$(for u in www-data apache nginx; do
    id "$u" >/dev/null 2>&1 || continue
    ps -o pid=,cmd= -u "$u" 2>/dev/null | grep -E '\b(sh|bash|dash|nc|ncat|python[0-9.]*|perl|socat|curl|wget|whoami|id)\b' \
        | while IFS= read -r l; do sus "$u is running: $l"; done
    ss -tnpH state established 2>/dev/null | grep -E "\"(sh|bash|nc|ncat|python[0-9.]*|perl|php)\"" | while IFS= read -r l; do sus "shell with network connection: $l"; done
done)
[ -n "$OUT10" ] && echo "$OUT10" || echo "        none"

# ---------------------------------------------------------------
header "11. Web logs - shell-style requests"
LOGS=$(ls "$LOGDIR"/access*log* "$LOGDIR"/*access*log* 2>/dev/null | sort -u)
if [ -z "$LOGS" ]; then
    echo "  (no access logs found - check: ls /var/log/apache2 /var/log/httpd /var/log/nginx)"
else
    zcat -f $LOGS 2>/dev/null | grep -iE '[?&](cmd|exec|command|c|shell|run|e|x|q|pass)=|whoami|uname|/etc/passwd|/bin/(ba)?sh|%2Fbin%2F|wget|curl|base64|nc\+|\.\./\.\./' \
        | tail -25 | cut -c1-250 | sed 's/^/        /'
    echo -e "\n  ${YEL}POST requests per file (shells are usually POSTed to, from 1-2 IPs):${NC}"
    zcat -f $LOGS 2>/dev/null | awk '$6 ~ /POST/ {split($7,a,"?"); print a[1]}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/        /'
    echo -e "\n  ${YEL}Top IPs:${NC}"
    zcat -f $LOGS 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/        /'
    echo -e "\n  ${YEL}Error log - signs of commands being run:${NC}"
    zcat -f "$LOGDIR"/error*log* 2>/dev/null | grep -iE 'sh: |command not found|system\(\)|shell_exec|passthru' | tail -10 | cut -c1-250 | sed 's/^/        /'
fi

echo -e "\n${GRN}[*] Done.${NC} Copy each shell to /root/evidence first. Whole-file shell -> delete it."
echo "    Shell lines added to a REAL page -> delete only those lines (deleting the page breaks the site)."
echo "    php -S server -> systemctl stop/mask the service that started it (section 1), then delete the file."
