#!/usr/bin/env bash
# sliver_hunt.sh - Sliver implant hunt (and optional kill) for Linux (CCDC)
#
# usage: sudo ./sliver_hunt.sh [options] [rules_file] [extra_dir ...]
#   rules_file         defaults to /srv/sliver.yar (.yarc = compiled, uses -C)
#                      if missing, it gets downloaded; if yara is missing, it gets installed
#   extra_dir          any extra directories to YARA scan on disk
#
# options:
#   --kill             remediate HIGH (YARA-confirmed) hits: block C2, freeze, strip
#                      persistence, kill, quarantine binaries
#   --include-suspect  with --kill, also remediate heuristic-only (SUSPECT) hits. risky.
#   --no-block         with --kill, don't add firewall rules for C2 peers
#   -y, --yes          with --kill, skip the confirmation prompt
#
# Without --kill it's read-only: it finds, reports, and logs.

set -u

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLD=$'\e[1m'; RST=$'\e[0m'
die()  { echo "${RED}[!] $*${RST}" >&2; exit 1; }
info() { echo "${BLD}[*]${RST} $*"; }
warn() { echo "${YEL}[~]${RST} $*"; }
ok()   { echo "${GRN}[ok]${RST} $*"; }
hit()  { echo "${RED}${BLD}[+]${RST} $*"; }

KILL=0; INCLUDE_SUSPECT=0; ASSUME_YES=0; NO_BLOCK=0; POS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kill) KILL=1 ;;
        --include-suspect) INCLUDE_SUSPECT=1 ;;
        --no-block) NO_BLOCK=1 ;;
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        --) shift; POS+=("$@"); break ;;
        -*) die "unknown option: $1 (try --help)" ;;
        *) POS+=("$1") ;;
    esac
    shift
done

RULES="${POS[0]:-/srv/sliver.yar}"
EXTRA_DIRS=(${POS[@]+"${POS[@]:1}"})
HOST=$(hostname)
TS=$(date +%Y%m%d_%H%M%S)
LOG="/root/sliver_hunt_${HOST}_${TS}.log"
QDIR="/root/sliver_quarantine_${HOST}_${TS}"
YTIMEOUT=60   # seconds per yara memory scan, so one huge process can't stall the hunt

# ---------- preflight ----------
RULES_URL="https://raw.githubusercontent.com/Immersive-Labs-Sec/SliverC2-Forensics/main/Rules/sliver.yar"

[[ $EUID -eq 0 ]] || die "run as root (sudo -i), memory scans need it"

install_yara() {
    info "yara not found, installing..."
    if command -v apt-get >/dev/null; then
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq yara
    elif command -v dnf >/dev/null; then
        dnf install -y -q yara || { dnf install -y -q epel-release && dnf install -y -q yara; }
    elif command -v yum >/dev/null; then
        yum install -y -q yara || { yum install -y -q epel-release && yum install -y -q yara; }
    elif command -v pacman >/dev/null; then
        pacman -Sy --noconfirm --needed yara
    elif command -v zypper >/dev/null; then
        zypper --non-interactive install yara
    elif command -v apk >/dev/null; then
        apk add --no-cache yara
    else
        return 1
    fi
}

fetch() {   # fetch <url> <dest>
    if command -v curl >/dev/null; then curl -fsSL --max-time 30 "$1" -o "$2"
    elif command -v wget >/dev/null; then wget -q -T 30 "$1" -O "$2"
    else return 1; fi
}

if ! command -v yara >/dev/null; then
    install_yara >/dev/null 2>&1 || true
    command -v yara >/dev/null || die "couldn't install yara (no internet? egress blocked? no supported package manager?). drop a binary in PATH and rerun"
    ok "yara installed: $(yara --version)"
fi

if [[ ! -s "$RULES" ]]; then
    info "rules not found at $RULES, downloading from Immersive Labs repo..."
    mkdir -p "$(dirname "$RULES")"
    TMPR=$(mktemp)
    if fetch "$RULES_URL" "$TMPR" && grep -q '^rule sliver' "$TMPR"; then
        mv "$TMPR" "$RULES"; chmod 644 "$RULES"
        ok "rules saved to $RULES"
    else
        rm -f "$TMPR"
        die "couldn't download rules from $RULES_URL (no curl/wget, no internet, or egress blocked)"
    fi
fi
[[ -r "$RULES" ]] || die "can't read rules file: $RULES"
RULES_REAL=$(realpath "$RULES")

YFLAGS=(-w)
case "$RULES" in *.yarc|*.compiled) YFLAGS+=(-C) ;; esac

TO=()
command -v timeout >/dev/null && TO=(timeout "$YTIMEOUT")

exec > >(tee -a "$LOG") 2>&1
info "Sliver hunt on ${BLD}$HOST${RST} at $(date)"
info "rules: $RULES_REAL | log: $LOG"

# ---------- sanity check: do the rules actually fire? ----------
TMPT=$(mktemp)
printf 'sliverpb github.com/bishopfox/ chacha20poly1305' > "$TMPT"
if yara "${YFLAGS[@]}" "$RULES" "$TMPT" 2>/dev/null | grep -q .; then
    ok "rules compile and fire on test string"
else
    rm -f "$TMPT"
    die "rules did NOT fire on a known-bad test string, fix yara/rules before trusting results"
fi
rm -f "$TMPT"

# ---------- snapshot state ----------
mapfile -t PIDS < <(ls /proc | grep -E '^[0-9]+$')
SS_OUT=$(ss -tanpuH 2>/dev/null)

declare -A FLAGS EXE CMD CONN
flag() { FLAGS[$1]+="$2; "; }

# ---------- process sweep ----------
info "sweeping ${#PIDS[@]} processes (memory + backing binary + heuristics)..."
for p in "${PIDS[@]}"; do
    [[ "$p" == "$$" || "$p" == "$BASHPID" ]] && continue
    [[ -d /proc/$p ]] || continue
    exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue   # kernel threads have no exe
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
    name=$(basename "${exe% (deleted)}")
    conns=$(grep "pid=$p," <<< "$SS_OUT" | awk '{print $1, $2, $5, "->", $6}')

    EXE[$p]="$exe"; CMD[$p]="$cmd"; CONN[$p]="$conns"

    # heuristics
    [[ "$exe" == *" (deleted)" ]] && flag "$p" "binary deleted from disk"
    [[ "$exe" == /memfd:* ]]     && flag "$p" "running from memfd (fileless)"
    case "$exe" in
        /tmp/*|/dev/shm/*|/var/tmp/*|/run/user/*|/home/*|/root/*) flag "$p" "exe in user-writable path" ;;
    esac
    [[ "$name" =~ ^[A-Z]+_[A-Z]+(\.[A-Za-z0-9]+)?$ ]] && flag "$p" "ADJECTIVE_NOUN filename (Sliver default naming)"
    [[ "$cmd" == \[* ]] && flag "$p" "spoofed kernel thread name (real kthreads have no exe)"
    grep -q "SYN-SENT" <<< "$conns" && flag "$p" "stuck in SYN-SENT (beacon hitting your egress block?)"

    if [[ -n "$conns" ]]; then
        case "$exe" in
            /usr/*|/bin/*|/sbin/*|/lib*) ;;
            *) file -bL "/proc/$p/exe" 2>/dev/null | grep -q "Go BuildID" \
                   && flag "$p" "Go binary with network activity outside system paths" ;;
        esac
    fi

    # yara: process memory
    mem=$("${TO[@]}" yara "${YFLAGS[@]}" "$RULES" "$p" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, -)
    [[ -n "$mem" ]] && flag "$p" "YARA memory hit: $mem"

    # yara: backing binary (works even if deleted from disk)
    bin=$("${TO[@]}" yara "${YFLAGS[@]}" "$RULES" "/proc/$p/exe" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, -)
    [[ -n "$bin" ]] && flag "$p" "YARA binary hit: $bin"
done

# ---------- disk sweep ----------
DIRS=(/tmp /dev/shm /var/tmp /var/www /home /root /opt /usr/local /etc /srv ${EXTRA_DIRS[@]+"${EXTRA_DIRS[@]}"})
SCAN=()
for d in "${DIRS[@]}"; do [[ -e "$d" ]] && SCAN+=("$d"); done

info "YARA disk scan: ${SCAN[*]}"
DISK_HITS=$(yara -r "${YFLAGS[@]}" -p 4 "$RULES" "${SCAN[@]}" 2>/dev/null | grep -vF "$RULES_REAL")

info "looking for ELF executables in temp dirs..."
TMP_ELF=$(find /tmp /dev/shm /var/tmp -xdev -type f -perm -u+x 2>/dev/null \
          | while read -r f; do file -b "$f" 2>/dev/null | grep -q '^ELF' && echo "$f"; done)

# ---------- persistence lookup ----------
PERSIST_LOCS=(/etc/systemd /lib/systemd/system /usr/lib/systemd/system /etc/cron* /var/spool/cron
              /etc/rc.local /etc/init.d /etc/xdg/autostart /etc/udev/rules.d /etc/update-motd.d
              /etc/profile /etc/profile.d /etc/bash.bashrc /etc/ld.so.preload
              /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.config/systemd)
find_persist() {
    local path="${1% (deleted)}"
    [[ -z "$path" || "$path" == /memfd:* ]] && return
    grep -rlF "$path" "${PERSIST_LOCS[@]}" 2>/dev/null
}

# ---------- report ----------
echo
echo "${BLD}==================== RESULTS: $HOST ====================${RST}"
HASHES=(); REMOTES=(); TARGETS=(); DISK_FILES=()

if [[ ${#FLAGS[@]} -eq 0 ]]; then
    ok "no suspicious processes"
else
    for p in "${!FLAGS[@]}"; do
        if [[ "${FLAGS[$p]}" == *YARA* ]]; then
            sev="${RED}${BLD}HIGH${RST}"; TARGETS+=("$p")
        else
            sev="${YEL}SUSPECT${RST}"; [[ $INCLUDE_SUSPECT -eq 1 ]] && TARGETS+=("$p")
        fi
        ppid=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null)
        user=$(stat -c %U "/proc/$p" 2>/dev/null)
        pcomm=$(cat "/proc/$ppid/comm" 2>/dev/null)
        sha=$(sha256sum "/proc/$p/exe" 2>/dev/null | awk '{print $1}')
        [[ -n "$sha" ]] && HASHES+=("$sha  ${EXE[$p]}")

        echo
        hit "[$sev] PID $p  user=$user  parent=$ppid ($pcomm)"
        echo "     exe:     ${EXE[$p]}"
        echo "     cmdline: ${CMD[$p]}"
        echo "     sha256:  ${sha:-n/a}"
        echo "     why:     ${FLAGS[$p]}"
        if [[ -n "${CONN[$p]}" ]]; then
            echo "     network:"; sed 's/^/       /' <<< "${CONN[$p]}"
            while read -r peer; do REMOTES+=("$peer"); done < <(awk '{print $5}' <<< "${CONN[$p]}" | sed 's/:[0-9]*$//')
        fi
        pers=$(find_persist "${EXE[$p]}")
        [[ -n "$pers" ]] && { echo "     ${RED}persistence refs:${RST}"; sed 's/^/       /' <<< "$pers"; }
    done
fi

echo
if [[ -n "$DISK_HITS" ]]; then
    hit "YARA disk hits:"; sed 's/^/     /' <<< "$DISK_HITS"
    while read -r _ f; do
        [[ -f "$f" ]] && { HASHES+=("$(sha256sum "$f" | awk '{print $1}')  $f"); DISK_FILES+=("$f"); }
        pers=$(find_persist "$f"); [[ -n "$pers" ]] && { echo "     ${RED}persistence refs for $f:${RST}"; sed 's/^/       /' <<< "$pers"; }
    done <<< "$DISK_HITS"
else
    ok "no YARA disk hits"
fi

echo
if [[ -n "$TMP_ELF" ]]; then
    warn "ELF executables sitting in temp dirs (check these by hand):"; sed 's/^/     /' <<< "$TMP_ELF"
fi

echo
echo "${BLD}---- IOCs to share with the team ----${RST}"
if [[ ${#HASHES[@]} -gt 0 ]]; then
    echo "hashes:"; printf '  %s\n' "${HASHES[@]}" | sort -u
fi
if [[ ${#REMOTES[@]} -gt 0 ]]; then
    echo "remote peers of flagged procs:"; printf '  %s\n' "${REMOTES[@]}" | grep -vE '^\s*(\*|0\.0\.0\.0|\[?::\]?|127\.)' | sort -u
fi

# =====================================================================
# ---------- remediation (--kill) ----------
# =====================================================================
if [[ $KILL -eq 0 ]]; then
    echo
    info "done (read-only). full log: $LOG"
    if [[ ${#TARGETS[@]} -gt 0 || ${#DISK_FILES[@]} -gt 0 ]]; then
        info "rerun with --kill to remediate HIGH hits"
    fi
    exit 0
fi

echo
echo "${BLD}==================== REMEDIATION ====================${RST}"
if [[ ${#TARGETS[@]} -eq 0 && ${#DISK_FILES[@]} -eq 0 ]]; then
    ok "nothing to remediate"
    exit 0
fi

# ---------- helpers ----------
pkg_owner() {   # prints owning package of a path, empty if none
    local f="$1" alt out
    if [[ "$f" == /usr/* ]]; then alt="${f#/usr}"; else alt="/usr$f"; fi
    for x in "$f" "$alt"; do
        if command -v dpkg >/dev/null; then
            out=$(dpkg -S "$x" 2>/dev/null | awk -F': ' -v f="$x" '$2==f && $1 !~ /^diversion/ {print $1; exit}' | cut -d, -f1)
        elif command -v rpm >/dev/null; then
            out=$(rpm -qf "$x" 2>/dev/null | grep -v 'not owned' | head -1)
        elif command -v pacman >/dev/null; then
            out=$(pacman -Qoq "$x" 2>/dev/null | head -1)
        elif command -v apk >/dev/null; then
            out=$(apk info --who-owns "$x" 2>/dev/null | awk '/is owned by/{print $NF; exit}')
        fi
        [[ -n "$out" ]] && { echo "$out"; return 0; }
    done
    return 1
}

pkg_modified() {   # pkg_modified <pkg> <path>: true if the package manager says the file changed
    local pkg="$1" f="$2"
    if command -v dpkg >/dev/null; then
        dpkg -V "$pkg" 2>/dev/null | awk '{print $NF}' | grep -qxF -e "$f" -e "${f#/usr}"
    elif command -v rpm >/dev/null; then
        rpm -V "$pkg" 2>/dev/null | awk '$1 ~ /5/ {print $NF}' | grep -qxF -e "$f" -e "${f#/usr}"
    else
        return 1
    fi
}

reinstall_pkg() {
    local pkg="$1"
    if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -qq "$pkg"
    elif command -v dnf >/dev/null; then dnf reinstall -y -q "$pkg"
    elif command -v yum >/dev/null; then yum reinstall -y -q "$pkg"
    elif command -v pacman >/dev/null; then pacman -S --noconfirm "$pkg"
    else return 1; fi
}

unlock() {   # strip immutable/append-only from a path and its parent dir
    command -v chattr >/dev/null || { warn "chattr missing (red team may have removed it), can't clear immutable attrs"; return 0; }
    local x
    for x in "$1" "$(dirname "$1")"; do
        [[ -e "$x" ]] || continue
        if lsattr -d "$x" 2>/dev/null | awk '{print $1}' | grep -q '[ia]'; then
            chattr -i -a "$x" 2>/dev/null && warn "cleared immutable/append-only on $x" || warn "couldn't clear attrs on $x"
        fi
    done
}

safe_rm() {   # safe_rm <path>: returns 0 only if it's actually gone
    unlock "$1"
    rm -f "$1" 2>/dev/null
    if [[ -e "$1" ]]; then warn "FAILED to delete $1"; return 1; fi
    hit "deleted $1"; return 0
}

# ---------- classify every target ----------
# implant  = binary no package owns (incl. disguised copies under /usr/lib etc) -> kill, delete, strip persistence
# trojaned = package-owned path but contents changed / duplicated  -> kill, reinstall package
# injected = genuine untouched package binary with sliver in memory -> kill, restart its service
declare -A CLASS SHA PKG PATHS_FOR_SHA DELETED
SAFE_TARGETS=()
for p in "${TARGETS[@]}"; do
    [[ "$p" == 1 ]] && { warn "skipping PID 1 (init), investigate by hand"; continue; }
    [[ -d /proc/$p ]] || { warn "PID $p already gone"; continue; }
    SAFE_TARGETS+=("$p")
    SHA[$p]=$(sha256sum "/proc/$p/exe" 2>/dev/null | awk '{print $1}')
    clean="${EXE[$p]% (deleted)}"
    [[ -n "${SHA[$p]}" && "${PATHS_FOR_SHA[${SHA[$p]}]:-}" != *"|$clean|"* ]] && PATHS_FOR_SHA[${SHA[$p]}]+="|$clean|"
done

for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    clean="${EXE[$p]% (deleted)}"
    ndup=$(grep -o '|[^|]*|' <<< "${PATHS_FOR_SHA[${SHA[$p]:-x}]:-}" | wc -l)
    if [[ "$clean" == /memfd:* ]]; then
        CLASS[$p]=implant
    elif pkg=$(pkg_owner "$clean"); then
        PKG[$p]="$pkg"
        if [[ "$ndup" -gt 1 ]] || pkg_modified "$pkg" "$clean"; then CLASS[$p]=trojaned; else CLASS[$p]=injected; fi
    else
        CLASS[$p]=implant
    fi
done

echo "will remediate:"
for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    case "${CLASS[$p]}" in
        implant)  echo "  PID $p  ${EXE[$p]}  ${RED}[implant: no package owns it -> kill, delete, strip persistence]${RST}" ;;
        trojaned) echo "  PID $p  ${EXE[$p]}  ${RED}[trojaned ${PKG[$p]}: file modified -> kill, reinstall package]${RST}" ;;
        injected) echo "  PID $p  ${EXE[$p]}  ${YEL}[injected into real ${PKG[$p]} -> kill, restart its service]${RST}" ;;
    esac
done
for f in ${DISK_FILES[@]+"${DISK_FILES[@]}"}; do echo "  file $f"; done

if [[ $ASSUME_YES -eq 0 ]]; then
    echo
    read -r -p "type KILL to proceed: " ans < /dev/tty
    [[ "$ans" == "KILL" ]] || { warn "aborted, nothing changed"; exit 0; }
fi

mkdir -p "$QDIR"/{bin,persist}; chmod 700 "$QDIR"
info "quarantine/backups: $QDIR"

# all implant paths, used to decide if a systemd unit is malicious
IMPLANT_PATHS=()
for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    [[ "${CLASS[$p]}" == implant ]] && IMPLANT_PATHS+=("${EXE[$p]% (deleted)}")
done
IMPLANT_PATHS+=(${DISK_FILES[@]+"${DISK_FILES[@]}"})

# ---- 1. block C2 peers ----
if [[ $NO_BLOCK -eq 0 ]]; then
    MY_IPS=" $(hostname -I 2>/dev/null) "
    declare -A BLOCKED
    for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
        while read -r peer; do
            ip=$(sed -E 's/:[0-9*]+$//; s/^\[//; s/\]$//; s/^::ffff://' <<< "$peer")
            [[ -z "$ip" || "$ip" == "*" || "$ip" == "0.0.0.0" || "$ip" == "::" || "$ip" == 127.* || "$ip" == "::1" ]] && continue
            [[ "$MY_IPS" == *" $ip "* || -n "${BLOCKED[$ip]:-}" ]] && continue
            if [[ "$ip" == *:* ]]; then fw=ip6tables; else fw=iptables; fi
            if command -v "$fw" >/dev/null; then
                "$fw" -I OUTPUT -d "$ip" -j DROP -m comment --comment "sliver_hunt C2" 2>/dev/null \
                    || "$fw" -I OUTPUT -d "$ip" -j DROP
                "$fw" -I INPUT -s "$ip" -j DROP -m comment --comment "sliver_hunt C2" 2>/dev/null \
                    || "$fw" -I INPUT -s "$ip" -j DROP
                hit "blocked $ip ($fw in+out)"
            else
                warn "no $fw, block $ip by hand (and at the perimeter)"
            fi
            BLOCKED[$ip]=1
        done < <(awk '{print $5}' <<< "${CONN[$p]:-}")
    done
    [[ ${#BLOCKED[@]} -eq 0 ]] && info "no external C2 peers seen on flagged procs (beacon may have been sleeping)"
fi

# ---- 2. freeze so watchdogs / sibling implants can't respawn each other ----
for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    kill -STOP "$p" 2>/dev/null && info "froze PID $p (${CLASS[$p]})"
done

# ---- 3. systemd units hosting the implant ----
NEED_RELOAD=0
RESTART_UNITS=()
declare -A UNIT_DONE
remove_unit() {   # remove_unit <unit> <fragment>
    local u="$1" frag="$2"
    systemctl disable --now "$u" >/dev/null 2>&1
    if [[ -n "$frag" && -e "$frag" ]]; then
        cp -a --parents "$frag" "$QDIR/persist/" 2>/dev/null
        safe_rm "$frag" && hit "removed malicious unit $u" || warn "unit $u stopped but its file is still there"
    else
        hit "stopped + disabled $u"
    fi
    NEED_RELOAD=1
}
for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    unit=$(grep -oE '[^/]+\.service' "/proc/$p/cgroup" 2>/dev/null | tail -1)
    [[ -z "$unit" || -n "${UNIT_DONE[$unit]:-}" ]] && continue
    UNIT_DONE[$unit]=1
    frag=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
    refs_implant=0
    for ip in ${IMPLANT_PATHS[@]+"${IMPLANT_PATHS[@]}"}; do
        [[ -n "$frag" ]] && grep -qF "$ip" "$frag" 2>/dev/null && refs_implant=1
    done
    if [[ $refs_implant -eq 1 ]]; then
        remove_unit "$unit" "$frag"
    elif [[ "${CLASS[$p]}" == implant ]]; then
        if [[ -n "$frag" ]] && ! pkg_owner "$frag" >/dev/null; then
            warn "implant PID $p runs under $unit ($frag), not package-owned and doesn't name the binary directly. CHECK IT BY HAND (wrapper script?), not touching it"
        else
            info "implant PID $p was spawned under legit $unit (web shell / exploited service?), leaving the unit alone"
        fi
    else
        RESTART_UNITS+=("$unit")
    fi
done

# ---- 4. strip persistence (implant paths only, never real package paths) ----
strip_persistence() {   # strip_persistence <implant_path>
    local path="${1% (deleted)}" ref unit
    while read -r ref; do
        [[ -z "$ref" ]] && continue
        cp -a --parents "$ref" "$QDIR/persist/" 2>/dev/null
        case "$ref" in
            */systemd/*.service|*/systemd/*.timer|*/systemd/*.socket|*/systemd/*/*.service|*/systemd/*/*.timer)
                remove_unit "$(basename "$ref")" "$ref"
                ;;
            */systemd/*.service.d/*.conf)
                safe_rm "$ref"; NEED_RELOAD=1
                ;;
            *)
                # cron, rc files, profile, ld.so.preload, init.d, etc: drop only the lines that reference the implant
                unlock "$ref"
                { grep -vF "$path" "$ref" || true; } > "$QDIR/.strip_tmp" && cat "$QDIR/.strip_tmp" > "$ref" 2>/dev/null
                rm -f "$QDIR/.strip_tmp"
                if grep -qF "$path" "$ref" 2>/dev/null; then
                    warn "FAILED to strip $path from $ref (still immutable? fix by hand)"
                else
                    hit "stripped implant lines from $ref"
                fi
                ;;
        esac
    done < <(find_persist "$path")
}
for ip in ${IMPLANT_PATHS[@]+"${IMPLANT_PATHS[@]}"}; do strip_persistence "$ip"; done
[[ $NEED_RELOAD -eq 1 ]] && systemctl daemon-reload 2>/dev/null

# ---- 5. kill ----
declare -A IOC_SHA
for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    exe="${EXE[$p]}"; clean="${exe% (deleted)}"; sha="${SHA[$p]:-}"

    # evidence copy first (works for deleted binaries too)
    [[ -n "$sha" ]] && cp "/proc/$p/exe" "$QDIR/bin/${sha}.bin" 2>/dev/null && chmod 000 "$QDIR/bin/${sha}.bin"
    [[ "${CLASS[$p]}" != injected && -n "$sha" ]] && IOC_SHA[$sha]=1

    # red team shells/tools spawned by the implant (not for injected real services, those are workers)
    [[ "${CLASS[$p]}" != injected ]] && pkill -KILL -P "$p" 2>/dev/null

    kill -KILL "$p" 2>/dev/null && hit "killed PID $p ($exe) [${CLASS[$p]}]"
done

# any other running copy of the same implant, whatever it's named
for q in $(ls /proc | grep -E '^[0-9]+$'); do
    [[ "$q" == "$$" || "$q" == "$BASHPID" || "$q" == 1 ]] && continue
    s=$(sha256sum "/proc/$q/exe" 2>/dev/null | awk '{print $1}')
    [[ -n "$s" && -n "${IOC_SHA[$s]:-}" ]] && kill -KILL "$q" 2>/dev/null && hit "killed copy PID $q ($(readlink "/proc/$q/exe")) same hash"
done

# ---- 6. delete implants / reinstall trojaned packages ----
declare -A PKG_DONE
for p in ${SAFE_TARGETS[@]+"${SAFE_TARGETS[@]}"}; do
    clean="${EXE[$p]% (deleted)}"
    case "${CLASS[$p]}" in
        implant)
            [[ "$clean" == /memfd:* ]] && continue
            [[ -e "$clean" ]] && safe_rm "$clean" && DELETED[$clean]=1
            ;;
        trojaned)
            pkg="${PKG[$p]}"; [[ -n "${PKG_DONE[$pkg]:-}" ]] && continue; PKG_DONE[$pkg]=1
            unlock "$clean"
            if reinstall_pkg "$pkg" >/dev/null 2>&1; then
                ok "reinstalled $pkg (restored clean $clean)"
            else
                warn "couldn't reinstall $pkg. $clean is STILL TROJANED, its service will relaunch the implant. fix by hand"
            fi
            ;;
    esac
done

for f in ${DISK_FILES[@]+"${DISK_FILES[@]}"}; do
    [[ -f "$f" ]] || continue
    if pkg=$(pkg_owner "$f"); then
        warn "YARA disk hit on $f owned by $pkg (trojaned?), not deleting. try reinstalling $pkg"
        continue
    fi
    sha=$(sha256sum "$f" | awk '{print $1}')
    IOC_SHA[$sha]=1
    cp "$f" "$QDIR/bin/${sha}.bin" && chmod 000 "$QDIR/bin/${sha}.bin"
    safe_rm "$f" && DELETED[$f]=1
done

# dormant copies of the same implant hiding elsewhere on disk (match by size, then hash)
if [[ ${#IOC_SHA[@]} -gt 0 ]]; then
    info "hunting for dormant copies of the implant hash(es) on disk..."
    declare -A SIZES
    for s in "${!IOC_SHA[@]}"; do
        [[ -f "$QDIR/bin/$s.bin" ]] && SIZES[$(stat -c %s "$QDIR/bin/$s.bin")]=1
    done
    for sz in "${!SIZES[@]}"; do
        while read -r f; do
            s=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            [[ -n "${IOC_SHA[$s]:-}" ]] || continue
            if pkg_owner "$f" >/dev/null; then warn "copy at package-owned $f, check by hand"; continue; fi
            hit "dormant copy: $f"
            strip_persistence "$f"
            safe_rm "$f" && DELETED[$f]=1
        done < <(find / -xdev \( -path /proc -o -path /sys -o -path "$QDIR" \) -prune -o -type f -size "${sz}c" -print 2>/dev/null)
    done
    [[ $NEED_RELOAD -eq 1 ]] && systemctl daemon-reload 2>/dev/null
fi

# restart real services that had sliver injected (or got their package reinstalled)
for u in $(printf '%s\n' ${RESTART_UNITS[@]+"${RESTART_UNITS[@]}"} | sort -u); do
    systemctl restart "$u" 2>/dev/null && ok "restarted $u clean" || warn "couldn't restart $u, check it NOW (scored service?)"
done

# ---- 7. verify ----
info "waiting 10s to see if anything respawns..."
sleep 10
BACK=0
for q in $(ls /proc | grep -E '^[0-9]+$'); do
    s=$(sha256sum "/proc/$q/exe" 2>/dev/null | awk '{print $1}')
    [[ -n "$s" && -n "${IOC_SHA[$s]:-}" ]] && { hit "RESPAWNED: PID $q $(readlink "/proc/$q/exe")"; BACK=1; }
done
for f in ${IMPLANT_PATHS[@]+"${IMPLANT_PATHS[@]}"} "${!DELETED[@]}"; do
    [[ "$f" == /memfd:* || ! -e "$f" ]] && continue
    if [[ -n "${DELETED[$f]:-}" ]]; then hit "binary came BACK on disk: $f"; else hit "binary still on disk (delete failed): $f"; fi
    BACK=1
done
if [[ $BACK -eq 1 ]]; then
    warn "not clean yet: check other implants, timers, root crontabs, wrapper scripts, rootkits, then rerun the hunt"
else
    ok "nothing came back"
fi

echo
info "done. full log: $LOG | quarantine: $QDIR"
info "next: push the IOCs to the team and sweep the other boxes for the same hashes/IPs"
