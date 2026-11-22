#!/usr/bin/env bash
# sliver_hunt.sh - read-only Sliver implant hunt for Linux (CCDC)
#
# usage: sudo ./sliver_hunt.sh [rules_file] [extra_dir ...]
#   rules_file  defaults to /srv/sliver.yar (.yarc = compiled, uses -C)
#               if missing, it gets downloaded; if yara is missing, it gets installed
#   extra_dir   any extra directories to YARA scan on disk
#
# Does NOT kill or delete anything. It finds, reports, and logs.

set -u

RULES="${1:-/srv/sliver.yar}"
shift || true
EXTRA_DIRS=("$@")
HOST=$(hostname)
TS=$(date +%Y%m%d_%H%M%S)
LOG="/root/sliver_hunt_${HOST}_${TS}.log"
YTIMEOUT=60   # seconds per yara memory scan, so one huge process can't stall the hunt

RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLD=$'\e[1m'; RST=$'\e[0m'
die()  { echo "${RED}[!] $*${RST}" >&2; exit 1; }
info() { echo "${BLD}[*]${RST} $*"; }
warn() { echo "${YEL}[~]${RST} $*"; }
ok()   { echo "${GRN}[ok]${RST} $*"; }
hit()  { echo "${RED}${BLD}[+]${RST} $*"; }

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
              /etc/rc.local /etc/profile /etc/profile.d /etc/bash.bashrc /etc/ld.so.preload
              /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.config/systemd)
find_persist() {
    local path="${1% (deleted)}"
    [[ -z "$path" || "$path" == /memfd:* ]] && return
    grep -rlF "$path" "${PERSIST_LOCS[@]}" 2>/dev/null
}

# ---------- report ----------
echo
echo "${BLD}==================== RESULTS: $HOST ====================${RST}"
HASHES=(); REMOTES=()

if [[ ${#FLAGS[@]} -eq 0 ]]; then
    ok "no suspicious processes"
else
    for p in "${!FLAGS[@]}"; do
        if [[ "${FLAGS[$p]}" == *YARA* ]]; then sev="${RED}${BLD}HIGH${RST}"; else sev="${YEL}SUSPECT${RST}"; fi
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
        [[ -f "$f" ]] && HASHES+=("$(sha256sum "$f" | awk '{print $1}')  $f")
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
echo
info "done. full log: $LOG"
info "kill order: block C2 at firewall -> remove persistence -> kill PID -> sweep other boxes for the hashes"
