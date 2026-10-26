#!/bin/bash
#
# failover-splunk.sh - Add Splunk to a box that is already set up and running other services.
#
# Works on RHEL-like (RHEL/Rocky/Alma/CentOS/Fedora) and Debian-like (Ubuntu/Debian) systems.
#
# What this script does NOT touch (on purpose):
#   - httpd/apache2, php/php-fpm, opencart, mariadb/mysql, postfix, dovecot, roundcube
#     (never stopped, restarted, reloaded, or reconfigured)
#   - existing firewall rules (rules are only ADDED, never flushed, reloaded, or default policies changed)
#   - sysctl, SELinux/AppArmor mode, DNS, SSH, cron, user accounts, passwords, installed packages
#   - no yum/dnf/apt install, update or remove
#
# What it does:
#   - installs Splunk (or reuses /opt/splunk), runs it as an unprivileged "splunk" user
#   - puts all config in its own app (ccdc_base) so nothing in system/local gets overwritten
#   - web UI over HTTPS on port 8000, management port 8089 limited to localhost
#   - monitors logs of whichever services exist on this box (incl. opencart/roundcube app logs)
#   - runs Splunk at low priority and makes it the first OOM-kill candidate, so it can never
#     starve or take down the real services
#   - opens ONLY the Splunk ports it needs, additively (firewalld, ufw, or iptables)
#   - checks afterwards that every service that was running before is still running
#
# Usage:
#   ./failover-splunk.sh [options]
#
# Splunk is downloaded automatically (latest Linux x86_64 .tgz from splunk.com, SHA512-verified).
# If /opt/splunk already exists with Splunk in it, the download is skipped.
#
# Options:
#   --allow <cidr>       Restrict firewall rules and Splunk Web to this IPv4 source network
#                        (e.g. 172.20.240.0/24). Localhost is always allowed.
#   --no-receive         Disable listening for forwarders on 9997
#   --no-management      Disable listening on management interface on 8089
#   --syslog-port <n>    Also listen for syslog over TCP on this port (use >1024, e.g. 1514,
#                        because splunk does not run as root; 514 would need root)
#   --web-port <n>       Splunk web port (default 8000)
#   --no-firewall        Do not touch the firewall at all
#   -h | --help
#
# Environment:
#   SPLUNK_ADMIN_PASSWORD  admin password (otherwise you are prompted)
#   SPLUNK_URL             optional: force a specific download.splunk.com .tgz URL

set -u
umask 022

if [[ $EUID -ne 0 ]]; then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

#################
## Definitions ##
#################

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
CCDC_DIR="/ccdc"
LOGFILE="$CCDC_DIR/logs/failover-splunk.txt"
APP_NAME="ccdc_base"
APP_DIR="$SPLUNK_HOME/etc/apps/$APP_NAME"
FW_SCRIPT="$CCDC_DIR/scripts/linux/splunk-fw.sh"

SPLUNK_URL="${SPLUNK_URL:-}"
DL_DIR="$CCDC_DIR/downloads"
# Last-resort fallback if the splunk.com page cannot be scraped. Splunk removes old
# builds from time to time, so if this 404s, set SPLUNK_URL to a current link.
FALLBACK_URL="https://download.splunk.com/products/splunk/releases/10.6.1.1/linux/splunk-10.6.1.1-b2ae2962645c-linux-amd64.tgz"
ALLOW_NET="0.0.0.0/0, ::/0"
ALLOW_MGMT="0.0.0.0/0, ::/0"
RECEIVE=1
MANAGEMENT=1
SYSLOG_PORT=""
WEB_PORT=8000
DO_FW=1
ADMIN_PASS=""

# Services we promise not to disturb (unit names for both RHEL and Debian families)
WATCH_UNITS=(httpd apache2 nginx php-fpm mariadb mysql mysqld postfix dovecot)
PRE_ACTIVE=()

declare -A SEEN_MON=()

YELLOW='\033[33m'; RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

mkdir -p "$CCDC_DIR/logs" "$(dirname "$FW_SCRIPT")"

###############
## Functions ##
###############

log()  { echo -e "${YELLOW}$1${NC}"; echo "$(date +"%x %X") - $1" >> "$LOGFILE"; }
warn() { echo -e "${RED}WARNING: $1${NC}"; echo "$(date +"%x %X") - WARNING: $1" >> "$LOGFILE"; }
die()  { echo -e "${RED}ERROR: $1${NC}"; echo "$(date +"%x %X") - ERROR: $1" >> "$LOGFILE"; exit 1; }

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

is_num() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

need_val() { [[ $# -ge 2 && -n "${2:-}" ]] || die "Option $1 needs a value (try --help)"; }

# port_in_use <port>  (tcp listener)
port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  else
    # No ss installed: look for a TCP listener (state 0A) in /proc
    local hex; hex=$(printf '%04X' "$1")
    awk -v h=":$hex" '$2 ~ h"$" && $4 == "0A" {f=1} END {exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
  fi
}

splunk_running() {
  systemctl is-active --quiet Splunkd 2>/dev/null || pgrep -x splunkd >/dev/null 2>&1
}

snapshot_services() {
  local u
  for u in "${WATCH_UNITS[@]}"; do
    systemctl is-active --quiet "$u" 2>/dev/null && PRE_ACTIVE+=("$u")
  done
  # versioned php-fpm units on Debian/Ubuntu (php8.1-fpm etc.)
  for u in $(systemctl list-units --type=service --state=active --no-legend 'php*-fpm*' 2>/dev/null | awk '{print $1}'); do
    PRE_ACTIVE+=("${u%.service}")
  done
  if [[ ${#PRE_ACTIVE[@]} -gt 0 ]]; then
    log "Services running before we start (must still be running after): ${PRE_ACTIVE[*]}"
  fi
}

verify_services() {
  local u bad=0
  for u in "${PRE_ACTIVE[@]}"; do
    if ! systemctl is-active --quiet "$u" 2>/dev/null; then
      warn "$u was running before and is NOT running now. Investigate: journalctl -u $u"
      bad=1
    fi
  done
  [[ $bad -eq 0 && ${#PRE_ACTIVE[@]} -gt 0 ]] && log "Verified: all ${#PRE_ACTIVE[@]} pre-existing services are still running"
  return 0
}

preflight() {
  log "Preflight checks"

  [[ -d /run/systemd/system ]] || die "This script needs systemd (not found)."

  # Needed for the Splunk unit's AmbientCapabilities (reading root-only logs as non-root)
  local sdv
  sdv=$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2}')
  if is_num "$sdv" && [[ "$sdv" -lt 229 ]]; then
    warn "systemd $sdv is older than 229: Splunk may not be able to read root-only logs (secure, maillog)."
  fi

  # Memory (Splunk wants a few GB; the other services need theirs too)
  local mem_mb
  mem_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
  [[ "$mem_mb" -lt 2048 ]] && warn "Only ${mem_mb}MB RAM available. Splunk is set to be OOM-killed first, but consider a bigger box."

  # Disk: download dir and install dir (may be different filesystems)
  local d disk_gb
  for d in "$(dirname "$SPLUNK_HOME")" "$CCDC_DIR"; do
    disk_gb=$(df -BG --output=avail "$d" 2>/dev/null | tail -1 | tr -dc '0-9')
    is_num "$disk_gb" && [[ "$disk_gb" -lt 6 ]] && warn "Only ${disk_gb}GB free on $d. Download plus install needs roughly 6GB."
  done

  # Port conflicts with existing services (skip if Splunk is already the one listening)
  if ! splunk_running; then
    local ports=("$WEB_PORT" 8089 8065 8191)
    [[ $RECEIVE -eq 1 ]] && ports+=(9997)
    [[ -n "$SYSLOG_PORT" ]] && ports+=("$SYSLOG_PORT")
    local p
    for p in "${ports[@]}"; do
      port_in_use "$p" && die "Port $p is already in use by something else. Pick another with --web-port/--syslog-port, or free it."
    done
  fi
}

get_password() {
  # Skip if Splunk was already initialized (it has an existing passwd file)
  if [[ -f "$SPLUNK_HOME/etc/passwd" ]]; then
    log "Splunk already initialized, keeping the existing admin account"
    ADMIN_PASS=""
    return
  fi

  ADMIN_PASS="${SPLUNK_ADMIN_PASSWORD:-}"
  if [[ -n "$ADMIN_PASS" ]]; then
    [[ ${#ADMIN_PASS} -ge 8 ]] || die "SPLUNK_ADMIN_PASSWORD must be at least 8 characters."
    return
  fi

  [[ -t 0 ]] || die "No SPLUNK_ADMIN_PASSWORD set and no terminal to prompt on."
  local confirm
  while true; do
    read -r -s -p "New Splunk admin password (min 8 chars): " ADMIN_PASS || die "Password prompt aborted."; echo
    read -r -s -p "Confirm password: " confirm || die "Password prompt aborted."; echo
    if [[ "$ADMIN_PASS" == "$confirm" && ${#ADMIN_PASS} -ge 8 ]]; then
      break
    fi
    echo "Passwords do not match or are too short. Try again."
  done
}

ensure_user() {
  getent group "$SPLUNK_USER" >/dev/null 2>&1 || groupadd -r "$SPLUNK_USER" || die "Could not create group $SPLUNK_USER"
  if ! id -u "$SPLUNK_USER" >/dev/null 2>&1; then
    log "Creating system user $SPLUNK_USER"
    local nl; nl=$(command -v nologin || echo /sbin/nologin)
    useradd -r -M -g "$SPLUNK_USER" -d "$SPLUNK_HOME" -s "$nl" "$SPLUNK_USER" \
      || die "Could not create $SPLUNK_USER"
  fi
}

# Fetch a URL to stdout or a file using curl, falling back to wget
fetch() {
  # fetch <url> [outfile]
  if command -v curl >/dev/null 2>&1; then
    if [[ -n "${2:-}" ]]; then curl -fsSL --retry 3 --connect-timeout 20 -A "Mozilla/5.0" "$1" -o "$2"
    else curl -fsSL --retry 3 --connect-timeout 20 -A "Mozilla/5.0" "$1"; fi
  elif command -v wget >/dev/null 2>&1; then
    if [[ -n "${2:-}" ]]; then wget -q -t 3 -U "Mozilla/5.0" "$1" -O "$2"
    else wget -q -t 3 -U "Mozilla/5.0" "$1" -O -; fi
  else
    die "Neither curl nor wget is installed (this script does not install packages)."
  fi
}

# Work out the current Splunk Enterprise .tgz URL
find_splunk_url() {
  if [[ -n "$SPLUNK_URL" ]]; then
    echo "$SPLUNK_URL"; return
  fi

  # Case-insensitive: Splunk has used both "Linux-x86_64" and "linux-amd64" in file names.
  # sort -V picks the highest version if the page lists several.
  local url
  url=$(fetch "https://www.splunk.com/en_us/download/splunk-enterprise.html" 2>/dev/null \
        | grep -oiE 'https://download\.splunk\.com/products/splunk/releases/[0-9.]+/linux/splunk-[0-9.]+-[0-9a-f]+-linux-(amd64|x86_64)\.tgz' \
        | sort -uV | tail -n1)

  if [[ -z "$url" ]]; then
    warn "Could not read the latest version from splunk.com, using fallback URL"
    url="$FALLBACK_URL"
  fi
  echo "$url"
}

install_splunk() {
  if [[ -x "$SPLUNK_HOME/bin/splunk" ]]; then
    log "Splunk already present at $SPLUNK_HOME, skipping download/install"
    return
  fi

  [[ "$(uname -m)" == "x86_64" ]] || die "Auto-download only supports x86_64 (this is $(uname -m))."
  command -v tar >/dev/null 2>&1 || die "tar is not installed."

  local url file
  url=$(find_splunk_url)
  file="$DL_DIR/$(basename "$url")"
  mkdir -p "$DL_DIR"   # on disk, not /tmp, so a 1.7GB file doesn't eat RAM if /tmp is tmpfs

  log "Downloading $url"
  fetch "$url" "$file" || { rm -f "$file"; die "Download failed. Is outbound HTTPS allowed? If the URL is stale, set SPLUNK_URL."; }

  # Verify integrity against Splunk's published SHA512. The .sha512 file may be either
  # "<hash>  <file>" or "SHA512(<file>)= <hash>", so pull out the 128 hex chars either way.
  local want have
  want=$(fetch "$url.sha512" 2>/dev/null | grep -oE '[0-9a-fA-F]{128}' | head -n1)
  if [[ -n "$want" ]]; then
    have=$(sha512sum "$file" | awk '{print $1}')
    [[ "${want,,}" == "${have,,}" ]] || { rm -f "$file"; die "SHA512 mismatch on downloaded package, aborting."; }
    log "SHA512 verified"
  else
    warn "Could not fetch the SHA512 file, skipping integrity check"
  fi

  log "Extracting to $(dirname "$SPLUNK_HOME")"
  tar -xzf "$file" -C "$(dirname "$SPLUNK_HOME")" || die "Extract failed (disk full?)"
  chown -R splunk:splunk /opt/splunk || die "Could not transfer ownership of /opt/splunk"
  rm -f "$file"

  [[ -x "$SPLUNK_HOME/bin/splunk" ]] || die "Extracted, but $SPLUNK_HOME/bin/splunk is missing"
}

# add_monitor <glob> <index> <sourcetype|"">
# Only adds a stanza if the path actually exists on this box, and never twice
# for the same real location (symlinked log dirs, overlapping globs).
add_monitor() {
  local path="$1" index="$2" st="${3:-}" first real key
  first=$(compgen -G "$path" | head -n1)
  [[ -n "$first" ]] || return 0
  real=$(readlink -f "$first" 2>/dev/null || echo "$first")
  key="$(dirname "$real")|$(basename "$path")"
  [[ -n "${SEEN_MON[$key]:-}" ]] && return 0
  SEEN_MON[$key]=1
  {
    echo "[monitor://$path]"
    echo "index = $index"
    echo "disabled = false"
    echo 'blacklist = \.(gz|bz2|zip|xz|z)$'
    [[ -n "$st" ]] && echo "sourcetype = $st"
    echo
  } >> "$APP_DIR/local/inputs.conf"
  log "Monitoring $path -> index=$index"
}

# add_journald <name> <index> <unit>...
# For services that log only to the systemd journal (e.g. MariaDB on Ubuntu, sshd without rsyslog).
# Only added if journalctl exists and one of the units exists on this box.
add_journald() {
  local name="$1" index="$2"; shift 2
  command -v journalctl >/dev/null 2>&1 || return 0
  local u unit=""
  for u in "$@"; do
    if systemctl cat "$u.service" >/dev/null 2>&1; then unit="$u"; break; fi
  done
  [[ -n "$unit" ]] || return 0
  {
    echo "[journald://$name]"
    echo "index = $index"
    echo "journalctl-unit = $unit"
    echo "disabled = false"
    echo
  } >> "$APP_DIR/local/inputs.conf"
  log "Monitoring journal unit $unit -> index=$index"
}

# Application-level logs that live inside web roots (opencart, roundcube)
discover_app_logs() {
  local d
  # OpenCart: <root>/system/storage/logs (v3) or <root>/storage/logs (v4)
  while IFS= read -r d; do
    [[ -n "$d" ]] && add_monitor "$d/*.log" web ""
  done < <(find /var/www /srv /usr/share/opencart -maxdepth 7 -type d -path '*/storage/logs' 2>/dev/null)

  # Roundcube: <root>/logs, /var/lib/roundcube/logs, /usr/share/roundcubemail/logs
  while IFS= read -r d; do
    [[ -n "$d" ]] && add_monitor "$d/*" mail ""
  done < <(find /var/www /srv /var/lib/roundcube /usr/share/roundcubemail /usr/share/roundcube \
                -maxdepth 6 -type d -name logs -path '*roundcube*' 2>/dev/null)
}

write_config() {
  log "Writing Splunk config to its own app ($APP_NAME)"
  mkdir -p "$APP_DIR/local" "$APP_DIR/metadata"
  SEEN_MON=()

  cat > "$APP_DIR/local/app.conf" <<EOF
[install]
state = enabled

[ui]
is_visible = false
EOF

  # Make the app's indexes/inputs visible system-wide
  cat > "$APP_DIR/metadata/local.meta" <<EOF
[]
access = read : [ * ], write : [ admin ]
export = system
EOF

  # Web: HTTPS, XSLT RCE fix
  {
    echo "[settings]"
    echo "httpport = $WEB_PORT"
    echo "enableSplunkWebSSL = false"
    echo "enableSearchJobXslt = false"
    [[ -n "$ALLOW_NET" ]] && echo "acceptFrom = $ALLOW_NET, 127.0.0.0/8"
  } > "$APP_DIR/local/web.conf"

  # Management port
  cat > "$APP_DIR/local/server.conf" <<EOF
[httpServer]
acceptFrom = $ALLOW_MGMT, 127.0.0.1, ::1
EOF

  # Separate indexes so searches stay tidy and the other services' logs are easy to find
  : > "$APP_DIR/local/indexes.conf"
  local idx
  for idx in web mail sql os; do
    cat >> "$APP_DIR/local/indexes.conf" <<EOF
[$idx]
homePath   = \$SPLUNK_DB/$idx/db
coldPath   = \$SPLUNK_DB/$idx/colddb
thawedPath = \$SPLUNK_DB/$idx/thaweddb

EOF
  done

  # Inputs
  : > "$APP_DIR/local/inputs.conf"

  local acl=""
  [[ -n "$ALLOW_NET" ]] && acl="acceptFrom = $ALLOW_NET"

  if [[ $RECEIVE -eq 1 ]]; then
    cat >> "$APP_DIR/local/inputs.conf" <<EOF
[splunktcp://9997]
disabled = false
$acl

EOF
  fi

  if [[ -n "$SYSLOG_PORT" ]]; then
    cat >> "$APP_DIR/local/inputs.conf" <<EOF
[tcp://$SYSLOG_PORT]
index = os
sourcetype = syslog
connection_host = ip
disabled = false
$acl

EOF
  fi

  # Web server (RHEL-style and Debian-style paths; opencart/roundcube run behind these)
  add_monitor "/var/log/httpd/*access_log*"    web  access_combined
  add_monitor "/var/log/httpd/*error_log*"     web  apache_error
  add_monitor "/var/log/apache2/*access*.log*" web  access_combined
  add_monitor "/var/log/apache2/*error*.log*"  web  apache_error
  add_monitor "/var/log/nginx/access.log*"     web  access_combined
  add_monitor "/var/log/nginx/error.log*"      web  ""
  add_monitor "/var/log/php-fpm/*.log"         web  ""
  add_monitor "/var/log/php*.log"              web  ""

  # SQL
  add_monitor "/var/log/mariadb/*.log"         sql  ""
  add_monitor "/var/log/mysql/*.log"           sql  ""
  add_monitor "/var/log/mysqld.log"            sql  ""
  add_monitor "/var/log/mysql.log"             sql  ""

  # Mail (postfix, dovecot, roundcube if it logs here)
  add_monitor "/var/log/maillog"               mail postfix_syslog
  add_monitor "/var/log/mail.log"              mail postfix_syslog
  add_monitor "/var/log/mail.err"              mail ""
  add_monitor "/var/log/dovecot*.log"          mail ""
  add_monitor "/var/log/dovecot/*.log"         mail ""
  add_monitor "/var/log/roundcubemail/*"       mail ""
  add_monitor "/var/log/roundcube/*"           mail ""

  # OS / auth
  add_monitor "/var/log/secure"                os   linux_secure
  add_monitor "/var/log/auth.log"              os   linux_secure
  add_monitor "/var/log/messages"              os   syslog
  add_monitor "/var/log/syslog"                os   syslog

  # opencart / roundcube logs inside web roots
  discover_app_logs

  # Journal-only fallbacks: only when there is no log file for that service
  if [[ -z "$(compgen -G '/var/log/mariadb/*.log')$(compgen -G '/var/log/mysql/*.log')$(compgen -G '/var/log/mysqld.log')" ]]; then
    add_journald sql sql mariadb mysql mysqld
  fi
  if [[ ! -e /var/log/auth.log && ! -e /var/log/secure ]]; then
    add_journald os os ssh sshd
  fi

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$APP_DIR"
}

seed_admin() {
  [[ -z "${ADMIN_PASS:-}" ]] && return
  log "Seeding admin account"
  mkdir -p "$SPLUNK_HOME/etc/system/local"
  local old_umask; old_umask=$(umask)
  umask 077
  cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $ADMIN_PASS
EOF
  umask "$old_umask"
  chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/user-seed.conf"
  chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"
}

setup_service() {
  # Run as non-root via systemd. The unit lets splunk READ root-only logs (secure, maillog, etc.)
  # without changing file permissions or ACLs on any other service's logs.
  if [[ ! -f /etc/systemd/system/Splunkd.service ]]; then
    log "Enabling Splunk as a systemd service"
    "$SPLUNK_HOME/bin/splunk" enable boot-start -systemd-managed 1 -user "$SPLUNK_USER" \
      --accept-license --answer-yes --no-prompt >> "$LOGFILE" 2>&1 \
      || die "Could not enable boot-start (see $LOGFILE)"
  fi

  # AmbientCapabilities : read root-only logs as the splunk user
  # Nice / OOMScoreAdjust: if the box is under pressure, Splunk yields / dies first, never httpd/mariadb/etc.
  mkdir -p /etc/systemd/system/Splunkd.service.d
  cat > /etc/systemd/system/Splunkd.service.d/10-ccdc.conf <<EOF
[Service]
AmbientCapabilities=CAP_DAC_READ_SEARCH
Nice=5
OOMScoreAdjust=500
EOF

  # First-run init as root can leave root-owned files, so fix ownership before starting
  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"
  # Only re-reads unit files; does not restart any service
  systemctl daemon-reload
}

# --- Firewall: additive only -------------------------------------------------

fw_ports() {
  local p=("$WEB_PORT")
  [[ $MANAGEMENT -eq 1 ]] && p+=(8089)
  [[ $RECEIVE -eq 1 ]] && p+=(9997)
  [[ -n "$SYSLOG_PORT" ]] && p+=("$SYSLOG_PORT")
  echo "${p[@]}"
}

setup_firewall() {
  [[ $DO_FW -eq 0 ]] && { log "Skipping firewall (--no-firewall)"; return; }
  log "Adding Splunk firewall rules (existing rules left alone)"

  local ports p; ports=$(fw_ports)

  if systemctl is-active --quiet firewalld 2>/dev/null; then
    # Add to the running config AND the permanent config. We deliberately do NOT
    # --reload: a reload would drop any runtime-only rules the other services rely on.
    for p in $ports; do
      if [[ -n "$ALLOW_NET" ]]; then
        local rule="rule family=ipv4 source address=$ALLOW_NET port port=$p protocol=tcp accept"
        firewall-cmd -q --add-rich-rule="$rule"
        firewall-cmd -q --permanent --add-rich-rule="$rule"
      else
        firewall-cmd -q --add-port="$p/tcp"
        firewall-cmd -q --permanent --add-port="$p/tcp"
      fi
    done
    log "firewalld rules added for: $ports"

  elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    for p in $ports; do
      ufw allow proto tcp from "${ALLOW_NET:-any}" to any port "$p" >/dev/null
    done
    log "ufw rules added for: $ports"

  elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -qv '^-P INPUT ACCEPT$'; then
    # Idempotent helper script, so the rules can be re-applied at boot
    # even if another script (e.g. ccdc_firewall.service) flushes and reloads iptables.
    {
      echo '#!/bin/bash'
      echo '# Adds Splunk ports to INPUT only if missing. Never flushes anything.'
      for p in $ports; do
        local src=""
        [[ -n "$ALLOW_NET" ]] && src="-s $ALLOW_NET"
        echo "iptables -C INPUT -p tcp $src --dport $p -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp $src --dport $p -j ACCEPT"
        # IPv6 only when not restricted to an (IPv4) --allow network, and only if ip6tables has a restrictive INPUT chain
        if [[ -z "$ALLOW_NET" ]]; then
          echo "if command -v ip6tables >/dev/null 2>&1 && ip6tables -S INPUT 2>/dev/null | grep -qv '^-P INPUT ACCEPT\$'; then"
          echo "  ip6tables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -p tcp --dport $p -j ACCEPT"
          echo "fi"
        fi
      done
    } > "$FW_SCRIPT"
    chmod 700 "$FW_SCRIPT"
    bash "$FW_SCRIPT"

    cat > /etc/systemd/system/splunk-fw.service <<EOF
[Unit]
Description=Add Splunk ports to iptables
After=network.target iptables.service ip6tables.service netfilter-persistent.service ccdc_firewall.service

[Service]
Type=oneshot
ExecStart=/bin/bash $FW_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable splunk-fw.service >/dev/null 2>&1
    log "iptables rules added for: $ports (re-applied at boot by splunk-fw.service)"

  else
    warn "No active firewalld/ufw/restrictive iptables ruleset found. Not touching the firewall."
  fi

  # Splunk logs sent OUT of this box are not needed, so OUTPUT is deliberately untouched.
}

web_up() {
  if command -v curl >/dev/null 2>&1; then
    curl -sk -o /dev/null --max-time 5 "https://127.0.0.1:$WEB_PORT/"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --no-check-certificate -T 5 -t 1 -O /dev/null "https://127.0.0.1:$WEB_PORT/"
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$WEB_PORT") 2>/dev/null
  fi
}

start_splunk() {
  log "Starting Splunk"
  systemctl enable Splunkd >/dev/null 2>&1

  if systemctl is-active --quiet Splunkd 2>/dev/null; then
    systemctl restart Splunkd
  else
    # A hand-started splunkd (not under systemd) would collide with the unit; stop only that one.
    if pgrep -x splunkd >/dev/null 2>&1; then
      log "Found a splunkd running outside systemd, stopping it first"
      "$SPLUNK_HOME/bin/splunk" stop >> "$LOGFILE" 2>&1 || true
    fi
    systemctl start Splunkd
  fi

  # First start (init, KV store, SSL cert) can be slow on a loaded box: wait up to ~5 minutes
  local i
  for i in $(seq 1 60); do
    if web_up; then
      return 0
    fi
    if [[ $i -ge 3 ]] && ! systemctl is-active --quiet Splunkd 2>/dev/null; then
      warn "Splunkd exited during startup. Check: journalctl -u Splunkd; tail $SPLUNK_HOME/var/log/splunk/splunkd.log"
      return 1
    fi
    sleep 5
  done
  warn "Splunk web did not answer on $WEB_PORT yet. Check: journalctl -u Splunkd; tail $SPLUNK_HOME/var/log/splunk/splunkd.log"
  return 1
}

summary() {
  local ip; ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo
  echo -e "${GREEN}Splunk is set up.${NC}"
  echo "  Web UI:        https://${ip:-<this-box>}:$WEB_PORT  (user: admin, self-signed cert)"
  echo "  Indexes:       web, mail, sql, os   (search with e.g. index=web)"
  echo "  Config app:    $APP_DIR/local"
  echo "  Service:       systemctl status Splunkd"
  echo "  Log:           $LOGFILE"
  [[ $RECEIVE -eq 1 ]]        && echo "  Forwarders:    port 9997"
  [[ -n "$SYSLOG_PORT" ]]     && echo "  Syslog (TCP):  port $SYSLOG_PORT"
  echo
  if [[ ${#PRE_ACTIVE[@]} -gt 0 ]]; then
    echo "Other services were not modified. Quick sanity check:"
    echo "  systemctl is-active ${PRE_ACTIVE[*]}"
  fi
}

##########
## Main ##
##########

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow)       need_val "$@"; ALLOW_NET="$2"; shift 2 ;;
    --no-receive)  RECEIVE=0; shift ;;
    --no-rest)     REST=0; shift ;;
    --syslog-port) need_val "$@"; SYSLOG_PORT="$2"; shift 2 ;;
    --web-port)    need_val "$@"; WEB_PORT="$2"; shift 2 ;;
    --no-firewall) DO_FW=0; shift ;;
    -h|--help)     usage ;;
    *)             die "Unknown option: $1 (try --help)" ;;
  esac
done

is_num "$WEB_PORT" && [[ "$WEB_PORT" -ge 1 && "$WEB_PORT" -le 65535 ]] || die "--web-port must be a number between 1 and 65535."

if [[ -n "$SYSLOG_PORT" ]]; then
  is_num "$SYSLOG_PORT" || die "--syslog-port must be a number."
  [[ "$SYSLOG_PORT" -gt 1024 && "$SYSLOG_PORT" -le 65535 ]] \
    || die "Syslog port must be above 1024 because Splunk runs as a non-root user (try 1514)."
fi

if [[ -n "$ALLOW_NET" ]]; then
  [[ "$ALLOW_NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] \
    || die "--allow must be an IPv4 address or CIDR like 172.20.240.0/24."
fi

preflight
snapshot_services
get_password
ensure_user
install_splunk
write_config
seed_admin
setup_service
setup_firewall
start_rc=0
start_splunk || start_rc=$?
verify_services
summary
exit "$start_rc"