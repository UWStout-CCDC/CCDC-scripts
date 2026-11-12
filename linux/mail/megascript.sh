#!/bin/bash
#
# megascript.sh - startup hardening for the 2026 mail service box (Ubuntu)
#
# Scored services (never removed): sshd, postfix, dovecot, roundcube, kerberos client.
# Authentication is AD via LDAP or Kerberos. Those services are assumed to be
# already configured and working, so this script only hardens, it does not configure.
#
# Usage: sudo ./megascript.sh [--no-apt]
#   --no-apt (alias --report-only)
#       Make no package changes at all: no apt update/install/reinstall/upgrade/purge
#       and no snap removal. Everything that would have been done is logged instead
#       as "REPORT-ONLY (not done)" lines in the final report. All other hardening
#       (permissions, sysctl, sessions, remote-tool lockdown, ...) still runs.
#
# Layout:
#   1. Bootstrap     : clean environment, shared variables and helpers
#   2. Pre-flight    : keylogger checks, then password prompts
#   3. Steps         : one function per hardening task
#   4. Step table    : ordered list with time estimates
#   5. Runner/report : progress bar, ETA, final report


# =============================================================================
# 1. BOOTSTRAP
# =============================================================================

# Survive a dropped or frozen terminal (ssh disconnect, closed window, Ctrl-Z,
# background tty writes). Signals ignored here stay ignored across the exec
# below and are inherited by every child process.
# Ctrl-C is deliberately left working so you can still abort.
trap '' HUP PIPE TSTP TTIN TTOU

# Options. Parsed before the re-exec below (which passes "$@" on) so --help works
# without sudo and the flag survives the clean-environment restart.
NO_PACKAGE_CHANGES=0
for argument in "$@"; do
  case $argument in
    --no-apt|--report-only) NO_PACKAGE_CHANGES=1 ;;
    -h|--help)
      echo "Usage: sudo $0 [--no-apt|--report-only]"
      echo "  --no-apt   make no package changes (no apt install/reinstall/upgrade/purge,"
      echo "             no snap removal); log what would be repaired instead"
      exit 0 ;;
    *) echo "Unknown option: $argument (try --help)" >&2; exit 1 ;;
  esac
done
readonly NO_PACKAGE_CHANGES

# Require sudo, then re-run this script inside an empty environment so no
# aliases, functions, bash profile, BASH_ENV, LD_PRELOAD or other inherited
# variables can interfere. Only the values passed to `env -i` below survive.
if [[ -z ${MEGASCRIPT_CLEAN_ENV:-} ]]; then
  if [[ $EUID -ne 0 || -z ${SUDO_USER:-} ]]; then
    echo "Run with: sudo $0" >&2
    exit 1
  fi

  exec /usr/bin/env -i \
    MEGASCRIPT_CLEAN_ENV=1 \
    INVOKING_USER="$SUDO_USER" \
    INVOKING_TTY="$(tty 2>/dev/null)" \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root \
    TERM="${TERM:-xterm}" \
    LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    /bin/bash --noprofile --norc "$(readlink -f "$0")" "$@"
fi

# Belt and braces: nothing should be defined in a fresh `env -i` shell.
unalias -a 2>/dev/null
hash -r
umask 077

# Disable Ctrl-S/Ctrl-Q flow control so an accidental Ctrl-S cannot freeze the
# output (and therefore the script). Terminal settings are restored on exit.
ORIGINAL_TTY_SETTINGS=$(stty -g 2>/dev/null)
stty -ixon 2>/dev/null
trap '[[ -n $ORIGINAL_TTY_SETTINGS ]] && stty "$ORIGINAL_TTY_SETTINGS" 2>/dev/null' EXIT

SCRIPT_PID=$$

# Private working directory on tmpfs (cleared on reboot). Holds logs and state.
WORK_DIR=/run/megascript
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"
export WORK_DIR   # the background upgrade script reads this

MAIN_LOG="$WORK_DIR/main.log"                          # output of every step
WARNINGS_FILE="$WORK_DIR/warnings.log"                 # shown in the final report
PREFLIGHT_FINDINGS_FILE="$WORK_DIR/preflight.log"      # keylogger check findings
UPGRADE_LOG="$WORK_DIR/upgrade.log"
FINAL_REPORT_FILE="$WORK_DIR/final_report.txt"
UPGRADE_PID_FILE="$WORK_DIR/upgrade.pid"
UPGRADE_STATUS_FILE="$WORK_DIR/upgrade_status"
PURGE_LIST_FILE="$WORK_DIR/purge.list"
OWNED_PATHS_INDEX="$WORK_DIR/owned_paths.index"

readonly WORK_DIR MAIN_LOG WARNINGS_FILE PREFLIGHT_FINDINGS_FILE
readonly UPGRADE_LOG UPGRADE_PID_FILE UPGRADE_STATUS_FILE FINAL_REPORT_FILE PURGE_LIST_FILE OWNED_PATHS_INDEX

: > "$MAIN_LOG"
: > "$WARNINGS_FILE"
: > "$PREFLIGHT_FINDINGS_FILE"

# Options for every apt-get call: non-interactive, wait up to 30 min for the
# dpkg lock (the background upgrade holds it), keep existing config files.
APT_OPTIONS=(-y -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::=--force-confold
             -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
readonly -a APT_OPTIONS

# PIDs of this script and its parents, so checks never kill our own session.
ANCESTOR_PIDS=" $$ "


# ---- Small shared helpers ---------------------------------------------------

# add_warning MESSAGE
#   Queue a message for the "Attention" section of the final report.
add_warning() {
  printf '%s\n' "$*" >> "$WARNINGS_FILE"
}

# report_only_note MESSAGE
#   --no-apt mode: log what would have been installed, reinstalled or removed and
#   queue it for the final report.
report_only_note() {
  echo "[report-only] $*"
  add_warning "REPORT-ONLY (not done): $*"
}

# build_owned_path_index
#   Write every path any installed package ships to OWNED_PATHS_INDEX, with the
#   merged-/usr prefix stripped (/usr/lib/x and /lib/x both become /lib/x). This
#   avoids dpkg -S false negatives on usr-merged systems and is much faster.
build_owned_path_index() {
  sed 's#^/usr/#/#' /var/lib/dpkg/info/*.list 2>/dev/null \
    | sort -u > "$OWNED_PATHS_INDEX.tmp"

  # Atomic replace: steps running in parallel never see a half-written index.
  mv -f "$OWNED_PATHS_INDEX.tmp" "$OWNED_PATHS_INDEX"
}

# is_package_owned PATH
#   True if an installed package ships PATH (symlinks resolved, /usr merged).
is_package_owned() {
  local resolved_path
  resolved_path=$(readlink -f "$1")

  [[ $resolved_path == /usr/* ]] && resolved_path=${resolved_path#/usr}

  grep -Fxq -- "$resolved_path" "$OWNED_PATHS_INDEX"
}

# installed_packages_matching REGEX
#   Print the names of installed packages whose name matches REGEX.
installed_packages_matching() {
  local name_regex=$1

  dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' \
    | awk -v name_regex="$name_regex" '$1=="ii" && $2 ~ name_regex {print $2}'
}

# verify_modified_files PACKAGE...
#   Print the non-config files of PACKAGE... that differ from what dpkg
#   installed (changed content, mode, owner or missing). Missing documentation,
#   man pages and locales are ignored: minimal images strip them on purpose.
#   Needs at least one package: `dpkg --verify` with no arguments would verify
#   the whole system.
verify_modified_files() {
  (($# > 0)) || return 0

  dpkg --verify "$@" 2>/dev/null \
    | grep -v ' c /' \
    | grep -Ev '^missing +/usr/share/(doc|man|info|locale|lintian)/'
}

# package_failed_verification PACKAGE
#   True if any non-config file of PACKAGE differs from what dpkg installed.
package_failed_verification() {
  verify_modified_files "$1" | grep -q .
}
export -f verify_modified_files package_failed_verification   # needed by the parallel workers below

# find_tampered_packages PACKAGE...
#   Verify packages in parallel (one worker per CPU, read-only) and print the
#   names of those that fail verification, one per line, sorted.
find_tampered_packages() {
  (($# > 0)) || return 0

  # shellcheck disable=SC2016  # the single-quoted script is meant for the child shell
  printf '%s\0' "$@" \
    | xargs -0 -n1 -P "$(nproc)" \
        bash -c 'package_failed_verification "$1" && printf "%s\n" "$1"; exit 0' _ \
    | sort
}

# quiesce_background_apt_jobs
#   Stop Ubuntu's own apt timers and unattended-upgrades, which often hold the
#   dpkg lock at boot and would stall every apt call in this script.
quiesce_background_apt_jobs() {
  timeout -k 5 60 systemctl stop apt-daily.timer apt-daily-upgrade.timer \
                 apt-daily.service apt-daily-upgrade.service \
                 unattended-upgrades.service packagekit.service 2>/dev/null
}

# protected_pids
#   Print " pid pid ... " of everything the script must never kill: itself, every
#   descendant (also the detached upgrade, which is reparented to init), anything in
#   its own session, and its ancestors (ancestors' other children are NOT protected).
protected_pids() {
  local upgrade_pid
  upgrade_pid=$(cat "$UPGRADE_PID_FILE" 2>/dev/null)

  ps -e -o pid=,ppid=,sid= 2>/dev/null | awk -v me="$SCRIPT_PID" -v up="$upgrade_pid" -v anc="$ANCESTOR_PIDS" '
    { par[$1]=$2; sid[$1]=$3; ids[NR]=$1 }
    END {
      keep[me]=1; if (up != "") keep[up]=1
      do {
        changed=0
        for (i=1; i<=NR; i++) { p=ids[i]; if (!(p in keep) && (par[p] in keep)) { keep[p]=1; changed=1 } }
      } while (changed)
      for (i=1; i<=NR; i++) if (sid[ids[i]] == sid[me]) keep[ids[i]]=1
      n=split(anc, a, " "); for (i=1; i<=n; i++) keep[a[i]]=1
      printf " "; for (p in keep) printf "%s ", p
    }'
}

build_owned_path_index
quiesce_background_apt_jobs


# =============================================================================
# 1b. SHELL ENVIRONMENT CLEAN (runs BEFORE pre-flight)
# =============================================================================
# Nothing below may trust inherited shell state (profiles, PROMPT_COMMAND,
# /etc/environment, ld.so.preload), so it is reset before any check runs.

# reinstall_shell_packages
#   apt update + reinstall of bash and base-files, with hard caps so it cannot hang.
reinstall_shell_packages() {
  local lock_holders modified_files

  # If something holds the dpkg/apt lock, say who, so a stall is explainable.
  if command -v fuser > /dev/null; then
    lock_holders=$(fuser -v /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock 2>&1)
    [[ -n $lock_holders ]] && echo "[reset] lock currently held by: $lock_holders"
  fi

  # Refresh package lists first: --reinstall fetches the exact installed version,
  # which 404s if the lists are stale.
  echo "[reset] $(date +%T) running apt-get update"
  NEEDRESTART_SUSPEND=1 timeout -k 10 120 apt-get update \
      -o DPkg::Lock::Timeout=90 \
      -o Acquire::Retries=0 \
      -o Acquire::http::Timeout=15 \
      -o Acquire::https::Timeout=15 \
      < /dev/null \
    || add_warning "apt-get update failed in profile reset step (lock held or mirror unreachable; see $MAIN_LOG)"

  echo "[reset] $(date +%T) reinstalling bash and base-files with apt-get"

  # Hard caps so this can never hang the run: 90 s waiting for the lock, 150 s total
  # (then SIGKILL). No pty and no needrestart hook (it scans and can restart
  # services, including ssh, mid-run), stdin closed so nothing can wait for input.
  NEEDRESTART_SUSPEND=1 timeout -k 10 150 apt-get -y --reinstall \
      -o Dpkg::Options::=--force-confnew \
      -o DPkg::Lock::Timeout=90 \
      -o Dpkg::Use-Pty=0 \
      -o Acquire::Retries=0 \
      -o Acquire::http::Timeout=15 \
      -o Acquire::https::Timeout=15 \
      install bash base-files < /dev/null \
    || add_warning "could not reinstall bash/base-files defaults (lock held, stale package lists or mirror unreachable; see $MAIN_LOG)"

  echo "[reset] $(date +%T) apt-get finished"

  modified_files=$(
    {
      verify_modified_files bash base-files
      dpkg --verify bash base-files 2>/dev/null | grep -E ' c /etc/(profile|bash\.bashrc|skel/)'
    } | sort -u
  )
  [[ -n $modified_files ]] \
    && add_warning "bash/base-files STILL modified after reinstall: $(head -5 <<< "$modified_files" | tr '\n' ';')"
}

# Restore Ubuntu default shell profiles for root and sysadmin, remove injected
# PROMPT_COMMAND and environment variables, and drop LD_PRELOAD config.
step_reset_shell_profiles() {
  local account home_dir modified_files

  # The shell defaults come from the bash and base-files packages. Scan them with
  # dpkg first and only touch apt if something was changed. verify_modified_files
  # skips config files, so the ones that matter here (/etc/profile, bash.bashrc and
  # the /etc/skel dotfiles) are checked explicitly as well.
  echo "[reset] $(date +%T) scanning bash and base-files with dpkg --verify"
  modified_files=$(
    {
      verify_modified_files bash base-files
      dpkg --verify bash base-files 2>/dev/null | grep -E ' c /etc/(profile|bash\.bashrc|skel/)'
    } | sort -u
  )

  if [[ -z $modified_files ]]; then
    echo "[reset] $(date +%T) scan clean, skipping apt-get"
  else
    echo "[reset] modified files found:"
    echo "$modified_files"
    add_warning "bash/base-files failed dpkg verification: $(head -5 <<< "$modified_files" | tr '\n' ';')"

    if ((NO_PACKAGE_CHANGES)); then
      report_only_note "bash/base-files failed verification, would run: apt-get update; apt-get --reinstall install bash base-files"
    else
      reinstall_shell_packages
    fi
  fi

  echo "[reset] $(date +%T) resetting profiles"

  [[ -f /etc/skel/.bashrc ]] || add_warning "/etc/skel/.bashrc missing"

  if [[ -s /etc/ld.so.preload ]]; then
    add_preflight_finding "/etc/ld.so.preload existed (removed by shell reset): $(tr '\n' ' ' < /etc/ld.so.preload)"
  fi
  rm -f /etc/ld.so.preload

  # /etc/environment keeps only PATH.
  grep -E '^PATH=' /etc/environment > "$WORK_DIR/environment.keep" 2>/dev/null
  cat "$WORK_DIR/environment.keep" > /etc/environment

  sed -i '/PROMPT_COMMAND/d' /etc/profile.d/*.sh 2>/dev/null

  for account in root sysadmin; do
    # Local accounts only: a plain getent would query sssd/LDAP and can stall.
    home_dir=$(getent -s files passwd "$account" | cut -d: -f6)
    [[ -d $home_dir ]] || continue

    rm -f "$home_dir"/.bashrc "$home_dir"/.profile "$home_dir"/.bash_profile \
          "$home_dir"/.bash_login "$home_dir"/.bash_logout "$home_dir"/.bash_aliases \
          "$home_dir"/.inputrc

    cp /etc/skel/.bashrc /etc/skel/.profile /etc/skel/.bash_logout "$home_dir"/

    chown "$account:$(id -gn "$account")" "$home_dir"/.bashrc "$home_dir"/.profile "$home_dir"/.bash_logout
    chmod 644 "$home_dir"/.bashrc "$home_dir"/.profile "$home_dir"/.bash_logout
  done
}

echo "Cleaning shell environment (before pre-flight)"
step_reset_shell_profiles >> "$MAIN_LOG" 2>&1
echo "  done. Log: $MAIN_LOG"
echo


# =============================================================================
# 2. PRE-FLIGHT: KEYLOGGER CHECKS, THEN PASSWORD PROMPTS
# =============================================================================

# add_preflight_finding MESSAGE
#   Record a keylogger-check finding (also shown in the final report).
add_preflight_finding() {
  printf '%s\n' "$*" >> "$PREFLIGHT_FINDINGS_FILE"
  add_warning "PREFLIGHT: $*"
}

# collect_ancestor_pids
#   Fill ANCESTOR_PIDS with this shell and every parent up to init.
collect_ancestor_pids() {
  local pid=$$

  while [[ -n $pid && $pid -gt 1 ]]; do
    ANCESTOR_PIDS+="$pid "
    pid=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
  done
}

# preflight_check_preload_hooks
#   Remove /etc/ld.so.preload and flag processes started with LD_PRELOAD.
#   One grep over every environ file instead of several forks per process.
preflight_check_preload_hooks() {
  local environ_file pid

  if [[ -s /etc/ld.so.preload ]]; then
    add_preflight_finding "/etc/ld.so.preload existed (removed): $(tr '\n' ' ' < /etc/ld.so.preload)"
  fi
  rm -f /etc/ld.so.preload

  while read -r environ_file; do
    pid=${environ_file#/proc/}
    pid=${pid%/environ}
    add_preflight_finding "pid $pid ($(readlink "/proc/$pid/exe")) has LD_PRELOAD set"
  done < <(grep -lzs '^LD_PRELOAD=' /proc/[0-9]*/environ 2>/dev/null)
}

# preflight_check_ptrace_taps
#   Any process being ptraced (strace on sshd/sudo/login etc.) gets its tracer killed.
preflight_check_ptrace_taps() {
  local status_line pid tracer_pid

  # Lines look like: /proc/<pid>/status:TracerPid:<TAB><tracer pid>
  while read -r status_line; do
    pid=${status_line#/proc/}
    pid=${pid%%/*}
    tracer_pid=${status_line##*[[:space:]]}

    [[ $ANCESTOR_PIDS == *" $tracer_pid "* ]] && continue

    add_preflight_finding "pid $pid ($(cat "/proc/$pid/comm" 2>/dev/null)) is traced by pid $tracer_pid ($(readlink "/proc/$tracer_pid/exe")), killing tracer"
    kill -9 "$tracer_pid"
  done < <(grep -s '^TracerPid:[[:space:]]*[1-9]' /proc/[0-9]*/status 2>/dev/null)
}

# preflight_check_tty_sniffers
#   Kill well-known tty/key logging tools and flag pam_tty_audit.
preflight_check_tty_sniffers() {
  local pid pam_line

  for pid in $(pgrep -x 'script|ttyrec|ttysnoop|logkeys|lkl|keylogger' 2>/dev/null); do
    [[ $ANCESTOR_PIDS == *" $pid "* ]] && continue

    add_preflight_finding "tty/key logger process killed: pid $pid ($(cat "/proc/$pid/comm" 2>/dev/null))"
    kill -9 "$pid"
  done

  grep -rn 'pam_tty_audit' /etc/pam.d 2>/dev/null | while read -r pam_line; do
    add_preflight_finding "pam_tty_audit in use: $pam_line"
  done
}

# preflight_check_pam_and_login_binaries
#   Verify auth-related packages, reinstall tampered ones, then flag PAM modules
#   that are missing or not owned by any package.
preflight_check_pam_and_login_binaries() {
  local auth_package_regex='^(libpam-modules|libpam-modules-bin|libpam-runtime|libpam0g|libpam-krb5|libpam-sss|sudo|login|passwd|openssh-server)$'
  local auth_packages=() tampered_packages=()
  local package module_name module_path module_file

  mapfile -t auth_packages < <(installed_packages_matching "$auth_package_regex")
  mapfile -t tampered_packages < <(find_tampered_packages "${auth_packages[@]}")

  if ((${#tampered_packages[@]} > 0)); then
    if ((NO_PACKAGE_CHANGES)); then
      add_preflight_finding "tampered auth packages, NOT reinstalled (--no-apt): ${tampered_packages[*]}"
    else
      add_preflight_finding "tampered auth packages, reinstalling: ${tampered_packages[*]}"
      echo "  NOTICE: running apt-get --reinstall on tampered packages (may take a while, may wait for the dpkg lock)"
      apt-get "${APT_OPTIONS[@]}" --reinstall install "${tampered_packages[@]}" >> "$MAIN_LOG" 2>&1

      for package in "${tampered_packages[@]}"; do
        if package_failed_verification "$package"; then
          add_preflight_finding "STILL TAMPERED after reinstall: $package"
        fi
      done
    fi
  fi

  # Every .so named in /etc/pam.d must exist and belong to a package.
  grep -hsv '^\s*#' /etc/pam.d/* \
    | grep -Eo '[A-Za-z0-9_./-]+\.so' \
    | sort -u \
    | while read -r module_name; do
        if [[ $module_name == /* ]]; then
          module_path=$module_name
        else
          module_path=$(find /usr/lib/*/security /usr/lib/security /lib/security -maxdepth 1 -name "$module_name" 2>/dev/null | head -1)
        fi

        if [[ -z $module_path || ! -e $module_path ]]; then
          add_preflight_finding "PAM module referenced but not found: $module_name"
          continue
        fi

        is_package_owned "$module_path" || add_preflight_finding "unpackaged PAM module in use: $module_path"
      done

  # Any unpackaged file sitting in a PAM module directory is suspicious.
  find /usr/lib/*/security /usr/lib/security /lib/security -maxdepth 1 -type f 2>/dev/null \
    | while read -r module_file; do
        is_package_owned "$module_file" || add_preflight_finding "unpackaged file in PAM module dir: $module_file"
      done
}

# preflight_check_kernel_modules
#   Flag loaded kernel modules whose file no package owns (rootkits, but also
#   legitimate DKMS/out-of-tree drivers).
preflight_check_kernel_modules() {
  local module_name module_file

  lsmod | awk 'NR>1 {print $1}' | while read -r module_name; do
    module_file=$(modinfo -n "$module_name" 2>/dev/null)

    [[ $module_file == /* ]] || continue   # built-in modules have no file

    is_package_owned "$module_file" || add_preflight_finding "kernel module not owned by a package: $module_name ($module_file)"
  done
}

# preflight_check_ebpf_programs
#   Informational only: systemd loads some eBPF programs itself.
preflight_check_ebpf_programs() {
  local program_count

  command -v bpftool > /dev/null || return 0

  program_count=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]')

  if ((program_count > 0)); then
    add_warning "PREFLIGHT info: $program_count eBPF programs loaded (systemd loads some), review with: bpftool prog show"
  fi
}

# preflight_harden_ptrace_and_tty
#   Block ptrace by non-root and block TIOCSTI keystroke injection.
preflight_harden_ptrace_and_tty() {
  sysctl -qw kernel.yama.ptrace_scope=2 >> "$MAIN_LOG" 2>&1
  sysctl -qw dev.tty.legacy_tiocsti=0   >> "$MAIN_LOG" 2>&1   # kernel 6.2+ only
}

# run_preflight
#   Run all keylogger checks. If anything was found, show it and let the user
#   abort before any password is typed.
run_preflight() {
  local answer
  local background_scan_pids=()

  collect_ancestor_pids

  echo "Pre-flight: keylogger checks (before any password is typed)"

  # The two read-only scans touch nothing the other checks change, so they run
  # in the background while the sequential checks proceed. Findings are appended
  # to the findings file (single short writes, safe to interleave).
  preflight_check_kernel_modules &
  background_scan_pids+=($!)
  preflight_check_ebpf_programs &
  background_scan_pids+=($!)

  echo "  [1/7] preload hooks";           preflight_check_preload_hooks
  echo "  [2/7] ptrace/strace taps";      preflight_check_ptrace_taps
  echo "  [3/7] tty sniffers";            preflight_check_tty_sniffers
  echo "  [4/7] PAM and login binaries";  preflight_check_pam_and_login_binaries
  echo "  [5/7] kernel modules (parallel scan)"
  echo "  [6/7] eBPF programs (parallel scan)"
  echo "  [7/7] ptrace and tty hardening"; preflight_harden_ptrace_and_tty

  wait "${background_scan_pids[@]}"

  if [[ -s $PREFLIGHT_FINDINGS_FILE ]]; then
    echo
    echo "--- Pre-flight findings ---"
    cat "$PREFLIGHT_FINDINGS_FILE"
    echo

    read -rp "Findings above. Enter passwords anyway? [y/N] " answer < /dev/tty
    if [[ $answer != [yY]* ]]; then
      echo "Aborted before password entry."
      exit 1
    fi
  else
    echo "  clean."
  fi

  echo
}

# prompt_new_password USERNAME VARIABLE_NAME
#   Ask twice (hidden input) and store the confirmed password in VARIABLE_NAME.
prompt_new_password() {
  local username=$1
  local result_variable=$2
  local first_entry second_entry

  while true; do
    read -rsp "New password for $username: " first_entry < /dev/tty
    echo
    read -rsp "Confirm: " second_entry < /dev/tty
    echo

    if [[ -n $first_entry && $first_entry == "$second_entry" ]]; then
      printf -v "$result_variable" '%s' "$first_entry"
      return
    fi

    echo "Empty or mismatch, again."
  done
}

run_preflight

prompt_new_password "$INVOKING_USER" NEW_USER_PASSWORD
prompt_new_password root             NEW_ROOT_PASSWORD

# Remote-access packages that are not scored. They are disabled right away and
# purged after the background upgrade finishes (the upgrade holds the apt lock).
cat > "$PURGE_LIST_FILE" <<'PURGE_LIST_EOF'
telnet telnetd inetutils-telnetd telnetd-ssl rsh-client rsh-server rsh-redone-client rsh-redone-server
xinetd openbsd-inetd inetutils-inetd tftpd tftpd-hpa atftpd vsftpd proftpd-basic pure-ftpd
netcat netcat-openbsd netcat-traditional ncat socat tmate autossh sshfs
tightvncserver x11vnc tigervnc-standalone-server tigervnc-scraping-server vino xrdp
cockpit webmin samba nfs-kernel-server snmpd openvpn teamviewer anydesk
PURGE_LIST_EOF


# =============================================================================
# 3. STEPS (each runs in the background, output goes to MAIN_LOG)
# =============================================================================

# Set the new passwords collected during pre-flight.
step_change_passwords() {
  printf '%s:%s\n' "$INVOKING_USER" "$NEW_USER_PASSWORD" | chpasswd \
    || add_warning "user password change failed"

  printf 'root:%s\n' "$NEW_ROOT_PASSWORD" | chpasswd \
    || add_warning "root password change failed"
}

# Kill every logged-in terminal session except the one this script was started
# from. With sudo's default use_pty the script runs on a private pty that `who`
# never lists, so comparing against our own tty is not enough (it would kill the
# real login terminal, and us with it). The terminals of every parent process
# (login shell, ssh session, tmux) are protected as well.
step_kill_other_sessions() {
  local protected_ttys=" ${INVOKING_TTY#/dev/} "
  local ancestor_pid ancestor_tty terminal pid protected

  for ancestor_pid in $ANCESTOR_PIDS; do
    ancestor_tty=$(ps -o tty= -p "$ancestor_pid" 2>/dev/null | tr -d ' ')
    [[ -n $ancestor_tty && $ancestor_tty != '?' ]] && protected_ttys+="$ancestor_tty "
  done

  # Never `pkill -t`: it kills everything on the tty, including our own tree.
  who | awk '{print $2}' | sort -u | while read -r terminal; do
    [[ $protected_ttys == *" $terminal "* ]] && continue

    protected=" $(protected_pids) "
    for pid in $(ps -t "$terminal" -o pid= 2>/dev/null); do
      [[ $protected == *" $pid "* ]] || kill -9 "$pid"
    done
  done
}

# apt update, install fish and make sure it is a valid login shell.
step_install_fish() {
  local fish_path

  if ((NO_PACKAGE_CHANGES)); then
    command -v fish > /dev/null \
      || report_only_note "fish not installed, would run: apt-get update; apt-get install fish"
  else
    apt-get update || add_warning "apt update failed"
    apt-get "${APT_OPTIONS[@]}" install fish || add_warning "fish install failed"
  fi

  fish_path=$(command -v fish) || return 0   # nothing to register without fish
  grep -qx "$fish_path" /etc/shells || echo "$fish_path" >> /etc/shells
}

step_set_root_shell_to_fish() {
  command -v fish > /dev/null || { add_warning "fish not installed, root shell left unchanged"; return 0; }

  chsh -s "$(command -v fish)" root || add_warning "could not set root shell to fish"
}

# Remove snap entirely. Any snap that looks like a scored or supporting service
# is first migrated to its apt package. If one cannot be migrated, snapd is kept.
step_remove_snap() {
  local scored_service_regex='postfix|dovecot|roundcube|ssh|krb5|kerberos|sssd|php|apache|nginx|mysql|mariadb|postgres'
  local keep_snapd=0
  local migrated_services=()
  local snap_name application_snaps

  if ((NO_PACKAGE_CHANGES)); then
    if command -v snap > /dev/null || dpkg -s snapd &> /dev/null; then
      report_only_note "snap/snapd present, would migrate scored snaps to apt, remove all snaps and purge snapd. Snaps: $(timeout 10 snap list 2>/dev/null | awk 'NR>1 {print $1}' | tr '\n' ' ')"
    fi
    return 0
  fi

  if command -v snap > /dev/null; then

    # Migrate scored/supporting snaps to apt packages of the same name.
    for snap_name in $(snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -E "$scored_service_regex"); do
      if apt-cache policy "$snap_name" | grep -q 'Candidate: [^(]' \
         && apt-get "${APT_OPTIONS[@]}" install "$snap_name"; then
        migrated_services+=("$snap_name")
        add_warning "migrated snap $snap_name to apt: copy its config/data manually"
      else
        add_warning "scored snap $snap_name has no apt equivalent: snapd NOT removed"
        keep_snapd=1
      fi
    done

    ((keep_snapd)) && return 1

    # Remove applications first (a few passes for dependency order).
    for _ in 1 2 3; do
      application_snaps=$(snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Ev '^(snapd|core[0-9]*|bare)$')
      [[ -z $application_snaps ]] && break

      for snap_name in $application_snaps; do
        snap remove --purge "$snap_name"
      done
    done

    # Then bases (core*, bare, gnome-*), then snapd itself.
    for snap_name in $(snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -v '^snapd$'); do
      snap remove --purge "$snap_name"
    done
    snap remove --purge snapd
  fi

  systemctl disable --now snapd.service snapd.socket snapd.seeded.service 2>/dev/null

  mount | awk '$3 ~ "^/snap/" {print $3}' | sort -r | xargs -r umount -l

  apt-get "${APT_OPTIONS[@]}" purge snapd
  apt-mark hold snapd

  rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd /root/snap /home/*/snap

  # Pin snapd so apt never pulls it back in.
  printf 'Package: snapd\nPin: release a=*\nPin-Priority: -10\n' > /etc/apt/preferences.d/nosnap.pref

  # Migrated services may have failed to bind their ports while the snap ran.
  for snap_name in "${migrated_services[@]}"; do
    systemctl restart "$snap_name" 2>/dev/null
  done

  if command -v snap > /dev/null; then
    add_warning "snap binary still present"
    return 1
  fi
}

# Start `apt upgrade` detached in the background, security-relevant packages
# (kernel, PHP, mail stack, auth libraries) first. After the upgrade it purges
# the remote-access packages from PURGE_LIST_FILE.
step_start_background_upgrade() {
  local package upgradable_count purge_targets=""

  if ((NO_PACKAGE_CHANGES)); then
    upgradable_count=$(apt-get -s --with-new-pkgs upgrade 2>/dev/null | grep -c '^Inst')
    report_only_note "apt upgrade skipped: $upgradable_count packages upgradable per the current package lists (no apt update was run)"

    for package in $(cat "$PURGE_LIST_FILE"); do
      [[ $(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null) == ii* ]] && purge_targets+=" $package"
    done
    [[ -n $purge_targets ]] && report_only_note "unscored remote-access packages installed, would purge:$purge_targets"

    return 0
  fi

  cat > "$WORK_DIR/upgrade.sh" <<'UPGRADE_SCRIPT_EOF'
echo $$ > "$WORK_DIR/upgrade.pid"

APT_OPTIONS=(-y -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::=--force-confold
             -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)

priority_regex='^(linux-(image|modules|headers)|php|postfix|dovecot|openssh|openssl|libssl|krb5|libkrb5|sssd|libpam|libc6|sudo|systemd|apache2|nginx|roundcube|libldap|libsasl2)'
priority_packages=$(dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' \
  | awk -v priority_regex="$priority_regex" '$1=="ii" && $2 ~ priority_regex {print $2}')

# 1. Priority packages first
if [ -n "$priority_packages" ]; then
  apt-get "${APT_OPTIONS[@]}" install --only-upgrade $priority_packages
fi

# 2. Everything else (--with-new-pkgs lets new kernels install, like `apt upgrade`)
apt-get "${APT_OPTIONS[@]}" --with-new-pkgs upgrade
echo "upgrade=$?" > "$WORK_DIR/upgrade_status"

# 3. Purge unscored remote-access packages
installed_purge_targets=""
for package in $(cat "$WORK_DIR/purge.list"); do
  if dpkg -s "$package" > /dev/null 2>&1; then
    installed_purge_targets="$installed_purge_targets $package"
  fi
done

if [ -n "$installed_purge_targets" ]; then
  apt-get "${APT_OPTIONS[@]}" purge $installed_purge_targets
fi

apt-get "${APT_OPTIONS[@]}" autoremove --purge
echo "purge=$?" >> "$WORK_DIR/upgrade_status"
UPGRADE_SCRIPT_EOF

  setsid nohup /bin/bash --noprofile --norc "$WORK_DIR/upgrade.sh" \
    < /dev/null > "$UPGRADE_LOG" 2>&1 &
}

# Replace every other firewall with one nftables ruleset: allow icmp, ssh, smtp,
# http, pop3, imap and established traffic in, everything out. Handles immutable files.
step_build_nftables_firewall() {
  local nft_conf=/etc/nftables.conf
  local service_name binary_name table_name chain_name path

  # chattr -i -a on a path (symlinks resolved) only if the flags are set
  unlock_path() {
    local resolved
    resolved=$(readlink -f "$1" 2>/dev/null || echo "$1")
    [[ -e $resolved ]] || return 0
    if lsattr -d "$resolved" 2>/dev/null | awk '{print $1}' | grep -qE '[ia]'; then
      chattr -i -a "$resolved"
    fi
    return 0
  }

  if ! command -v nft > /dev/null; then
    if ((NO_PACKAGE_CHANGES)); then
      report_only_note "nft not installed, would run: apt-get install nftables"
      return 0
    fi
    apt-get "${APT_OPTIONS[@]}" install nftables || { add_warning "nftables install failed, no firewall applied"; return 1; }
  fi

  # Stop, disable and mask every other firewall
  for service_name in ufw firewalld iptables ip6tables ebtables netfilter-persistent shorewall; do
    if systemctl cat "$service_name" &>/dev/null; then
      systemctl disable --now "$service_name"
      systemctl mask "$service_name"
    fi
  done
  systemctl unmask nftables 2>/dev/null

  # Reset legacy iptables-family rules (legacy and nft backends)
  for binary_name in iptables iptables-legacy ip6tables ip6tables-legacy; do
    command -v "$binary_name" > /dev/null || continue
    for chain_name in INPUT FORWARD OUTPUT; do "$binary_name" -P "$chain_name" ACCEPT 2>/dev/null; done
    for table_name in filter nat mangle raw security; do
      "$binary_name" -t "$table_name" -F 2>/dev/null
      "$binary_name" -t "$table_name" -X 2>/dev/null
      "$binary_name" -t "$table_name" -Z 2>/dev/null
    done
  done
  for binary_name in ebtables arptables; do
    command -v "$binary_name" > /dev/null && { "$binary_name" -F 2>/dev/null; "$binary_name" -X 2>/dev/null; }
  done

  nft flush ruleset

  # Config dir, config file and unit files may be immutable
  for path in /etc "$nft_conf" /etc/systemd/system/nftables.service \
              /lib/systemd/system/nftables.service /usr/lib/systemd/system/nftables.service; do
    unlock_path "$path"
  done

  cat > "$nft_conf" <<'NFT_EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    ct state invalid drop
    iif "lo" accept

    ip protocol icmp accept

    tcp dport { 22, 25, 80, 110, 143 } ct state new accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
NFT_EOF
  chmod 600 "$nft_conf"

  # Validate before applying so a typo cannot leave the box wide open
  if ! nft -c -f "$nft_conf"; then
    add_warning "nftables config failed validation, no firewall applied"
    return 1
  fi

  nft -f "$nft_conf" || { add_warning "nft failed to apply $nft_conf"; return 1; }
  systemctl enable --now nftables || add_warning "could not enable nftables service"
}

# Neutralise unscored remote-access tools immediately: stop and mask their
# services and make their binaries unexecutable. Packages are purged later.
step_disable_remote_access_tools() {
  local service_name binary_name binary_path

  for service_name in telnet.socket telnetd xinetd inetd vsftpd proftpd pure-ftpd tftpd-hpa \
                      smbd nmbd nfs-server snmpd xrdp vncserver x11vnc cockpit.socket cockpit \
                      webmin openvpn teamviewerd anydesk tmate autossh; do
    if systemctl cat "$service_name" &>/dev/null; then
      systemctl disable --now "$service_name"
      systemctl mask "$service_name"
    fi
  done

  for binary_name in nc ncat netcat socat telnet tmate rsh rlogin rcp x11vnc vncserver xrdp anydesk teamviewer; do
    binary_path=$(command -v "$binary_name") && chmod 000 "$(readlink -f "$binary_path")"
  done
}

# Verify bootloader and kernel packages, reinstall on tampering, strip dangerous
# kernel parameters, regenerate grub config and initramfs, warn if unfixable.
step_check_bootloader() {
  local boot_packages=()
  local modified_files script_path
  local reinstalled=0

  mapfile -t boot_packages < <(installed_packages_matching '^(grub|shim|linux-image|linux-modules)')

  modified_files=$(verify_modified_files "${boot_packages[@]}")

  if [[ -n $modified_files ]]; then
    if ((NO_PACKAGE_CHANGES)); then
      report_only_note "bootloader/kernel files failed verification, would reinstall: ${boot_packages[*]} (changed: $(head -5 <<< "$modified_files" | tr '\n' ';'))"
    else
      add_warning "bootloader/kernel files failed verification, reinstalling"
      apt-get "${APT_OPTIONS[@]}" --reinstall install "${boot_packages[@]}"
      reinstalled=1
    fi
  fi

  # Remove kernel parameters that give a shell or swap init.
  sed -i -E 's/ ?(init=[^" ]*|rd\.break[^" ]*|systemd\.unit=[^" ]*|single)//g' /etc/default/grub

  grep -rEl 'init=/|rd\.break' /etc/grub.d 2>/dev/null | while read -r script_path; do
    add_warning "suspicious grub.d script: $script_path"
  done

  chown root:root /boot/grub/grub.cfg 2>/dev/null
  update-grub
  update-initramfs -u -k all

  if grep -Eq 'init=/|rd\.break|systemd\.unit=' /boot/grub/grub.cfg; then
    add_warning "grub.cfg still has suspicious kernel params"
  fi

  # Only re-verify if we reinstalled; otherwise the first (clean) result stands.
  if ((reinstalled)); then
    modified_files=$(verify_modified_files "${boot_packages[@]}")

    if [[ -n $modified_files ]]; then
      add_warning "UNFIXABLE bootloader tampering, inspect manually: $(head -5 <<< "$modified_files" | tr '\n' ';')"
    fi
  fi
}

# Least-privilege ownership and modes across /etc, /root, homes and the filesystem.
# authorized_keys files are deliberately never touched (another tool manages them).
step_fix_permissions() {
  local home_dir home_user entry_type entry_mode entry_path entry_mode_bits

  # Packages installed since startup (snap migration, upgrade) must count as owned,
  # otherwise their legitimate setuid files would be stripped below.
  build_owned_path_index

  # --- Top-level directories ---
  chown root:root / /etc /root
  chmod 755 / /etc
  chmod 700 /root
  find /root ! -name 'authorized_keys*' -exec chown -h root:root {} +

  # --- /etc: everything root-owned, nothing group/world writable ---
  find /etc -xdev ! -user root -exec chown root {} + 2>/dev/null
  find /etc -xdev ! -type l \( -perm -0002 -o -perm -0020 \) -exec chmod go-w {} + 2>/dev/null

  # --- Account databases and sudo ---
  chmod 644 /etc/passwd /etc/group
  chown root:shadow /etc/shadow /etc/gshadow
  chmod 640 /etc/shadow /etc/gshadow
  chmod 440 /etc/sudoers
  chmod 750 /etc/sudoers.d
  chmod 440 /etc/sudoers.d/* 2>/dev/null

  # --- ssh, kerberos and sssd secrets ---
  chmod 600 /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key /etc/krb5.keytab /etc/sssd/sssd.conf 2>/dev/null
  chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
  chmod 700 /etc/sssd 2>/dev/null

  # --- dovecot ---
  chmod 640 /etc/dovecot/dovecot-ldap.conf.ext /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null
  chown root:dovecot /etc/dovecot/dovecot-ldap.conf.ext 2>/dev/null

  # --- roundcube (config holds credentials, web server group may read) ---
  if [[ -d /etc/roundcube ]]; then
    chown -R root:www-data /etc/roundcube
    find /etc/roundcube -type d -exec chmod 750 {} +
    find /etc/roundcube -type f -exec chmod 640 {} +
  fi

  # --- postfix ---
  if command -v postfix > /dev/null; then
    postfix set-permissions
  fi

  # --- cron ---
  chmod 600 /var/spool/cron/crontabs/* 2>/dev/null
  chmod 644 /etc/crontab

  # --- home directories: owned by their user, private ---
  for home_dir in /home/*/; do
    home_dir=${home_dir%/}
    home_user=${home_dir##*/}

    if id "$home_user" &>/dev/null; then
      find "$home_dir" ! -name 'authorized_keys*' -exec chown -h "$home_user:$(id -gn "$home_user")" {} +
    else
      find "$home_dir" ! -name 'authorized_keys*' -exec chown -h root:root {} +
      add_warning "home without user: $home_dir"
    fi

    chmod 700 "$home_dir"
  done

  # --- Whole filesystem, ONE find pass for all three checks ---
  #   * world-writable files lose o+w
  #   * world-writable directories without the sticky bit lose o+w
  #   * setuid/setgid files that no package owns lose those bits
  # find prints "<type> <octal mode> <path>" NUL-terminated for each candidate.
  while IFS=$'\t' read -r -d '' entry_type entry_mode entry_path; do
    entry_mode_bits=$((8#$entry_mode))

    if [[ $entry_type == d ]]; then
      chmod o-w "$entry_path"
      continue
    fi

    if ((entry_mode_bits & 0002)) && [[ ${entry_path##*/} != authorized_keys* ]]; then
      chmod o-w "$entry_path"
    fi

    if ((entry_mode_bits & 06000)) && ! is_package_owned "$entry_path"; then
      chmod ug-s "$entry_path"
      add_warning "stripped suid/sgid from unpackaged file: $entry_path"
    fi
  done < <(
    find / -xdev \( \
        \( -type f \( -perm -0002 -o -perm -4000 -o -perm -2000 \) \) \
        -o \( -type d -perm -0002 ! -perm -1000 \) \
      \) -printf '%y\t%m\t%p\0' 2>/dev/null
  )
}

# Verify key binaries (ssh, sudo, PAM, mail stack, libc, apt, ...) against dpkg
# checksums and reinstall any that were modified.
step_check_binary_integrity() {
  local critical_package_regex='^(openssh-server|openssh-client|openssh-sftp-server|sudo|login|passwd|util-linux|coreutils|bash|libc6|apt|dpkg|libpam-modules|libpam-modules-bin|libpam-runtime|libpam0g|libpam-krb5|libpam-sss|libnss-sss|krb5-user|libkrb5-3|sssd|sssd-common|postfix|postfix-ldap|dovecot-core|dovecot-imapd|dovecot-pop3d|dovecot-ldap|systemd|openssl)$'
  local critical_packages=() tampered_packages=()
  local package changed_files

  mapfile -t critical_packages < <(installed_packages_matching "$critical_package_regex")
  mapfile -t tampered_packages < <(find_tampered_packages "${critical_packages[@]}")

  ((${#tampered_packages[@]} == 0)) && return 0

  if ((NO_PACKAGE_CHANGES)); then
    for package in "${tampered_packages[@]}"; do
      changed_files=$(verify_modified_files "$package" | awk '{print $NF}' | head -3 | tr '\n' ' ')
      report_only_note "binary integrity failed, would reinstall: $package ($changed_files)"
    done
    return 0
  fi

  add_warning "binary integrity failed, reinstalling: ${tampered_packages[*]}"
  apt-get "${APT_OPTIONS[@]}" --reinstall install "${tampered_packages[@]}"

  for package in "${tampered_packages[@]}"; do
    if package_failed_verification "$package"; then
      changed_files=$(verify_modified_files "$package" | awk '{print $NF}' | head -3 | tr '\n' ' ')
      add_warning "STILL TAMPERED after reinstall: $package ($changed_files)"
    fi
  done
}

# Kernel and network hardening that does not affect ssh or mail delivery.
step_apply_sysctl_hardening() {
  cat > /etc/sysctl.d/99-megascript.conf <<'SYSCTL_EOF'
# Network: no forwarding, no redirects, no source routing, spoof protection
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Kernel: ASLR, hide kernel pointers and logs, restrict ptrace and BPF
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
-dev.tty.legacy_tiocsti = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Filesystem: no suid core dumps, protected links and fifos
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTL_EOF
  chmod 644 /etc/sysctl.d/99-megascript.conf

  # Disable core dumps for all users.
  echo '* hard core 0' > /etc/security/limits.d/99-nocore.conf
  chmod 644 /etc/security/limits.d/99-nocore.conf

  sysctl --system || add_warning "sysctl --system reported errors (see $MAIN_LOG)"
}

# Read-only audit of postfix, dovecot, PHP and roundcube. Nothing is changed,
# findings go to the final report.
step_check_mail_and_php() {
  local mynetworks php_ini_file installer_dir php_file

  # --- postfix: open relay and TLS ---
  if command -v postconf > /dev/null; then
    mynetworks=$(postconf -h mynetworks 2>/dev/null)

    if echo "$mynetworks" | grep -Eq '(^|[ ,])(0\.0\.0\.0|::)/0|(^|[ ,])[0-9.]+/([0-9]|1[0-5])([ ,]|$)'; then
      add_warning "POSTFIX mynetworks is very broad (possible open relay): $mynetworks"
    fi

    if ! postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | grep -q reject_unauth_destination; then
      add_warning "POSTFIX: reject_unauth_destination not in relay/recipient restrictions (possible open relay)"
    fi

    if ! postconf -h smtpd_tls_security_level 2>/dev/null | grep -Eq 'may|encrypt'; then
      add_warning "POSTFIX: smtpd TLS not enabled"
    fi
  fi

  # --- dovecot: TLS and plaintext auth ---
  if command -v doveconf > /dev/null; then
    [[ $(doveconf -h ssl 2>/dev/null) == no ]] \
      && add_warning "DOVECOT: ssl = no"

    [[ $(doveconf -h disable_plaintext_auth 2>/dev/null) == no ]] \
      && add_warning "DOVECOT: disable_plaintext_auth = no"
  fi

  # --- PHP: risky settings in every php.ini ---
  for php_ini_file in /etc/php/*/*/php.ini; do
    [[ -f $php_ini_file ]] || continue

    grep -Eiq '^\s*expose_php\s*=\s*(on|1)' "$php_ini_file" \
      && add_warning "PHP expose_php is On: $php_ini_file"

    grep -Eiq '^\s*display_errors\s*=\s*(on|1|stdout)' "$php_ini_file" \
      && add_warning "PHP display_errors is On: $php_ini_file"

    grep -Eiq '^\s*allow_url_include\s*=\s*(on|1)' "$php_ini_file" \
      && add_warning "PHP allow_url_include is On: $php_ini_file"
  done

  # --- roundcube: leftover installer and info-leak files ---
  find /usr/share/roundcube /var/lib/roundcube /var/www /opt -maxdepth 4 -type d -name installer 2>/dev/null \
    | while read -r installer_dir; do
        if [[ $installer_dir == *oundcube* || -f $installer_dir/../program/include/iniset.php ]]; then
          add_warning "ROUNDCUBE installer dir present: $installer_dir"
        fi
      done

  grep -Eqs "enable_installer'\]?\s*=\s*true" /etc/roundcube/*.php \
    && add_warning "ROUNDCUBE enable_installer is true"

  grep -rIl --include='*.php' 'phpinfo\s*(' /var/www /usr/share/roundcube 2>/dev/null \
    | while read -r php_file; do
        add_warning "phpinfo() found: $php_file"
      done
}

# Delete temporary files. Kept: systemd-private-* (running services use them as
# PrivateTmp=) and the scratch dirs of in-flight initramfs/dpkg/apt runs, which the
# background upgrade may be using right now.
step_remove_temp_files() {
  find /tmp /var/tmp -xdev -mindepth 1 -maxdepth 1 \
    ! -name 'systemd-private-*' ! -name 'mkinitramfs*' ! -name 'dpkg*' ! -name 'apt*' ! -name 'needrestart*' \
    -exec rm -rf {} + 2>/dev/null

  rm -rf /dev/shm/* /var/crash/* /root/.cache 2>/dev/null
}

# Kill processes running from memory only (deleted binary or memfd). Package
# binaries replaced by the upgrade are NOT killed (that would take down sshd and
# friends), they are listed as "restart needed" instead.
step_stop_memory_only_processes() {
  local exe_link pid exe_path binary_path protected

  # One find lists only the /proc/<pid>/exe links that point at deleted/memfd files.
  while read -r exe_link; do
    pid=${exe_link#/proc/}
    pid=${pid%/exe}
    protected=" $(protected_pids) "
    [[ $protected == *" $pid "* ]] && continue

    exe_path=$(readlink "$exe_link" 2>/dev/null) || continue
    binary_path=${exe_path% (deleted)}

    # The index can be stale or half-written while the background upgrade runs,
    # so fall back to a live dpkg lookup before deciding a binary is unpackaged.
    if [[ $exe_path != /memfd:* ]] && { is_package_owned "$binary_path" \
         || dpkg -S "$binary_path" &>/dev/null || dpkg -S "${binary_path#/usr}" &>/dev/null; }; then
      add_warning "packaged binary updated, restart needed: pid $pid ($binary_path)"
      continue
    fi

    kill -9 "$pid" && add_warning "killed memory-only process $pid ($exe_path)"
  done < <(find /proc/[0-9]*/exe -maxdepth 0 \( -lname '* (deleted)' -o -lname '/memfd:*' \) 2>/dev/null)
}

step_reload_systemd() {
  systemctl daemon-reload
}


# =============================================================================
# 4. STEP TABLE
# =============================================================================
# Format: "estimated seconds|description|function"
# Estimates are tuned for a 2 vCPU / 4 GB VM. They drive the progress bar and ETA,
# and are rescaled by how fast the earlier steps actually ran.
#
# PARALLELISM. A step listed in OVERLAPPED_STEPS is started the moment its
# "trigger" step starts, and its own row below only waits for it (so its estimate
# is the expected *remaining* wait, usually tiny). Only steps that cannot interfere
# with each other are overlapped:
#
#   Group 1 (nothing running yet, no apt activity):
#     kill sessions | disable remote tools | binary integrity | sysctl
#     Integrity must finish before any apt step starts, otherwise dpkg --verify
#     could see a half-installed package and report false tampering.
#
#   The profile reset is not a step: it runs before pre-flight (section 1b).
#
#   Group 2 (apt chain: fish -> root shell -> snap):
#     runs alongside the bootloader check (grub, initramfs, no apt unless tampered).
#     The background upgrade is only started AFTER the bootloader step, so it can
#     never run update-initramfs at the same time as ours.
#
#   Group 3 (after the firewall step, which runs alone):
#     permissions | mail/PHP audit (read-only) | temp cleanup | memory-only processes
#
# Never overlapped: the apt steps with each other (they share one dpkg lock anyway),
# the firewall step (flushes rules mid-run), and daemon-reload (must see every change).

readonly -a STEPS=(
  "2|Change user and root passwords|step_change_passwords"

  "2|Kill other shell sessions|step_kill_other_sessions"
  "1|Disable unscored remote access tools (parallel)|step_disable_remote_access_tools"
  "8|Binary integrity check (parallel)|step_check_binary_integrity"
  "1|Apply sysctl hardening (parallel)|step_apply_sysctl_hardening"

  "45|apt update and install fish|step_install_fish"
  "1|Set root shell to fish|step_set_root_shell_to_fish"
  "90|Migrate scored snaps, remove snap|step_remove_snap"
  "5|Check and fix bootloader (parallel)|step_check_bootloader"
  "2|Start background apt upgrade|step_start_background_upgrade"

  "4|Build nftables firewall|step_build_nftables_firewall"

  "45|Fix permissions and ownership|step_fix_permissions"
  "2|Mail and PHP read-only checks (parallel)|step_check_mail_and_php"
  "1|Remove temp files (parallel)|step_remove_temp_files"
  "1|Stop memory-only processes (parallel)|step_stop_memory_only_processes"

  "3|Daemon reload|step_reload_systemd"
)

# Steps to launch early. Format: "step to start early:step that triggers it".
# The trigger step must come BEFORE the overlapped step in STEPS.
readonly -a OVERLAPPED_STEPS=(
  "step_disable_remote_access_tools:step_kill_other_sessions"
  "step_check_binary_integrity:step_kill_other_sessions"
  "step_apply_sysctl_hardening:step_kill_other_sessions"

  "step_check_bootloader:step_install_fish"

  "step_check_mail_and_php:step_fix_permissions"
  "step_remove_temp_files:step_fix_permissions"
  "step_stop_memory_only_processes:step_fix_permissions"
)

# =============================================================================
# 5. RUNNER AND FINAL REPORT
# =============================================================================

# Steps that call apt-get. A notice is printed on the terminal when they start.
readonly -a APT_STEPS=(
  step_check_binary_integrity step_install_fish
  step_remove_snap step_check_bootloader step_start_background_upgrade
  step_build_nftables_firewall
)

# announce_apt_step FUNCTION DESCRIPTION
announce_apt_step() {
  local candidate

  ((NO_PACKAGE_CHANGES)) && return 0
  for candidate in "${APT_STEPS[@]}"; do
    if [[ $candidate == "$1" ]]; then
      printf '\r\033[K  NOTICE: "%s" may run apt-get. It can wait for the dpkg lock (up to a few minutes). Do not interrupt it. Log: %s\n' "$2" "$MAIN_LOG"
      return
    fi
  done
}

BAR_FILLED='##############################'
BAR_EMPTY='..............................'
BAR_WIDTH=30
readonly BAR_FILLED BAR_EMPTY BAR_WIDTH

# run_all_steps
#   Run each step in the background and redraw a per-step progress bar (based on
#   its estimate) plus an overall ETA until it finishes.
run_all_steps() {
  local total_steps=${#STEPS[@]}
  local total_estimate_seconds=0
  local finished_estimate_seconds=0
  local run_start=$SECONDS
  local step_number=0

  local step_entry estimate_seconds description function_name
  local step_pid step_start elapsed percent filled_width
  local speed_ratio_percent eta_seconds exit_code
  local overlap overlapped_function trigger_function
  local -A early_pids=()   # step function -> PID of a step already running in parallel
  local -A step_description=()   # step function -> description

  for step_entry in "${STEPS[@]}"; do
    total_estimate_seconds=$((total_estimate_seconds + ${step_entry%%|*}))
    IFS='|' read -r _ description function_name <<< "$step_entry"
    step_description[$function_name]=$description
  done

  for step_entry in "${STEPS[@]}"; do
    IFS='|' read -r estimate_seconds description function_name <<< "$step_entry"
    step_number=$((step_number + 1))
    step_start=$SECONDS

    # Start any read-only steps that are meant to overlap with this one.
    for overlap in "${OVERLAPPED_STEPS[@]}"; do
      overlapped_function=${overlap%%:*}
      trigger_function=${overlap##*:}

      if [[ $trigger_function == "$function_name" ]]; then
        announce_apt_step "$overlapped_function" "${step_description[$overlapped_function]}"
        "$overlapped_function" >> "$MAIN_LOG" 2>&1 &
        early_pids[$overlapped_function]=$!
      fi
    done

    if [[ -n ${early_pids[$function_name]:-} ]]; then
      step_pid=${early_pids[$function_name]}   # already running, only wait for it
    else
      announce_apt_step "$function_name" "$description"
      "$function_name" >> "$MAIN_LOG" 2>&1 &
      step_pid=$!
    fi

    while kill -0 "$step_pid" 2>/dev/null; do
      elapsed=$((SECONDS - step_start))

      percent=$((elapsed * 100 / estimate_seconds))
      ((percent > 99)) && percent=99
      filled_width=$((percent * BAR_WIDTH / 100))

      # How much slower/faster than estimated the finished steps ran (100 = on time).
      speed_ratio_percent=100
      if ((finished_estimate_seconds > 0)); then
        speed_ratio_percent=$(( (SECONDS - run_start) * 100 / finished_estimate_seconds ))
      fi

      eta_seconds=$(( (total_estimate_seconds - finished_estimate_seconds) * speed_ratio_percent / 100 - elapsed ))
      ((eta_seconds < 0)) && eta_seconds=0

      printf '\r\033[K[%d/%d] %s [%s%s] %d%% | overall ETA ~%ds' \
        "$step_number" "$total_steps" "$description" \
        "${BAR_FILLED:0:filled_width}" "${BAR_EMPTY:0:BAR_WIDTH-filled_width}" \
        "$percent" "$eta_seconds"

      sleep 0.5
    done

    wait "$step_pid"
    exit_code=$?
    finished_estimate_seconds=$((finished_estimate_seconds + estimate_seconds))

    printf '\r\033[K[%d/%d] %s [%s] done in %ds%s\n' \
      "$step_number" "$total_steps" "$description" "$BAR_FILLED" \
      "$((SECONDS - step_start))" \
      "$([[ $exit_code -ne 0 ]] && echo " (rc=$exit_code, see $MAIN_LOG)")"
  done

  echo
  echo "Total time: $((SECONDS - run_start))s"
}

# report_results
#   Print warnings, then the state of the background apt upgrade. If it is still
#   running, stream its output until it finishes.
report_results() {
  if [[ -s $WARNINGS_FILE ]]; then
    echo "--- Attention ---"
    cat "$WARNINGS_FILE"
  fi

  echo "--- apt upgrade (background) ---"

  if ((NO_PACKAGE_CHANGES)); then
    echo "Skipped (--no-apt): no package changes were made. See the REPORT-ONLY lines above."
  elif [[ -f $UPGRADE_STATUS_FILE ]] && grep -q '^purge=' "$UPGRADE_STATUS_FILE"; then
    echo "Finished: $(tr '\n' ' ' < "$UPGRADE_STATUS_FILE")"
  else
    echo "Still running. Live output (ends when it finishes):"
    tail -n 20 -f --pid="$(cat "$UPGRADE_PID_FILE" 2>/dev/null)" "$UPGRADE_LOG"
    echo "Finished: $(tr '\n' ' ' < "$UPGRADE_STATUS_FILE" 2>/dev/null)"
  fi

  echo "Logs: $MAIN_LOG  $UPGRADE_LOG (tmpfs, gone on reboot)"
}

if ((NO_PACKAGE_CHANGES)); then
  echo "NOTICE: --no-apt: NO package changes will be made. Repairs that would need apt are"
  echo "only logged (REPORT-ONLY lines in the final report)."
else
  echo "NOTICE: this script runs apt-get in several steps (reinstalls, snap removal, a full"
  echo "background upgrade). Steps may pause while waiting for the dpkg lock. Do not interrupt."
fi
echo "If this terminal drops, the script keeps running. Reattach with: tail -f $MAIN_LOG"
echo

run_all_steps

# Passwords are no longer needed.
unset NEW_USER_PASSWORD NEW_ROOT_PASSWORD

# Also save the report to a file in case the terminal is gone by now.
report_results | tee --output-error=warn "$FINAL_REPORT_FILE"