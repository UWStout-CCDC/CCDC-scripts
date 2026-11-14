#!/usr/bin/env bash
# splunk-backup.sh [label]  -> root-only tarball of $SPLUNK_HOME/etc + unit files + inventory + sha256
# Label the FIRST one "evidence"/"first10". Only call a backup "known-good" after Web+API+query score green.
. "$(dirname "$(readlink -f "$0")")/common.sh"
need_root; mkcc
L="${1:-manual}"; SH=$(splunk_home); UNIT=$(splunk_unit)
[ -d "$SH/etc" ] || fail "no $SH/etc (set SPLUNK_HOME=)"
O="$CC/splunk-backup-$L-$TS"; mkdir -p "$O"
df -h "$SH" "$CC" | sed 's/^/disk: /'
tar --acls --xattrs -C "$SH" -czpf "$O/etc.tgz" etc 2>"$O/tar.err" || ylw "tar warnings (files changing?) see $O/tar.err"
( cd "$O" && sha256sum etc.tgz > etc.tgz.sha256 && cat etc.tgz.sha256 )
{
  echo "# $TS label=$L unit=${UNIT:-none} home=$SH user=$(splunk_user)"
  [ -x "$SH/bin/splunk" ] && "$SH/bin/splunk" version 2>/dev/null
  [ -n "$UNIT" ] && { systemctl show "$UNIT" -p FragmentPath -p DropInPaths -p User -p ExecStart -p UnitFileState; systemctl cat "$UNIT" 2>&1; }
  echo "--- listeners"; ss -lntp | grep -E ':(22|8000|8089|8191|9997|514|1514|8088)\b'
  echo "--- index paths"; as_splunk "$SH/bin/splunk" btool indexes list --debug 2>/dev/null | grep -E 'homePath|coldPath|thawedPath' | sort -u | head -20
  echo "--- data size"; du -sh "$SH/var/lib/splunk" 2>/dev/null
  echo "--- cert fingerprints"; for c in "$SH"/etc/auth/*.pem "$SH"/etc/auth/*/*.pem; do [ -f "$c" ] && openssl x509 -in "$c" -noout -fingerprint -sha256 -enddate 2>/dev/null | sed "s|^|$c: |"; done
  echo "--- full unit/dropin files"; for f in /etc/systemd/system/$UNIT /etc/systemd/system/$UNIT.d/* /etc/init.d/splunk; do [ -e "$f" ] && { echo "## $f"; cat "$f"; }; done
} > "$O/inventory.txt" 2>&1
log "splunk backup $L -> $O"
grn "Backup: $O  (copy etc.tgz + .sha256 off-box ONLY via an approved method)"
echo "KV store (if used):  sudo -u $(splunk_user) $SH/bin/splunk backup kvstore -archiveName kv-$TS   (needs splunk auth)"
echo "Index data: do NOT copy hot buckets live; see Splunk 'back up indexed data'. Warm/cold only."
