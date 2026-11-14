#!/usr/bin/env bash
# splunk-recover.sh  Guided native recovery of a down/masked Splunk. Asks before each change; logs to timeline.
# Order matters: find the TRIGGER before restarting, or it comes right back.
. "$(dirname "$(readlink -f "$0")")/common.sh"
need_root; mkcc
SH=$(splunk_home); UNIT=$(splunk_unit); SU=$(splunk_user)
[ -n "$UNIT" ] || fail "no splunk unit. Try: ls /etc/init.d/splunk ; $SH/bin/splunk enable boot-start -systemd-managed 1 -user $SU"
hdr "1 current state"; systemctl status "$UNIT" --no-pager 2>&1 | head -12
systemctl is-enabled "$UNIT" 2>&1; ls -l "/etc/systemd/system/$UNIT" 2>&1
journalctl -u "$UNIT" -b --no-pager 2>/dev/null | tail -15
hdr "2 who/what is stopping or masking it? (check BEFORE starting)"
grep -RnE "splunk" /etc/cron* /var/spool/cron 2>/dev/null | sed 's/^/!! cron: /'
systemctl list-timers --all --no-pager | grep -iE 'splunk|stop|update|helper' | sed 's/^/!! timer: /'
journalctl --since "6 hours ago" --no-pager 2>/dev/null | grep -iE "splunk.*(mask|stop|disable)|systemctl.*splunk|Stopping $UNIT" | tail -8
ylw "If any line above is a trigger: ./contain.sh unit/file/cron on it FIRST."
confirm "Continue to recovery?" || exit 0
hdr "3 unmask"
if [ "$(systemctl is-enabled "$UNIT" 2>&1)" = masked ]; then
  mkdir -p "$CC/quarantine"; cp -a "/etc/systemd/system/$UNIT" "$CC/quarantine/mask-$UNIT-$TS" 2>/dev/null
  confirm "systemctl unmask $UNIT" && { systemctl unmask "$UNIT"; log "unmasked $UNIT"; }
fi
[ -d "/etc/systemd/system/$UNIT.d" ] && { ylw "drop-ins present:"; for f in /etc/systemd/system/$UNIT.d/*; do echo "## $f"; cat "$f"; done; }
systemctl daemon-reload
hdr "4 config sanity as $SU"
as_splunk "$SH/bin/splunk" btool check 2>&1 | tail -20
echo "-- missing cert/key files:"
grep -rhE '^\s*(serverCert|privKeyPath|caCertFile|sslRootCAPath|caPath|sslKeysfile|certPath)\s*=' "$SH"/etc/system/local "$SH"/etc/apps/*/local 2>/dev/null | sed -E 's/^[^=]*=\s*//; s|\$SPLUNK_HOME|'"$SH"'|g' | sort -u | while read -r p; do [ -e "$p" ] || red "MISSING $p"; done
echo "-- ownership (should be $SU):"; find "$SH" -xdev -not -user "$SU" -not -path "$SH/var/run/*" 2>/dev/null | head -5
echo "-- web/mgmt effective:"; as_splunk "$SH/bin/splunk" btool web list settings 2>/dev/null | grep -E '^(httpport|enableSplunkWebSSL|startwebserver|mgmtHostPort)'
echo "-- disk:"; df -h "$SH" | tail -1; df -i "$SH" | tail -1
ylw "Fix config by restoring ONE reviewed file from etc.tgz (tar -xzpf <backup> -C /tmp/x etc/path ; diff ; cp -a), not the whole tree."
confirm "Start $UNIT now?" || exit 0
hdr "5 start"
systemctl reset-failed "$UNIT" 2>/dev/null; systemctl start "$UNIT"; sleep 8; systemctl status "$UNIT" --no-pager | head -8
log "recover: started $UNIT"
"$(dirname "$(readlink -f "$0")")/splunk-check.sh"
ylw "Not done until: Web OK, API 401/200, search OK, quotient green on the NEXT scoring round. Boot-enable: systemctl enable $UNIT (only after it's healthy)."
