#!/usr/bin/env bash
# splunk-check.sh [-u USER]   End-to-end local check: unit -> listener -> bind -> web -> API -> (auth) search -> fresh data.
# With -u it prompts for the password (never on the command line / history).
. "$(dirname "$(readlink -f "$0")")/common.sh"
USERNAME=""; [ "${1:-}" = "-u" ] && USERNAME="${2:-}"
SH=$(splunk_home); UNIT=$(splunk_unit)
ok(){ grn "OK   $*"; }; bad(){ red "FAIL $*"; }

hdr "1 unit"
if [ -z "$UNIT" ]; then bad "no splunk unit file found (init.d? 'ls /etc/init.d/splunk')"; else
  st=$(systemctl is-active "$UNIT"); en=$(systemctl is-enabled "$UNIT" 2>&1)
  [ "$st" = active ] && ok "$UNIT active" || bad "$UNIT is $st"
  case "$en" in masked*) bad "MASKED -> splunk-recover.sh";; enabled) ok "enabled at boot";; *) ylw "enable state: $en";; esac
fi
pgrep -a splunkd | head -3

hdr "2 listeners + bind address (127.0.0.1-only = scorer can't reach it)"
for p in 8000 8089; do
  l=$(ss -H -lnt "sport = :$p" 2>/dev/null | awk '{print $4}' | tr '\n' ' ')
  if [ -z "$l" ]; then bad "nothing listening on $p"
  elif echo "$l" | grep -qE '^(127\.0\.0\.1|\[::1\])' && ! echo "$l" | grep -qE '(0\.0\.0\.0|\*|\[::\]|172\.)'; then bad "$p bound to loopback only: $l"
  else ok "$p listening: $l"; fi
done
ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -E ':(8191|9997|9090|23)$' | sed 's/^/note: other listener /'

hdr "3 web (8000)"
for s in http https; do c=$(curl -sk -o /dev/null -m 6 -w '%{http_code}' "$s://127.0.0.1:8000/en-US/account/login"); echo "$s -> $c"; done
echo "(200/302 on one scheme = web is up; the other scheme failing is normal)"

hdr "4 mgmt API (8089) unauthenticated -> expect 401"
c=$(curl -sk -o /dev/null -m 6 -w '%{http_code}' https://127.0.0.1:8089/services/server/info); echo "https 8089 -> $c"
[ "$c" = 401 ] && ok "API alive (401 = wants auth)" || bad "unexpected code $c"

if [ -n "$USERNAME" ]; then
  read -r -s -p "Password for $USERNAME: " PW; echo
  PWE=${PW//\\/\\\\}; PWE=${PWE//\"/\\\"}
  api(){ printf 'user = "%s:%s"\n' "$USERNAME" "$PWE" | curl -sk -K - -m 40 "$@"; }
  hdr "5 authenticated API"
  c=$(api -o /dev/null -w '%{http_code}' https://127.0.0.1:8089/services/server/info); echo "auth -> $c"
  [ "$c" = 200 ] && ok "login works" || bad "auth code $c (401 bad creds / 403 role / 503 starting)"
  hdr "6 search engine"
  api https://127.0.0.1:8089/services/search/jobs/export -d output_mode=json --data-urlencode 'search=| makeresults count=1 | eval ok="search-engine-ok"' | head -c 400; echo
  hdr "7 fresh data last 15m (by index/host)"
  api https://127.0.0.1:8089/services/search/jobs/export -d output_mode=csv --data-urlencode 'search=search index=* earliest=-15m | stats count latest(_time) as t by index host | eval age_s=now()-t | fields index host count age_s' | head -20
  echo "(your SCORED query may need a specific index/field: test that exact search in Splunk Web as the scoring user)"
  PW=""; PWE=""
else ylw "skipping 5-7: re-run with  -u <scoring-or-admin-user>  to test login + search + data"; fi

hdr "8 host health"
df -h "$SH" /var 2>/dev/null; df -i "$SH" 2>/dev/null | tail -1; free -m | sed -n 1,2p
timedatectl 2>/dev/null | grep -E 'System clock|NTP'
hdr "9 config + recent errors"
[ -x "$SH/bin/splunk" ] && as_splunk "$SH/bin/splunk" btool check 2>&1 | tail -15
echo "-- TLS/cert paths referenced in local config:"
grep -rhE '^\s*(serverCert|privKeyPath|caCertFile|sslRootCAPath|caPath|sslKeysfile|certPath)\s*=' "$SH"/etc/system/local "$SH"/etc/apps/*/local 2>/dev/null \
 | sed -E 's/^[^=]*=\s*//; s|\$SPLUNK_HOME|'"$SH"'|g' | sort -u | while read -r p; do [ -e "$p" ] && echo "ok   $p" || red "MISSING $p"; done
tail -n 15 "$SH/var/log/splunk/splunkd.log" 2>/dev/null | grep -iE 'error|fatal|warn' | tail -8
hdr "10 local firewall"; nft list tables 2>/dev/null; command -v ufw >/dev/null && ufw status 2>/dev/null | head -3
echo; echo "Then confirm on https://quotient.ccdc.events/ (local OK != scorer OK)."
