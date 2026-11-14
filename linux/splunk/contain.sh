#!/usr/bin/env bash
# contain.sh unit NAME.service | file PATH | cron USER | user NAME | kill PID
# Every action: shows what it is, asks to confirm, saves a copy + sha256 to /root/ccdc/quarantine, logs to timeline.
. "$(dirname "$(readlink -f "$0")")/common.sh"
need_root; mkcc
Q="$CC/quarantine/$TS"; mkdir -p "$Q"
[ $# -ge 2 ] || fail "usage: contain.sh unit|file|cron|user|kill TARGET"
cmd=$1; t=$2
case "$cmd" in
 unit)
   case "$t" in *.service|*.timer|*.socket|*.path) ;; *) t="$t.service";; esac
   hdr "$t"; systemctl cat "$t" --no-pager 2>&1 | head -40; systemctl status "$t" --no-pager 2>&1 | head -8
   systemctl show "$t" -p FragmentPath -p DropInPaths -p TriggeredBy -p Triggers
   [ "$t" = "$(splunk_unit)" ] && red "!! this is the SPLUNK unit - use splunk-recover.sh instead"
   PAY=$(systemctl show "$t" -p ExecStart --value 2>/dev/null | grep -o 'path=[^ ;]*' | head -3 | cut -d= -f2)
   confirm "Stop+disable $t and quarantine its unit files?" || exit 0
   systemctl disable --now "$t" 2>&1
   ok=1
   for f in $(systemctl show "$t" -p FragmentPath -p DropInPaths --value); do
     [ -f "$f" ] || continue
     cp -a "$f" "$Q/"; sha256sum "$f" >> "$Q/sha256.txt"
     if rmforce "$f"; then echo "quarantined+removed $f"; else ok=0; fi
   done
   systemctl daemon-reload; systemctl reset-failed "$t" 2>/dev/null
   if [ $ok = 1 ]; then grn "VERIFIED removed: $t"; else red "NOT fully removed - read FAILED lines above"; fi
   log "contained unit $t ok=$ok (copy in $Q)"
   [ -n "$PAY" ] && { ylw "PAYLOAD it ran:"; echo "$PAY"; ylw "-> next: ./contain.sh file <that path>"; }
   ylw "Who else references it (the REBUILDER - remove that FIRST next time):"; refs "${t%.*}"; for p in $PAY; do refs "$(basename "$p")"; done
 ;;
 file)
   [ -e "$t" ] || fail "no such file"
   hdr "$t"; stat "$t"; file "$t"; sha256sum "$t"; lsattr -d "$t" 2>/dev/null; dpkg -S "$t" 2>&1 | head -2; head -c 600 "$t" | strings | head -15
   confirm "Quarantine (copy + remove) $t?" || exit 0
   n="$Q/$(echo "$t" | tr / _)"; cp -a "$t" "$n"; sha256sum "$t" >> "$Q/sha256.txt"
   chmod 000 "$n"
   if rmforce "$t"; then grn "VERIFIED removed: $t"; log "quarantined file $t -> $n"; else log "FAILED to remove $t"; exit 1; fi
   ylw "Who else references it (the REBUILDER):"; refs "$(basename "$t")"; refs "$t"
 ;;
 cron)
   crontab -l -u "$t" 2>&1; confirm "Save + remove crontab for $t?" || exit 0
   crontab -l -u "$t" > "$Q/crontab-$t.txt" 2>/dev/null; crontab -r -u "$t"
   crontab -l -u "$t" >/dev/null 2>&1 && red "crontab still present" || grn "VERIFIED removed"; log "removed crontab of $t (copy $Q)"
 ;;
 user)
   id "$t"; last -n 5 "$t" 2>/dev/null; confirm "Lock $t, nologin shell, kill sessions?" || exit 0
   usermod -L -s /usr/sbin/nologin "$t"; pkill -KILL -u "$t" 2>/dev/null; log "locked user $t"; grn done
 ;;
 kill)
   [ -d "/proc/$t" ] || fail "no such pid"
   hdr "pid $t"; ps -o user,pid,ppid,lstart,cmd -p "$t"; ls -l "/proc/$t/exe" "/proc/$t/cwd"; tr '\0' ' ' < "/proc/$t/cmdline"; echo
   ss -tunp 2>/dev/null | grep "pid=$t,"
   confirm "Save binary + kill -9 $t?" || exit 0
   cp "/proc/$t/exe" "$Q/pid$t.bin" 2>/dev/null; sha256sum "$Q/pid$t.bin" >> "$Q/sha256.txt" 2>/dev/null
   kill -9 "$t"; log "killed pid $t (exe copy $Q)"; ylw "Find the parent/trigger that started it (ps -ef --forest, timers, cron) or it will return."
 ;;
 *) fail "unknown action $cmd";;
esac
