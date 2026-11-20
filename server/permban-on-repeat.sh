#!/bin/sh
# Permanently block an address once fail2ban has banned it more than once.
#
# Invoked from the permban-on-repeat fail2ban action with the ticket's <ip>,
# <bancount> and <name>.
#
# Why the database and not <bancount>: fail2ban increments an address's ban
# counter in the observer, *after* it runs the ban action (server/observer.py,
# incrBanTime). Measured on 1.0.2, <bancount> is 1 on every fresh ticket, even
# on the fifth ban of the same address, so it cannot decide this. The observed
# wait for the observer to record the row is well under a second; this script
# runs detached, so it simply reads the history table once it is there.
#
# The curated list (/etc/permban4.list) is never modified. Automatic entries go
# to /etc/permban4-auto.list so hand-picked and machine-added addresses stay
# distinguishable, and removing an automatic entry is a single delete.
#
# Every refusal path exits 0: this runs after the ban action, and a non-zero
# exit would only add noise to fail2ban's log without changing the outcome.
set -eu

IP=${1:-}
TAG_COUNT=${2:-}
JAIL=${3:-unknown}

THRESHOLD=${PERMBAN_THRESHOLD:-2}
CURATED_LIST=${PERMBAN_CURATED_LIST:-/etc/permban4.list}
AUTO_LIST=${PERMBAN_AUTO_LIST:-/etc/permban4-auto.list}
IGNORE_FILE=${PERMBAN_IGNORE_FILE:-/etc/permban4-auto.ignore}
DB=${PERMBAN_DB:-/var/lib/fail2ban/fail2ban.sqlite3}
SYNC=${PERMBAN_SYNC:-/usr/local/sbin/permban4-sync}
LOCK=${PERMBAN_LOCK:-/run/permban-auto.lock}
SET=${PERMBAN_SET:-permban4}
WAIT=${PERMBAN_WAIT:-1}

log() { logger -t permban-auto -- "$*" 2>/dev/null || printf '%s\n' "$*" >&2; }

is_ipv4() {
    case "$1" in *.*.*.*) ;; *) return 1 ;; esac
    old_ifs=$IFS; IFS=.; set -- $1; IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for o in "$@"; do
        case "$o" in ''|*[!0-9]*) return 1 ;; esac
        [ "$o" -le 255 ] || return 1
    done
}

# True when $IP appears as a bare entry in file $1 (comments stripped).
listed_in() {
    [ -f "$1" ] || return 1
    awk -v ip="$IP" '
        { sub(/#.*/, ""); gsub(/[ \t\r]/, ""); if ($0 == ip) found = 1 }
        END { exit !found }
    ' "$1"
}

# Number of bans this address has on record, across all jails.
# Overrides PERMBAN_COUNT_CMD for testing. Prints -1 when the history is
# unavailable, so callers can fall back instead of guessing "zero bans".
count_bans() {
    if [ -n "${PERMBAN_COUNT_CMD:-}" ]; then
        sh -c "$PERMBAN_COUNT_CMD"
        return
    fi
    command -v python3 >/dev/null 2>&1 || { echo -1; return; }
    python3 - "$IP" "$DB" <<'PY' 2>/dev/null || echo -1
import sqlite3, sys
ip, path = sys.argv[1], sys.argv[2]
try:
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5)
    print(c.execute("select count(*) from bans where ip=?", (ip,)).fetchone()[0])
except Exception:
    print(-1)
PY
}

if ! is_ipv4 "$IP"; then
    log "ignoring non-IPv4 address '$IP' (${SET} is IPv4-only)"
    exit 0
fi

# Never permanently block an address that cannot be a remote attacker, nor one
# the owner uses to get back in. fail2ban's ignoreip already prevents the ban
# that would trigger this, but a mistake there must not cost access.
case "$IP" in
    127.*|10.*|192.168.*|169.254.*|0.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
        log "refusing to permaban non-routable $IP"
        exit 0
        ;;
esac
if listed_in "$IGNORE_FILE"; then
    log "refusing to permaban $IP: listed in $IGNORE_FILE"
    exit 0
fi

if listed_in "$CURATED_LIST" || listed_in "$AUTO_LIST"; then
    log "$IP is already blocked permanently; nothing to do"
    exit 0
fi

# Wait for the observer to record this ban, then count. A missing history is
# not evidence of a repeat offender, so it never escalates on its own.
if [ "$WAIT" != 0 ]; then sleep "$WAIT"; fi
COUNT=$(count_bans)
tries=0
while [ "$COUNT" = 0 ] && [ "$tries" -lt 5 ]; do
    sleep 1
    COUNT=$(count_bans)
    tries=$((tries + 1))
done

case "$COUNT" in
    ''|-1)
        log "history unavailable for $IP; not escalating (tag bancount=$TAG_COUNT)"
        exit 0
        ;;
    *[!0-9]*)
        log "unexpected history count '$COUNT' for $IP; not escalating"
        exit 0
        ;;
esac

if [ "$COUNT" -lt "$THRESHOLD" ]; then
    log "$IP has $COUNT ban(s) on record, below threshold $THRESHOLD"
    exit 0
fi

# Serialise: two jails can hit the threshold for the same address at once, and
# permban4-sync flushes then refills the set.
exec 9>"$LOCK"
if ! flock -n 9; then
    log "another permban-auto run holds $LOCK; skipping $IP"
    exit 0
fi

# Re-check under the lock: a concurrent run may have just added it.
if listed_in "$CURATED_LIST" || listed_in "$AUTO_LIST"; then
    log "$IP was blocked by a concurrent run; nothing to do"
    exit 0
fi

mkdir -p "$(dirname "$AUTO_LIST")"
printf '%s    # auto: ban #%s in %s at %s\n' \
    "$IP" "$COUNT" "$JAIL" "$(date -Is)" >> "$AUTO_LIST"
log "ban #$COUNT in $JAIL reached the threshold of $THRESHOLD; appended $IP to $AUTO_LIST"

if "$SYNC"; then
    if ipset test "$SET" "$IP" 2>/dev/null; then
        log "confirmed: $IP is now in ipset $SET"
    else
        log "WARNING: sync succeeded but $IP is absent from ipset $SET"
    fi
else
    log "ERROR: $SYNC failed; $IP stays queued in $AUTO_LIST for the next sync"
fi

exit 0
