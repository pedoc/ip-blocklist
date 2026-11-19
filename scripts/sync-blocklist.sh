#!/bin/sh
# Fetch the public blocklist and load it into an ipset, then make sure a single
# INPUT drop rule references that set.
#
# Idempotent: safe on every boot and from a systemd timer. A failed download
# aborts before the set is touched, so a transient network error cannot wipe a
# working blocklist.
set -eu

# Default source is the jsDelivr CDN: it is reachable from mainland-China hosts
# where raw.githubusercontent.com is blocked, and it serves the file as-is.
# See README "Choosing a source URL" for first-party alternatives.
URL="${BLOCKLIST_URL:-https://cdn.jsdelivr.net/gh/pedoc/ip-blocklist@main/blocklist.txt}"
SET="${BLOCKLIST_SET:-pedoc_blocklist}"

log() { printf '%s sync-blocklist: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "$*" >&2; exit 1; }

command -v ipset >/dev/null 2>&1 || die "ipset not found (apt install ipset iptables)"
command -v iptables >/dev/null 2>&1 || die "iptables not found"

tmp=$(mktemp) || die "mktemp failed"
trap 'rm -f "$tmp"' EXIT INT TERM

log "fetching $URL"
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
    -o "$tmp" "$URL" || die "download failed; leaving the existing set untouched"

# Validate before touching the firewall. Anything that is not a bare IPv4
# address is skipped rather than trusted, and the download is rejected outright
# if it looks wrong (empty, or HTML from a captive portal / 404 page).
valid_ipv4() {
    case "$1" in
        *.*.*.*) ;;
        *) return 1 ;;
    esac
    old_ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086
    set -- $1
    IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for octet in "$@"; do
        case "$octet" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "$octet" -le 255 ] || return 1
    done
}

total=0
valid=0
while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | tr -d '\r' | sed -e 's/#.*//' -e 's/[[:space:]]//g')
    [ -n "$line" ] || continue
    total=$((total + 1))
    if valid_ipv4 "$line"; then
        valid=$((valid + 1))
    else
        log "skipping invalid entry: $line" >&2
    fi
done < "$tmp"

[ "$valid" -gt 0 ] || die "no valid IPv4 entries in download ($total candidates); refusing to apply"
[ "$valid" -eq "$total" ] || die "download contains $((total - valid)) invalid entries; refusing to apply a partially trusted list"

ipset create "$SET" hash:ip family inet -exist || die "cannot create ipset $SET"
ipset flush "$SET"

# shellcheck disable=SC2034  # read inside the loop below
loaded=0
while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | tr -d '\r' | sed -e 's/#.*//' -e 's/[[:space:]]//g')
    [ -n "$line" ] || continue
    ipset add "$SET" "$line" -exist && loaded=$((loaded + 1))
done < "$tmp"

if ! iptables -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null; then
    iptables -I INPUT 1 -m set --match-set "$SET" src -j DROP
    log "installed INPUT drop rule for set $SET"
else
    log "INPUT drop rule for set $SET already present"
fi

log "done: $loaded entries loaded into $SET"
