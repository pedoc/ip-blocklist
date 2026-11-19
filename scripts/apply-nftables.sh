#!/bin/sh
# Apply the public blocklist to a standalone nftables table.
#
# The set is rebuilt from the downloaded list each run, so nothing goes stale.
# Loading a separate table means an existing ruleset is never touched.
set -eu

# jsDelivr is the default source; see README "Choosing a source URL".
URL="${BLOCKLIST_URL:-https://cdn.jsdelivr.net/gh/pedoc/ip-blocklist@main/blocklist.txt}"
TABLE="${BLOCKLIST_TABLE:-ip_blocklist}"
SET="${BLOCKLIST_SET:-attackers}"

log() { printf '%s apply-nftables: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
command -v nft >/dev/null 2>&1 || die "nft not found"

tmp=$(mktemp) || die "mktemp failed"
trap 'rm -f "$tmp"' EXIT INT TERM

log "fetching $URL"
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
    -o "$tmp" "$URL" || die "download failed; ruleset untouched"

# Keep only syntactically valid IPv4 literals; nft would otherwise abort the
# whole transaction on the first bad line.
awk '
    /^[[:space:]]*(#|$)/ { next }
    {
        n = split($0, o, ".")
        if (n != 4) next
        for (i = 1; i <= 4; i++) if (o[i] !~ /^[0-9]+$/ || o[i] > 255) next
        print $0
    }
' "$tmp" > "$tmp.clean"

entries=$(wc -l < "$tmp.clean" | tr -d ' ')
[ "$entries" -gt 0 ] || die "no valid entries in download; ruleset untouched"

nft list table inet "$TABLE" >/dev/null 2>&1 || nft add table inet "$TABLE"
nft list set inet "$TABLE" "$SET" >/dev/null 2>&1 || \
    nft add set inet "$TABLE" "$SET" '{ type ipv4_addr; }'

# Rebuild the chain from scratch; this is what makes repeated runs idempotent.
nft list chain inet "$TABLE" input >/dev/null 2>&1 || \
    nft add chain inet "$TABLE" input '{ type filter hook input priority -5 ; policy accept ; }'
nft flush chain inet "$TABLE" input

nft flush set inet "$TABLE" "$SET"

# Batch elements so the whole list is one transaction per chunk.
awk -v table="$TABLE" -v set="$SET" '
    { buf = buf (buf == "" ? "" : ", ") $0; n++ }
    n == 500 { printf "add element inet %s %s { %s }\n", table, set, buf; buf = ""; n = 0 }
    END { if (buf != "") printf "add element inet %s %s { %s }\n", table, set, buf }
' "$tmp.clean" > "$tmp.nft"

nft -f "$tmp.nft" || die "nft transaction failed"

# Exactly one drop rule: the chain was flushed above.
nft add rule inet "$TABLE" input ip saddr "@$SET" counter drop

log "done: $entries entries in inet $TABLE set $SET"
nft list set inet "$TABLE" "$SET" | sed -n '1,6p'
