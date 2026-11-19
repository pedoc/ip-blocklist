#!/bin/sh
# Restrict inbound traffic on selected ports to a country's address space.
#
# The default country is CN (mainland China). The intent is ports that exist
# only for the owner's own use — an RDP or SSH forward — where the entire rest
# of the internet is noise.
#
# Safety properties, in order of importance:
#   * A failed or implausible download aborts before the firewall is touched,
#     so a network blip cannot lock anybody out.
#   * A trusted set is checked first and always wins, so a mistake upstream
#     cannot lock out the owner.
#   * The rule chain is appended/updated idempotently; running twice is a no-op.
#   * `--dry-run` and `--check` never modify anything.
#
# Usage:
#   geo-allowlist.sh --dry-run            # show what would change
#   geo-allowlist.sh --check 1.2.3.4      # is this address inside the country set?
#   geo-allowlist.sh                      # apply / refresh
#   geo-allowlist.sh --remove             # remove the rules entirely
set -eu

# jsDelivr mirror of the daily-generated mainland-China CIDR list. Reachable
# from mainland hosts where raw.githubusercontent.com is blocked.
URL="${GEO_URL:-https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt}"
PORTS="${GEO_PORTS:-30003 30004}"
SET="${GEO_SET:-cn_ipv4}"
TRUSTED_SET="${GEO_TRUSTED_SET:-geo_trusted}"
TRUSTED_FILE="${GEO_TRUSTED_FILE:-/etc/geo-allowlist.trusted}"
CHAIN="${GEO_CHAIN:-GEO-CN-ALLOW}"
STATE_DIR="${GEO_STATE_DIR:-/var/lib/geo-allowlist}"

MODE=apply
CHECK_IP=""

log()  { printf '%s geo-allowlist: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die()  { log "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (or pass --dry-run only)"; }

valid_ipv4() {
    case "$1" in *.*.*.*) ;; *) return 1 ;; esac
    old_ifs=$IFS; IFS=.; set -- $1; IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for o in "$@"; do
        case "$o" in ''|*[!0-9]*) return 1 ;; esac
        [ "$o" -le 255 ] || return 1
    done
}

valid_cidr() {
    prefix="${1#*/}"
    [ "$prefix" != "$1" ] || return 1
    case "$prefix" in ''|*[!0-9]*) return 1 ;; esac
    [ "$prefix" -le 32 ] || return 1
    valid_ipv4 "${1%/*}"
}

usage() {
    cat <<'EOF'
geo-allowlist.sh - restrict inbound traffic on selected ports to one country

Usage:
  geo-allowlist.sh --dry-run            show what would change, touch nothing
  geo-allowlist.sh --check 1.2.3.4      test an address against the country set
  geo-allowlist.sh                      apply or refresh
  geo-allowlist.sh --remove             remove the rules entirely

Options:
  --ports "30003 30004"   ports to restrict (default: 30003 30004)

Environment:
  GEO_URL           country CIDR list (default: CN list on jsDelivr)
  GEO_SET           ipset name for the country space (default: cn_ipv4)
  GEO_TRUSTED_SET   ipset name for always-allowed addresses (default: geo_trusted)
  GEO_TRUSTED_FILE  file of always-allowed addresses/CIDRs
                    (default: /etc/geo-allowlist.trusted)
EOF
    exit "${1:-0}"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) MODE=dry-run ;;
        --check)   [ "$#" -ge 2 ] || die "--check needs an address"; CHECK_IP=$2; shift; MODE=check ;;
        --remove)  MODE=remove ;;
        --ports)   [ "$#" -ge 2 ] || die "--ports needs a value"; PORTS=$2; shift ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
done

[ -n "$PORTS" ] || die "port list is empty"
for p in $PORTS; do
    case "$p" in ''|*[!0-9]*) die "invalid port: $p" ;; esac
done

# ---------------------------------------------------------------------------
# Download and validate. Everything below only acts on a fully validated list.
# ---------------------------------------------------------------------------
download() {
    tmp=$(mktemp) || die "mktemp failed"
    trap 'rm -f "$tmp" "${tmp:-}.clean"' EXIT INT TERM
    log "fetching $URL"
    curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 90 \
        -o "$tmp" "$URL" || die "download failed; nothing changed"
}

normalize() {
    total=0; good=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r' | sed -e 's/#.*//' -e 's/[[:space:]]//g')
        [ -n "$line" ] || continue
        total=$((total + 1))
        if valid_cidr "$line"; then
            printf '%s\n' "$line" >> "$tmp.clean"
            good=$((good + 1))
        fi
    done < "$tmp"

    [ "$good" -gt 0 ] || die "no valid CIDRs in download; nothing changed"
    # A country list that suddenly shrinks by more than half is not a country
    # list, it is a truncated download. Refuse it.
    if [ -f "$STATE_DIR/last-count" ]; then
        prev=$(cat "$STATE_DIR/last-count" 2>/dev/null || echo 0)
        if [ "$prev" -gt 100 ] && [ "$good" -lt $((prev / 2)) ]; then
            die "download has $good entries, previous run had $prev; refusing a suspicious shrink"
        fi
    fi
    log "validated $good CIDRs out of $total lines"
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
do_check() {
    valid_ipv4 "$CHECK_IP" || die "not an IPv4 address: $CHECK_IP"
    if ipset list "$SET" >/dev/null 2>&1; then
        if ipset test "$SET" "$CHECK_IP" 2>/dev/null; then
            echo "$CHECK_IP: inside $SET (allowed by geo rule)"
        else
            echo "$CHECK_IP: outside $SET (would be dropped)"
        fi
        return 0
    fi

    # Set not built yet: evaluate against a throwaway copy.
    download; normalize
    tmpset="geo_check_$$"
    ipset create "$tmpset" hash:net family inet -exist
    while IFS= read -r c; do ipset add "$tmpset" "$c" -exist; done < "$tmp.clean"
    if ipset test "$tmpset" "$CHECK_IP" 2>/dev/null; then
        echo "$CHECK_IP: inside the country set (allowed)"
    else
        echo "$CHECK_IP: outside the country set (would be dropped)"
    fi
    ipset destroy "$tmpset" 2>/dev/null || true
}

do_remove() {
    need_root
    while iptables -C INPUT -p tcp -m multiport --dports "$PORTS" -j "$CHAIN" 2>/dev/null; do
        iptables -D INPUT -p tcp -m multiport --dports "$PORTS" -j "$CHAIN"
    done
    while iptables -C INPUT -p udp -m multiport --dports "$PORTS" -j "$CHAIN" 2>/dev/null; do
        iptables -D INPUT -p udp -m multiport --dports "$PORTS" -j "$CHAIN"
    done
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    log "rules removed; ipset $SET left in place (destroy it manually if unwanted)"
}

do_apply() {
    [ "$MODE" = dry-run ] || need_root
    download
    normalize

    if [ "$MODE" = dry-run ]; then
        log "dry run: $good CIDRs would load into $SET; chain $CHAIN would cover ports $PORTS"
        log "dry run: nothing was changed"
        return 0
    fi

    mkdir -p "$STATE_DIR"
    cp -f "$tmp.clean" "$STATE_DIR/country.cidr"

    ipset create "$SET" hash:net family inet maxelem 200000 -exist \
        || die "cannot create ipset $SET"
    ipset create "$TRUSTED_SET" hash:net family inet maxelem 4096 -exist \
        || die "cannot create ipset $TRUSTED_SET"

    ipset flush "$SET"
    while IFS= read -r c; do ipset add "$SET" "$c" -exist; done < "$tmp.clean"

    # Trusted addresses: checked first, always win. Seeded from a plain file so
    # the owner can add an address without editing this script.
    ipset flush "$TRUSTED_SET"
    if [ -f "$TRUSTED_FILE" ]; then
        while IFS= read -r entry || [ -n "$entry" ]; do
            entry=$(printf '%s' "$entry" | tr -d '\r' | sed -e 's/#.*//' -e 's/[[:space:]]//g')
            [ -n "$entry" ] || continue
            if valid_cidr "$entry" || valid_ipv4 "$entry"; then
                ipset add "$TRUSTED_SET" "$entry" -exist
            else
                log "ignoring invalid trusted entry: $entry" >&2
            fi
        done < "$TRUSTED_FILE"
    else
        log "no $TRUSTED_FILE; trusted set is empty" >&2
    fi
    trusted_n=$(ipset list "$TRUSTED_SET" | sed -n 's/^Number of entries: //p')
    [ "${trusted_n:-0}" -gt 0 ] || log "warning: trusted set is empty — a wrong country list would lock you out" >&2

    # Rebuild the chain so repeat runs converge instead of stacking.
    iptables -N "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN"
    iptables -A "$CHAIN" -m set --match-set "$TRUSTED_SET" src -j RETURN
    iptables -A "$CHAIN" -m set --match-set "$SET" src -j RETURN
    iptables -A "$CHAIN" -j DROP

    # Hook the chain in ahead of the fail2ban chains, so foreign traffic is
    # dropped before it is counted, and mainland traffic still reaches the
    # jails and their notification mails.
    hook() {
        proto=$1
        if iptables -C INPUT -p "$proto" -m multiport --dports "$PORTS" -j "$CHAIN" 2>/dev/null; then
            return 0
        fi
        pos=$(iptables -L INPUT --line-numbers -n 2>/dev/null | awk '/f2b-/ {print $1; exit}')
        if [ -n "$pos" ]; then
            iptables -I INPUT "$pos" -p "$proto" -m multiport --dports "$PORTS" -j "$CHAIN"
        else
            iptables -A INPUT -p "$proto" -m multiport --dports "$PORTS" -j "$CHAIN"
        fi
    }
    hook tcp
    case " $PORTS " in
        *" 30003 "*) hook udp ;;
    esac

    printf '%s\n' "$good" > "$STATE_DIR/last-count"
    log "done: $good CIDRs in $SET, $trusted_n trusted entries, chain $CHAIN on ports $PORTS"
}

case "$MODE" in
    check)   need_root; do_check ;;
    remove)  do_remove ;;
    dry-run) do_apply ;;
    apply)   do_apply ;;
esac
