# ip-blocklist

IPv4 addresses caught attacking a small private server fleet. Every entry was
banned by **fail2ban** on a live host after tripping a real rule — these are
automated scanners hitting exposed ports, not one-off visitors.

The list stays short on purpose: only addresses that actually triggered a rule
on real traffic are added. Nothing is imported from third-party feeds, so there
is no risk of inheriting someone else's stale or over-broad ranges.

## Assets

| File | What it is |
|---|---|
| [`blocklist.txt`](blocklist.txt) | Canonical list. One bare IPv4 per line, sorted, no comments. |
| [`blocklist.json`](blocklist.json) | Same addresses plus `first_seen`, `last_seen`, `hits`, `category`. |
| [`scripts/sync-blocklist.sh`](scripts/sync-blocklist.sh) | Download the list and load it into an ipset. Idempotent. |
| [`scripts/apply-nftables.sh`](scripts/apply-nftables.sh) | Same, for nftables: builds a dedicated table and drop rule. |
| [`scripts/geo-allowlist.sh`](scripts/geo-allowlist.sh) | Opposite direction: restrict chosen ports to one country (default CN). |
| [`install.sh`](install.sh) | Install the ipset script plus an hourly systemd timer. |

### Choosing a source URL

No clone, no API key. Three ways to reach the same file:

| Source | URL | Notes |
|---|---|---|
| jsDelivr (default) | `https://cdn.jsdelivr.net/gh/pedoc/ip-blocklist@main/blocklist.txt` | Works from mainland China. Branch content is cached up to 12 h. |
| GitHub raw | `https://raw.githubusercontent.com/pedoc/ip-blocklist/main/blocklist.txt` | First-party, no cache. **Blocked on many mainland-China hosts.** |
| Release asset | `https://github.com/pedoc/ip-blocklist/releases/latest/download/blocklist.txt` | First-party and reachable from China, but pinned to a release snapshot. |

Measured from a Tencent Cloud host in mainland China: `github.com` and
`cdn.jsdelivr.net` respond in ~1 s; `raw.githubusercontent.com` times out
outright. That is why the scripts default to jsDelivr rather than raw — set
`BLOCKLIST_URL` to override.

```sh
# default (jsDelivr)
curl -fsSL https://cdn.jsdelivr.net/gh/pedoc/ip-blocklist@main/blocklist.txt
```

## Fields

| Field | Meaning |
|---|---|
| `ip` | IPv4 address. |
| `first_seen` | First observed ban, ISO 8601 with offset. |
| `last_seen` | Most recent observed ban. Equal to `first_seen` for one-off scanners. |
| `hits` | Number of separate bans observed; >1 means the source came back after its ban expired. |
| `category` | `rdp-connection-flood` or `ssh-connection-flood`. |

`category` describes **connection volume**, not failed logins. The exposure sits
behind a TCP proxy that cannot see authentication results, so the rule counts
connections per source inside a 15-minute window. A single hit is a burst; 4–5
hits over a few hours is a persistent scanner.

## Using it

### ipset + iptables (recommended on Debian/Ubuntu)

```sh
sudo ./install.sh
```

That installs `/usr/local/sbin/sync-blocklist.sh`, an hourly `systemd` timer, and
runs one sync immediately. The script creates `pedoc_blocklist`, flushes and
refills it from this repository, then guarantees a single
`-m set --match-set pedoc_blocklist src -j DROP` rule at the top of `INPUT`.

Manual run, or one-shot without systemd:

```sh
sudo ./scripts/sync-blocklist.sh
sudo ipset list pedoc_blocklist | sed -n '/Number of entries/,+1p'
```

Override the source or set name with environment variables:

```sh
sudo BLOCKLIST_URL=https://example.org/list.txt BLOCKLIST_SET=my_blocklist \
    ./scripts/sync-blocklist.sh
```

Remove an address locally without waiting for upstream:

```sh
sudo ipset del pedoc_blocklist 203.0.113.7
```

### nftables

```sh
sudo ./scripts/apply-nftables.sh
```

Creates a standalone `inet ip_blocklist` table containing one set and one drop
rule, rebuilt from the downloaded list on every run. The chain hooks `input` at
priority `-5`, ahead of fail2ban's default priority `0`, so known offenders are
dropped before they reach a jail.

### fail2ban

fail2ban bans expire and are per-jail. This list is the opposite: static,
host-independent, and permanent. Run both — the `ipset`/`nftables` drop rule
sits in front of the fail2ban chains, so an address that is already on this
list never reaches a jail at all.

fail2ban 1.x has no "load a static blacklist" jail. The supported pattern is
exactly what this repository ships: a firewall-level set refreshed by a timer.
If you only want to add these addresses to a specific jail's ban list, loop over
`blocklist.txt`:

```sh
while read -r ip; do
    fail2ban-client set sshd banip "$ip"
done < blocklist.txt
```

That writes into fail2ban's database and is re-applied on restart; the ipset
route needs no database at all.

### Automatic escalation: permaban on the second ban

Maintaining the list by hand means a scanner keeps coming back until somebody
reads the mail. [`server/permban-on-repeat.sh`](server/permban-on-repeat.sh)
closes that loop: when fail2ban bans the same address a second time, the address
is appended to a separate auto list and the blocklist is rebuilt.

```sh
sudo install -m 0755 server/permban-on-repeat.sh /usr/local/libexec/
sudo install -m 0644 server/permban-on-repeat.conf /etc/fail2ban/action.d/
# then add "permban-on-repeat" to the jail's action list
```

| File | Role |
|---|---|
| `server/permban-on-repeat.sh` | Decides and appends; also calls the sync script |
| `server/permban-on-repeat.conf` | fail2ban action wrapper |
| `server/permban4-sync` | Rebuilds the ipset from both lists |

Two lists, deliberately kept apart:

- `/etc/permban4.list` — curated by hand, reviewed.
- `/etc/permban4-auto.list` — appended by the script, one line per escalation.

Keeping them separate means a bad automatic decision never pollutes the curated
list, and undoing one is `sed -i '/<ip>/d'` on the auto file followed by a sync.

**The threshold is ban count, not failure count.** `<bancount>` cannot be used
for this: fail2ban increments an address's counter in its observer *after* the
ban action runs, so on 1.0.2 the tag reads `1` on every fresh ticket — measured
across five consecutive bans of one address. The script therefore reads the
recorded history from `/var/lib/fail2ban/fail2ban.sqlite3` after a short wait,
which is deterministic. If the history is unreadable it declines to escalate
rather than guessing.

Safety rails, all covered by the script's own checks:

- Non-routable ranges (RFC 1918, loopback, link-local) are never permabanned.
- `/etc/permban4-auto.ignore` is checked first, so the address you use to get
  back in can be excluded even if it somehow trips a ban.
- Addresses already on either list are skipped, and a lock keeps two jails from
  racing on the same address.
- The action sets `norestored = true`: fail2ban re-runs ban actions for bans it
  restores on restart, and those are not new offences. Without it every restart
  could permanently block addresses banned only once.

### Country allowlist (opposite direction)

Denying known attackers is one approach; the other is refusing the rest of the
world on ports nobody legitimate should reach. [`scripts/geo-allowlist.sh`](scripts/geo-allowlist.sh)
does the latter for a country's address space, defaulting to mainland China.

```sh
sudo ./scripts/geo-allowlist.sh --dry-run          # report only, changes nothing
sudo ./scripts/geo-allowlist.sh --check 1.2.3.4    # is this address in the set?
sudo ./scripts/geo-allowlist.sh --ports "30003"    # apply to one port
sudo ./scripts/geo-allowlist.sh --remove           # roll back
```

It builds `cn_ipv4` (from the daily-updated [17mon list](https://github.com/17mon/china_ip_list)),
plus `geo_trusted` read from `/etc/geo-allowlist.trusted`, and inserts a chain
ahead of the fail2ban chains:

```
geo_trusted  -> RETURN      # always allowed, wins over everything
cn_ipv4      -> RETURN      # allowed
otherwise    -> DROP
```

Design notes that matter in production:

- **The trusted file is the escape hatch.** It is checked first, so a bad or
  truncated country list cannot lock out the addresses listed there.
- **A failed download changes nothing**; a list that shrinks by more than half
  against the previous run is rejected outright.
- **Port 22 is never touched** by the script. Keep a management path outside
  the restricted ports — that is what makes the restriction safe to try.
- Because the chain sits before the jails, foreign traffic stops generating
  ban notifications; mainland traffic still reaches fail2ban as before.

Caveats: country lists lag real allocations by days, and cloud/VPS ranges are
reassigned often. Mobile roaming and VPN exits make your own source address
look foreign, so keep the trusted file current.

### Anything else

`blocklist.txt` is plain text. Feed it to `ufw deny from`, `pf` tables, a
Cloudflare/Security-Group import, or your own loader. Lines are bare addresses
with no comment syntax, so `grep -v '^#'` and friends are unnecessary.

## Scope and caveats

- **IPv4 only.** No IPv6 yet.
- **Volatile hosting.** Many entries live in cloud ranges (Vultr, Google Cloud,
  CDN/hosting ASNs). Addresses in those ranges are routinely reassigned, so an
  entry can later belong to an innocent tenant. Prefer per-IP entries over
  widening to a /24 — a whole-range block in a shared cloud is how you block
  real users.
- **No guarantee of freshness.** Entries are appended when a ban is observed and
  are not aged out automatically; `last_seen` tells you how stale an entry is.
  Prune aggressively if you consume this list at scale.
- **Not a reputation service.** Low volume, single-observer vantage point. Treat
  it as extra defense in depth, never as your only control.

## Maintenance

Entries are added from fail2ban ban notifications on the publishing hosts.
`blocklist.txt` and `blocklist.json` must stay in sync — CI enforces that, along
with validity, sort order, duplicate detection, and a refusal to publish private,
loopback, link-local, multicast or reserved addresses.

## License

Code is MIT. The data (`blocklist.txt`, `blocklist.json`) is dedicated to the
public domain under CC0 1.0 — use it for anything, no attribution required.
