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
