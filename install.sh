#!/bin/sh
# Install the blocklist sync script and its hourly systemd timer, then run one
# sync. Re-running is safe: files are replaced, the timer is left enabled.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "install.sh: must run as root" >&2; exit 1; }

src_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

command -v ipset >/dev/null 2>&1 || {
    echo "install.sh: ipset is required (apt install ipset iptables)" >&2
    exit 1
}

install -m 0755 "$src_dir/scripts/sync-blocklist.sh" /usr/local/sbin/sync-blocklist.sh
install -m 0644 "$src_dir/systemd/ip-blocklist.service" /etc/systemd/system/ip-blocklist.service
install -m 0644 "$src_dir/systemd/ip-blocklist.timer" /etc/systemd/system/ip-blocklist.timer

systemctl daemon-reload
systemctl enable --now ip-blocklist.timer
systemctl start ip-blocklist.service

echo
echo "installed. current state:"
systemctl --no-pager --lines=0 status ip-blocklist.service || true
ipset list "${BLOCKLIST_SET:-pedoc_blocklist}" | sed -n '/Number of entries/,+1p' || true
echo
echo "next refresh: $(systemctl show -p NextElapseUSecRealtime --value ip-blocklist.timer)"
