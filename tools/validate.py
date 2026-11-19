#!/usr/bin/env python3
"""Validate the published assets.

Checks run in CI and can be run locally with `python3 tools/validate.py`.
Exit code is non-zero on the first class of problem found; all problems are
reported rather than stopping at the first bad line.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TXT = ROOT / "blocklist.txt"
JSON = ROOT / "blocklist.json"

CATEGORIES = {"rdp-connection-flood", "ssh-connection-flood"}
errors: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def version_key(ip: str) -> tuple[int, int, int, int]:
    return tuple(int(p) for p in ip.split("."))  # type: ignore[return-value]


def check_txt() -> list[str]:
    if not TXT.exists():
        err("blocklist.txt is missing")
        return []

    raw = TXT.read_bytes()
    if not raw.endswith(b"\n"):
        err("blocklist.txt must end with a newline")
    if b"\r" in raw:
        err("blocklist.txt must use LF line endings, not CRLF")

    ips: list[str] = []
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if line.strip() != line:
            err(f"blocklist.txt:{lineno}: leading/trailing whitespace")
            continue
        if line == "" or line.startswith("#"):
            err(f"blocklist.txt:{lineno}: blank lines and comments are not allowed")
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            err(f"blocklist.txt:{lineno}: not an IP address: {line!r}")
            continue
        if addr.version != 4:
            err(f"blocklist.txt:{lineno}: IPv6 is not supported yet: {line}")
            continue
        for attr in ("is_private", "is_loopback", "is_link_local",
                     "is_multicast", "is_reserved", "is_unspecified"):
            if getattr(addr, attr):
                err(f"blocklist.txt:{lineno}: {line} is a {attr[3:]} address "
                    "and must never be published")
        ips.append(line)

    dupes = {ip for ip in ips if ips.count(ip) > 1}
    for ip in sorted(dupes, key=version_key):
        err(f"blocklist.txt: duplicate entry {ip}")

    if ips != sorted(ips, key=version_key):
        err("blocklist.txt must be sorted numerically (octet order)")

    return ips


def check_json(txt_ips: list[str]) -> None:
    if not JSON.exists():
        err("blocklist.json is missing")
        return
    try:
        data = json.loads(JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        err(f"blocklist.json: invalid JSON: {exc}")
        return

    if not isinstance(data, dict):
        err("blocklist.json: top level must be an object")
        return
    entries = data.get("entries")
    if not isinstance(entries, list):
        err("blocklist.json: 'entries' must be an array")
        return

    if data.get("count") != len(entries):
        err(f"blocklist.json: count says {data.get('count')}, "
            f"but there are {len(entries)} entries")

    json_ips: list[str] = []
    for i, entry in enumerate(entries):
        where = f"blocklist.json: entries[{i}]"
        if not isinstance(entry, dict):
            err(f"{where}: must be an object")
            continue
        ip = entry.get("ip")
        if ip not in txt_ips:
            err(f"{where}: ip {ip!r} is not in blocklist.txt")
        else:
            json_ips.append(ip)
        for field in ("first_seen", "last_seen"):
            try:
                datetime.fromisoformat(str(entry.get(field)))
            except ValueError:
                err(f"{where}: {field} is not ISO 8601: {entry.get(field)!r}")
        if not isinstance(entry.get("hits"), int) or entry["hits"] < 1:
            err(f"{where}: hits must be a positive integer")
        if entry.get("category") not in CATEGORIES:
            err(f"{where}: category must be one of {sorted(CATEGORIES)}")

    if len(json_ips) != len(set(json_ips)):
        err("blocklist.json: duplicate ip entries")
    missing = set(txt_ips) - set(json_ips)
    if missing:
        err(f"blocklist.json: {len(missing)} address(es) from blocklist.txt "
            f"are missing metadata: {', '.join(sorted(missing, key=version_key))}")


def main() -> int:
    txt_ips = check_txt()
    check_json(txt_ips)

    if errors:
        print(f"validation failed with {len(errors)} problem(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"ok: {len(txt_ips)} unique IPv4 addresses, txt and json in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
