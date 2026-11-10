#!/usr/bin/env bash
# Publish the repository's detection rules to the running QA SIEM.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
target=/etc/qa-siem/rules.json
group=$(stat -c %G "$target" 2>/dev/null || echo qa-siem)
install -o root -g "$group" -m 0640 "$root/config/siem.rules.json" "$target"
systemctl restart qa-siem.service
sleep 1
curl -fsS http://127.0.0.1:8088/healthz >/dev/null
echo "rules synced: $target (group $group)"
