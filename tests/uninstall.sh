#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "uninstall: $*" >&2; exit 1; }

out="$("$ROOT/scripts/uninstall.sh" --dry-run --purge)"
grep -Fq 'dry run complete: nothing was removed' <<<"$out" \
  || fail "dry run did not complete"
grep -Fq '/etc/qa-siem' <<<"$out" \
  || fail "purge plan does not mention /etc/qa-siem"
grep -Fq '/var/lib/qa-siem' <<<"$out" \
  || fail "purge plan does not mention /var/lib/qa-siem"

if "$ROOT/scripts/install.sh" --purge >/dev/null 2>&1; then
  fail "--purge without --uninstall must fail"
fi
"$ROOT/scripts/uninstall.sh" --help >/dev/null

echo "uninstall: ok"
