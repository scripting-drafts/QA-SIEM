#!/usr/bin/env bash
# Remove QA SIEM from a systemd host.
#
# Default: stop and disable the service, then remove the unit, binary, web
# assets, docs, configuration/token, and legacy forwarder units. Keeps
# /var/lib/qa-siem and the qa-siem user so a reinstall keeps events.
#
# Usage: sudo qa-siem-uninstall [--purge] [--dry-run] [--yes]
#        sudo scripts/uninstall.sh [--purge] [--dry-run] [--yes]
set -Eeuo pipefail

PROJECT_NAME="QA SIEM"
SERVICE_NAME="qa-siem.service"
LEGACY_UNITS=(qa-siem-forward.service qa-siem-forward.timer)
ALL_UNITS=("$SERVICE_NAME" "${LEGACY_UNITS[@]}")
UNIT_DIR=/etc/systemd/system
DROPIN="$UNIT_DIR/qa-siem.service.d"
BIN=/usr/local/bin/qa-siem
UNINSTALLER=/usr/local/sbin/qa-siem-uninstall
WEB=/usr/share/qa-siem
DOC=/usr/share/doc/qa-siem
ETC=/etc/qa-siem
STATE=/var/lib/qa-siem
PURGE=0
DRY_RUN=0
ASSUME_YES=0
FAILED=0
KEPT=()

usage() {
  cat <<'EOF'
Usage: sudo qa-siem-uninstall [--purge] [--dry-run] [--yes]
       sudo scripts/uninstall.sh [--purge] [--dry-run] [--yes]

  --purge    also remove /var/lib/qa-siem and the qa-siem user/group
  --dry-run  print what would be removed, change nothing
  --yes      do not prompt
  -h, --help show this text
EOF
}
die() { echo "$*" >&2; exit 2; }

while (($#)); do
  case "$1" in
    --purge)   PURGE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

if (( ! DRY_RUN )) && [[ ${EUID} -ne 0 ]]; then
  die "run as root: sudo $0"
fi

run() {
  printf '   $ %s\n' "$*"
  if (( ! DRY_RUN )); then "$@"; fi
}

try() {
  printf '   $ %s\n' "$*"
  if (( ! DRY_RUN )); then
    "$@" || { echo "   ! failed, continuing" >&2; FAILED=1; }
  fi
}

remove_path() {
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    run rm -rf -- "$path"
  fi
}

unit_loaded() {
  systemctl cat "$1" >/dev/null 2>&1
}

installed_units=()
for unit in "${ALL_UNITS[@]}"; do
  if unit_loaded "$unit" || [[ -e "$UNIT_DIR/$unit" ]]; then
    installed_units+=("$unit")
  fi
done

echo "$PROJECT_NAME uninstaller"
echo
echo "will remove"
if [[ ${#installed_units[@]} -gt 0 ]]; then
  echo "  systemd units: ${installed_units[*]}"
else
  echo "  systemd units: none installed"
fi
echo "  $BIN"
echo "  $UNINSTALLER"
echo "  $WEB"
echo "  $DOC"
echo "  $ETC (token, rules, TLS material)"
echo "  legacy qa-siem-forward units and timer stamp"
if (( PURGE )); then
  echo "  $STATE (database)"
  echo "  qa-siem user and group"
else
  KEPT+=("$STATE (database)" "qa-siem user and group (database owner)")
fi
echo
if [[ ${#KEPT[@]} -gt 0 ]]; then
  echo "will keep"
  for item in "${KEPT[@]}"; do echo "  $item"; done
  echo "  use --purge to remove them"
  echo
fi

if (( ! DRY_RUN && ! ASSUME_YES )); then
  if [[ ! -t 0 ]]; then
    die "no terminal for confirmation; rerun with --yes"
  fi
  if (( PURGE )); then
    read -r -p "Type PURGE to delete the database, logs, and the qa-siem user: " answer || answer=""
    [[ "$answer" == "PURGE" ]] || die "aborted; nothing was removed"
  fi
  read -r -p "Proceed? [y/N] " reply || reply=""
  [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted; nothing was removed"; exit 1; }
  echo
fi

# ---------------------------------------------------------------- services
if command -v systemctl >/dev/null 2>&1 && [[ ${#installed_units[@]} -gt 0 ]]; then
  try systemctl disable --now "${installed_units[@]}"
  systemctl reset-failed "${installed_units[@]}" >/dev/null 2>&1 || true
fi

while IFS= read -r -d '' link; do
  remove_path "$link"
done < <(
  find "$UNIT_DIR" -maxdepth 2 -type l \
    \( -name 'qa-siem.service' -o -name 'qa-siem-forward.service' -o -name 'qa-siem-forward.timer' \) \
    -print0 2>/dev/null
)

for unit in "${ALL_UNITS[@]}"; do
  remove_path "$UNIT_DIR/$unit"
done
remove_path "$DROPIN"

if command -v systemctl >/dev/null 2>&1; then
  try systemctl daemon-reload
fi

# ---------------------------------------------------------------- files
remove_path "$BIN"
remove_path "$UNINSTALLER"
remove_path "$WEB"
remove_path "$DOC"
remove_path "$ETC"
remove_path /run/qa-siem
remove_path /etc/logrotate.d/qa-siem
remove_path /etc/cron.d/qa-siem
remove_path /etc/tmpfiles.d/qa-siem.conf
remove_path /etc/sysusers.d/qa-siem.conf
for manpage in /usr/share/man/man1/qa-siem.1 /usr/share/man/man1/qa-siem.1.gz; do
  remove_path "$manpage"
done
remove_path /var/lib/systemd/timers/stamp-qa-siem-forward.timer

while IFS= read -r -d '' path; do
  remove_path "$path"
done < <(
  find /var/tmp -maxdepth 1 -type d -name 'systemd-private-*-qa-siem.service-*' \
    -print0 2>/dev/null
)

# ---------------------------------------------------------------- data and account
if (( PURGE )); then
  remove_path "$STATE"
  remove_path /var/log/qa-siem

  if getent passwd qa-siem >/dev/null 2>&1; then
    try userdel qa-siem
  fi
  if getent group qa-siem >/dev/null 2>&1; then
    try groupdel qa-siem
  fi
  if command -v crontab >/dev/null 2>&1 && crontab -u qa-siem -l >/dev/null 2>&1; then
    try crontab -u qa-siem -r
  fi
fi

# ---------------------------------------------------------------- verify
if (( ! DRY_RUN )); then
  echo
  echo "verifying"
  for path in \
    "$UNIT_DIR/$SERVICE_NAME" "$DROPIN" "$BIN" "$UNINSTALLER" "$WEB" "$DOC" "$ETC" \
    /run/qa-siem /etc/logrotate.d/qa-siem /etc/cron.d/qa-siem \
    /etc/tmpfiles.d/qa-siem.conf /etc/sysusers.d/qa-siem.conf \
    /var/lib/systemd/timers/stamp-qa-siem-forward.timer; do
    if [[ -e "$path" || -L "$path" ]]; then
      echo "   ! remains: $path" >&2
      FAILED=1
    fi
  done
  while IFS= read -r -d '' link; do
    echo "   ! remains: $link" >&2
    FAILED=1
  done < <(
    find "$UNIT_DIR" -maxdepth 2 -type l \
      \( -name 'qa-siem.service' -o -name 'qa-siem-forward.service' -o -name 'qa-siem-forward.timer' \) \
      -print0 2>/dev/null
  )
  if (( PURGE )); then
    for path in "$STATE" /var/log/qa-siem; do
      if [[ -e "$path" || -L "$path" ]]; then
        echo "   ! remains: $path" >&2
        FAILED=1
      fi
    done
    if getent passwd qa-siem >/dev/null 2>&1; then
      echo "   ! remains: user qa-siem" >&2
      FAILED=1
    fi
    if getent group qa-siem >/dev/null 2>&1; then
      echo "   ! remains: group qa-siem" >&2
      FAILED=1
    fi
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo "   ! remains: $SERVICE_NAME is still active" >&2
    FAILED=1
  fi
  if command -v ss >/dev/null 2>&1 && ss -ltnH 'sport = :8088' 2>/dev/null | grep -q .; then
    echo "   note: something is still listening on port 8088" >&2
  fi
fi

echo
if (( DRY_RUN )); then
  echo "dry run complete: nothing was removed"
elif (( FAILED )); then
  echo "uninstall finished with warnings: some items may remain" >&2
  exit 1
elif (( PURGE )); then
  echo "uninstalled; data, configuration, and account purged"
else
  echo "uninstalled; data and configuration kept"
fi
