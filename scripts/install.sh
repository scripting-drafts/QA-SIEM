#!/usr/bin/env bash
# Install qa-siem on Ubuntu 22.04/24.04/26.04-compatible systemd hosts.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/qa-siem.service
BIN=/usr/local/bin/qa-siem
WEB=/usr/share/qa-siem/web
DOC=/usr/share/doc/qa-siem
ETC=/etc/qa-siem
STATE=/var/lib/qa-siem
TOKEN="$ETC/token"
RULES="$ETC/rules.json"
PURGE=0
UNINSTALL=0
TOKEN_GROUP="${QA_TOKEN_GROUP:-qa-siem}"

usage() {
  echo "Usage: sudo $0 [--uninstall] [--purge] [--token-group GROUP]" >&2
}
while (($#)); do
  case "$1" in
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --token-group)
      TOKEN_GROUP="${2:-}"
      [[ -n "$TOKEN_GROUP" ]] || { usage; exit 2; }
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

if [[ $(id -u) -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

if (( UNINSTALL )); then
  systemctl disable --now qa-siem.service 2>/dev/null || true
  rm -f "$SERVICE" "$BIN"
  systemctl daemon-reload
  rm -rf "$WEB" "$DOC"
  if (( PURGE )); then
    rm -rf "$STATE" "$ETC"
    userdel qa-siem 2>/dev/null || true
  fi
  echo "qa-siem service removed."
  exit 0
fi

if ! id -u qa-siem >/dev/null 2>&1; then
  useradd --system --home "$STATE" --shell /usr/sbin/nologin --user-group qa-siem
fi
if ! getent group "$TOKEN_GROUP" >/dev/null 2>&1; then
  echo "token group does not exist: $TOKEN_GROUP" >&2
  exit 2
fi

make -C "$ROOT" clean all
install -d -o qa-siem -g qa-siem -m 0700 "$STATE"
install -d -o root -g "$TOKEN_GROUP" -m 0750 "$ETC"
install -d -o root -g root -m 0755 "$WEB"
install -d -o root -g root -m 0755 "$DOC"
install -o root -g root -m 0755 "$ROOT/qa-siem" "$BIN"
install -o root -g root -m 0644 "$ROOT/web/index.html" "$WEB/index.html"
install -o root -g root -m 0644 "$ROOT/web/app.js" "$WEB/app.js"
install -o root -g root -m 0644 "$ROOT/web/style.css" "$WEB/style.css"
install -o root -g root -m 0644 "$ROOT/README.md" "$DOC/README.md"
install -o root -g root -m 0644 "$ROOT/docs/"*.md "$DOC/"
if [[ ! -e "$RULES" ]]; then
  install -o root -g qa-siem -m 0640 "$ROOT/config/siem.rules.json" "$RULES"
fi
if [[ ! -e "$TOKEN" ]]; then
  umask 007
  openssl rand -hex 32 >"$TOKEN"
  chown "root:$TOKEN_GROUP" "$TOKEN"
  chmod 0640 "$TOKEN"
  echo "Generated bearer token: $TOKEN"
  echo "Use its contents as the QA Sentinels SIEM token."
fi
chown "root:$TOKEN_GROUP" "$TOKEN"
chmod 0640 "$TOKEN"
install -o root -g root -m 0644 "$ROOT/systemd/qa-siem.service" "$SERVICE"
if [[ "$TOKEN_GROUP" != "qa-siem" ]]; then
  sed -i "/^Group=qa-siem$/a SupplementaryGroups=$TOKEN_GROUP" "$SERVICE"
fi
systemctl daemon-reload
systemctl enable --now qa-siem.service
sleep 1
systemctl --no-pager --lines=0 status qa-siem.service || true
echo "Dashboard: http://127.0.0.1:8088/  (token: $TOKEN, group: $TOKEN_GROUP)"
echo "Health:    curl -fsS http://127.0.0.1:8088/healthz"
