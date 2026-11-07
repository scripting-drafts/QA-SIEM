#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
PORT="${QA_SIEM_TEST_PORT:-18088}"
TOKEN="test-token-0123456789abcdef"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
printf '%s\n' "$TOKEN" >"$TMP/token"
chmod 600 "$TMP/token"

"$ROOT/qa-siem" \
  --db "$TMP/siem.db" \
  --bind 127.0.0.1 \
  --port "$PORT" \
  --token-file "$TMP/token" \
  --rules "$ROOT/config/siem.rules.json" \
  --web-root "$ROOT/web" \
  >"$TMP/server.log" 2>&1 &
PID=$!

for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.05
done
curl -fsS "http://127.0.0.1:$PORT/healthz" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="ok"'

CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/v1/stats")"
[[ "$CODE" == "401" ]]

EVENT='{"schema_version":"1.0","event_id":"test:1","ts":"2026-11-07T12:00:00Z","host_id":"host-test","event_type":"finding","source":"test","rule":"test.rule","severity":"error","status":"open","subject":"test","detail":"unit test","fingerprint":"fp-test"}'
printf '%s' "$EVENT" | curl -fsS -X POST "http://127.0.0.1:$PORT/ingest" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @- \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["accepted"]==1 and d["alerts"]>=1, d'

printf '%s' "$EVENT" | curl -fsS -X POST "http://127.0.0.1:$PORT/ingest" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @- \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["duplicates"]==1, d'

curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/stats" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["events"]==1 and d["alerts_open"]>=1, d'

ALERT_ID="$(curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/alerts?status=open" \
  | python3 -c 'import json,sys; a=json.load(sys.stdin); assert a; print(a[0]["id"])')"

curl -fsS -X POST "http://127.0.0.1:$PORT/api/v1/alerts/ack" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"id\":$ALERT_ID}" >/dev/null

curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/alerts?status=open" \
  | python3 -c 'import json,sys; assert json.load(sys.stdin)==[], "alert not acknowledged"'

echo "integration: ok"
