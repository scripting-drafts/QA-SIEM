# Integration

## QA Sentinels side

For a QA Sentinels host that runs as a different account, share the token
through that account's group:

```bash
sudo scripts/install.sh --token-group gerard
```

The installer gives the `qa-siem` service supplementary access to that group
and makes the token readable by both the service and the QA operator. Create `config/siem.json` from
`config/siem.example.json`:

```json
{
  "endpoint": "http://127.0.0.1:8088/ingest",
  "token_file": "/etc/qa-siem/token",
  "batch_size": 200,
  "timeout_s": 15,
  "lookback_hours": 24,
  "types": ["findings", "events", "crashes", "boots", "hardware", "lsm", "tickets"]
}
```

Forward once:

```bash
./bin/qa forward --config config/siem.json
```

Preview without sending:

```bash
./bin/qa export --since 24h --format jsonl | head
./bin/qa forward --config config/siem.json --dry-run
```

Schedule forwarding after the cycle, for example in a systemd unit or cron:

```bash
./bin/qa forward --config config/siem.json >>var/siem-forward.log 2>&1
```

The forwarder re-sends a bounded lookback window. QA SIEM deduplicates by
`event_id`, so retries and overlapping windows are safe.

## QA SIEM side

Health check:

```bash
curl -fsS http://127.0.0.1:8088/healthz
```

Ingest a single event:

```bash
TOKEN="$(cat /etc/qa-siem/token)"
curl -fsS -X POST http://127.0.0.1:8088/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @event.json
```

Query:

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8088/api/v1/events?severity=critical&limit=20'
curl -fsS -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8088/api/v1/alerts?status=open&limit=50'
curl -fsS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8088/api/v1/stats
```

Acknowledge an alert:

```bash
curl -fsS -X POST http://127.0.0.1:8088/api/v1/alerts/ack \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id": 1}'
```

## Remote hosts

For a remote QA Sentinels host, use TLS:

```bash
qa-siem --bind 0.0.0.0 --port 8443 \
  --tls-cert /etc/qa-siem/tls/server.crt \
  --tls-key  /etc/qa-siem/tls/server.key
```

Then set `"endpoint": "https://siem.example:8443/ingest"` and place the CA
certificate where the QA host trusts it. Plaintext HTTP is refused on
non-loopback binds unless `--allow-plaintext` is explicitly set.

## Event mapping

| QA Sentinels source | `event_type` | Typical severity | Rule |
|---|---|---|---|
| findings | `finding` | critical/error/warning | exact finding rule |
| journal events | `event` | critical/error | `journal.<severity>` |
| crashes | `crash` | critical/warning | `crash.core2` / `crash` |
| boots | `boot` | warning/info | `boot.unclean` / `boot.clean` |
| hardware runs | `hardware` | info/warning | `hardware.run` |
| LSM runs | `lsm` | info/warning | `lsm.run` |
| ticket drafts | `ticket` | info | `ticket.draft` |

Core-2 findings are ordinary findings with dedicated rules:
`core2.retired.online`, `core2.isolation.unfenced`, `core2.isolation.missing`,
`core2.lab.*`, `core2.irq.affinity`, `core2.topology.*`, and the fault-lab
verdicts `core2.ab.divergence`, `core2.ab.hw_suspect`,
`core2.ab.control_unstable`. The shipped rules in `config/siem.rules.json`
alert immediately on retired-online, unfenced cgroups and A/B divergence, and
after two cycles on incomplete isolation parameters.

All payloads are redacted by the QA Sentinels exporter before transmission.
