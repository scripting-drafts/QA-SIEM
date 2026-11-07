# Architecture

QA SIEM is a single-host, local-first collector. It is intentionally small:
the Quality-Assurance-Sentinels host does detection and evidence collection;
QA SIEM adds durable storage, alert state, search, and a dashboard.

## Components

- `qa-siem` — C11 process. HTTP ingestion, query API, dashboard, retention.
- SQLite (`/var/lib/qa-siem/siem.db`) — WAL mode, prepared statements, idempotent event IDs.
- `libmicrohttpd` — bounded HTTP server, optional TLS through GnuTLS/OpenSSL build.
- `cJSON` — strict JSON parsing and response generation.
- Systemd unit — unprivileged `qa-siem` user, no capabilities, read-only system.

## Data flow

```text
QA Sentinels (findings/events/crashes/boots/hardware/LSM)
        |
        | HTTPS POST /ingest  (Bearer token)
        v
qa-siem -> validate -> INSERT OR IGNORE by event_id
        -> severity alerts
        -> threshold rules
        -> resolved-state closure
        -> SQLite WAL
        -> dashboard /api/v1/*
```

## Event envelope

QA Sentinels sends one JSON object per event:

```json
{
  "schema_version": "1.0",
  "event_id": "finding:<fingerprint>:<status>:<last_ts>",
  "ts": "2026-11-07T12:00:00Z",
  "host_id": "sha256:...",
  "event_type": "finding",
  "source": "lsm",
  "rule": "lsm.state_unreadable",
  "severity": "warning",
  "status": "open",
  "subject": "lsm",
  "detail": "...",
  "fingerprint": "...",
  "count": 3,
  "first_seen": "...",
  "last_seen": "...",
  "evidence_ref": "evidence/...",
  "tags": ["apparmor", "host-security"]
}
```

`event_id` is the idempotency key. Re-sending the same event is safe.

## Detection

Built-in rules are loaded from `/etc/qa-siem/rules.json`:

- alert on selected severities (`critical`, `error` by default)
- threshold rules keyed by host, rule, and fingerprint
- ignored rule names
- resolved events close matching open/acked alerts

Alert state lives in SQLite. The dashboard acknowledges alerts; it never
deletes them.

## Scale

This is a single-node SIEM. For a fleet, run one QA SIEM per trust domain and
forward its alerts/events to a central SIEM, or place a reverse proxy in front
of the API. Do not expose plaintext HTTP beyond loopback.
