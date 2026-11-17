# Privacy and data handling — QA SIEM

QA SIEM is local-first. It stores security events and alerts in SQLite on the
host and does not send telemetry.

## Data

- Events, alerts, source rules, and acknowledgement state in
  `/var/lib/qa-siem/siem.db`.
- Bearer token in `/etc/qa-siem/token` (mode `0640`, group-controlled).
- Detection rules in `/etc/qa-siem/rules.json`.
- Service logs through the systemd journal.

Events can contain host identifiers, usernames, process names, paths, and
security details. Treat the database and token as sensitive.

## Access

- The API and ingest endpoints require a bearer token.
- Bind to loopback by default. Non-loopback binds require TLS unless explicitly
  overridden.
- The dashboard stores the token in browser memory only; it is not persisted by
  the web page.

## Retention

`--retention-days` (default 30) controls event retention. Alerts and
acknowledgement state are retained until the database is pruned or removed.
Back up and delete the database according to your incident-retention policy.

## Sharing

Review events and alerts before exporting or sharing them. Remove hostnames,
usernames, paths, and tokens that are not needed for diagnosis.
