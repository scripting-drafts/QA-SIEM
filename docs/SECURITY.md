# Security

## Defaults

- Bind `127.0.0.1:8088`.
- Bearer authentication required for `/ingest` and `/api/v1/*`.
- Token from `SIEM_TOKEN` or `/etc/qa-siem/token`, expected mode `0640`.
- TLS required for any non-loopback bind unless `--allow-plaintext` is set.
- `--allow-no-auth` is accepted only on loopback binds.

## Process hardening

The systemd unit runs as the unprivileged `qa-siem` user with:

- no capabilities
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
- `ProtectKernelTunables/Modules/ControlGroups=yes`
- `RestrictAddressFamilies=AF_INET AF_INET6`
- `RestrictNamespaces=yes`, `LockPersonality=yes`
- `MemoryDenyWriteExecute=yes`
- a system-service syscall filter
- `UMask=0077`

## Input handling

- Request body limit: 8 MiB.
- Batch limit: 5000 events.
- Field length limits are enforced before SQLite writes.
- All SQL uses prepared statements.
- Event IDs are idempotent; duplicate submissions are ignored.
- Raw request bodies are never logged.
- Token comparison uses `CRYPTO_memcmp`.

## Data handling

- Store only the normalized event payload and fields needed by rules.
- QA Sentinels performs redaction before transmission.
- Evidence bundles stay on the QA host; the SIEM receives an `evidence_ref`.
- Retention defaults to 30 days; resolved/acked alerts are pruned, open alerts
  are kept.

## Network exposure

This is not a public-facing service. For remote ingestion use TLS and a
firewall allowlist. If a reverse proxy is used, keep the bearer token check at
the application layer and terminate TLS with a current configuration.

## Known limits

No per-IP rate limiter is built in; connection limits are enforced by
libmicrohttpd. Put a reverse proxy in front of any untrusted network. The
dashboard stores the token in `sessionStorage`, not a cookie; use it only over
TLS on remote hosts.
