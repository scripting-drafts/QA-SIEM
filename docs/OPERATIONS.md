# Operations

## Install

```bash
sudo scripts/bootstrap-ubuntu.sh
sudo scripts/install.sh --token-group gerard
```

The installer creates the system user, `/var/lib/qa-siem`, `/etc/qa-siem`, the
token, rules, web assets, and `qa-siem.service`.

## Check

```bash
systemctl status qa-siem.service
curl -fsS http://127.0.0.1:8088/healthz
journalctl -u qa-siem.service -n 50
```

## Token rotation

```bash
sudo sh -c 'umask 007; openssl rand -hex 32 >/etc/qa-siem/token'
sudo chown root:qa-siem /etc/qa-siem/token
sudo chmod 0640 /etc/qa-siem/token
sudo systemctl restart qa-siem.service
```

Update the QA Sentinels `config/siem.json` token path or environment.

## Backup and retention

The database is a single SQLite file. Stop the service or use SQLite backup:

```bash
sqlite3 /var/lib/qa-siem/siem.db '.backup /var/backups/qa-siem.db'
```

Retention runs at startup and hourly. Configure it with `--retention-days`.
Open alerts are retained even when older than the cutoff.

## TLS

```bash
qa-siem --bind 0.0.0.0 --port 8443 \
  --tls-cert /etc/qa-siem/tls/server.crt \
  --tls-key  /etc/qa-siem/tls/server.key
```

Use a certificate from a trusted CA or a private CA distributed to the QA
hosts. Do not use plaintext HTTP for remote ingestion.

## Upgrade

```bash
git pull
sudo scripts/install.sh
```

SQLite schema changes are additive; back up before major upgrades. The binary
is built from source on the host, so no interpreter or runtime version drift is
introduced.

## Uninstall

```bash
sudo scripts/install.sh --uninstall
sudo scripts/install.sh --uninstall --purge   # also removes data and user
```
