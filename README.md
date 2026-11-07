# QA SIEM
Local-first C11 SIEM for Quality-Assurance-Sentinels. SQLite, libmicrohttpd, OpenSSL.
```bash
sudo scripts/bootstrap-ubuntu.sh
sudo scripts/install.sh
curl -fsS http://127.0.0.1:8088/healthz
```
Dashboard: `http://127.0.0.1:8088/`; token: `/etc/qa-siem/token`.
See `docs/INTEGRATION.md`, `docs/SECURITY.md`, `docs/OPERATIONS.md`.
