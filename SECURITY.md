# Security policy

Report vulnerabilities privately to the maintainer through the repository's
security advisory feature. Do not open a public issue with exploit details.

## Scope

- Bearer-token authentication and TLS handling
- Ingest validation, body limits, and SQL parameterization
- Static web root and route allowlist
- Database file and token permissions
- Legal manifest and web legal page

Keep the default bind on loopback, require TLS off-loopback, and never expose
tokens in logs or the web page.
