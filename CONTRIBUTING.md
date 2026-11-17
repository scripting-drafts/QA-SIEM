# Contributing

Contributions are accepted under the MIT License (inbound = outbound). Sign off
commits with the Developer Certificate of Origin 1.1 (`git commit -s`).

- Keep the default bind on loopback and authentication enabled.
- Do not add telemetry or outbound network calls.
- Add tests for parsing, SQL, routing, retention, and legal-register changes.
- Run `make test` and `make integration`; run `make legal-check` before release.
- Do not include tokens, personal data, host-specific paths, or secrets.
