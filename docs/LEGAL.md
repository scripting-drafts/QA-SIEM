# Legal and release policy — QA SIEM

This document is an inventory and release checklist, not legal advice.

## Required artifacts

- `LICENSE` — full MIT text.
- `THIRD-PARTY-NOTICES.md` — SQLite, libmicrohttpd, cJSON, OpenSSL.
- `legal/manifest.json` — machine-readable compliance register.
- `docs/PRIVACY.md` — local data handling and retention.
- `CONTRIBUTING.md` — inbound licensing and DCO.
- `SECURITY.md` — private vulnerability reporting.

## Before every release

1. Run `make test`, `make integration`, and `make legal-check`.
2. Update `lastReviewed`, `reviewedVersion`, and `reviewedComponents`.
3. Confirm `legal.json` in the web root matches `legal/manifest.json`.
4. Confirm the installer ships `LICENSE`, notices, privacy, and legal policy.
5. Review OpenSSL export/cryptography obligations for target jurisdictions.
6. Run the third-party scanner against the repository and review blocked or
   unknown findings.

## Distribution notes

- SQLite, libmicrohttpd, cJSON, and OpenSSL are host runtime dependencies.
- libmicrohttpd is LGPL-2.1-or-later; preserve its notice and source-offer
  terms.
- OpenSSL is Apache-2.0; preserve attribution.
