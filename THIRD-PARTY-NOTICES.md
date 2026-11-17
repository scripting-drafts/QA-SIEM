# Third-party notices — QA SIEM

QA SIEM is licensed under the MIT License. See `LICENSE`.

QA SIEM links dynamically against host libraries. The Debian/Ubuntu packages
provide them; they are not bundled in this repository.

| Component | Scope | License | Notes |
| --- | --- | --- | --- |
| SQLite | runtime | Public domain | https://www.sqlite.org/copyright.html |
| libmicrohttpd | runtime | LGPL-2.1-or-later | https://www.gnu.org/software/libmicrohttpd/ |
| cJSON | runtime | MIT | https://github.com/DaveGamble/cJSON |
| OpenSSL | runtime | Apache-2.0 | https://www.openssl.org/source/license.html |
| systemd | runtime | LGPL-2.1-or-later | Host service manager; not linked. |

## Distribution notes

- libmicrohttpd is LGPL-2.1-or-later. Keep its copyright and license notice
  available, and preserve the host package's source-offer terms.
- OpenSSL is Apache-2.0. Keep its attribution and license notice.
- The application's own C source, web assets, and systemd unit are MIT.
- Do not strip license files from a redistributed package.
