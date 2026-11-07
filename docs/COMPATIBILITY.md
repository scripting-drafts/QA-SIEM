# Compatibility

## Target baseline

- Ubuntu 22.04.5 LTS
- Linux kernel 5.15+ (tested on 6.8)
- systemd 249+
- glibc 2.35
- SQLite 3.37+
- libmicrohttpd 0.9.75+
- cJSON 1.7.15+
- OpenSSL 3.0+

## Supported upgrade path

The implementation uses C11, POSIX, and the stable public APIs of SQLite,
libmicrohttpd, cJSON, and OpenSSL. It avoids distribution-specific ABIs and
vendored libraries. The systemd unit uses directives available since systemd
249 and remains valid through the 26.10 release line.

Expected compatibility:

| Release | Status |
|---|---|
| 22.04 LTS | baseline, tested |
| 24.04 LTS | supported |
| 24.10 | supported |
| 25.04 | supported |
| 25.10 | supported |
| 26.04 LTS | supported |
| 26.10 | supported |

On each release upgrade:

```bash
sudo scripts/bootstrap-ubuntu.sh
make clean test
sudo scripts/install.sh --token-group <qa-group>
```

The SQLite schema is additive and uses `IF NOT EXISTS`; back up
`/var/lib/qa-siem/siem.db` before a major upgrade.

## Keeping repositories in sync

The companion Quality-Assurance-Sentinels repository maintains the same Ubuntu
22.04-26.10 matrix in `docs/COMPATIBILITY.md` and exposes `qa compat --strict`.
Update both matrices and run both test suites in the same change when the
baseline moves.

## Portability notes

- `MHD_HTTP_CONTENT_TOO_LARGE` is used when available; a 413 fallback is
  compiled for older libmicrohttpd builds.
- TLS is optional. Plain HTTP is refused on non-loopback binds.
- No kernel modules, eBPF, or custom kernel interfaces are required.
- The QA Sentinels connector uses the Python 3 standard library only.
