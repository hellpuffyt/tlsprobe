# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-08-30

### Added

- Initial release.
- Certificate chain fetch over TLS using `rustls` (no OpenSSL).
- Certificate parsing via `x509-parser`: subject, issuer, SANs, validity
  window, serial, key algorithm/size, signature algorithm.
- Pure, offline-testable analysis rules producing findings with severity
  and remediation:
  - `EXPIRED`, `EXPIRING_CRITICAL` (<7 days), `EXPIRING_WARNING` (<30 days)
  - `WEAK_SIGNATURE_SHA1`
  - `WEAK_KEY_RSA` (RSA < 2048 bits)
  - `HOSTNAME_MISMATCH` (with wildcard SAN support)
  - `SELF_SIGNED`
  - `LONG_VALIDITY` (> 398 days)
  - `MISSING_INTERMEDIATE`
  - `CHAIN_ORDER`
  - `DEPRECATED_PROTOCOL` (SSLv2/SSLv3/TLS 1.0/TLS 1.1)
  - `WEAK_CIPHER` (RC4/3DES/DES/NULL/EXPORT/MD5/CBC+SHA1)
- A/B/C/D/F grading with a `--min-grade` CI gate.
- Text and JSON (`--json`) report output.
- Multi-target scanning in a single invocation.
