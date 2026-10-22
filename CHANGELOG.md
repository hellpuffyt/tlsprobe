# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security

- Updated `rustls` 0.23.43 → 0.23.46, `rustls-webpki` 0.103.15 → 0.103.16
  and `webpki-roots` 1.0.9 → 1.0.10 (RUSTSEC-2026-0285, -0346, -0348,
  -0349, -0381, -0382).

### Fixed

- The chain of trust was never validated: `webpki-roots` was a dependency
  but unused, so a chain from a private or unknown CA (not self-signed)
  graded A. New `UNTRUSTED_CHAIN` (critical) finding from `webpki`
  validation against the Mozilla roots; expiry and hostname problems are
  isolated so they do not mask or duplicate it.
- IPv6 targets: `::1` was parsed as host `:` port 1, `[::1]:443` was
  rejected; and IPv6 SANs never matched a compressed target address.
- `--json` error lines were built with `format!` and were invalid JSON
  when the message contained quotes (e.g. an invalid hostname).
- MD5-signed certificates were described but not flagged
  (`WEAK_SIGNATURE_MD5`).

### Changed

- README: example output replaced with a real local run; states that
  rustls cannot negotiate deprecated protocols or weak ciphers, so those
  rules cannot fire and tlsprobe does not detect servers that merely
  enable them.

### Added

- `tests/trust.rs` (runtime-generated PKI, local servers only);
  `SECURITY.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`.

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
