# tlsprobe

Audit a TLS endpoint's certificate chain, expiry, and protocol/cipher
configuration — and get back plain-language findings with severity and
remediation, not a wall of protocol facts.

## What

`tlsprobe` connects to a host over TLS, inspects the certificate chain the
server actually serves, and checks it against a set of practical rules:
is it expired or about to be, does the chain validate the way a browser
expects, is the key or signature algorithm weak, does the hostname
actually match, is the negotiated protocol or cipher suite deprecated.
Each problem it finds comes with a severity and a concrete remediation
step, and the whole audit is summarized as a single A–F grade.

## Why

Most TLS checkers dump every protocol detail they can extract and leave
you to interpret it. What you actually need to know as an operator is:
*when does this expire, will this work in a real browser, is anything
here actually dangerous, and what do I do about it.* `tlsprobe` is built
around that question.

## Features

- **Certificate inspection** — subject, issuer, SANs, validity window,
  days to expiry, key algorithm and size, signature algorithm, serial.
- **Chain analysis** — chain length, self-signed detection, chain
  ordering, and detection of a very common real misconfiguration: a
  server that serves its leaf certificate without the intermediate. That
  setup often still works in browsers that cache the intermediate or do
  AIA fetching, and fails for everything else (curl, mobile apps, IoT).
- **Findings with severity and remediation** in the style of a security
  report — see the [reference table](#findings-reference) below.
- **Protocol/cipher reporting** for the negotiated connection, with
  deprecated versions and weak cipher suites flagged.
- **A–F grading**, text and JSON output, a `--min-grade` gate for CI, and
  support for auditing multiple targets in one invocation.

## Architecture

The crate is deliberately split so the rule set is testable without a
network:

```
src/
  cert.rs      Parses DER certificates into plain data (CertInfo, ChainInfo).
               No network access.
  fetch.rs     Connects over TLS (rustls), gathers the served chain and
               negotiated connection parameters. No analysis.
  analysis.rs  Pure functions: (ChainInfo, ConnectionInfo, now) -> Vec<Finding>.
               Every rule lives here and is unit-tested with fixture data
               entirely offline.
  report.rs    Renders a Report (chain + connection + findings + grade) as
               text or JSON.
  main.rs      CLI (clap): wires fetch -> analysis -> report together.
```

`fetch.rs` uses a permissive certificate verifier on purpose: this tool's
job is to audit whatever a server presents, including broken or invalid
chains. A normal HTTPS client would abort the handshake exactly where
this tool needs to start looking.

No OpenSSL anywhere in the dependency tree — TLS is `rustls`, trust
anchors are `webpki-roots`, and certificate parsing is `x509-parser`.

## Installation

```sh
git clone https://github.com/hellpuffyt/tlsprobe
cd tlsprobe
cargo build --release
# binary at target/release/tlsprobe
```

Requires Rust 1.88 or newer (see [MSRV](#msrv)).

## Usage

```sh
# Audit one host (defaults to port 443)
tlsprobe example.com

# Audit multiple targets, some with explicit ports
tlsprobe example.com internal.example.com:8443

# Machine-readable output
tlsprobe --json example.com

# CI gate: fail (nonzero exit) if the grade drops below B on any target
tlsprobe --min-grade B example.com

# Custom timeout / default port
tlsprobe --timeout 5 --port 8443 example.com
```

Example text output:

```
== example.com (example.com:443) ==
Protocol: TLSv1.3   Cipher: TLS13_AES_256_GCM_SHA384
Grade: A
Chain length: 2

Leaf certificate:
  Subject:   CN=example.com
  Issuer:    C=US, O=Example CA, CN=Example CA
  SANs:      example.com, www.example.com
  Serial:    01:02:03:...
  Key:       EC 256 bits
  Signature: ecdsa-with-SHA256
  Validity:  2026-01-01T00:00:00Z -> 2026-04-01T00:00:00Z

Findings: none
```

## Findings reference

| ID | Severity | What it means | Remediation |
| --- | --- | --- | --- |
| `EXPIRED` | Critical | Certificate's `not_after` is in the past. | Renew and deploy immediately. |
| `EXPIRING_CRITICAL` | High | Expires within 7 days. | Renew now. |
| `EXPIRING_WARNING` | Medium | Expires within 30 days. | Schedule renewal, ideally via ACME automation. |
| `HOSTNAME_MISMATCH` | Critical | Requested hostname isn't in the cert's SANs (wildcards supported). | Issue a cert covering the hostname, or connect to a covered one. |
| `WEAK_SIGNATURE_SHA1` | High | Certificate signed with SHA-1. | Reissue with SHA-256 or stronger. |
| `WEAK_KEY_RSA` | High | RSA key smaller than 2048 bits. | Reissue with >=2048-bit RSA or switch to EC. |
| `SELF_SIGNED` | High | Leaf certificate's issuer equals its subject. | Use a publicly trusted CA for anything reachable by real clients. |
| `MISSING_INTERMEDIATE` | Medium | Server served only the leaf, no intermediate. | Configure the server to serve its full chain. |
| `CHAIN_ORDER` | Medium | Served certificates aren't in issuer-linked order. | Serve leaf-to-root, verify each issuer actually issued the next cert. |
| `LONG_VALIDITY` | Low | Validity period exceeds 398 days (CA/Browser Forum baseline). | Reissue at <=398 days; prefer short-lived automated issuance. |
| `DEPRECATED_PROTOCOL` | High | Negotiated SSLv2/SSLv3/TLS 1.0/TLS 1.1. | Disable on the server; require TLS 1.2+, prefer TLS 1.3. |
| `WEAK_CIPHER` | Medium | Negotiated cipher suite is RC4/3DES/DES/NULL/EXPORT/MD5/legacy-CBC. | Restrict to modern AEAD suites. |

Grading: any `Critical` finding forces an `F`. Otherwise the grade starts
at 100 and subtracts per finding (High -20, Medium -10, Low -4), then maps
to A (90+) / B (80+) / C (70+) / D (60+) / F.

## Testing

```sh
cargo test --all-targets
```

The rule set in `src/analysis.rs` is tested entirely offline against
in-memory fixture data — every rule has both a triggering case and a
false-positive guard. `src/cert.rs` is tested against real DER
certificates generated on the fly with `rcgen` (no OpenSSL, no committed
key material). The integration tests in `tests/integration.rs` spin up a
throwaway TLS server on `127.0.0.1` and probe it end-to-end; none of the
test suite requires reaching the public internet.

## Security

- `#![forbid(unsafe_code)]` at the crate level.
- No OpenSSL: the entire TLS/crypto/parsing stack is pure Rust.
- `tlsprobe` intentionally does **not** reject invalid certificate chains
  during the handshake — that's the point of the tool, it's auditing what
  a server presents, including misconfigurations. Do not mistake a
  successful `tlsprobe` run for proof a connection is trustworthy; read
  the findings and the grade.
- No secrets, private keys, or credentials are read, stored, or
  transmitted by this tool.

Found a security issue in `tlsprobe` itself? Please open an issue with
details.

## License

MIT. See [LICENSE](LICENSE).

## MSRV

Rust 1.88, verified in CI against the `1.88` toolchain directly (not just
"whatever `stable` happens to be").
