# Production readiness — tlsprobe

Audit date: 2026-10-22. Branch: `audit/production-readiness`.
Tested commit: `5c39a3e` (the final commit adds only this file).

## Scope

`tlsprobe` connects to `host:port` over TLS (rustls, ring, TLS 1.2/1.3)
with an accept-all verifier so that broken chains can still be
inspected, parses the served chain (`x509-parser`), validates the chain
of trust separately against the Mozilla roots (`webpki-roots`, new
`src/trust.rs`), and turns the facts into findings with severity,
remediation and an A–F grade (text/JSON, `--min-grade` gate).

## Platforms and prerequisites

- Rust 1.88+; `cargo +1.88 test --all-targets --locked` passed (79/79)
  on the audit host after the dependency updates.
- Verified on macOS 27 (Apple M5); CI covers Linux, macOS, Windows.
- **No test contacts the internet**; all TLS servers are bound to
  `127.0.0.1` / `::1` inside the test process with certificates generated
  at runtime by `rcgen`. No key material is committed (`*.pem`/`*.key`
  are git-ignored and absent from history).

## Clean-clone verification (literal README steps)

```
git clone -b audit/production-readiness <repo> tlsprobe && cd tlsprobe
cargo build --release                      # exit 0; binary at target/release/tlsprobe
cargo test --all-targets                   # exit 0 — 79 passed (62 lib, 4 bin, 4 integration, 9 trust), 0 failed, 0 ignored
cargo clippy --all-targets -- -D warnings  # exit 0
cargo fmt --all -- --check                 # exit 0
tlsprobe 127.0.0.1:<local openssl s_server, self-signed>          # Grade F: UNTRUSTED_CHAIN + SELF_SIGNED, exit 0
tlsprobe --min-grade B 127.0.0.1:<same>                            # exit 1
tlsprobe --json --port <same> localhost                            # grade "F", trust.status "untrusted"
```

## Commands and results (audit host)

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | 0 | clean |
| `cargo test --all-targets --locked` (baseline) | 0 | 66 passed, 0 failed, 0 ignored |
| `cargo test --all-targets --locked` (after) | 0 | 79 passed, 0 failed, 0 ignored |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` | 0 | clean |
| `cargo audit --db <local advisory-db> --no-fetch` (baseline) | 1 | **6 vulnerabilities**: `rustls` 0.23.43 (4), `rustls-webpki` 0.103.15, `webpki-roots` 1.0.9 |
| same (after `cargo update -p rustls -p rustls-webpki -p webpki-roots@1.0.9`) | 0 | 0 vulnerabilities |
| `cargo +1.88 test --all-targets --locked` | 0 | 79 passed |
| `cargo deny check` | — | not configured |

## CI status

Default branch: `success` (run on `d236b9a`, 2026-08-30).
Audit branch: pending until pushed. Actions pinned by tag; unchanged.

## Bugs found and fixed (each with a regression test)

| # | Severity | Defect | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | High (dependencies) | Six RUSTSEC advisories in the TLS stack. | Lockfile updates within semver. | `cargo audit` exit 0 |
| 2 | **High (false negative, advertised feature missing)** | README: "does the chain validate the way a browser expects" and "trust anchors are `webpki-roots`" — but `webpki-roots` was never used; no trust validation existed. A leaf + intermediate from an unknown CA graded **A**. | `trust::verify_chain` (webpki against Mozilla roots, retrying inside the validity window / with a covered name so expiry and hostname findings neither mask nor duplicate it); `UNTRUSTED_CHAIN` critical finding. | `tests/trust.rs` (5 trust tests incl. `probing_a_private_ca_chain_reports_untrusted_but_not_missing_intermediate`), `analysis::tests::untrusted_chain_is_critical_and_forces_f` |
| 3 | Medium | IPv6 targets: `::1` became host `:` port 1; `[::1]:443` was an invalid hostname; IPv6 SANs (rendered uncompressed) never matched. | Bracket/bare IPv6 parsing; IP targets compared as `IpAddr`. | `tests::parse_target_ipv6_forms`, `ipv6_target_matches_a_fully_written_ipv6_san`, `trust::ipv6_loopback_target_is_probed_and_matched` |
| 4 | Low | `--json` error lines were invalid JSON when the message had quotes. | `serde_json::json!`. | `trust::json_errors_are_valid_json_even_with_quotes_in_the_message` |
| 5 | Low | MD5 signatures described but not flagged. | `WEAK_SIGNATURE_MD5`. | `analysis::tests::md5_signature_flagged` |
| 6 | Docs | README example output (`Example CA`, `Serial: 01:02:03:...`) was not from a run; `DEPRECATED_PROTOCOL`/`WEAK_CIPHER` were presented as working although rustls cannot negotiate those values. | Real local output; limitation stated. | — |

Also covered now: a server that closes immediately and a silent server
both return errors within the timeout (no hang).

## Security review

- `#![forbid(unsafe_code)]`; pure-Rust TLS/crypto.
- The accept-all verifier is intentional and documented; trust is now
  reported explicitly rather than implied by a successful handshake.
- Timeouts on connect/read/write; only the first resolved address is tried.
- Secret scan of the tree and full history: no hits.
- Workflow permissions: `contents: read`.

## Known limitations

- Cannot detect servers that *also* enable TLS ≤ 1.1 or weak ciphers
  (rustls never offers them); a server offering only those fails to
  connect.
- Weak-signature checks look at the leaf only.
- Revocation (OCSP/CRL) and CT are not checked.
- Only the first resolved address is probed.
- `cargo deny` not configured.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
| --- | --- | --- | --- | --- | --- |
| Certificate facts | Subject/issuer/SANs/validity/key/signature parsed | `cert` unit tests (rcgen DER) | pass | — | `src/cert.rs` |
| Rule set | Each rule triggers and has a false-positive guard | `cargo test --lib` | pass | 62/62 | `src/analysis.rs` |
| Chain of trust | Public-root validation, isolated from expiry/name | `cargo test --test trust` | pass (feature absent before) | 9/9 | `src/trust.rs` |
| End-to-end probe | Local TLS server → findings, grade | `tests/integration.rs`, `tests/trust.rs`, clean-clone runs | pass | F for self-signed | `src/fetch.rs` |
| CI gate | `--min-grade` exit code | clean-clone run | pass | exit 1 below B | `src/main.rs` |
| Robustness | No hang on closed/silent servers | `tests/trust.rs` | pass | < 5 s | `src/fetch.rs` |
| Dependencies | No known advisories | `cargo audit` | pass (failed before) | 0 | `Cargo.lock` |

## Classification proposal

**Partially Verified** — documented behaviour, including the newly
implemented trust validation, is tested against local servers on macOS;
not verified: a publicly trusted chain end-to-end (requires a real
public endpoint, deliberately not contacted), deprecated-protocol
detection (not possible with rustls), and CI for the audit branch.
