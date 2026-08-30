# Contributing

Thanks for considering a contribution to `tlsprobe`.

## Development environment

The crate builds with a plain `cargo` toolchain (MSRV 1.88). No external
services are required to run the test suite: rule tests use in-memory
fixture data, and integration tests spin up a local TLS server on
`127.0.0.1` rather than reaching the public internet.

```sh
cargo build
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Design principles to preserve

- **The analysis is a pure function.** Everything in `src/analysis.rs`
  takes already-parsed data (`ChainInfo`, `ConnectionInfo`) and a
  timestamp, and returns `Finding`s. It must not perform I/O. This is what
  lets the entire rule set be tested offline, deterministically, and
  quickly. Network code lives only in `src/fetch.rs`.
- **No OpenSSL.** Dependencies are pure-Rust (`rustls`, `x509-parser`,
  `webpki-roots`). Don't introduce a dependency that links OpenSSL.
- **`unsafe_code` is forbidden** at the crate level (`#![forbid(unsafe_code)]`
  plus the `Cargo.toml` lint). Don't add `#[allow(unsafe_code)]` escape
  hatches; find another way.
- **Every finding needs a remediation.** A finding without a concrete "do
  this" recommendation isn't useful to the person reading the report.

## Adding a new finding rule

1. Add a `check_*` function in `src/analysis.rs` that takes parsed data and
   returns `Vec<Finding>`.
2. Wire it into `analyze()`.
3. Add tests in the `#[cfg(test)] mod tests` block at the bottom of the same
   file: at minimum, one test that triggers the finding and one
   false-positive guard that confirms healthy input does *not* trigger it.
4. Update the findings reference table in `README.md`.
5. Add a `CHANGELOG.md` entry.

## Pull requests

- Keep commits focused; explain *why*, not just *what*, in the commit
  message.
- Run the full gate list above before opening a PR. CI runs the same
  checks on Linux, Windows, and macOS, plus an MSRV job and a release
  smoke test against a real host.
