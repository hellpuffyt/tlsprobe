//! tlsprobe: audit a TLS endpoint's certificate chain, expiry, and
//! protocol/cipher configuration, producing findings with severity and
//! remediation rather than a raw dump of protocol facts.
//!
//! The crate is split so the analysis rules are a pure function of parsed
//! certificate data (see [`analysis`]), independent of the network fetch
//! (see [`fetch`]). That split is what makes the rule set unit-testable
//! offline with fixture certificates.

#![forbid(unsafe_code)]

pub mod analysis;
pub mod cert;
pub mod fetch;
pub mod report;

/// Current time as seconds since the Unix epoch.
///
/// # Panics
/// Panics if the system clock is set before the Unix epoch.
#[must_use]
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
