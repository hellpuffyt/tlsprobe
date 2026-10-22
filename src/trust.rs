//! Does the served chain validate the way a browser would validate it?
//!
//! The handshake in [`crate::fetch`] deliberately accepts any certificate so
//! that broken chains can still be inspected. Trust is therefore checked
//! separately, after the fact, by running the same `webpki` path validation a
//! rustls client performs against the Mozilla root set shipped in
//! `webpki-roots`.
//!
//! Expiry and hostname problems already have their own findings, so this
//! check isolates the *chain of trust*: when validation fails only because of
//! the clock or the name, it is repeated at a moment inside the chain's
//! validity window and for a name the leaf covers. What is left is "no path
//! from this leaf to a trusted root" (unknown issuer, bad signature, missing
//! intermediate that cannot be found, wrong key usage, ...).

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error, RootCertStore};
use serde::Serialize;

use crate::cert::CertInfo;

/// The outcome of validating a served chain against a set of trust anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum TrustStatus {
    /// A path to a trusted root exists (ignoring expiry and hostname, which
    /// are reported by their own rules).
    Trusted,
    /// No valid path to a trusted root; the reason is the validator's error.
    Untrusted(String),
    /// Trust was not evaluated (for example, fixture data in tests).
    NotChecked,
}

/// The public web PKI roots (Mozilla's set, via `webpki-roots`).
#[must_use]
pub fn public_roots() -> Arc<RootCertStore> {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(store)
}

/// Validate `chain` (leaf first, as served) against `roots`.
///
/// `parsed` must be the same chain parsed with [`CertInfo::from_der`]; it is
/// used to pick a validation time and name when expiry or hostname problems
/// would otherwise mask the trust result.
#[must_use]
pub fn verify_chain(
    chain: &[CertificateDer<'_>],
    parsed: &[CertInfo],
    hostname: &str,
    roots: Arc<RootCertStore>,
    now: UnixTime,
) -> TrustStatus {
    let Some((leaf, intermediates)) = chain.split_first() else {
        return TrustStatus::Untrusted("no certificates".to_string());
    };
    let verifier = match WebPkiServerVerifier::builder(roots).build() {
        Ok(v) => v,
        Err(e) => return TrustStatus::Untrusted(format!("no usable trust anchors: {e}")),
    };

    let attempt = |name: &str, at: UnixTime| -> Result<(), Error> {
        let server_name = ServerName::try_from(name.to_string())
            .map_err(|_| Error::General(format!("unusable name {name:?}")))?;
        verifier
            .verify_server_cert(leaf, intermediates, &server_name, &[], at)
            .map(|_| ())
    };

    let mut name = hostname.to_string();
    let mut at = now;
    // Up to three attempts: as requested, then with the clock moved into
    // the validity window, then with a name the leaf actually covers.
    for _ in 0..3 {
        match attempt(&name, at) {
            Ok(()) => return TrustStatus::Trusted,
            Err(Error::InvalidCertificate(
                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. },
            )) => match inside_validity(parsed) {
                Some(t) if t != at => at = t,
                _ => {
                    return TrustStatus::Untrusted(
                        "no moment where the whole chain is valid".into(),
                    )
                }
            },
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => match parsed.first().and_then(|leaf| leaf.sans.first()) {
                Some(san) if *san != name => name = san.replacen("*.", "wildcard-probe.", 1),
                _ => return TrustStatus::Untrusted("leaf names no usable subject".into()),
            },
            Err(e) => return TrustStatus::Untrusted(e.to_string()),
        }
    }
    TrustStatus::Untrusted("validation did not converge".into())
}

/// A moment at which every certificate in the chain is within its validity
/// period, if there is one.
fn inside_validity(parsed: &[CertInfo]) -> Option<UnixTime> {
    let start = parsed.iter().map(|c| c.not_before).max()?;
    let end = parsed.iter().map(|c| c.not_after).min()?;
    if start > end {
        return None;
    }
    let t = u64::try_from(start.saturating_add(1).min(end)).ok()?;
    Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        t,
    )))
}
