//! Chain-of-trust validation and end-to-end probes against local TLS servers
//! built from a throwaway CA generated at runtime (no key material is
//! committed, nothing touches the internet).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read as _;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use time::{Duration as TimeDuration, OffsetDateTime};

use tlsprobe::cert::CertInfo;
use tlsprobe::fetch::probe;
use tlsprobe::trust::{public_roots, verify_chain, TrustStatus};

struct Pki {
    root: Certificate,
    chain: Vec<CertificateDer<'static>>,
    leaf_key: PrivateKeyDer<'static>,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// Root -> intermediate -> leaf. `leaf_days` is (start, end) relative to now.
fn pki(sans: &[&str], leaf_days: (i64, i64)) -> Pki {
    let root_key = KeyPair::generate().unwrap();
    let root = ca_params("tlsprobe test root")
        .self_signed(&root_key)
        .unwrap();

    let inter_key = KeyPair::generate().unwrap();
    let inter = ca_params("tlsprobe test intermediate")
        .signed_by(&inter_key, &root, &root_key)
        .unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params =
        CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, sans[0]);
    leaf_params.distinguished_name = dn;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now + TimeDuration::days(leaf_days.0);
    leaf_params.not_after = now + TimeDuration::days(leaf_days.1);
    let leaf = leaf_params
        .signed_by(&leaf_key, &inter, &inter_key)
        .unwrap();

    Pki {
        chain: vec![leaf.der().clone(), inter.der().clone()],
        leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        root,
    }
}

fn roots_with(root: &Certificate) -> Arc<RootCertStore> {
    let mut store = RootCertStore::empty();
    store.add(root.der().clone()).unwrap();
    Arc::new(store)
}

fn parsed(chain: &[CertificateDer<'_>]) -> Vec<CertInfo> {
    chain
        .iter()
        .map(|c| CertInfo::from_der(c.as_ref()).unwrap())
        .collect()
}

fn check(
    _pki: &Pki,
    chain: &[CertificateDer<'static>],
    name: &str,
    roots: Arc<RootCertStore>,
) -> TrustStatus {
    verify_chain(chain, &parsed(chain), name, roots, UnixTime::now())
}

#[test]
fn full_chain_to_a_trusted_root_is_trusted() {
    let pki = pki(&["localhost"], (-1, 30));
    assert_eq!(
        check(&pki, &pki.chain, "localhost", roots_with(&pki.root)),
        TrustStatus::Trusted
    );
}

#[test]
fn a_private_ca_is_untrusted_by_the_public_roots() {
    let pki = pki(&["localhost"], (-1, 30));
    match check(&pki, &pki.chain, "localhost", public_roots()) {
        TrustStatus::Untrusted(reason) => assert!(reason.contains("UnknownIssuer"), "{reason}"),
        other => panic!("expected Untrusted, got {other:?}"),
    }
}

#[test]
fn a_missing_intermediate_breaks_the_path() {
    let pki = pki(&["localhost"], (-1, 30));
    let leaf_only = vec![pki.chain[0].clone()];
    assert!(matches!(
        check(&pki, &leaf_only, "localhost", roots_with(&pki.root)),
        TrustStatus::Untrusted(_)
    ));
}

#[test]
fn expiry_and_name_problems_do_not_mask_a_valid_trust_path() {
    // Expired, and requested under a name it does not cover - both have
    // their own findings; the chain of trust itself is fine.
    let pki = pki(&["svc.internal.test"], (-60, -10));
    assert_eq!(
        check(&pki, &pki.chain, "other.test", roots_with(&pki.root)),
        TrustStatus::Trusted
    );
}

fn serve_tls(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut conn = ServerConnection::new(config).unwrap();
            let _ = conn.complete_io(&mut sock);
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
            let mut buf = [0u8; 16];
            let _ = rustls::Stream::new(&mut conn, &mut sock).read(&mut buf);
        }
    });
    port
}

#[test]
fn probing_a_private_ca_chain_reports_untrusted_but_not_missing_intermediate() {
    let pki = pki(&["127.0.0.1"], (-1, 30));
    let port = serve_tls(pki.chain.clone(), pki.leaf_key.clone_key());
    let (chain, conn) = probe("127.0.0.1", port, Duration::from_secs(5)).expect("probe");
    assert_eq!(chain.certs.len(), 2);
    assert!(
        matches!(conn.trust, TrustStatus::Untrusted(_)),
        "{:?}",
        conn.trust
    );

    let findings = tlsprobe::analysis::analyze(&chain, &conn, tlsprobe::now_unix());
    let ids: Vec<_> = findings.iter().map(|f| f.id).collect();
    assert!(ids.contains(&"UNTRUSTED_CHAIN"), "{ids:?}");
    assert!(!ids.contains(&"MISSING_INTERMEDIATE"), "{ids:?}");
    assert!(!ids.contains(&"HOSTNAME_MISMATCH"), "{ids:?}");
    assert!(!ids.contains(&"SELF_SIGNED"), "{ids:?}");
    assert_eq!(
        tlsprobe::analysis::grade(&findings),
        tlsprobe::analysis::Grade::F
    );
}

#[test]
fn a_server_that_closes_immediately_is_an_error_not_a_hang() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            drop(sock);
        }
    });
    let start = Instant::now();
    assert!(probe("127.0.0.1", port, Duration::from_secs(2)).is_err());
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_silent_server_hits_the_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let held: Vec<_> = listener.incoming().take(1).collect();
        thread::sleep(Duration::from_secs(10));
        drop(held);
    });
    let start = Instant::now();
    assert!(probe("127.0.0.1", port, Duration::from_secs(1)).is_err());
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn json_errors_are_valid_json_even_with_quotes_in_the_message() {
    // Regression: the error line was built with format!, and the
    // invalid-hostname message contains quotes.
    let out = Command::new(env!("CARGO_BIN_EXE_tlsprobe"))
        .args(["--json", "--timeout", "1", "bad host!"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let line = String::from_utf8(out.stderr).unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON on stderr");
    assert_eq!(v["target"], "bad host!");
    assert!(v["error"].as_str().unwrap().contains('"'));
}

#[test]
fn ipv6_loopback_target_is_probed_and_matched() {
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        panic!("precondition: IPv6 loopback must be available");
    };
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let pki = pki(&["::1"], (-1, 30));
    let listener = TcpListener::bind(("::1", port)).unwrap();
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), pki.leaf_key.clone_key())
            .unwrap(),
    );
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut conn = ServerConnection::new(config).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
        }
    });
    let out = Command::new(env!("CARGO_BIN_EXE_tlsprobe"))
        .args(["--json", &format!("[::1]:{port}")])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json report");
    let ids: Vec<_> = v[0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert!(!ids.contains(&"HOSTNAME_MISMATCH".to_string()), "{ids:?}");
}
