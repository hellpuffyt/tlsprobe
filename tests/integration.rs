//! End-to-end integration tests against a TLS server this test process
//! spins up itself on `127.0.0.1`. No public internet access is required
//! or used.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use tlsprobe::fetch::probe;

/// Build a self-signed certificate + key pair for the given SAN list.
fn make_cert(sans: Vec<String>) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key_pair = KeyPair::generate().expect("generate key pair");
    let mut params = CertificateParams::new(sans).expect("cert params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "tlsprobe-integration-test");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair).expect("self sign");
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (cert_der, key_der)
}

/// Start a single-connection TLS echo server on an ephemeral localhost
/// port and return the port it bound to. The server handles exactly one
/// TLS handshake then exits.
fn spawn_server(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    thread::spawn(move || {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config");
        let config = Arc::new(config);

        if let Ok((mut sock, _)) = listener.accept() {
            if let Ok(mut conn) = ServerConnection::new(config) {
                while conn.is_handshaking() {
                    if conn.wants_read() && conn.read_tls(&mut sock).is_err() {
                        return;
                    }
                    if conn.process_new_packets().is_err() {
                        return;
                    }
                    if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
                        return;
                    }
                }
                let mut stream = StreamOwned::new(conn, sock);
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"ok");
            }
        }
    });

    // Give the listener a moment to be ready to accept.
    thread::sleep(Duration::from_millis(50));
    port
}

#[test]
fn probes_self_signed_server_and_reports_self_signed_finding() {
    let (cert, key) = make_cert(vec!["127.0.0.1".to_string()]);
    let port = spawn_server(cert, key);

    let (chain, conn) =
        probe("127.0.0.1", port, Duration::from_secs(5)).expect("probe should succeed");

    assert_eq!(chain.certs.len(), 1);
    let leaf = chain.leaf().expect("leaf present");
    assert!(leaf.is_self_signed);
    assert!(leaf.sans.contains(&"127.0.0.1".to_string()));
    assert_eq!(conn.hostname, "127.0.0.1");
    assert_eq!(conn.port, port);
    assert!(conn.protocol_version.starts_with("TLSv1."));
    assert!(!conn.cipher_suite.is_empty());

    let findings = tlsprobe::analysis::analyze(&chain, &conn, tlsprobe::now_unix());
    assert!(findings.iter().any(|f| f.id == "SELF_SIGNED"));
    // A self-signed leaf is its own root: MISSING_INTERMEDIATE should not
    // additionally fire (that would be a redundant, confusing finding).
    assert!(!findings.iter().any(|f| f.id == "MISSING_INTERMEDIATE"));
}

#[test]
fn probe_reports_hostname_mismatch_via_analysis() {
    let (cert, key) = make_cert(vec!["only-this-name.example".to_string()]);
    let port = spawn_server(cert, key);

    // Connect via an IP literal that differs from the certificate's SAN;
    // rustls will still complete the handshake because tlsprobe uses a
    // permissive verifier (that's the point: it audits what's served).
    let (chain, conn) =
        probe("127.0.0.1", port, Duration::from_secs(5)).expect("probe should succeed");

    let findings = tlsprobe::analysis::analyze(&chain, &conn, tlsprobe::now_unix());
    assert!(findings.iter().any(|f| f.id == "HOSTNAME_MISMATCH"));
    assert_eq!(
        tlsprobe::analysis::grade(&findings),
        tlsprobe::analysis::Grade::F
    );
}

#[test]
fn probe_unreachable_port_returns_error() {
    // Port 1 is reserved/unlikely to be listening; connect should fail
    // quickly rather than hang.
    let result = probe("127.0.0.1", 1, Duration::from_millis(500));
    assert!(result.is_err());
}

#[test]
fn probe_invalid_hostname_returns_error() {
    let result = probe("not a valid host name!", 443, Duration::from_millis(200));
    assert!(result.is_err());
}
