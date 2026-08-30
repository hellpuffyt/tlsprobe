//! Network layer: connects to a TLS endpoint and extracts the raw
//! certificate chain and negotiated connection parameters.
//!
//! This module intentionally does no analysis -- it just gathers facts.
//! See [`crate::analysis`] for the rules that turn those facts into
//! findings.

use std::io::Write as _;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

use crate::cert::{CertInfo, ChainInfo, ConnectionInfo};

/// Errors that can occur while probing a target.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("invalid hostname \"{0}\"")]
    InvalidHostname(String),
    #[error("DNS resolution failed for {0}: {1}")]
    Resolution(String, std::io::Error),
    #[error("could not resolve any address for {0}")]
    NoAddress(String),
    #[error("TCP connection failed: {0}")]
    Connect(std::io::Error),
    #[error("TLS handshake failed: {0}")]
    Handshake(rustls::Error),
    #[error("server presented no certificates")]
    NoCertificates,
    #[error("failed to parse certificate: {0}")]
    CertParse(#[from] crate::cert::CertParseError),
}

/// A verifier that accepts any certificate chain without validating it.
///
/// This tool audits *what a server presents*, including broken or invalid
/// chains -- that is the point of the findings it produces. Rejecting the
/// handshake for an invalid chain (as a normal HTTPS client would) would
/// prevent us from ever inspecting the certificates that are actually
/// misconfigured.
#[derive(Debug)]
struct AcceptAllVerifier {
    supported_schemes: Vec<SignatureScheme>,
}

impl AcceptAllVerifier {
    fn new() -> Self {
        Self {
            supported_schemes: vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
            ],
        }
    }
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_schemes.clone()
    }
}

/// Connect to `hostname:port`, perform a TLS handshake, and return the
/// served certificate chain plus negotiated connection parameters.
///
/// # Errors
/// Returns [`ProbeError`] for DNS/connect/handshake failures, or if the
/// server presents no certificates / unparsable certificates.
pub fn probe(
    hostname: &str,
    port: u16,
    timeout: Duration,
) -> Result<(ChainInfo, ConnectionInfo), ProbeError> {
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|_| ProbeError::InvalidHostname(hostname.to_string()))?;

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier::new()))
        .with_no_client_auth();
    let config = Arc::new(config);

    let mut conn = ClientConnection::new(config, server_name).map_err(ProbeError::Handshake)?;

    let addr = format!("{hostname}:{port}");
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|e| ProbeError::Resolution(addr.clone(), e))?
        .next()
        .ok_or_else(|| ProbeError::NoAddress(addr.clone()))?;

    let mut sock =
        TcpStream::connect_timeout(&socket_addr, timeout).map_err(ProbeError::Connect)?;
    sock.set_read_timeout(Some(timeout))
        .map_err(ProbeError::Connect)?;
    sock.set_write_timeout(Some(timeout))
        .map_err(ProbeError::Connect)?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    // A minimal write is enough to drive the handshake to completion on
    // most servers; we don't need to send a real HTTP request.
    let _ = tls.write_all(b"");
    tls.flush().ok();
    // Force the handshake if it hasn't completed yet.
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(tls.sock)
            .map_err(ProbeError::Connect)?;
    }

    let peer_certs = conn.peer_certificates().ok_or(ProbeError::NoCertificates)?;
    if peer_certs.is_empty() {
        return Err(ProbeError::NoCertificates);
    }

    let certs = peer_certs
        .iter()
        .map(|der| CertInfo::from_der(der.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;

    let protocol_version = conn
        .protocol_version()
        .map_or_else(|| "unknown".to_string(), describe_protocol_version);
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map_or_else(|| "unknown".to_string(), describe_cipher_suite);

    Ok((
        ChainInfo { certs },
        ConnectionInfo {
            hostname: hostname.to_string(),
            port,
            protocol_version,
            cipher_suite,
        },
    ))
}

fn describe_protocol_version(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::SSLv2 => "SSLv2".to_string(),
        rustls::ProtocolVersion::SSLv3 => "SSLv3".to_string(),
        rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0".to_string(),
        rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        other => format!("{other:?}"),
    }
}

fn describe_cipher_suite(cs: rustls::SupportedCipherSuite) -> String {
    format!("{:?}", cs.suite())
}
