//! Certificate and connection data model.
//!
//! Everything in this module is a plain data structure produced by parsing
//! DER-encoded certificates. Nothing here touches the network, which keeps
//! the analysis rules in [`crate::analysis`] testable with fixture data.

use serde::Serialize;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

/// A single parsed certificate.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    /// Seconds since the Unix epoch.
    pub not_before: i64,
    /// Seconds since the Unix epoch.
    pub not_after: i64,
    pub serial: String,
    pub signature_algorithm: String,
    pub signature_is_sha1: bool,
    pub key_algorithm: String,
    pub key_size_bits: Option<u32>,
    pub is_ca: bool,
    /// Heuristic: subject and issuer are identical. A true self-signature
    /// check would require verifying the signature against the cert's own
    /// public key; the subject/issuer comparison is the same heuristic most
    /// lightweight TLS auditors use and is accurate for the overwhelming
    /// majority of real-world certificates.
    pub is_self_signed: bool,
}

/// Error parsing a DER-encoded certificate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertParseError {
    #[error("failed to parse X.509 certificate: {0}")]
    Malformed(String),
}

impl CertInfo {
    /// Parse a single DER-encoded certificate.
    ///
    /// # Errors
    /// Returns [`CertParseError`] if the bytes are not a well-formed X.509
    /// certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, CertParseError> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|e| CertParseError::Malformed(e.to_string()))?;
        Ok(Self::from_parsed(&cert))
    }

    fn from_parsed(cert: &X509Certificate<'_>) -> Self {
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let sans = extract_sans(cert);
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let serial = cert.raw_serial_as_string();
        let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
        let signature_is_sha1 = is_sha1_signature(&sig_oid);
        let signature_algorithm = describe_signature_oid(&sig_oid);
        let (key_algorithm, key_size_bits) = describe_public_key(cert);
        let is_ca = cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|bc| bc.value.ca);
        let is_self_signed = subject == issuer;

        Self {
            subject,
            issuer,
            sans,
            not_before,
            not_after,
            serial,
            signature_algorithm,
            signature_is_sha1,
            key_algorithm,
            key_size_bits,
            is_ca,
            is_self_signed,
        }
    }
}

fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(ext)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    ext.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_string()),
            GeneralName::IPAddress(ip) => Some(format_ip(ip)),
            _ => None,
        })
        .collect()
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
        16 => bytes
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => "invalid-ip".to_string(),
    }
}

fn is_sha1_signature(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.5" // sha1WithRSAEncryption
            | "1.2.840.10040.4.3" // dsa-with-sha1
            | "1.2.840.10045.4.1" // ecdsa-with-SHA1
    )
}

fn describe_signature_oid(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".to_string(),
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".to_string(),
        "1.2.840.10040.4.3" => "dsa-with-sha1".to_string(),
        "1.3.101.112" => "ed25519".to_string(),
        other => format!("unknown({other})"),
    }
}

fn describe_public_key(cert: &X509Certificate<'_>) -> (String, Option<u32>) {
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bits = rsa_modulus_bits(rsa.modulus);
            ("RSA".to_string(), Some(bits))
        }
        Ok(PublicKey::EC(point)) => {
            let bits = ec_point_bits(point.data());
            ("EC".to_string(), bits)
        }
        Ok(PublicKey::DSA(_)) => ("DSA".to_string(), None),
        Ok(PublicKey::GostR3410(_) | PublicKey::GostR3410_2012(_)) => ("GOST".to_string(), None),
        Ok(PublicKey::Unknown(_)) | Err(_) => ("Unknown".to_string(), None),
    }
}

fn rsa_modulus_bits(modulus: &[u8]) -> u32 {
    let trimmed = modulus
        .iter()
        .skip_while(|b| **b == 0)
        .copied()
        .collect::<Vec<u8>>();
    if trimmed.is_empty() {
        return 0;
    }
    let leading_bits = 8 - trimmed[0].leading_zeros();
    let byte_len = u32::try_from(trimmed.len()).unwrap_or(u32::MAX);
    (byte_len - 1) * 8 + leading_bits
}

fn ec_point_bits(data: &[u8]) -> Option<u32> {
    // Uncompressed point: 0x04 || X || Y, each coordinate curve-order-sized.
    if data.first() == Some(&0x04) {
        let coord_len = (data.len() - 1) / 2;
        return Some(u32::try_from(coord_len).unwrap_or(u32::MAX) * 8);
    }
    None
}

/// The full certificate chain as served by the peer, leaf first.
#[derive(Debug, Clone, Serialize)]
pub struct ChainInfo {
    pub certs: Vec<CertInfo>,
}

impl ChainInfo {
    #[must_use]
    pub fn leaf(&self) -> Option<&CertInfo> {
        self.certs.first()
    }
}

/// Negotiated connection parameters, independent of certificate content.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub hostname: String,
    pub port: u16,
    pub protocol_version: String,
    pub cipher_suite: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use time::OffsetDateTime;

    fn self_signed_cert_der(
        sans: Vec<String>,
        not_before_unix: i64,
        not_after_unix: i64,
    ) -> Vec<u8> {
        let key_pair = KeyPair::generate().expect("key gen");
        let mut params = CertificateParams::new(sans).expect("params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "example.com");
        params.distinguished_name = dn;
        params.not_before =
            OffsetDateTime::from_unix_timestamp(not_before_unix).expect("not_before");
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after_unix).expect("not_after");
        let cert = params.self_signed(&key_pair).expect("self sign");
        cert.der().to_vec()
    }

    #[test]
    fn parses_self_signed_cert_basics() {
        let der = self_signed_cert_der(
            vec!["example.com".to_string(), "www.example.com".to_string()],
            1_700_000_000,
            1_800_000_000,
        );
        let info = CertInfo::from_der(&der).expect("parse");
        assert!(info.subject.contains("example.com"));
        assert_eq!(info.subject, info.issuer);
        assert!(info.is_self_signed);
        assert!(info.sans.contains(&"example.com".to_string()));
        assert!(info.sans.contains(&"www.example.com".to_string()));
        assert_eq!(info.not_before, 1_700_000_000);
        assert_eq!(info.not_after, 1_800_000_000);
        assert_eq!(info.key_algorithm, "EC");
        assert_eq!(info.key_size_bits, Some(256));
        assert!(!info.serial.is_empty());
    }

    #[test]
    fn parses_cert_without_sans() {
        let der = self_signed_cert_der(vec![], 1_700_000_000, 1_800_000_000);
        let info = CertInfo::from_der(&der).expect("parse");
        assert!(info.sans.is_empty());
    }

    #[test]
    fn malformed_der_is_rejected() {
        let junk = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = CertInfo::from_der(&junk);
        assert!(result.is_err());
    }

    #[test]
    fn empty_der_is_rejected() {
        let result = CertInfo::from_der(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn rsa_modulus_bits_exact_2048() {
        // 256 bytes, top bit set in the first byte -> exactly 2048 bits.
        let mut modulus = vec![0xFFu8; 256];
        modulus[0] = 0x80;
        assert_eq!(rsa_modulus_bits(&modulus), 2048);
    }

    #[test]
    fn rsa_modulus_bits_strips_leading_zero_padding() {
        // Leading 0x00 byte (sign padding) followed by a 2048-bit value.
        let mut modulus = vec![0u8; 257];
        modulus[0] = 0x00;
        modulus[1] = 0x80;
        assert_eq!(rsa_modulus_bits(&modulus), 2048);
    }

    #[test]
    fn rsa_modulus_bits_small_key() {
        // 128 bytes with top bit set -> 1024 bits (weak).
        let mut modulus = vec![0xFFu8; 128];
        modulus[0] = 0x80;
        assert_eq!(rsa_modulus_bits(&modulus), 1024);
    }

    #[test]
    fn rsa_modulus_bits_empty_is_zero() {
        assert_eq!(rsa_modulus_bits(&[]), 0);
    }

    #[test]
    fn format_ip_v4() {
        assert_eq!(format_ip(&[127, 0, 0, 1]), "127.0.0.1");
    }

    #[test]
    fn format_ip_v6() {
        let bytes = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(format_ip(&bytes), "0000:0000:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn format_ip_invalid_length() {
        assert_eq!(format_ip(&[1, 2, 3]), "invalid-ip");
    }

    #[test]
    fn is_sha1_signature_detects_known_oids() {
        assert!(is_sha1_signature("1.2.840.113549.1.1.5"));
        assert!(is_sha1_signature("1.2.840.10045.4.1"));
        assert!(!is_sha1_signature("1.2.840.113549.1.1.11"));
    }

    #[test]
    fn describe_signature_oid_known_and_unknown() {
        assert_eq!(
            describe_signature_oid("1.2.840.113549.1.1.11"),
            "sha256WithRSAEncryption"
        );
        assert_eq!(describe_signature_oid("9.9.9.9"), "unknown(9.9.9.9)");
    }
}
