//! Pure analysis rules.
//!
//! Every function in this module takes already-parsed data
//! ([`crate::cert::ChainInfo`], [`crate::cert::ConnectionInfo`]) plus a
//! reference "now" timestamp and produces [`Finding`]s. Nothing here
//! performs I/O, which is what makes the rule set unit-testable offline
//! with fixture certificates.

use serde::Serialize;
use std::cmp::Ordering;

use crate::cert::{ChainInfo, ConnectionInfo};

/// How dangerous a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single audit finding: what's wrong, how bad it is, and what to do
/// about it.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub remediation: &'static str,
}

/// Letter grade summarizing the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Grade::A => 4,
            Grade::B => 3,
            Grade::C => 2,
            Grade::D => 1,
            Grade::F => 0,
        }
    }

    /// Parse a grade letter (case-insensitive), used for `--min-grade`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A" => Some(Grade::A),
            "B" => Some(Grade::B),
            "C" => Some(Grade::C),
            "D" => Some(Grade::D),
            "F" => Some(Grade::F),
            _ => None,
        }
    }

    /// True if `self` meets or exceeds the required minimum grade.
    #[must_use]
    pub fn meets(self, minimum: Grade) -> bool {
        self.rank() >= minimum.rank()
    }
}

impl PartialOrd for Grade {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Grade {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

const SECONDS_PER_DAY: i64 = 86_400;
const MAX_REASONABLE_VALIDITY_DAYS: i64 = 398; // CA/Browser Forum baseline cap
const MIN_RSA_KEY_BITS: u32 = 2048;

/// Run every rule against a chain and connection, producing an ordered list
/// of findings (most severe first).
#[must_use]
pub fn analyze(chain: &ChainInfo, conn: &ConnectionInfo, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(leaf) = chain.leaf() {
        findings.extend(check_expiry(leaf, now));
        findings.extend(check_weak_signature(leaf));
        findings.extend(check_weak_key(leaf));
        findings.extend(check_hostname(leaf, &conn.hostname));
        findings.extend(check_self_signed(leaf));
        findings.extend(check_long_validity(leaf));
    }
    findings.extend(check_missing_intermediate(chain));
    findings.extend(check_chain_order(chain));
    findings.extend(check_protocol_version(conn));
    findings.extend(check_cipher_suite(conn));

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

/// Compute the overall grade from a finding set. Any `Critical` finding
/// forces an `F`: a critical issue (expired certificate, hostname
/// mismatch) means the connection is not trustworthy regardless of what
/// else is configured correctly.
#[must_use]
pub fn grade(findings: &[Finding]) -> Grade {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return Grade::F;
    }
    let mut score: i32 = 100;
    for f in findings {
        score -= match f.severity {
            Severity::Critical => 40, // unreachable due to early return above
            Severity::High => 20,
            Severity::Medium => 10,
            Severity::Low => 4,
            Severity::Info => 0,
        };
    }
    let score = score.clamp(0, 100);
    match score {
        90..=100 => Grade::A,
        80..=89 => Grade::B,
        70..=79 => Grade::C,
        60..=69 => Grade::D,
        _ => Grade::F,
    }
}

fn check_expiry(leaf: &crate::cert::CertInfo, now: i64) -> Vec<Finding> {
    let days_remaining = (leaf.not_after - now) / SECONDS_PER_DAY;

    if now > leaf.not_after {
        let days_ago = (now - leaf.not_after) / SECONDS_PER_DAY;
        return vec![Finding {
            id: "EXPIRED",
            severity: Severity::Critical,
            title: "Certificate has expired".to_string(),
            description: format!(
                "The leaf certificate for \"{}\" expired {days_ago} day(s) ago.",
                leaf.subject
            ),
            remediation: "Renew and deploy a new certificate immediately. Clients will reject \
                           this connection.",
        }];
    }

    if days_remaining < 7 {
        return vec![Finding {
            id: "EXPIRING_CRITICAL",
            severity: Severity::High,
            title: "Certificate expires within 7 days".to_string(),
            description: format!(
                "The leaf certificate for \"{}\" expires in {days_remaining} day(s).",
                leaf.subject
            ),
            remediation: "Renew now. If renewal fails or is delayed, the service will start \
                           rejecting connections.",
        }];
    }

    if days_remaining < 30 {
        return vec![Finding {
            id: "EXPIRING_WARNING",
            severity: Severity::Medium,
            title: "Certificate expires within 30 days".to_string(),
            description: format!(
                "The leaf certificate for \"{}\" expires in {days_remaining} day(s).",
                leaf.subject
            ),
            remediation: "Schedule renewal well ahead of the expiry date, ideally via \
                           automated issuance (e.g. ACME).",
        }];
    }

    Vec::new()
}

fn check_weak_signature(leaf: &crate::cert::CertInfo) -> Vec<Finding> {
    if leaf.signature_is_sha1 {
        return vec![Finding {
            id: "WEAK_SIGNATURE_SHA1",
            severity: Severity::High,
            title: "Certificate signed with SHA-1".to_string(),
            description: format!(
                "The leaf certificate uses the signature algorithm \"{}\", which relies on \
                 SHA-1. SHA-1 collisions are practical and modern browsers reject SHA-1 \
                 certificate signatures.",
                leaf.signature_algorithm
            ),
            remediation: "Reissue the certificate with a SHA-256 (or stronger) signature \
                           algorithm.",
        }];
    }
    Vec::new()
}

fn check_weak_key(leaf: &crate::cert::CertInfo) -> Vec<Finding> {
    if leaf.key_algorithm == "RSA" {
        if let Some(bits) = leaf.key_size_bits {
            if bits < MIN_RSA_KEY_BITS {
                return vec![Finding {
                    id: "WEAK_KEY_RSA",
                    severity: Severity::High,
                    title: "RSA key smaller than 2048 bits".to_string(),
                    description: format!(
                        "The leaf certificate uses a {bits}-bit RSA key. Keys below 2048 bits \
                         are considered breakable with modern computing resources."
                    ),
                    remediation: "Reissue the certificate with at least a 2048-bit RSA key, or \
                                   switch to an EC (P-256 or stronger) key.",
                }];
            }
        }
    }
    Vec::new()
}

fn check_hostname(leaf: &crate::cert::CertInfo, hostname: &str) -> Vec<Finding> {
    if hostname_matches(leaf, hostname) {
        return Vec::new();
    }
    vec![Finding {
        id: "HOSTNAME_MISMATCH",
        severity: Severity::Critical,
        title: "Certificate does not cover the requested hostname".to_string(),
        description: format!(
            "\"{hostname}\" is not present in the certificate's subject alternative names \
             ({:?}) or its subject.",
            leaf.sans
        ),
        remediation: "Issue a certificate that includes the hostname in its subject \
                       alternative names, or connect to a hostname the certificate actually \
                       covers.",
    }]
}

/// Case-insensitive hostname match against SANs, supporting a single
/// left-most wildcard label (`*.example.com`).
#[must_use]
pub fn hostname_matches(leaf: &crate::cert::CertInfo, hostname: &str) -> bool {
    let hostname = hostname.to_ascii_lowercase();
    leaf.sans.iter().any(|san| dns_name_matches(san, &hostname))
}

fn dns_name_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    if pattern == hostname {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        if let Some((_, host_rest)) = hostname.split_once('.') {
            return host_rest == rest;
        }
    }
    false
}

fn check_self_signed(leaf: &crate::cert::CertInfo) -> Vec<Finding> {
    if leaf.is_self_signed {
        return vec![Finding {
            id: "SELF_SIGNED",
            severity: Severity::High,
            title: "Leaf certificate is self-signed".to_string(),
            description: format!(
                "The certificate for \"{}\" is self-signed (issuer matches subject). It will \
                 not validate against public trust stores.",
                leaf.subject
            ),
            remediation: "Use a certificate issued by a publicly trusted CA (e.g. via ACME/Let's \
                           Encrypt) for anything reachable by real clients. Self-signed \
                           certificates are appropriate only for internal/dev environments with \
                           the CA pinned out of band.",
        }];
    }
    Vec::new()
}

fn check_long_validity(leaf: &crate::cert::CertInfo) -> Vec<Finding> {
    let validity_days = (leaf.not_after - leaf.not_before) / SECONDS_PER_DAY;
    if validity_days > MAX_REASONABLE_VALIDITY_DAYS {
        return vec![Finding {
            id: "LONG_VALIDITY",
            severity: Severity::Low,
            title: "Certificate validity period exceeds 398 days".to_string(),
            description: format!(
                "This certificate is valid for {validity_days} days, longer than the \
                 CA/Browser Forum baseline maximum of {MAX_REASONABLE_VALIDITY_DAYS} days. \
                 Modern browsers may reject it outright."
            ),
            remediation: "Reissue with a validity period of 398 days or less, and prefer \
                           automated short-lived issuance.",
        }];
    }
    Vec::new()
}

fn check_missing_intermediate(chain: &ChainInfo) -> Vec<Finding> {
    let Some(leaf) = chain.leaf() else {
        return Vec::new();
    };
    if leaf.is_self_signed {
        return Vec::new();
    }
    if chain.certs.len() < 2 {
        return vec![Finding {
            id: "MISSING_INTERMEDIATE",
            severity: Severity::Medium,
            title: "Server did not serve an intermediate certificate".to_string(),
            description: "Only the leaf certificate was presented. This often still works in \
                           browsers that have the intermediate cached or that use AIA fetching, \
                           but fails for many other clients (curl, mobile apps, IoT, older \
                           browsers) that don't."
                .to_string(),
            remediation: "Configure the server to serve its full chain, including all \
                           intermediates, not just the leaf certificate.",
        }];
    }
    Vec::new()
}

fn check_chain_order(chain: &ChainInfo) -> Vec<Finding> {
    if chain.certs.len() < 2 {
        return Vec::new();
    }
    for pair in chain.certs.windows(2) {
        let [current, next] = pair else { continue };
        if current.issuer != next.subject {
            return vec![Finding {
                id: "CHAIN_ORDER",
                severity: Severity::Medium,
                title: "Certificate chain is out of order or broken".to_string(),
                description: format!(
                    "Certificate \"{}\" was issued by \"{}\", but the next certificate served \
                     has subject \"{}\" -- these do not match.",
                    current.subject, current.issuer, next.subject
                ),
                remediation: "Serve the chain in leaf-to-root order, and confirm every \
                               intermediate actually issued the certificate before it.",
            }];
        }
    }
    Vec::new()
}

const DEPRECATED_PROTOCOLS: &[&str] = &["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"];

fn check_protocol_version(conn: &ConnectionInfo) -> Vec<Finding> {
    if DEPRECATED_PROTOCOLS.contains(&conn.protocol_version.as_str()) {
        return vec![Finding {
            id: "DEPRECATED_PROTOCOL",
            severity: Severity::High,
            title: "Deprecated TLS protocol version negotiated".to_string(),
            description: format!(
                "The connection negotiated {}, which is deprecated and disabled by modern \
                 browsers and standards (RFC 8996 deprecates TLS 1.0/1.1).",
                conn.protocol_version
            ),
            remediation: "Disable SSLv3/TLS 1.0/TLS 1.1 on the server. Support TLS 1.2 as a \
                           minimum, TLS 1.3 as the preferred version.",
        }];
    }
    Vec::new()
}

const WEAK_CIPHER_MARKERS: &[&str] = &["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "_CBC_SHA"];

fn check_cipher_suite(conn: &ConnectionInfo) -> Vec<Finding> {
    let upper = conn.cipher_suite.to_ascii_uppercase();
    // "_CBC_SHA" (SHA-1 MAC, no SHA256/384 suffix) flags legacy TLS 1.2 CBC
    // suites while not matching modern AEAD suite names.
    if WEAK_CIPHER_MARKERS
        .iter()
        .any(|marker| upper.contains(marker))
    {
        return vec![Finding {
            id: "WEAK_CIPHER",
            severity: Severity::Medium,
            title: "Negotiated cipher suite is weak or legacy".to_string(),
            description: format!(
                "The connection negotiated cipher suite \"{}\", which is considered weak or \
                 legacy.",
                conn.cipher_suite
            ),
            remediation: "Restrict the server's cipher suite list to modern AEAD suites (e.g. \
                           TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256) and disable \
                           CBC/RC4/3DES/export suites.",
        }];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::cert::CertInfo;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_700_000_000;

    fn healthy_leaf() -> CertInfo {
        CertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Example CA".to_string(),
            sans: vec!["example.com".to_string(), "*.wild.example.com".to_string()],
            not_before: NOW - 30 * DAY,
            not_after: NOW + 200 * DAY,
            serial: "01".to_string(),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            signature_is_sha1: false,
            key_algorithm: "RSA".to_string(),
            key_size_bits: Some(2048),
            is_ca: false,
            is_self_signed: false,
        }
    }

    fn intermediate() -> CertInfo {
        CertInfo {
            subject: "CN=Example CA".to_string(),
            issuer: "CN=Example Root CA".to_string(),
            sans: vec![],
            not_before: NOW - 1000 * DAY,
            not_after: NOW + 1000 * DAY,
            serial: "02".to_string(),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            signature_is_sha1: false,
            key_algorithm: "RSA".to_string(),
            key_size_bits: Some(2048),
            is_ca: true,
            is_self_signed: false,
        }
    }

    fn healthy_conn() -> ConnectionInfo {
        ConnectionInfo {
            hostname: "example.com".to_string(),
            port: 443,
            protocol_version: "TLSv1.3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
        }
    }

    fn has_finding(findings: &[Finding], id: &str) -> bool {
        findings.iter().any(|f| f.id == id)
    }

    #[test]
    fn expired_cert_flagged_critical() {
        let mut leaf = healthy_leaf();
        leaf.not_after = NOW - DAY;
        let findings = check_expiry(&leaf, NOW);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "EXPIRED");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn expiring_within_7_days_flagged_high() {
        let mut leaf = healthy_leaf();
        leaf.not_after = NOW + 3 * DAY;
        let findings = check_expiry(&leaf, NOW);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "EXPIRING_CRITICAL");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn expiring_within_30_days_flagged_medium() {
        let mut leaf = healthy_leaf();
        leaf.not_after = NOW + 20 * DAY;
        let findings = check_expiry(&leaf, NOW);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "EXPIRING_WARNING");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn healthy_expiry_produces_no_finding() {
        let leaf = healthy_leaf();
        assert!(check_expiry(&leaf, NOW).is_empty());
    }

    #[test]
    fn expiry_boundary_31_days_is_clean() {
        let mut leaf = healthy_leaf();
        leaf.not_after = NOW + 31 * DAY;
        assert!(check_expiry(&leaf, NOW).is_empty());
    }

    #[test]
    fn sha1_signature_flagged() {
        let mut leaf = healthy_leaf();
        leaf.signature_is_sha1 = true;
        leaf.signature_algorithm = "sha1WithRSAEncryption".to_string();
        let findings = check_weak_signature(&leaf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "WEAK_SIGNATURE_SHA1");
    }

    #[test]
    fn sha256_signature_not_flagged() {
        let leaf = healthy_leaf();
        assert!(check_weak_signature(&leaf).is_empty());
    }

    #[test]
    fn small_rsa_key_flagged() {
        let mut leaf = healthy_leaf();
        leaf.key_size_bits = Some(1024);
        let findings = check_weak_key(&leaf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "WEAK_KEY_RSA");
    }

    #[test]
    fn rsa_2048_not_flagged() {
        let leaf = healthy_leaf();
        assert!(check_weak_key(&leaf).is_empty());
    }

    #[test]
    fn ec_key_never_flagged_by_rsa_rule() {
        let mut leaf = healthy_leaf();
        leaf.key_algorithm = "EC".to_string();
        leaf.key_size_bits = Some(256);
        assert!(check_weak_key(&leaf).is_empty());
    }

    #[test]
    fn unknown_key_size_not_flagged() {
        let mut leaf = healthy_leaf();
        leaf.key_size_bits = None;
        assert!(check_weak_key(&leaf).is_empty());
    }

    #[test]
    fn exact_hostname_match() {
        let leaf = healthy_leaf();
        assert!(check_hostname(&leaf, "example.com").is_empty());
    }

    #[test]
    fn wildcard_hostname_match() {
        let leaf = healthy_leaf();
        assert!(check_hostname(&leaf, "foo.wild.example.com").is_empty());
    }

    #[test]
    fn wildcard_does_not_match_multiple_labels() {
        let leaf = healthy_leaf();
        let findings = check_hostname(&leaf, "foo.bar.wild.example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "HOSTNAME_MISMATCH");
    }

    #[test]
    fn mismatched_hostname_flagged_critical() {
        let leaf = healthy_leaf();
        let findings = check_hostname(&leaf, "not-example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn hostname_match_is_case_insensitive() {
        let leaf = healthy_leaf();
        assert!(check_hostname(&leaf, "EXAMPLE.COM").is_empty());
    }

    #[test]
    fn self_signed_leaf_flagged() {
        let mut leaf = healthy_leaf();
        leaf.is_self_signed = true;
        let findings = check_self_signed(&leaf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "SELF_SIGNED");
    }

    #[test]
    fn ca_signed_leaf_not_flagged_self_signed() {
        let leaf = healthy_leaf();
        assert!(check_self_signed(&leaf).is_empty());
    }

    #[test]
    fn overlong_validity_flagged() {
        let mut leaf = healthy_leaf();
        leaf.not_before = NOW - 400 * DAY;
        leaf.not_after = NOW + 400 * DAY;
        let findings = check_long_validity(&leaf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "LONG_VALIDITY");
    }

    #[test]
    fn validity_within_398_days_not_flagged() {
        let mut leaf = healthy_leaf();
        leaf.not_before = NOW;
        leaf.not_after = NOW + 398 * DAY;
        assert!(check_long_validity(&leaf).is_empty());
    }

    #[test]
    fn single_cert_chain_flags_missing_intermediate() {
        let chain = ChainInfo {
            certs: vec![healthy_leaf()],
        };
        let findings = check_missing_intermediate(&chain);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "MISSING_INTERMEDIATE");
    }

    #[test]
    fn two_cert_chain_does_not_flag_missing_intermediate() {
        let chain = ChainInfo {
            certs: vec![healthy_leaf(), intermediate()],
        };
        assert!(check_missing_intermediate(&chain).is_empty());
    }

    #[test]
    fn self_signed_single_cert_not_flagged_missing_intermediate() {
        let mut leaf = healthy_leaf();
        leaf.is_self_signed = true;
        let chain = ChainInfo { certs: vec![leaf] };
        assert!(check_missing_intermediate(&chain).is_empty());
    }

    #[test]
    fn well_ordered_chain_not_flagged() {
        let chain = ChainInfo {
            certs: vec![healthy_leaf(), intermediate()],
        };
        assert!(check_chain_order(&chain).is_empty());
    }

    #[test]
    fn broken_chain_order_flagged() {
        let mut wrong_intermediate = intermediate();
        wrong_intermediate.subject = "CN=Unrelated CA".to_string();
        let chain = ChainInfo {
            certs: vec![healthy_leaf(), wrong_intermediate],
        };
        let findings = check_chain_order(&chain);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "CHAIN_ORDER");
    }

    #[test]
    fn single_cert_chain_order_is_clean() {
        let chain = ChainInfo {
            certs: vec![healthy_leaf()],
        };
        assert!(check_chain_order(&chain).is_empty());
    }

    #[test]
    fn tls13_not_flagged() {
        assert!(check_protocol_version(&healthy_conn()).is_empty());
    }

    #[test]
    fn tls12_not_flagged() {
        let mut conn = healthy_conn();
        conn.protocol_version = "TLSv1.2".to_string();
        assert!(check_protocol_version(&conn).is_empty());
    }

    #[test]
    fn tls10_flagged_deprecated() {
        let mut conn = healthy_conn();
        conn.protocol_version = "TLSv1.0".to_string();
        let findings = check_protocol_version(&conn);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "DEPRECATED_PROTOCOL");
    }

    #[test]
    fn sslv3_flagged_deprecated() {
        let mut conn = healthy_conn();
        conn.protocol_version = "SSLv3".to_string();
        assert_eq!(check_protocol_version(&conn).len(), 1);
    }

    #[test]
    fn modern_aead_cipher_not_flagged() {
        assert!(check_cipher_suite(&healthy_conn()).is_empty());
    }

    #[test]
    fn rc4_cipher_flagged() {
        let mut conn = healthy_conn();
        conn.cipher_suite = "TLS_RSA_WITH_RC4_128_SHA".to_string();
        let findings = check_cipher_suite(&conn);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "WEAK_CIPHER");
    }

    #[test]
    fn cbc_sha_cipher_flagged() {
        let mut conn = healthy_conn();
        conn.cipher_suite = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string();
        assert_eq!(check_cipher_suite(&conn).len(), 1);
    }

    #[test]
    fn chacha20_cipher_not_flagged() {
        let mut conn = healthy_conn();
        conn.cipher_suite = "TLS13_CHACHA20_POLY1305_SHA256".to_string();
        assert!(check_cipher_suite(&conn).is_empty());
    }

    #[test]
    fn no_findings_is_grade_a() {
        assert_eq!(grade(&[]), Grade::A);
    }

    #[test]
    fn critical_finding_forces_f() {
        let findings = vec![Finding {
            id: "EXPIRED",
            severity: Severity::Critical,
            title: String::new(),
            description: String::new(),
            remediation: "",
        }];
        assert_eq!(grade(&findings), Grade::F);
    }

    #[test]
    fn single_medium_finding_is_still_a() {
        let findings = vec![Finding {
            id: "X",
            severity: Severity::Medium,
            title: String::new(),
            description: String::new(),
            remediation: "",
        }];
        assert_eq!(grade(&findings), Grade::A);
    }

    #[test]
    fn several_high_findings_drop_below_a() {
        let findings = vec![
            Finding {
                id: "X",
                severity: Severity::High,
                title: String::new(),
                description: String::new(),
                remediation: "",
            },
            Finding {
                id: "Y",
                severity: Severity::High,
                title: String::new(),
                description: String::new(),
                remediation: "",
            },
        ];
        assert_eq!(grade(&findings), Grade::D);
    }

    #[test]
    fn grade_ordering_and_min_grade_gate() {
        assert!(Grade::A.meets(Grade::B));
        assert!(Grade::B.meets(Grade::B));
        assert!(!Grade::C.meets(Grade::B));
        assert!(Grade::A > Grade::F);
    }

    #[test]
    fn grade_parse_accepts_lowercase_and_rejects_garbage() {
        assert_eq!(Grade::parse("b"), Some(Grade::B));
        assert_eq!(Grade::parse("Z"), None);
    }

    #[test]
    fn analyze_healthy_target_has_no_findings() {
        let chain = ChainInfo {
            certs: vec![healthy_leaf(), intermediate()],
        };
        let findings = analyze(&chain, &healthy_conn(), NOW);
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
        assert_eq!(grade(&findings), Grade::A);
    }

    #[test]
    fn analyze_stacks_multiple_problems() {
        let mut leaf = healthy_leaf();
        leaf.not_after = NOW - DAY;
        leaf.key_size_bits = Some(1024);
        let chain = ChainInfo { certs: vec![leaf] };
        let mut conn = healthy_conn();
        conn.protocol_version = "TLSv1.0".to_string();

        let findings = analyze(&chain, &conn, NOW);
        assert!(has_finding(&findings, "EXPIRED"));
        assert!(has_finding(&findings, "WEAK_KEY_RSA"));
        assert!(has_finding(&findings, "MISSING_INTERMEDIATE"));
        assert!(has_finding(&findings, "DEPRECATED_PROTOCOL"));
        assert_eq!(grade(&findings), Grade::F);
    }

    #[test]
    fn findings_sorted_most_severe_first() {
        let mut leaf = healthy_leaf();
        leaf.not_after = NOW + 20 * DAY;
        let chain = ChainInfo { certs: vec![leaf] };
        let mut conn = healthy_conn();
        conn.hostname = "totally-different.com".to_string();

        let findings = analyze(&chain, &conn, NOW);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
