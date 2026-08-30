//! Human-readable and JSON report rendering.

use serde::Serialize;
use std::fmt::Write as _;

use crate::analysis::{Finding, Grade, Severity};
use crate::cert::{ChainInfo, ConnectionInfo};

/// The complete audit result for one target, ready to render.
#[derive(Debug, Serialize)]
pub struct Report {
    pub target: String,
    pub connection: ConnectionInfo,
    pub chain: ChainInfo,
    pub findings: Vec<Finding>,
    pub grade: Grade,
}

impl Serialize for Grade {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl Report {
    #[must_use]
    pub fn new(target: String, chain: ChainInfo, connection: ConnectionInfo) -> Self {
        let now = crate::now_unix();
        let findings = crate::analysis::analyze(&chain, &connection, now);
        let grade = crate::analysis::grade(&findings);
        Self {
            target,
            connection,
            chain,
            findings,
            grade,
        }
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "== {} ({}:{}) ==",
            self.target, self.connection.hostname, self.connection.port
        );
        let _ = writeln!(
            out,
            "Protocol: {}   Cipher: {}",
            self.connection.protocol_version, self.connection.cipher_suite
        );
        let _ = writeln!(out, "Grade: {}", self.grade.as_str());
        let _ = writeln!(out, "Chain length: {}", self.chain.certs.len());

        if let Some(leaf) = self.chain.leaf() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Leaf certificate:");
            let _ = writeln!(out, "  Subject:   {}", leaf.subject);
            let _ = writeln!(out, "  Issuer:    {}", leaf.issuer);
            let _ = writeln!(out, "  SANs:      {}", leaf.sans.join(", "));
            let _ = writeln!(out, "  Serial:    {}", leaf.serial);
            let _ = writeln!(
                out,
                "  Key:       {} {}",
                leaf.key_algorithm,
                leaf.key_size_bits
                    .map_or_else(|| "?".to_string(), |b| format!("{b} bits"))
            );
            let _ = writeln!(out, "  Signature: {}", leaf.signature_algorithm);
            let _ = writeln!(
                out,
                "  Validity:  {} -> {}",
                format_timestamp(leaf.not_before),
                format_timestamp(leaf.not_after)
            );
        }

        let _ = writeln!(out);
        if self.findings.is_empty() {
            let _ = writeln!(out, "Findings: none");
        } else {
            let _ = writeln!(out, "Findings ({}):", self.findings.len());
            for f in &self.findings {
                let _ = writeln!(
                    out,
                    "  [{}] {} -- {}",
                    severity_label(f.severity),
                    f.id,
                    f.title
                );
                let _ = writeln!(out, "      {}", f.description);
                let _ = writeln!(out, "      Fix: {}", f.remediation);
            }
        }
        out
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Render a Unix timestamp as an ISO-8601-ish UTC date, without pulling in
/// a chrono dependency for one formatting call.
fn format_timestamp(ts: i64) -> String {
    const SECS_PER_DAY: i64 = 86_400;
    let days_since_epoch = ts.div_euclid(SECS_PER_DAY);
    let secs_of_day = ts.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days_since_epoch);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days` algorithm, converting a day count
/// since 1970-01-01 into a (year, month, day) civil calendar date. Kept in
/// `i64` throughout (rather than the canonical `u64` intermediates) so no
/// signed/unsigned cast can lose information.
#[allow(clippy::many_single_char_names)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    let d = u32::try_from(d).unwrap_or(1);
    let m = u32::try_from(m).unwrap_or(1);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn format_timestamp_epoch() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_known_date() {
        // 2024-01-01T00:00:00Z
        assert_eq!(format_timestamp(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_leap_day() {
        // 2024-02-29T12:00:00Z
        assert_eq!(format_timestamp(1_709_208_000), "2024-02-29T12:00:00Z");
    }
}
