//! CLI entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use tlsprobe::analysis::Grade;
use tlsprobe::fetch;
use tlsprobe::report::Report;

/// Audit a TLS endpoint's certificate chain, expiry, and protocol/cipher
/// configuration, with plain-language findings and remediation.
#[derive(Parser, Debug)]
#[command(name = "tlsprobe", version, about)]
struct Cli {
    /// One or more targets to probe, as `host` or `host:port`.
    #[arg(required = true)]
    targets: Vec<String>,

    /// Default port to use for targets that don't specify one.
    #[arg(long, default_value_t = 443)]
    port: u16,

    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Emit machine-readable JSON instead of a text report.
    #[arg(long)]
    json: bool,

    /// Fail (nonzero exit) if any target's grade is below this letter
    /// (A/B/C/D/F). Useful as a CI gate.
    #[arg(long, value_name = "GRADE")]
    min_grade: Option<String>,
}

fn parse_target(raw: &str, default_port: u16) -> (String, u16) {
    // IPv6 literals: `[::1]:8443`, `[::1]`, or a bare `::1` (no port possible
    // without brackets, since the address itself contains colons).
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }
    if raw.parse::<std::net::Ipv6Addr>().is_ok() {
        return (raw.to_string(), default_port);
    }
    if let Some((host, port_str)) = raw.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (raw.to_string(), default_port)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let min_grade = match cli.min_grade.as_deref().map(Grade::parse) {
        Some(Some(g)) => Some(g),
        Some(None) => {
            eprintln!(
                "error: invalid --min-grade value {:?} (expected one of A, B, C, D, F)",
                cli.min_grade.unwrap_or_default()
            );
            return ExitCode::FAILURE;
        }
        None => None,
    };

    let timeout = Duration::from_secs(cli.timeout);
    let mut had_failure = false;
    let mut reports = Vec::new();

    for target in &cli.targets {
        let (host, port) = parse_target(target, cli.port);
        match fetch::probe(&host, port, timeout) {
            Ok((chain, conn)) => {
                let report = Report::new(target.clone(), chain, conn);
                if let Some(min) = min_grade {
                    if !report.grade.meets(min) {
                        had_failure = true;
                    }
                }
                reports.push(report);
            }
            Err(e) => {
                had_failure = true;
                if cli.json {
                    // serde_json escapes quotes in the message (e.g. an
                    // invalid hostname is reported in quotes).
                    eprintln!(
                        "{}",
                        serde_json::json!({ "target": target, "error": e.to_string() })
                    );
                } else {
                    eprintln!("== {target} ==\nERROR: {e}\n");
                }
            }
        }
    }

    if cli.json {
        let json_reports: Vec<_> = reports.iter().collect();
        match serde_json::to_string_pretty(&json_reports) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("error: failed to serialize report: {e}"),
        }
    } else {
        for report in &reports {
            println!("{}", report.to_text());
        }
    }

    if had_failure {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn parse_target_with_port() {
        assert_eq!(
            parse_target("example.com:8443", 443),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn parse_target_without_port_uses_default() {
        assert_eq!(
            parse_target("example.com", 443),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn parse_target_ipv6_forms() {
        // Regression: "::1" was split into host ":" and port 1.
        assert_eq!(parse_target("::1", 443), ("::1".to_string(), 443));
        assert_eq!(parse_target("[::1]:8443", 443), ("::1".to_string(), 8443));
        assert_eq!(parse_target("[::1]", 443), ("::1".to_string(), 443));
    }

    #[test]
    fn parse_target_invalid_port_falls_back_to_default() {
        assert_eq!(
            parse_target("example.com:notaport", 443),
            ("example.com:notaport".to_string(), 443)
        );
    }
}
