//! Stable fingerprint computation for findings.
//!
//! Fingerprints provide a stable identifier for findings across runs,
//! enabling deduplication and tracking.

use diffguard_types::Finding;
use sha2::{Digest, Sha256};

/// Computes a stable fingerprint for a finding.
///
/// The fingerprint is a SHA-256 hash of `rule_id:path:line:match_text`,
/// truncated to 16 hex characters (8 bytes).
pub fn compute_fingerprint(f: &Finding) -> String {
    let input = format!("{}:{}:{}:{}", f.rule_id, f.path, f.line, f.match_text);
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::Severity;

    fn test_finding() -> Finding {
        Finding {
            rule_id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "Avoid unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            column: Some(10),
            match_text: ".unwrap()".to_string(),
            snippet: "let x = foo.unwrap();".to_string(),
        }
    }

    #[test]
    fn fingerprint_is_16_hex_chars() {
        let f = test_finding();
        let fp = compute_fingerprint(&f);
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_stable() {
        let f = test_finding();
        let fp1 = compute_fingerprint(&f);
        let fp2 = compute_fingerprint(&f);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_differs_for_different_rule_id() {
        let f1 = test_finding();
        let mut f2 = test_finding();
        f2.rule_id = "rust.no_dbg".to_string();

        assert_ne!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn fingerprint_differs_for_different_path() {
        let f1 = test_finding();
        let mut f2 = test_finding();
        f2.path = "src/main.rs".to_string();

        assert_ne!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn fingerprint_differs_for_different_line() {
        let f1 = test_finding();
        let mut f2 = test_finding();
        f2.line = 100;

        assert_ne!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn fingerprint_differs_for_different_match_text() {
        let f1 = test_finding();
        let mut f2 = test_finding();
        f2.match_text = ".expect()".to_string();

        assert_ne!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn fingerprint_ignores_severity() {
        let f1 = test_finding();
        let mut f2 = test_finding();
        f2.severity = Severity::Warn;

        // Severity is not part of the fingerprint
        assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn fingerprint_ignores_message() {
        let f1 = test_finding();
        let mut f2 = test_finding();
        f2.message = "Different message".to_string();

        // Message is not part of the fingerprint
        assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn snapshot_fingerprint_value() {
        let f = test_finding();
        let fp = compute_fingerprint(&f);
        // This ensures the fingerprint algorithm doesn't change unexpectedly
        insta::assert_snapshot!(fp, @"d559ee3767f8ccda");
    }
}
