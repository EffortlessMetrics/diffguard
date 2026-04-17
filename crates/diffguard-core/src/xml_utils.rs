//! XML utility functions for diffguard output formatters.
//!
//! Provides shared XML escaping functionality used by JUnit, Checkstyle,
//! and other XML-based output formats.

use std::fmt::Write;

/// Escapes special XML characters and illegal control characters in a string.
///
/// Handles:
/// - 5 named XML entities: `&`, `<`, `>`, `"`, `'`
/// - Illegal control characters (0x00-0x1F except tab/LF/CR) as `&#xNN;` entities
///
/// Legal control characters (tab=0x09, LF=0x0A, CR=0x0D) are preserved as-is
/// since they are allowed in XML character content.
pub fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Illegal XML control characters (0x00-0x1F except tab/LF/CR)
            c if c <= '\u{001F}' && c != '\t' && c != '\n' && c != '\r' => {
                // write! to a String can only fail on system errors (OOM, signal) —
                // not logic errors — so unwrap is safe and appropriate here.
                write!(out, "&#x{:X};", c as u32).unwrap();
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_xml_handles_all_special_chars() {
        assert_eq!(escape_xml("&"), "&amp;");
        assert_eq!(escape_xml("<"), "&lt;");
        assert_eq!(escape_xml(">"), "&gt;");
        assert_eq!(escape_xml("\""), "&quot;");
        assert_eq!(escape_xml("'"), "&apos;");
        assert_eq!(escape_xml("normal text"), "normal text");
        assert_eq!(escape_xml("<a & b>"), "&lt;a &amp; b&gt;");
    }

    #[test]
    fn escape_xml_escapes_illegal_control_chars() {
        // NUL
        let result = escape_xml("a\x00b");
        assert!(result.contains("&#x0;"));
        assert!(!result.contains('\x00'));

        // BEL (0x07)
        let result = escape_xml("a\x07b");
        assert!(result.contains("&#x7;"));

        // ESC (0x1B)
        let result = escape_xml("a\x1Bb");
        assert!(result.contains("&#x1B;"));
    }

    #[test]
    fn escape_xml_preserves_legal_control_chars() {
        // Tab
        let result = escape_xml("a\tb");
        assert!(result.contains('\t'));
        assert!(!result.contains("&#x9;"));

        // LF
        let result = escape_xml("a\nb");
        assert!(result.contains('\n'));
        assert!(!result.contains("&#xA;"));

        // CR
        let result = escape_xml("a\rb");
        assert!(result.contains('\r'));
        assert!(!result.contains("&#xD;"));
    }

    #[test]
    fn escape_xml_empty_string() {
        assert_eq!(escape_xml(""), "");
    }
}
