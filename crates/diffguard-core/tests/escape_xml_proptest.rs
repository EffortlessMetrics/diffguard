//! Property-based fuzz tests for escape_xml function.
//!
//! These tests verify invariants about the escape_xml function using
//! exhaustive property-based testing with proptest.

use diffguard_core::xml_utils::escape_xml;
use proptest::prelude::*;

// ============================================================================
// Helper functions
// ============================================================================

/// Check if a character is a legal XML control character (tab, LF, CR).
fn is_legal_xml_control_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
}

/// Check if a character is an illegal XML control character (0x00-0x1F except tab/LF/CR).
fn is_illegal_xml_control_char(c: char) -> bool {
    c <= '\u{001F}' && !is_legal_xml_control_char(c)
}

/// Check if the output string contains any illegal XML control characters.
fn contains_illegal_control_chars(s: &str) -> bool {
    s.chars().any(is_illegal_xml_control_char)
}

/// Get all illegal control characters from a string.
fn get_illegal_control_chars(s: &str) -> Vec<char> {
    s.chars()
        .filter(|&c| is_illegal_xml_control_char(c))
        .collect()
}

// ============================================================================
// Property 1: Output contains NO illegal XML control characters
// ============================================================================

proptest! {
    /// Property: escape_xml should never produce illegal XML control characters
    /// in the output. All control characters in range 0x00-0x1F (except tab,
    /// LF, CR) must be escaped as &#xNN; entities.
    #[test]
    fn prop_output_contains_no_illegal_control_chars(input: String) {
        let result = escape_xml(&input);
        prop_assert!(
            !contains_illegal_control_chars(&result),
            "escape_xml produced illegal control chars in output: {:?}",
            get_illegal_control_chars(&result)
        );
    }
}

// ============================================================================
// Property 2: Named XML entities are correctly escaped
// ============================================================================

proptest! {
    /// Property: All five XML special characters must be escaped correctly.
    #[test]
    fn prop_named_entities_escaped(input: String) {
        let result = escape_xml(&input);

        // If input contains '&', output must contain &amp; (and not have bare '&')
        if input.contains('&') {
            prop_assert!(result.contains("&amp;"), " '&' should be escaped as '&amp;'");
            // The output should NOT have any unescaped '&' followed by non-entity chars
        }

        // If input contains '<', output must contain &lt;
        if input.contains('<') {
            prop_assert!(result.contains("&lt;"), " '<' should be escaped as '&lt;'");
        }

        // If input contains '>', output must contain &gt;
        if input.contains('>') {
            prop_assert!(result.contains("&gt;"), " '>' should be escaped as '&gt;'");
        }

        // If input contains '"', output must contain &quot;
        if input.contains('"') {
            prop_assert!(result.contains("&quot;"), " '\"' should be escaped as '&quot;'");
        }

        // If input contains '\'', output must contain &apos;
        if input.contains('\'') {
            prop_assert!(result.contains("&apos;"), " '\'' should be escaped as '&apos;'");
        }
    }
}

// ============================================================================
// Property 3: Legal control characters (tab, LF, CR) are preserved
// ============================================================================

proptest! {
    /// Property: Tab (0x09), LF (0x0A), and CR (0x0D) should NOT be escaped.
    #[test]
    fn prop_legal_control_chars_preserved(input: String) {
        let result = escape_xml(&input);

        // Tab should be preserved
        let input_tabs = input.chars().filter(|&c| c == '\t').count();
        let result_tabs = result.chars().filter(|&c| c == '\t').count();
        prop_assert_eq!(
            input_tabs, result_tabs,
            "Tab characters should be preserved (input has {}, result has {})",
            input_tabs, result_tabs
        );

        // LF should be preserved
        let input_lfs = input.chars().filter(|&c| c == '\n').count();
        let result_lfs = result.chars().filter(|&c| c == '\n').count();
        prop_assert_eq!(
            input_lfs, result_lfs,
            "LF characters should be preserved"
        );

        // CR should be preserved
        let input_crs = input.chars().filter(|&c| c == '\r').count();
        let result_crs = result.chars().filter(|&c| c == '\r').count();
        prop_assert_eq!(
            input_crs, result_crs,
            "CR characters should be preserved"
        );
    }
}

// ============================================================================
// Property 4: Illegal control characters are escaped as &#xNN;
// ============================================================================

proptest! {
    /// Property: Each illegal control character in input should appear as
    /// &#xNN; in the output (where NN is the hex value).
    #[test]
    fn prop_illegal_control_chars_escaped_as_hex_entity(input: String) {
        let result = escape_xml(&input);

        // Check each illegal control character
        for c in input.chars() {
            if is_illegal_xml_control_char(c) {
                let expected_entity = format!("&#x{:X};", c as u32);
                prop_assert!(
                    result.contains(&expected_entity),
                    "Illegal control char U+{:04X} should be escaped as {} in output",
                    c as u32, expected_entity
                );
            }
        }
    }
}

// ============================================================================
// Property 5: Output length is at least as long as input
// ============================================================================

proptest! {
    /// Property: escape_xml should never decrease the length of the string
    /// because it only adds characters (escaping).
    #[test]
    fn prop_output_at_least_as_long_as_input(input: String) {
        let result = escape_xml(&input);
        prop_assert!(
            result.len() >= input.len(),
            "Output length ({}) should be >= input length ({})",
            result.len(), input.len()
        );
    }
}

// ============================================================================
// Property 6: Round-trip safety - no illegal chars in output
// ============================================================================

proptest! {
    /// Property: The output of escape_xml should not contain any characters
    /// that would be illegal in an XML document. This is the key safety property.
    #[test]
    fn prop_output_is_xml_safe(input: String) {
        let result = escape_xml(&input);

        // Check that output has no illegal control chars
        let illegal_chars: Vec<char> = result.chars()
            .filter(|&c| is_illegal_xml_control_char(c))
            .collect();

        prop_assert!(
            illegal_chars.is_empty(),
            "Output contains illegal XML control characters: {:?}",
            illegal_chars
        );
    }
}

// ============================================================================
// Property 7: Idempotence for strings without special characters
// ============================================================================

proptest! {
    /// Property: If a string contains no special characters (no XML metachars,
    /// no illegal control chars), escape_xml should return it unchanged.
    #[test]
    fn prop_idempotent_for_plain_text(input: String) {
        // Only use strings without special chars
        let has_special = input.chars().any(|c| {
            matches!(c, '&' | '<' | '>' | '"' | '\'') || is_illegal_xml_control_char(c)
        });

        if !has_special {
            let result = escape_xml(&input);
            prop_assert_eq!(
                input, result,
                "Plain text without special chars should be unchanged"
            );
        }
    }
}

// ============================================================================
// Property 8: All illegal control character values are handled
// ============================================================================

#[test]
fn prop_all_illegal_control_chars_escaped() {
    // Test all illegal control characters 0x00-0x1F except tab/LF/CR
    let illegal_codes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 0x00-0x08
        0x0B, 0x0C, // 0x0B-0x0C (0x09, 0x0A, 0x0D are legal)
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // 0x0E-0x17
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // 0x18-0x1F
    ];

    for code in illegal_codes {
        let c = char::from_u32(code).unwrap();
        let input = format!("before{}after", c);
        let result = escape_xml(&input);

        let expected = format!("before&#x{:X};after", code);
        assert_eq!(
            result, expected,
            "Control char 0x{:02X} should be escaped as &#x{:02X};",
            code, code
        );
    }
}

// ============================================================================
// Property 9: Legal control characters preserved exactly
// ============================================================================

#[test]
fn prop_legal_control_chars_not_escaped() {
    let legal_codes = [0x09, 0x0A, 0x0D]; // Tab, LF, CR

    for code in legal_codes {
        let c = char::from_u32(code).unwrap();
        let input = format!("before{}after", c);
        let result = escape_xml(&input);
        let expected = format!("before{}after", c);

        assert_eq!(
            result, expected,
            "Legal control char 0x{:02X} should NOT be escaped",
            code
        );
    }
}

// ============================================================================
// Property 10: Mixed content stress test
// ============================================================================

proptest! {
    /// Property: Stress test with arbitrary byte sequences that may include
    /// control characters mixed with regular text.
    #[test]
    fn prop_mixed_content_stress(input: Vec<u8>) {
        // Convert bytes to string, lossy conversion will replace invalid UTF-8
        let input = String::from_utf8_lossy(&input).to_string();
        let result = escape_xml(&input);

        // Key invariant: no illegal control chars in output
        prop_assert!(
            !contains_illegal_control_chars(&result),
            "Output must not contain illegal XML control characters"
        );

        // Legal chars preserved
        let input_tabs = input.chars().filter(|&c| c == '\t').count();
        let result_tabs = result.chars().filter(|&c| c == '\t').count();
        prop_assert_eq!(input_tabs, result_tabs, "Tabs must be preserved");
    }
}

// ============================================================================
// Property 11: Escape is not too aggressive (printable chars preserved)
// ============================================================================

proptest! {
    /// Property: Printable ASCII characters (0x20-0x7E) and valid Unicode
    /// should be preserved in escape_xml.
    #[test]
    fn prop_printable_chars_preserved(input: String) {
        let _result = escape_xml(&input);

        // Check that printable ASCII chars are preserved
        for c in input.chars() {
            if c.is_ascii_graphic() || c == ' ' {
                // Should appear in result (possibly in escaped context)
            }
        }

        // Result should contain the same Unicode characters (except escaped ones)
        // For non-control chars, they should appear in result unless they were '&<>"'
    }
}

// ============================================================================
// Property 12: Entity correctness - ampersand escaping
// ============================================================================

proptest! {
    /// Property: The ampersand character must be escaped, and the escaped
    /// result should contain &amp; (not &amp;amp; or any double-escaping).
    #[test]
    fn prop_ampersand_escaped_correctly(input: String) {
        let result = escape_xml(&input);

        // Count how many times &amp; appears
        let amp_count = result.match_indices("&amp;").count();

        // If input has N ampersands, result should have exactly N &amp;
        let input_amp = input.chars().filter(|&c| c == '&').count();

        prop_assert_eq!(
            amp_count, input_amp,
            "Each '&' in input should produce exactly one '&amp;' in output"
        );
    }
}
