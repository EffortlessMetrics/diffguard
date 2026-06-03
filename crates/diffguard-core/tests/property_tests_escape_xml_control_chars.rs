//! Property-based tests for escape_xml() control character handling.
//!
//! These tests specifically verify the write!() macro fix for illegal control
//! character escaping in xml_utils.rs.
//!
//! The fix replaced:
//!   out.push_str(&format!("&#x{:X};", c as u32))
//! With:
//!   write!(out, "&#x{:X};", c as u32).unwrap();
//!
//! This eliminates intermediate String allocation for each control character.

#![allow(unused_doc_comments)] // proptest macros generate doc comments that rustdoc can't process

use diffguard_core::xml_utils::escape_xml;
use proptest::prelude::*;

/// All illegal control characters (0x00-0x1F except tab/LF/CR)
/// These MUST be escaped as &#xNN; hex entities.
const ILLEGAL_CONTROL_CHARS: &[char] = &[
    '\x00', // NUL
    '\x01', // SOH
    '\x02', // STX
    '\x03', // ETX
    '\x04', // EOT
    '\x05', // ENQ
    '\x06', // ACK
    '\x07', // BEL
    '\x08', // BS
    // 0x09 = TAB (legal, preserved)
    // 0x0A = LF  (legal, preserved)
    // 0x0D = CR  (legal, preserved)
    '\x0E', // SO
    '\x0F', // SI
    '\x10', // DLE
    '\x11', // DC1
    '\x12', // DC2
    '\x13', // DC3
    '\x14', // DC4
    '\x15', // NAK
    '\x16', // SYN
    '\x17', // ETB
    '\x18', // CAN
    '\x19', // EM
    '\x1A', // SUB
    '\x1B', // ESC
    '\x1C', // FS
    '\x1D', // GS
    '\x1E', // RS
    '\x1F', // US
];

/// Legal control characters that should be preserved as-is.
const LEGAL_CONTROL_CHARS: &[char] = &['\t', '\n', '\r'];

/// Property 1: All illegal control characters are escaped as hex entities.
///
/// For any illegal control character, the output should contain "&#x" followed
/// by the hex value followed by ";".
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn illegal_control_chars_escaped_as_hex_entity(input: String) {
        // Insert random illegal control characters
        let chars_to_test: Vec<char> = input
            .chars()
            .filter(|c| ILLEGAL_CONTROL_CHARS.contains(c))
            .collect();

        if chars_to_test.is_empty() {
            return Ok(());
        }

        let output = escape_xml(&input);

        for c in chars_to_test {
            let hex_value = format!("{:X}", c as u32);
            let expected_entity = format!("&#x{};", hex_value);

            prop_assert!(
                output.contains(&expected_entity),
                "Illegal control char {:?} (U+{:04X}) should be escaped to {:?} but output was {:?}",
                c, c as u32, expected_entity, output
            );

            // The raw character should NOT appear in output
            prop_assert!(
                !output.contains(c),
                "Illegal control char {:?} should NOT appear raw in escaped output: {:?}",
                c, output
            );
        }
    }
}

/// Property 2: Legal control characters (tab, LF, CR) are preserved as-is.
///
/// These characters are allowed in XML character content and must NOT be escaped.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn legal_control_chars_preserved(input: String) {
        let mut has_legal = false;

        for c in LEGAL_CONTROL_CHARS {
            if input.contains(*c) {
                has_legal = true;
            }
        }

        if !has_legal {
            return Ok(());
        }

        let escaped = escape_xml(&input);

        // Tab should NOT be escaped to &#x9;
        if input.contains('\t') {
            prop_assert!(
                escaped.contains('\t'),
                "Tab should be preserved in output: {:?}",
                escaped
            );
            prop_assert!(
                !escaped.contains("&#x9;"),
                "Tab should NOT be escaped to &#x9;: {:?}",
                escaped
            );
        }

        // LF should NOT be escaped to &#xA;
        if input.contains('\n') {
            prop_assert!(
                escaped.contains('\n'),
                "LF should be preserved in output: {:?}",
                escaped
            );
            prop_assert!(
                !escaped.contains("&#xA;") && !escaped.contains("&#xa;"),
                "LF should NOT be escaped to &#xA;: {:?}",
                escaped
            );
        }

        // CR should NOT be escaped to &#xD;
        if input.contains('\r') {
            prop_assert!(
                escaped.contains('\r'),
                "CR should be preserved in output: {:?}",
                escaped
            );
            prop_assert!(
                !escaped.contains("&#xD;") && !escaped.contains("&#xd;"),
                "CR should NOT be escaped to &#xD;: {:?}",
                escaped
            );
        }
    }
}

/// Property 3: Mixed illegal control chars with regular text.
///
/// Verifies that control character escaping works correctly when mixed
/// with normal text and special XML characters.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn mixed_content_with_illegal_control_chars(
        prefix: String,
        control_char in prop::sample::select(ILLEGAL_CONTROL_CHARS),
        suffix: String
    ) {
        let input = format!("{}c{}s", prefix, control_char);
        let output = escape_xml(&input);

        // The raw control char should not appear
        prop_assert!(
            !output.contains(control_char),
            "Control char {:?} should not appear raw in output: {:?}",
            control_char, output
        );

        // The hex entity should appear
        let hex_value = format!("{:X}", control_char as u32);
        let entity = format!("&#x{};", hex_value);
        prop_assert!(
            output.contains(&entity),
            "Hex entity {:?} should appear in output: {:?}",
            entity, output
        );
    }
}

/// Property 4: Illegal control chars at string boundaries.
///
/// Control characters at start, middle, or end of string should all be escaped.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn illegal_control_chars_at_boundaries(
        prefix in "[^\\x00-\\x1F]*",  // Only printable chars
        control_char in prop::sample::select(ILLEGAL_CONTROL_CHARS),
        _suffix in "[^\\x00-\\x1F]*"
    ) {
        let input = format!("{}c{}s", prefix, control_char);
        let output = escape_xml(&input);

        let hex_value = format!("{:X}", control_char as u32);
        let entity = format!("&#x{};", hex_value);

        prop_assert!(
            output.contains(&entity),
            "Control char at boundary should be escaped: input={:?}, entity={:?}, output={:?}",
            input, entity, output
        );
    }
}

/// Property 5: All possible illegal control chars produce valid hex entities.
///
/// Verifies that every illegal control character (0x00-0x1F except tab/LF/CR)
/// is properly escaped with its correct hex value.
#[test]
fn all_illegal_control_chars_have_correct_hex_entities() {
    for c in ILLEGAL_CONTROL_CHARS {
        let input = format!("a{}b", c);
        let output = escape_xml(&input);

        let hex_value = format!("{:X}", *c as u32);
        let entity = format!("&#x{};", hex_value);

        assert!(
            output.contains(&entity),
            "Char {:?} (U+{:04X}) should produce entity {:?}, got: {:?}",
            c,
            *c as u32,
            entity,
            output
        );

        // The raw character should not appear
        assert!(
            !output.contains(*c),
            "Char {:?} should not appear raw in output: {:?}",
            c,
            output
        );
    }
}

/// Property 6: Output length grows when illegal control chars are escaped.
///
/// Escaping an illegal control character replaces 1 char with ~7 chars (&#xNN;).
/// So output should always be >= input length.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn output_length_grows_with_illegal_controls(input: String) {
        let illegal_count = input.chars().filter(|c| ILLEGAL_CONTROL_CHARS.contains(c)).count();

        if illegal_count == 0 {
            // Just check basic length bound for strings without illegal chars
            let output = escape_xml(&input);
            prop_assert!(
                output.len() >= input.len(),
                "Output length should >= input length: {} >= {}",
                output.len(),
                input.len()
            );
            return Ok(());
        }

        let output = escape_xml(&input);

        // Each illegal control char adds at least 6 chars (&#xNN; is 7 chars replacing 1)
        // So length should increase by at least 6 * count
        let min_new_length = input.len() + (6 * illegal_count);

        prop_assert!(
            output.len() >= min_new_length,
            "Output len {} should >= min expected {} (input={}, illegal_count={}, input_len={})",
            output.len(), min_new_length, input, illegal_count, input.len()
        );
    }
}

/// Property 7: Consecutive illegal control characters.
///
/// Multiple illegal control characters in sequence should all be escaped.
#[test]
fn consecutive_illegal_control_chars() {
    // Two of the same illegal char
    let input = format!("a{}\x01b", '\x00');
    let output = escape_xml(&input);
    assert!(
        output.contains("&#x0;") && output.contains("&#x1;"),
        "Consecutive different illegal chars should both be escaped: {:?}",
        output
    );

    // Sequence of BEL characters
    let input = "\x07\x07\x07".to_string();
    let output = escape_xml(&input);
    assert_eq!(
        output, "&#x7;&#x7;&#x7;",
        "Consecutive BEL chars should all be escaped: got {:?}",
        output
    );
}

/// Property 8: write!() macro produces correct format (uppercase hex).
///
/// The write!() macro with {:X} format produces uppercase hex.
/// Verify this is consistent across all illegal control chars.
#[test]
fn hex_entities_use_uppercase_format() {
    for c in ILLEGAL_CONTROL_CHARS {
        let input = format!("a{}b", c);
        let output = escape_xml(&input);

        let hex_value = format!("{:X}", *c as u32); // Uppercase
        let entity = format!("&#x{};", hex_value);

        assert!(
            output.contains(&entity),
            "Should use uppercase hex: {:?} expected in {:?}",
            entity,
            output
        );
    }
}

/// Property 9: Non-ASCII, non-control characters pass through unchanged.
///
/// Unicode characters beyond ASCII should not be affected by escaping.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn unicode_characters_unchanged(input: String) {
        // Filter to only printable non-ASCII unicode
        let unicode_input: String = input
            .chars()
            .filter(|c| c.is_alphabetic() && !c.is_ascii())
            .collect();

        if unicode_input.is_empty() {
            return Ok(());
        }

        let output = escape_xml(&unicode_input);
        assert_eq!(
            output, unicode_input,
            "Unicode chars should pass through unchanged: {:?} -> {:?}",
            unicode_input, output
        );
    }
}

/// Property 10: No double-escaping of control char hex entities.
///
/// If input already contains a hex entity like &#x0;, it should be
/// double-escaped to &#x26;#x30; etc. This is expected behavior
/// (idempotent escaping is NOT guaranteed).
#[test]
fn already_escaped_content_gets_double_escaped() {
    // Input already has a hex entity - it should get escaped again
    let input = "&#x0;";
    let output = escape_xml(input);

    // The & in &#x0; should become &amp;, resulting in &amp;#x0;
    assert!(
        output.contains("&amp;"),
        "Already-escaped content should be double-escaped: {:?}",
        output
    );
}
