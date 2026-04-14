//! Tests for xml_utils.rs control character escaping
//!
//! These tests verify that escape_xml produces correctly formatted hex escapes
//! for illegal control characters in the &#x{HEX}; format.
//!
//! The tests focus on verifying exact output format to catch any regression
//! in the escaping logic.

use diffguard_core::xml_utils::escape_xml;

/// Verifies that illegal control characters are escaped with the correct
/// uppercase hexadecimal format: `&#x{HEX};`
///
/// Each illegal control character (0x00-0x1F except tab/LF/CR) should produce
/// exactly one escape sequence in the format &#x{NN}; where NN is the
/// uppercase hexadecimal representation.
#[test]
fn escape_xml_control_char_uses_uppercase_hex_format() {
    // NUL character (0x00) should be &#x0; (uppercase X and hex digits)
    let result = escape_xml("\x00");
    assert_eq!(
        result, "&#x0;",
        "NUL should be escaped as &#x0; with uppercase hex"
    );

    // BEL character (0x07) should be &#x7;
    let result = escape_xml("\x07");
    assert_eq!(
        result, "&#x7;",
        "BEL should be escaped as &#x7; with uppercase hex"
    );

    // ESC character (0x1B) should be &#x1B;
    let result = escape_xml("\x1B");
    assert_eq!(
        result, "&#x1B;",
        "ESC should be escaped as &#x1B; with uppercase hex"
    );
}

/// Verifies all illegal control characters (0x00-0x1F except tab/LF/CR)
/// are correctly escaped in uppercase hexadecimal format.
#[test]
fn escape_xml_all_illegal_control_chars_correct_format() {
    // Characters that should be escaped: 0x00-0x1F except tab(0x09), LF(0x0A), CR(0x0D)
    let illegal_chars: Vec<char> = (0x00u32..=0x1Fu32)
        .filter(|&c| c != 0x09 && c != 0x0A && c != 0x0D)
        .map(|c| char::from_u32(c).unwrap())
        .collect();

    for c in illegal_chars {
        let input = format!("a{}b", c);
        let result = escape_xml(&input);
        let hex_str = format!("&#x{:X};", c as u32);
        assert!(
            result.contains(&hex_str),
            "Character U+{:04X} should be escaped as {} but got: {}",
            c as u32,
            hex_str,
            result
        );
        // Verify no original character remains
        assert!(
            !result.contains(c),
            "Character U+{:04X} should not appear unescaped in output: {}",
            c as u32,
            result
        );
    }
}

/// Verifies that control characters are NOT double-escaped or mangled.
#[test]
fn escape_xml_control_char_no_mangling() {
    // Multiple consecutive illegal control chars
    let input = "\x00\x01\x02";
    let result = escape_xml(input);
    assert_eq!(
        result, "&#x0;&#x1;&#x2;",
        "Consecutive control chars should each be escaped individually"
    );

    // Control chars mixed with safe chars
    let input = "a\x00b\x01c";
    let result = escape_xml(input);
    assert_eq!(
        result, "a&#x0;b&#x1;c",
        "Control chars surrounded by safe chars should be isolated"
    );

    // Illegal single-digit hex chars (0x00-0x0F except tab 0x09, LF 0x0A, CR 0x0D)
    // These should produce exactly 5 chars each: &#xN;
    let single_digit_illegal: [u32; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F,
    ];
    for code in single_digit_illegal {
        let c = char::from_u32(code).unwrap();
        let result = escape_xml(&c.to_string());
        let expected = format!("&#x{:X};", code);
        assert_eq!(
            result, expected,
            "U+{:04X} should be {:?}, got {:?}",
            code, expected, result
        );
        assert_eq!(
            result.len(),
            5,
            "Escape for U+{:04X} should be 5 chars, got: {:?}",
            code,
            result
        );
    }

    // Illegal double-digit hex chars (0x10-0x1F)
    // These should produce exactly 6 chars each: &#xNN;
    for code in 0x10u32..=0x1Fu32 {
        let c = char::from_u32(code).unwrap();
        let result = escape_xml(&c.to_string());
        let expected = format!("&#x{:X};", code);
        assert_eq!(
            result, expected,
            "U+{:04X} should be {:?}, got {:?}",
            code, expected, result
        );
        assert_eq!(
            result.len(),
            6,
            "Escape for U+{:04X} should be 6 chars, got: {:?}",
            code,
            result
        );
    }
}

/// Verifies the exact position and surrounding context of escaped control chars.
#[test]
fn escape_xml_control_char_exact_position_preserved() {
    // Control char at start
    let result = escape_xml("\x00abc");
    assert_eq!(
        result, "&#x0;abc",
        "Control char at start should be at position 0"
    );

    // Control char at end
    let result = escape_xml("abc\x00");
    assert_eq!(result, "abc&#x0;", "Control char at end should be last");

    // Control char in middle
    let result = escape_xml("ab\x00cd");
    assert_eq!(
        result, "ab&#x0;cd",
        "Control char in middle should not affect surrounding chars"
    );
}

/// Regression test: ensure control character escapes don't interfere with
/// special XML char escaping (&, <, >, ", ').
#[test]
fn escape_xml_control_and_special_chars_together() {
    // Mix of control chars and special XML chars
    let input = "&<\x00>";
    let result = escape_xml(input);
    assert_eq!(
        result, "&amp;&lt;&#x0;&gt;",
        "Both special chars and control chars should be escaped"
    );

    let input = "\x00&amp;\x01";
    let result = escape_xml(input);
    // Note: &amp; gets double-escaped since escape_xml is not idempotent
    assert_eq!(
        result, "&#x0;&amp;amp;&#x1;",
        "&amp; in input gets double-escaped"
    );
}

/// Verifies output length is correct when escaping control characters.
#[test]
fn escape_xml_control_char_correct_output_length() {
    // Single digit hex (0x00-0x0F, except tab): each illegal control char (1 char) becomes &#xN; (5 chars)
    let input = "\x00\x01";
    let result = escape_xml(input);
    assert_eq!(
        result.len(),
        10,
        "Two 1-char controls (single-digit hex) -> two 5-char escapes = 10 chars"
    );

    // Double digit hex (0x10-0x1F): each illegal control char (1 char) becomes &#xNN; (6 chars)
    let input = "\x10\x11";
    let result = escape_xml(input);
    assert_eq!(
        result.len(),
        12,
        "Two 1-char controls (double-digit hex) -> two 6-char escapes = 12 chars"
    );

    // Mixed single and double digit
    let input = "\x00\x10";
    let result = escape_xml(input);
    assert_eq!(
        result.len(),
        11,
        "Mixed single (5) and double (6) digit = 11 chars"
    );

    // Safe chars pass through unchanged (1 char each)
    let input = "abc";
    let result = escape_xml(input);
    assert_eq!(result.len(), 3, "Safe chars unchanged");

    // Mix: 1 control (1->5) + 3 safe (3) = 8
    let input = "a\x00bc";
    let result = escape_xml(input);
    assert_eq!(
        result.len(),
        8,
        "Mixed: 1 control (single-digit) + 3 safe = 8 chars"
    );
}
