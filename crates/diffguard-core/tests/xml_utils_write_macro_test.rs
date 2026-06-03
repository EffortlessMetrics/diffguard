//! Red test suite for xml_utils write!() macro implementation
//!
//! These tests verify the correct behavior of escape_xml() with respect to
//! the write!() macro fix for issue #305/#321.
//!
//! The fix replaced:
//!   `out.push_str(&format!("&#x{:X};", c as u32))`
//! With:
//!   `write!(out, "&#x{:X};", c as u32).unwrap()`
//!
//! These tests verify the functional correctness of the escape_xml output,
//! which would be identical regardless of whether format!() or write!() is used.
//! The behavioral difference is performance (no intermediate String allocation).

use diffguard_core::xml_utils::escape_xml;

#[test]
fn test_escape_xml_control_char_0x00_nul_is_escaped_as_hex_entity() {
    // NUL (0x00) is an illegal XML control character and must be escaped
    let input = "\x00";
    let output = escape_xml(input);
    // Must contain the hex entity reference
    assert!(
        output.contains("&#x0;"),
        "NUL should be escaped as &#x0;, got: {}",
        output
    );
    // Must NOT contain the raw NUL character
    assert!(
        !output.contains('\x00'.to_string().as_str()),
        "Output should not contain raw NUL"
    );
}

#[test]
fn test_escape_xml_control_char_0x01_soh_is_escaped_as_hex_entity() {
    // SOH (0x01) is an illegal XML control character
    let input = "\x01";
    let output = escape_xml(input);
    assert!(
        output.contains("&#x1;"),
        "SOH should be escaped as &#x1;, got: {}",
        output
    );
}

#[test]
fn test_escape_xml_control_char_0x1f_is_escaped_as_hex_entity() {
    // 0x1F (Unit Separator) is the highest illegal XML control character
    let input = "\x1F";
    let output = escape_xml(input);
    assert!(
        output.contains("&#x1F;"),
        "0x1F should be escaped as &#x1F;, got: {}",
        output
    );
}

#[test]
fn test_escape_xml_multiple_sequential_illegal_control_chars() {
    // Test that multiple consecutive illegal control chars are all escaped
    let input = "\x00\x01\x02";
    let output = escape_xml(input);
    assert!(output.contains("&#x0;"), "Should escape first control char");
    assert!(
        output.contains("&#x1;"),
        "Should escape second control char"
    );
    assert!(output.contains("&#x2;"), "Should escape third control char");
}

#[test]
fn test_escape_xml_illegal_and_legal_control_chars_mixed() {
    // Tab (0x09), LF (0x0A), CR (0x0D) are legal and should NOT be escaped
    // 0x00, 0x01, 0x02 are illegal and SHOULD be escaped
    let input = "\x00\x09\x01\x0A\x02\x0D\x03";
    let output = escape_xml(input);

    // Illegal chars should be escaped
    assert!(output.contains("&#x0;"), "NUL should be escaped");
    assert!(output.contains("&#x1;"), "SOH should be escaped");
    assert!(output.contains("&#x2;"), "0x02 should be escaped");
    assert!(output.contains("&#x3;"), "0x03 should be escaped");

    // Legal control chars should be preserved as-is
    assert!(output.contains('\t'), "Tab should be preserved");
    assert!(output.contains('\n'), "LF should be preserved");
    assert!(output.contains('\r'), "CR should be preserved");
}

#[test]
fn test_escape_xml_bel_character_0x07_escaped() {
    // BEL (0x07) is an illegal XML control character
    let input = "hello\x07world";
    let output = escape_xml(input);
    assert!(
        output.contains("&#x7;"),
        "BEL should be escaped as &#x7;, got: {}",
        output
    );
    // The rest of the string should be preserved
    assert!(output.contains("hello"), "hello should be preserved");
    assert!(output.contains("world"), "world should be preserved");
}

#[test]
fn test_escape_xml_escape_character_0x1b_escaped() {
    // ESC (0x1B) is an illegal XML control character
    let input = "test\x1Bend";
    let output = escape_xml(input);
    assert!(
        output.contains("&#x1B;"),
        "ESC should be escaped as &#x1B;, got: {}",
        output
    );
}

#[test]
fn test_escape_xml_control_chars_in_realistic_context() {
    // Simulate a realistic scenario with mixed content
    let input = "File: test.txt\x00Line 1\x0A\x09Line 2 with tab\x0D\x01hidden";
    let output = escape_xml(input);

    // Illegal control chars escaped
    assert!(output.contains("&#x0;"), "NUL should be escaped");
    assert!(output.contains("&#x1;"), "0x01 should be escaped");

    // Legal control chars preserved
    assert!(output.contains('\t'), "Tab should be preserved");
    assert!(output.contains('\n'), "LF should be preserved");
    assert!(output.contains('\r'), "CR should be preserved");

    // Text content preserved
    assert!(
        output.contains("File: test.txt"),
        "Text before NUL preserved"
    );
    assert!(output.contains("Line 1"), "Line 1 preserved");
    assert!(output.contains("Line 2 with tab"), "Line 2 preserved");
    assert!(output.contains("hidden"), "hidden text preserved");
}

#[test]
fn test_escape_xml_hex_entities_are_uppercase() {
    // XML hex entities should use uppercase hex digits
    // Use 0x0B (vertical tab) which is an illegal control char (not tab/LF/CR)
    // 0x0B = 11 decimal = B hex
    let input = "\x0B";
    let output = escape_xml(input);
    // The output should contain uppercase 'B', not lowercase 'b'
    assert!(
        output.contains("&#xB;"),
        "Hex entity should be uppercase, got: {}",
        output
    );
    assert!(
        !output.contains("&#xb;"),
        "Hex entity should NOT be lowercase, got: {}",
        output
    );
}
