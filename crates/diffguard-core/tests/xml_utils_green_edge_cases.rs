//! Green edge case tests for xml_utils escape_xml() function.
//!
//! These tests verify edge cases not covered by the red tests:
//! - All 5 named XML entities together
//! - Boundary: character at exactly 0x20 (printable space vs illegal control)
//! - DEL character (0x7F) - outside 0x00-0x1F range
//! - Unicode characters beyond BMP (emojis, supplementary chars)
//! - Multi-byte UTF-8 characters mixed with control chars
//! - Long strings with repeated control chars
//! - Named entities adjacent to control chars
//! - Null string (None-like empty string)
//!
//! These tests verify the write!() macro implementation handles all edge
//! cases correctly without panics, memory issues, or incorrect output.

use diffguard_core::xml_utils::escape_xml;

// =============================================================================
// Named Entity Edge Cases
// =============================================================================

#[test]
fn test_escape_xml_all_five_named_entities_together() {
    // All 5 XML named entities in one string
    let input = "&<>\"'";
    let output = escape_xml(input);
    assert_eq!(output, "&amp;&lt;&gt;&quot;&apos;");
}

#[test]
fn test_escape_xml_named_entity_at_string_boundaries() {
    // Named entities at beginning, middle, and end
    assert_eq!(escape_xml("&test"), "&amp;test");
    assert_eq!(escape_xml("test&"), "test&amp;");
    assert_eq!(escape_xml("&test&"), "&amp;test&amp;");
    assert_eq!(escape_xml("<test<"), "&lt;test&lt;");
    assert_eq!(escape_xml(">test>"), "&gt;test&gt;");
}

#[test]
fn test_escape_xml_named_entities_adjacent_to_control_chars() {
    // Named entity immediately followed by illegal control char
    let input = "&\x00<\x01>\x02";
    let output = escape_xml(input);
    // Each should be escaped independently
    assert!(output.contains("&amp;"));
    assert!(output.contains("&#x0;"));
    assert!(output.contains("&lt;"));
    assert!(output.contains("&#x1;"));
    assert!(output.contains("&gt;"));
    assert!(output.contains("&#x2;"));
}

#[test]
fn test_escape_xml_repeated_named_entities() {
    // Multiple repetitions of same entity
    let input = "&&&<&<<>>>";
    let output = escape_xml(input);
    assert_eq!(output, "&amp;&amp;&amp;&lt;&amp;&lt;&lt;&gt;&gt;&gt;");
}

// =============================================================================
// Boundary Edge Cases
// =============================================================================

#[test]
fn test_escape_xml_0x20_space_is_not_escaped() {
    // 0x20 (space) is a printable character, not a control character
    // It should NOT be escaped - it's outside the 0x00-0x1F illegal range
    let input = "a b";
    let output = escape_xml(input);
    assert_eq!(output, "a b");
    // Should NOT contain any entity reference
    assert!(!output.contains("&#x"));
}

#[test]
fn test_escape_xml_0x1f_boundary_is_escaped() {
    // 0x1F is the highest illegal control character - must be escaped
    let input = "\x1F";
    let output = escape_xml(input);
    assert!(output.contains("&#x1F;"));
    assert_eq!(output, "&#x1F;");
}

#[test]
fn test_escape_xml_0x20_boundary_not_escaped() {
    // 0x20 is a printable space - must NOT be escaped
    let input = "\x20";
    let output = escape_xml(input);
    assert_eq!(output, "\x20");
    assert!(!output.contains("&#x"));
}

#[test]
fn test_escape_xml_0x7f_del_not_escaped() {
    // DEL (0x7F) is outside the 0x00-0x1F illegal control char range
    // per XML spec, only 0x00-0x1F (except tab/LF/CR) are illegal
    let input = "a\x7Fb";
    let output = escape_xml(input);
    assert_eq!(output, "a\x7Fb");
    assert!(!output.contains("&#x"));
}

// =============================================================================
// Unicode Edge Cases
// =============================================================================

#[test]
fn test_escape_xml_unicode_basic_multibyte_chars_preserved() {
    // Multi-byte UTF-8 characters should be preserved
    let input = "Hello 世界 🌍";
    let output = escape_xml(input);
    assert!(output.contains("Hello"));
    assert!(output.contains("世界"));
    assert!(output.contains("🌍")); // emoji preserved
}

#[test]
fn test_escape_xml_unicode_control_chars_not_escaped() {
    // Unicode control characters beyond U+001F are not in the 0x00-0x1F range
    // They should be preserved (per the current implementation's spec)
    // U+0085 (NEL) is a Unicode control character
    let input = "hello\u{85}world";
    let output = escape_xml(input);
    assert!(output.contains("hello"));
    assert!(output.contains("world"));
    // The U+0085 should be preserved (not escaped by our implementation)
    assert!(output.contains("\u{85}"));
}

#[test]
fn test_escape_xml_mixed_unicode_and_illegal_control_chars() {
    // Mix of multi-byte Unicode and illegal ASCII control chars
    let input = "\x00日本\x01";
    let output = escape_xml(input);
    // Illegal control chars should be escaped
    assert!(output.contains("&#x0;"));
    assert!(output.contains("&#x1;"));
    // Unicode characters should be preserved
    assert!(output.contains("日本"));
}

#[test]
fn test_escape_xml_unicode_supplementary_plane_characters() {
    // Supplementary characters (beyond U+FFFF) - encoded as surrogate pairs in UTF-16
    // These should be preserved as-is since they're not control characters
    let input = "G clef: \u{1D11E}"; // U+1D11E is MUSICAL SYMBOL G CLEF
    let output = escape_xml(input);
    assert!(output.contains("G clef:"));
    assert!(output.contains("\u{1D11E}"));
}

// =============================================================================
// String Length Edge Cases
// =============================================================================

#[test]
fn test_escape_xml_empty_string() {
    let input = "";
    let output = escape_xml(input);
    assert_eq!(output, "");
}

#[test]
fn test_escape_xml_single_char_regular() {
    let input = "a";
    let output = escape_xml(input);
    assert_eq!(output, "a");
}

#[test]
fn test_escape_xml_single_char_control() {
    let input = "\x00";
    let output = escape_xml(input);
    assert_eq!(output, "&#x0;");
}

#[test]
fn test_escape_xml_single_char_named_entity() {
    let input = "&";
    let output = escape_xml(input);
    assert_eq!(output, "&amp;");
}

#[test]
fn test_escape_xml_long_string_with_repeated_control_chars() {
    // Long string with many control characters to stress the implementation
    let input = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
    let output = escape_xml(input);
    // All illegal control chars (0x00-0x1F except tab/LF/CR) should be escaped
    // Tab (0x09), LF (0x0A), CR (0x0D) are preserved
    // 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x10,
    // 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F should be escaped
    assert!(output.contains("&#x0;")); // NUL
    assert!(output.contains("&#x1;")); // SOH
    assert!(output.contains("&#x2;")); // STX
    assert!(output.contains("&#x3;")); // ETX
    assert!(output.contains("&#x4;")); // EOT
    assert!(output.contains("&#x5;")); // ENQ
    assert!(output.contains("&#x6;")); // ACK
    assert!(output.contains("&#x7;")); // BEL
    assert!(output.contains("&#x8;")); // BS
    // 0x09 tab is preserved (not escaped)
    // 0x0A LF is preserved (not escaped)
    assert!(output.contains("&#xB;")); // VT (0x0B)
    assert!(output.contains("&#xC;")); // FF (0x0C)
    // 0x0D CR is preserved (not escaped)
    assert!(output.contains("&#xE;")); // SO (0x0E)
    assert!(output.contains("&#xF;")); // SI (0x0F)
    assert!(output.contains("&#x10;")); // DLE
    assert!(output.contains("&#x11;")); // DC1
    assert!(output.contains("&#x12;")); // DC2
    assert!(output.contains("&#x13;")); // DC3
    assert!(output.contains("&#x14;")); // DC4
    assert!(output.contains("&#x15;")); // NAK
    assert!(output.contains("&#x16;")); // SYN
    assert!(output.contains("&#x17;")); // ETB
    assert!(output.contains("&#x18;")); // CAN
    assert!(output.contains("&#x19;")); // EM
    assert!(output.contains("&#x1A;")); // SUB
    assert!(output.contains("&#x1B;")); // ESC
    assert!(output.contains("&#x1C;")); // FS
    assert!(output.contains("&#x1D;")); // GS
    assert!(output.contains("&#x1E;")); // RS
    assert!(output.contains("&#x1F;")); // US
}

// =============================================================================
// Interaction Edge Cases
// =============================================================================

#[test]
fn test_escape_xml_no_special_chars_unchanged() {
    // String with no special characters should be unchanged
    let input = "Hello World 123";
    let output = escape_xml(input);
    assert_eq!(output, "Hello World 123");
}

#[test]
fn test_escape_xml_mixed_normal_and_special_chars() {
    // Mix of normal chars, named entities, and control chars
    let input = "Hello & World \x00!";
    let output = escape_xml(input);
    assert_eq!(output, "Hello &amp; World &#x0;!");
}

#[test]
fn test_escape_xml_apos_not_html_escaped() {
    // &apos; is XML entity for single quote (different from HTML &apos;)
    // The output should be &apos; (XML standard)
    let input = "'";
    let output = escape_xml(input);
    assert_eq!(output, "&apos;");
}

#[test]
fn test_escape_xml_xml_comment_like_content() {
    // Content that looks like XML comments should be properly escaped
    let input = "<!-- comment -->";
    let output = escape_xml(input);
    // < and > should be escaped even in comment-like content
    assert_eq!(output, "&lt;!-- comment --&gt;");
}

#[test]
fn test_escape_xml_xml_tag_like_content() {
    // Content that looks like XML tags
    let input = "<tag attr=\"value\">content</tag>";
    let output = escape_xml(input);
    assert_eq!(
        output,
        "&lt;tag attr=&quot;value&quot;&gt;content&lt;/tag&gt;"
    );
}
