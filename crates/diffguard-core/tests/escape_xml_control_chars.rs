//! Tests for XML control character escaping in xml_utils module.
//!
//! These tests verify that illegal XML control characters (0x00-0x1F except
//! tab, LF, CR) are properly escaped as &#xNN; entities, while legal control
//! characters (tab=0x09, LF=0x0A, CR=0x0D) are preserved.

use diffguard_core::xml_utils::escape_xml;

#[test]
fn test_illegal_control_char_0x00_nul_is_escaped() {
    // 0x00 (NUL) is illegal in XML and must be escaped
    let input = "before\x00after";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x0;"),
        "NUL char should be escaped as &#x0;"
    );
    assert!(
        !result.contains('\x00'),
        "Raw NUL should not appear in output"
    );
}

#[test]
fn test_illegal_control_char_0x01_is_escaped() {
    // 0x01 is illegal in XML
    let input = "text\x01more";
    let result = escape_xml(input);
    assert!(result.contains("&#x1;"), "0x01 should be escaped as &#x1;");
}

#[test]
fn test_illegal_control_char_0x02_is_escaped() {
    let input = "text\x02more";
    let result = escape_xml(input);
    assert!(result.contains("&#x2;"), "0x02 should be escaped as &#x2;");
}

#[test]
fn test_illegal_control_char_0x03_is_escaped() {
    let input = "text\x03more";
    let result = escape_xml(input);
    assert!(result.contains("&#x3;"), "0x03 should be escaped as &#x3;");
}

#[test]
fn test_illegal_control_char_0x04_is_escaped() {
    let input = "text\x04more";
    let result = escape_xml(input);
    assert!(result.contains("&#x4;"), "0x04 should be escaped as &#x4;");
}

#[test]
fn test_illegal_control_char_0x05_is_escaped() {
    let input = "text\x05more";
    let result = escape_xml(input);
    assert!(result.contains("&#x5;"), "0x05 should be escaped as &#x5;");
}

#[test]
fn test_illegal_control_char_0x06_is_escaped() {
    let input = "text\x06more";
    let result = escape_xml(input);
    assert!(result.contains("&#x6;"), "0x06 should be escaped as &#x6;");
}

#[test]
fn test_illegal_control_char_0x07_bel_is_escaped() {
    // 0x07 (BEL) is illegal in XML
    let input = "text\x07more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x7;"),
        "BEL char should be escaped as &#x7;"
    );
}

#[test]
fn test_illegal_control_char_0x08_bs_is_escaped() {
    // 0x08 (Backspace) is illegal in XML
    let input = "text\x08more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x8;"),
        "Backspace should be escaped as &#x8;"
    );
}

#[test]
fn test_illegal_control_char_0x0b_vt_is_escaped() {
    // 0x0B (Vertical Tab) is illegal in XML
    let input = "text\x0bmiddle";
    let result = escape_xml(input);
    assert!(
        result.contains("&#xB;"),
        "Vertical Tab should be escaped as &#xB;"
    );
}

#[test]
fn test_illegal_control_char_0x0c_ff_is_escaped() {
    // 0x0C (Form Feed) is illegal in XML
    let input = "text\x0cmore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#xC;"),
        "Form Feed should be escaped as &#xC;"
    );
}

#[test]
fn test_illegal_control_char_0x0e_is_escaped() {
    // 0x0E (Shift Out) is illegal in XML
    let input = "text\x0Emore";
    let result = escape_xml(input);
    assert!(result.contains("&#xE;"), "0x0E should be escaped as &#xE;");
}

#[test]
fn test_illegal_control_char_0x0f_is_escaped() {
    // 0x0F is illegal in XML
    let input = "text\x0Fmore";
    let result = escape_xml(input);
    assert!(result.contains("&#xF;"), "0x0F should be escaped as &#xF;");
}

#[test]
fn test_illegal_control_char_0x10_is_escaped() {
    // 0x10 is illegal in XML
    let input = "text\x10more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x10;"),
        "0x10 should be escaped as &#x10;"
    );
}

#[test]
fn test_illegal_control_char_0x11_is_escaped() {
    // 0x11 is illegal in XML
    let input = "text\x11more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x11;"),
        "0x11 should be escaped as &#x11;"
    );
}

#[test]
fn test_illegal_control_char_0x12_is_escaped() {
    // 0x12 is illegal in XML
    let input = "text\x12more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x12;"),
        "0x12 should be escaped as &#x12;"
    );
}

#[test]
fn test_illegal_control_char_0x13_is_escaped() {
    // 0x13 is illegal in XML
    let input = "text\x13more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x13;"),
        "0x13 should be escaped as &#x13;"
    );
}

#[test]
fn test_illegal_control_char_0x14_is_escaped() {
    // 0x14 is illegal in XML
    let input = "text\x14more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x14;"),
        "0x14 should be escaped as &#x14;"
    );
}

#[test]
fn test_illegal_control_char_0x15_is_escaped() {
    // 0x15 is illegal in XML
    let input = "text\x15more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x15;"),
        "0x15 should be escaped as &#x15;"
    );
}

#[test]
fn test_illegal_control_char_0x16_is_escaped() {
    // 0x16 is illegal in XML
    let input = "text\x16more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x16;"),
        "0x16 should be escaped as &#x16;"
    );
}

#[test]
fn test_illegal_control_char_0x17_is_escaped() {
    // 0x17 is illegal in XML
    let input = "text\x17more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x17;"),
        "0x17 should be escaped as &#x17;"
    );
}

#[test]
fn test_illegal_control_char_0x18_is_escaped() {
    // 0x18 (Cancel) is illegal in XML
    let input = "text\x18more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x18;"),
        "0x18 should be escaped as &#x18;"
    );
}

#[test]
fn test_illegal_control_char_0x19_is_escaped() {
    // 0x19 (End of Transmission) is illegal in XML
    let input = "text\x19more";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x19;"),
        "0x19 should be escaped as &#x19;"
    );
}

#[test]
fn test_illegal_control_char_0x1a_sub_is_escaped() {
    // 0x1A (Substitute) is illegal in XML
    let input = "text\x1Amore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x1A;"),
        "0x1A should be escaped as &#x1A;"
    );
}

#[test]
fn test_illegal_control_char_0x1b_esc_is_escaped() {
    // 0x1B (Escape) is illegal in XML
    let input = "text\x1Bmore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x1B;"),
        "0x1B should be escaped as &#x1B;"
    );
}

#[test]
fn test_illegal_control_char_0x1c_is_escaped() {
    // 0x1C (File Separator) is illegal in XML
    let input = "text\x1Cmore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x1C;"),
        "0x1C should be escaped as &#x1C;"
    );
}

#[test]
fn test_illegal_control_char_0x1d_is_escaped() {
    // 0x1D (Group Separator) is illegal in XML
    let input = "text\x1Dmore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x1D;"),
        "0x1D should be escaped as &#x1D;"
    );
}

#[test]
fn test_illegal_control_char_0x1e_is_escaped() {
    // 0x1E (Record Separator) is illegal in XML
    let input = "text\x1Emore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x1E;"),
        "0x1E should be escaped as &#x1E;"
    );
}

#[test]
fn test_illegal_control_char_0x1f_us_is_escaped() {
    // 0x1F (Unit Separator) is illegal in XML
    let input = "text\x1Fmore";
    let result = escape_xml(input);
    assert!(
        result.contains("&#x1F;"),
        "0x1F should be escaped as &#x1F;"
    );
}

// Legal control characters - should NOT be escaped

#[test]
fn test_legal_control_char_tab_0x09_is_preserved() {
    // Tab (0x09) is legal in XML and should NOT be escaped
    let input = "before\tafter";
    let result = escape_xml(input);
    assert!(result.contains('\t'), "Tab should be preserved as-is");
    assert!(!result.contains("&#x9;"), "Tab should NOT be escaped");
}

#[test]
fn test_legal_control_char_lf_0x0a_is_preserved() {
    // Line Feed (0x0A) is legal in XML and should NOT be escaped
    let input = "line1\nline2";
    let result = escape_xml(input);
    assert!(result.contains('\n'), "LF should be preserved as-is");
    assert!(!result.contains("&#xA;"), "LF should NOT be escaped");
}

#[test]
fn test_legal_control_char_cr_0x0d_is_preserved() {
    // Carriage Return (0x0D) is legal in XML and should NOT be escaped
    let input = "line1\rline2";
    let result = escape_xml(input);
    assert!(result.contains('\r'), "CR should be preserved as-is");
    assert!(!result.contains("&#xD;"), "CR should NOT be escaped");
}

// Mixed content tests

#[test]
fn test_mixed_illegal_and_legal_control_chars() {
    // Tab, LF, CR should be preserved; others should be escaped
    let input = "start\t\n\r\x00\x01\x1Fend";
    let result = escape_xml(input);

    // Legal chars preserved
    assert!(result.contains('\t'), "Tab should be preserved");
    assert!(result.contains('\n'), "LF should be preserved");
    assert!(result.contains('\r'), "CR should be preserved");

    // Illegal chars escaped
    assert!(result.contains("&#x0;"), "NUL should be escaped");
    assert!(result.contains("&#x1;"), "0x01 should be escaped");
    assert!(result.contains("&#x1F;"), "0x1F should be escaped");
}

#[test]
fn test_mixed_with_xml_special_chars() {
    // Control chars combined with XML special chars
    let input = "&amp;\x00<tag>\x1F";
    let result = escape_xml(input);

    // Standard XML chars should be escaped
    assert!(result.contains("&amp;"), "& should be escaped as &amp;");
    assert!(result.contains("&lt;"), "< should be escaped as &lt;");
    assert!(result.contains("&gt;"), "> should be escaped as &gt;");

    // Illegal control chars should be escaped
    assert!(result.contains("&#x0;"), "NUL should be escaped");
    assert!(result.contains("&#x1F;"), "0x1F should be escaped");
}

#[test]
fn test_control_chars_in_realistic_message() {
    // Simulates a finding message that might contain control characters
    let input = "Avoid unwrap\x07\x1Bhere\x0B"; // contains BEL, ESC, VT
    let result = escape_xml(input);

    assert!(result.contains("&#x7;"), "BEL should be escaped");
    assert!(result.contains("&#x1B;"), "ESC should be escaped");
    assert!(result.contains("&#xB;"), "VT should be escaped");
}

#[test]
fn test_empty_string() {
    let input = "";
    let result = escape_xml(input);
    assert_eq!(result, "");
}

#[test]
fn test_string_without_control_chars() {
    // Normal string with only printable characters
    let input = "Hello, World!";
    let result = escape_xml(input);
    assert_eq!(result, "Hello, World!");
}

#[test]
fn test_all_special_xml_chars() {
    // All the standard XML special characters
    let input = "&<>\"'";
    let result = escape_xml(input);
    assert_eq!(result, "&amp;&lt;&gt;&quot;&apos;");
}

#[test]
fn test_high_control_char_0x7f_not_escaped() {
    // DEL (0x7F) is technically not in the 0x00-0x1F range that XML restricts
    // but is often considered a control character. According to XML 1.0 spec,
    // only 0x00-0x1F (except 0x09, 0x0A, 0x0D) are illegal.
    let input = "text\x7Fmore";
    let result = escape_xml(input);
    // DEL (0x7F) is NOT in the illegal range 0x00-0x1F, so should be preserved
    assert!(
        result.contains('\x7F'),
        "DEL (0x7F) should be preserved (not in 0x00-0x1F range)"
    );
}

// Edge case tests

#[test]
fn test_very_long_string() {
    // Very long string with mixed content
    let input = "A".repeat(100_000);
    let result = escape_xml(&input);
    assert_eq!(result.len(), 100_000);
    assert_eq!(result, input);
}

#[test]
fn test_very_long_string_with_control_chars() {
    // Very long string with illegal control characters interspersed
    let mut input = String::new();
    for i in 0..10_000 {
        input.push('A');
        if i % 100 == 0 {
            input.push('\x00');
        }
    }
    let result = escape_xml(&input);
    // Every \x00 should be escaped as &#x0; (5 chars)
    let expected_extra_len = (10_000 / 100) * 4; // 100 \x00s, each adds 4 extra chars
    assert_eq!(result.len(), input.len() + expected_extra_len);
    assert!(result.contains("&#x0;"));
}

#[test]
fn test_string_with_only_illegal_control_chars() {
    // String containing only illegal control characters (no printable chars)
    let input = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
    let result = escape_xml(input);
    // Verify all illegal control chars are escaped
    assert!(result.contains("&#x0;"));
    assert!(result.contains("&#x1;"));
    assert!(result.contains("&#x1F;"));
    // Verify no raw control chars remain
    for c in input.chars() {
        assert!(
            !result.contains(c),
            "Control char {:?} should be escaped",
            c
        );
    }
    // Verify the output is longer than input (each illegal char becomes &#xNN;)
    assert!(result.len() > input.len());
}

#[test]
fn test_string_with_only_legal_control_chars() {
    // String containing only legal control characters (tab, LF, CR)
    let input = "\t\n\r\t\n\r";
    let result = escape_xml(input);
    // Legal chars should be preserved as-is
    assert_eq!(result, input);
    assert_eq!(result.len(), 6);
}

#[test]
fn test_mixed_unicode_and_control_chars() {
    // Unicode characters mixed with control characters
    let input = "日本語\x00中文\x1F한국어\x09";
    let result = escape_xml(input);
    assert!(result.contains("日本語"));
    assert!(result.contains("中文"));
    assert!(result.contains("한국어"));
    assert!(result.contains('\t')); // preserved
    assert!(result.contains("&#x0;")); // escaped
    assert!(result.contains("&#x1F;")); // escaped
}

#[test]
fn test_unicode_bmp_characters() {
    // Basic Multilingual Plane unicode chars (U+0000 to U+FFFF)
    let input = "ℕ ℤ ℚ ℝ ℂ π ∞";
    let result = escape_xml(input);
    assert_eq!(result, input);
}

#[test]
fn test_unicode_supplementary_characters() {
    // Supplementary characters (U+10000 and above) - encoded as surrogate pairs in UTF-16
    // These should be preserved correctly
    let input = "𝄞𝄢"; // Musical symbols U+1D11E, U+1D11F
    let result = escape_xml(input);
    assert_eq!(result, input);
}

#[test]
fn test_boundary_0x00_nul() {
    // Boundary: first illegal control char (0x00)
    let input = "start\x00end";
    let result = escape_xml(input);
    assert!(result.contains("&#x0;"));
    assert!(!result.contains('\x00'));
}

#[test]
fn test_boundary_0x09_tab_legal() {
    // Boundary: first legal control char (0x09 tab)
    let input = "start\x09end";
    let result = escape_xml(input);
    assert!(result.contains('\t'));
    assert!(!result.contains("&#x9;"));
}

#[test]
fn test_boundary_0x0a_lf_legal() {
    // Boundary: 0x0A line feed (legal)
    let input = "start\x0Aend";
    let result = escape_xml(input);
    assert!(result.contains('\n'));
    assert!(!result.contains("&#xA;"));
}

#[test]
fn test_boundary_0x0d_cr_legal() {
    // Boundary: 0x0D carriage return (legal)
    let input = "start\x0Dend";
    let result = escape_xml(input);
    assert!(result.contains('\r'));
    assert!(!result.contains("&#xD;"));
}

#[test]
fn test_boundary_0x1f_us_last_illegal() {
    // Boundary: last illegal control char (0x1F)
    let input = "start\x1Fend";
    let result = escape_xml(input);
    assert!(result.contains("&#x1F;"));
    assert!(!result.contains('\x1F'));
}

#[test]
fn test_boundary_0x20_space_first_printable() {
    // Boundary: 0x20 first printable ASCII
    let input = "start\x20end";
    let result = escape_xml(input);
    assert!(result.contains("start end"));
    assert!(result.contains('\x20')); // Space preserved
}

#[test]
fn test_multiple_consecutive_illegal_chars() {
    // Multiple consecutive illegal control characters
    let input = "\x00\x01\x00\x01\x00";
    let result = escape_xml(input);
    assert_eq!(result, "&#x0;&#x1;&#x0;&#x1;&#x0;");
}

#[test]
fn test_multiple_consecutive_legal_chars() {
    // Multiple consecutive legal control characters
    let input = "\t\t\t\n\n\n\r\r\r";
    let result = escape_xml(input);
    assert_eq!(result, "\t\t\t\n\n\n\r\r\r");
}

#[test]
fn test_escaped_xml_entities_not_double_escaped() {
    // Already escaped entities should not be double-escaped
    let input = "&amp; &lt; &gt; &quot; &apos;";
    let result = escape_xml(input);
    // The & in &amp; should become &amp;amp; but &amp; itself should not become &amp;amp;amp;
    assert!(result.contains("&amp;amp;")); // & became &amp;
    assert!(result.contains("&amp;lt;")); // < became &lt;
    assert!(result.contains("&amp;gt;")); // > became &gt;
}

#[test]
fn test_null_between_unicode() {
    // Unicode chars with null in between
    let input = "α\x00β\x00γ";
    let result = escape_xml(input);
    assert!(result.contains("α"));
    assert!(result.contains("β"));
    assert!(result.contains("γ"));
    assert!(result.contains("&#x0;"));
    assert!(
        !result.contains('\x00'),
        "Null should be escaped, not preserved"
    );
    assert!(!result.contains("α\x00β")); // null should be gone
}

#[test]
fn test_control_chars_with_newlines() {
    // Newlines and control chars
    let input = "line1\x00\nline2\x01\rline3";
    let result = escape_xml(input);
    assert!(result.contains("&#x0;")); // NUL escaped
    assert!(result.contains('\n')); // LF preserved
    assert!(result.contains('\r')); // CR preserved
    assert!(result.contains("&#x1;")); // 0x01 escaped
}

#[test]
fn test_large_emoji_with_control_chars() {
    // Emoji (which are multi-byte UTF-8) with control chars
    let input = "🔒\x00🔐\x1F🔑";
    let result = escape_xml(input);
    assert!(result.contains("🔒"));
    assert!(result.contains("🔐"));
    assert!(result.contains("🔑"));
    assert!(result.contains("&#x0;"));
    assert!(result.contains("&#x1F;"));
}

#[test]
fn test_xml_tag_like_content_with_control_chars() {
    // Content that looks like XML tags with control chars
    let input = "<tag\x00attr=\"val\x1F\">text</tag>";
    let result = escape_xml(input);
    // < becomes &lt;, > becomes &gt;, " becomes &quot;
    assert!(result.contains("&lt;tag"));
    assert!(result.contains("attr=&quot;val"));
    assert!(result.contains("&#x0;"));
    assert!(result.contains("&#x1F;"));
    assert!(result.contains("&gt;text&lt;/tag&gt;"));
}
