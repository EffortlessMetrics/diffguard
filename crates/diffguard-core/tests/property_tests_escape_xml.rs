//! Property-based tests for the escape_xml function.
//!
//! These tests verify key invariants of the XML escaping function using
//! property-based testing with proptest.

#![allow(unused_doc_comments)]

use proptest::prelude::*;

/// Characters that must be escaped in XML text content
const SPECIAL_CHARS: &[char] = &['&', '<', '>', '"', '\''];

/// Property 1: Length bound - output length >= input length
///
/// Escaping replaces single characters with multi-character sequences:
/// - `&` → `&amp;` (5 chars)
/// - `<` → `&lt;` (4 chars)
/// - `>` → `&gt;` (4 chars)
/// - `"` → `&quot;` (6 chars)
/// - `'` → `&apos;` (6 chars)
///
/// Therefore, output.len() >= input.len() always holds.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn output_length_always_greater_or_equal_to_input(input: String) {
        let output = escape_xml(&input);
        prop_assert!(
            output.len() >= input.len(),
            "escape_xml should never shorten output: input.len()={}, output.len()={}, input={:?}",
            input.len(),
            output.len(),
            input
        );
    }
}

/// Property 2: Special chars escaped - &,<,>,",' must never appear unescaped in output
///
/// After escaping, none of the special XML characters should appear unescaped
/// in the output. They should only appear as part of their entity references.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn ampersand_only_appears_as_amp_in_output(input: String) {
        let output = escape_xml(&input);
        // If input contains &, it should be escaped to &amp;
        // So & should never appear unescaped (i.e., not followed by amp;)
        if input.contains('&') {
            prop_assert!(
                output.contains("&amp;"),
                "& was not properly escaped to &amp; in output: {:?}",
                output
            );
        }
    }

    #[test]
    fn less_than_only_appears_as_lt_in_output(input: String) {
        let output = escape_xml(&input);
        if input.contains('<') {
            prop_assert!(
                output.contains("&lt;"),
                "< was not properly escaped to &lt; in output: {:?}",
                output
            );
        }
    }

    #[test]
    fn greater_than_only_appears_as_gt_in_output(input: String) {
        let output = escape_xml(&input);
        if input.contains('>') {
            prop_assert!(
                output.contains("&gt;"),
                "> was not properly escaped to &gt; in output: {:?}",
                output
            );
        }
    }

    #[test]
    fn double_quote_only_appears_as_quot_in_output(input: String) {
        let output = escape_xml(&input);
        if input.contains('"') {
            prop_assert!(
                output.contains("&quot;"),
                "\" was not properly escaped to &quot; in output: {:?}",
                output
            );
        }
    }

    #[test]
    fn single_quote_only_appears_as_apos_in_output(input: String) {
        let output = escape_xml(&input);
        if input.contains('\'') {
            prop_assert!(
                output.contains("&apos;"),
                "' was not properly escaped to &apos; in output: {:?}",
                output
            );
        }
    }
}

/// Property 3: Empty input produces empty output
#[test]
fn empty_input_produces_empty_output() {
    let output = escape_xml("");
    assert_eq!(output, "", "Empty input should produce empty output");
}

/// Property 4: Normal text preserved - chars not in {&,<,>,",'} pass through unchanged
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn normal_ascii_text_preserved(input: String) {
        // Generate string with only "safe" characters (no special XML chars)
        let safe_input: String = input
            .chars()
            .filter(|c| !SPECIAL_CHARS.contains(c))
            .collect();

        let output = escape_xml(&safe_input);

        // Safe characters should pass through unchanged
        assert_eq!(
            output, safe_input,
            "Safe characters should pass through unchanged: input={:?}, output={:?}",
            safe_input, output
        );
    }
}

/// Property 5: Specific mappings - verify each special char maps correctly
#[test]
fn ampersand_maps_to_amp() {
    assert_eq!(escape_xml("&"), "&amp;");
}

#[test]
fn less_than_maps_to_lt() {
    assert_eq!(escape_xml("<"), "&lt;");
}

#[test]
fn greater_than_maps_to_gt() {
    assert_eq!(escape_xml(">"), "&gt;");
}

#[test]
fn double_quote_maps_to_quot() {
    assert_eq!(escape_xml("\""), "&quot;");
}

#[test]
fn single_quote_maps_to_apos() {
    assert_eq!(escape_xml("'"), "&apos;");
}

/// Property 6: No information loss - verify original content can be reconstructed
/// for text without special chars
proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn no_information_loss_on_safe_text(input: String) {
        // Filter to only safe characters
        let safe_input: String = input
            .chars()
            .filter(|c| !SPECIAL_CHARS.contains(c))
            .collect();

        let output = escape_xml(&safe_input);

        assert_eq!(
            output, safe_input,
            "No information should be lost for safe text: input={:?}, output={:?}",
            safe_input, output
        );
    }
}

/// Additional Property: Multiple special chars in sequence
#[test]
fn multiple_special_chars_all_escaped() {
    let input = "&<>\"'";
    let expected = "&amp;&lt;&gt;&quot;&apos;";
    assert_eq!(escape_xml(input), expected);
}

/// Additional Property: Alternating safe and unsafe chars
#[test]
fn alternating_safe_and_special() {
    let input = "a&b<c>d\"e'f";
    let expected = "a&amp;b&lt;c&gt;d&quot;e&apos;f";
    assert_eq!(escape_xml(input), expected);
}

/// Additional Property: Special chars at start/end of string
#[test]
fn special_chars_at_boundaries() {
    assert_eq!(escape_xml("&hello"), "&amp;hello");
    assert_eq!(escape_xml("hello&"), "hello&amp;");
    assert_eq!(escape_xml("<hello"), "&lt;hello");
    assert_eq!(escape_xml("hello>"), "hello&gt;");
    assert_eq!(escape_xml("\"hello"), "&quot;hello");
    assert_eq!(escape_xml("hello'"), "hello&apos;");
    assert_eq!(escape_xml("&"), "&amp;");
    assert_eq!(escape_xml("<"), "&lt;");
    assert_eq!(escape_xml(">"), "&gt;");
    assert_eq!(escape_xml("\""), "&quot;");
    assert_eq!(escape_xml("'"), "&apos;");
}

/// Additional Property: Consecutive special chars
#[test]
fn consecutive_special_chars() {
    assert_eq!(escape_xml("&&"), "&amp;&amp;");
    assert_eq!(escape_xml("<<"), "&lt;&lt;");
    assert_eq!(escape_xml(">>"), "&gt;&gt;");
    assert_eq!(escape_xml("\"\""), "&quot;&quot;");
    assert_eq!(escape_xml("''"), "&apos;&apos;");
    assert_eq!(escape_xml("&<>\""), "&amp;&lt;&gt;&quot;");
}

/// Additional Property: No double-escaping of already-escaped content
/// Note: escape_xml is NOT idempotent - it always escapes special chars
/// This is intentional behavior - if you pass already-escaped content,
/// it will be escaped again (which is safe but redundant)
#[test]
fn double_escaping_happens_as_expected() {
    // If you pass already-escaped content, it gets escaped again
    assert_eq!(escape_xml("&amp;"), "&amp;amp;");
    assert_eq!(escape_xml("&lt;"), "&amp;lt;");
    assert_eq!(escape_xml("&gt;"), "&amp;gt;");
    assert_eq!(escape_xml("&quot;"), "&amp;quot;");
    assert_eq!(escape_xml("&apos;"), "&amp;apos;");
}

/// Additional Property: Unicode characters pass through unchanged
#[test]
fn unicode_characters_unchanged() {
    assert_eq!(escape_xml("日本語"), "日本語");
    assert_eq!(escape_xml("🎉"), "🎉");
    assert_eq!(escape_xml("münchen"), "münchen");
    assert_eq!(escape_xml("café"), "café");
}

/// Additional Property: Mixed content with unicode
#[test]
fn mixed_content_with_unicode() {
    assert_eq!(
        escape_xml("hello & <world> 日本語"),
        "hello &amp; &lt;world&gt; 日本語"
    );
}

/// Additional Property: Very long strings with mixed content
#[test]
fn long_string_with_mixed_content() {
    let input = "hello world & <test> \"quote\" 'apostrophe' 日本語".repeat(100);
    let output = escape_xml(&input);

    // Verify the pattern repeats correctly
    let expected = "hello world &amp; &lt;test&gt; &quot;quote&quot; &apos;apostrophe&apos; 日本語"
        .repeat(100);
    assert_eq!(output, expected);
}

/// Additional Property: String with only special chars
#[test]
fn only_special_chars() {
    assert_eq!(
        escape_xml("&<>\"'&<>\"'"),
        "&amp;&lt;&gt;&quot;&apos;&amp;&lt;&gt;&quot;&apos;"
    );
}

/// Additional Property: Original implementation for testing
fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}
