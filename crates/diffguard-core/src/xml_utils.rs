//! Shared XML utility functions.

/// Escapes XML special characters in text content.
///
/// This function replaces characters that have special meaning in XML with their
/// corresponding entity references, ensuring text is safe to embed in XML documents.
///
/// # Escaped Characters
/// - `&` → `&amp;` (ampersand must always be escaped)
/// - `<` → `&lt;` (less-than sign)
/// - `>` → `&gt;` (greater-than sign)
/// - `"` → `&quot;` (double quote)
/// - `'` → `&apos;` (single quote/apostrophe)
///
/// # Rationale
/// XML parsers interpret these characters as markup delimiters. Unescaped special
/// characters would cause malformed XML or parsing errors when the output is consumed
/// by CI systems (SonarQube, Jenkins, GitLab CI, etc.).
///
/// # Use Cases
/// This function must be called on all user-supplied text inserted into XML output:
/// - `message` field in checkstyle/junit reports
/// - `path` field (file paths may contain special characters on some systems)
/// - `rule_id` field (rule identifiers are user-defined)
/// - Any other descriptive text content
pub(crate) fn escape_xml(s: &str) -> String {
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
        assert_eq!(
            escape_xml("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn escape_xml_preserves_normal_text() {
        assert_eq!(escape_xml("normal text"), "normal text");
        assert_eq!(escape_xml(""), "");
        assert_eq!(escape_xml("hello world"), "hello world");
    }
}