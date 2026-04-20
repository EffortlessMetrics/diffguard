// Red tests for escape_md function — these should FAIL before the fix and PASS after
// Based on issue #472: escape_md duplicated in diffguard-core/render.rs and diffguard/main.rs

#[cfg(test)]
mod escape_md_red_tests {
    use diffguard_types::escape_md;

    /// Test that escape_md escapes pipe character.
    /// This is the core functionality being deduplicated.
    #[test]
    fn escape_md_escapes_pipe() {
        let input = "a|b";
        let output = escape_md(input);
        // Pipe should be escaped with backslash
        assert!(
            output.contains("\\|"),
            "Pipe should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes backtick character.
    #[test]
    fn escape_md_escapes_backtick() {
        let input = "code `example`";
        let output = escape_md(input);
        // Backticks should be escaped
        assert!(
            output.contains("\\`"),
            "Backtick should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes hash character.
    #[test]
    fn escape_md_escapes_hash() {
        let input = "section #1";
        let output = escape_md(input);
        assert!(
            output.contains("\\#"),
            "Hash should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes asterisk character.
    #[test]
    fn escape_md_escapes_asterisk() {
        let input = "*bold*";
        let output = escape_md(input);
        assert!(
            output.contains("\\*"),
            "Asterisk should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes underscore character.
    #[test]
    fn escape_md_escapes_underscore() {
        let input = "_italic_";
        let output = escape_md(input);
        assert!(
            output.contains("\\_"),
            "Underscore should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes brackets.
    #[test]
    fn escape_md_escapes_brackets() {
        let input = "[link](url)";
        let output = escape_md(input);
        assert!(
            output.contains("\\["),
            "Open bracket should be escaped: got {}",
            output
        );
        assert!(
            output.contains("\\]"),
            "Close bracket should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes greater-than character.
    #[test]
    fn escape_md_escapes_greater_than() {
        let input = "> quote";
        let output = escape_md(input);
        assert!(
            output.contains("\\>"),
            "Greater-than should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes CRLF line endings.
    /// The correct behavior is CRLF-first: \r\n -> \r\n (escaped as a unit)
    #[test]
    fn escape_md_escapes_crlf() {
        let input = "line1\r\nline2";
        let output = escape_md(input);
        // CRLF should be escaped as \r\n (not \\r\\n)
        assert!(
            output.contains("\\r\\n"),
            "CRLF should be escaped as \\\\r\\\\n: got {}",
            output
        );
    }

    /// Test that escape_md escapes standalone CR.
    #[test]
    fn escape_md_escapes_cr() {
        let input = "before\rafter";
        let output = escape_md(input);
        assert!(
            output.contains("\\r"),
            "CR should be escaped: got {}",
            output
        );
    }

    /// Test that escape_md escapes standalone LF.
    #[test]
    fn escape_md_escapes_lf() {
        let input = "before\nafter";
        let output = escape_md(input);
        assert!(
            output.contains("\\n"),
            "LF should be escaped: got {}",
            output
        );
    }

    /// Integration test: verify escape_md is accessible from diffguard_types crate.
    /// This is the whole point of the deduplication - the function should be
    /// importable from diffguard_types by both diffguard-core and diffguard.
    #[test]
    fn escape_md_importable_from_diffguard_types() {
        // This should compile and run without error
        let result = diffguard_types::escape_md("test | ` # * _ [ ] > \r\n");
        assert!(
            !result.is_empty(),
            "escape_md should return non-empty result"
        );
    }
}
