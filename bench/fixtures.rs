//! Synthetic fixture generators for benchmarks
//!
//! This module provides in-memory generators for all benchmark inputs.
//! Sizes beyond testkit bounds (e.g., 100K lines) are generated directly here.
//!
//! # Design Notes
//!
//! - All generators produce in-memory data (no file I/O)
//! - DiffLine → InputLine conversion helper is provided
//! - Preprocessor state management is documented in each benchmark

use diffguard_diff::DiffLine;
use diffguard_domain::InputLine;

/// Generate a synthetic unified diff text with the specified number of lines.
///
/// # Arguments
///
/// * `num_lines` - Number of content lines to generate (not counting diff headers)
/// * `path` - File path to use in the diff header
///
/// # Output Format
///
/// ```diff
/// diff --git a/path/to/file.rs b/path/to/file.rs
/// index 1234567..abcdefg 100644
/// --- a/path/to/file.rs
/// +++ b/path/to/file.rs
/// @@ -1,N +1,N @@
/// +line content here
/// ...
/// ```
///
/// # Performance Note
///
/// This generator is O(n) and allocates ~50 bytes per line.
/// For 100K lines, this is approximately 5MB of allocated text.
pub fn generate_unified_diff(num_lines: usize, path: &str) -> String {
    if num_lines == 0 {
        return String::new();
    }

    let mut output = String::with_capacity(num_lines * 60);

    // Diff header
    output.push_str(&format!("diff --git a/{} b/{}\n", path, path));
    output.push_str("index 1234567..abcdefg 100644\n");
    output.push_str(&format!("--- a/{}\n", path));
    output.push_str(&format!("+++ b/{}\n", path));

    // Hunk header - use a single hunk for simplicity
    output.push_str(&format!("@@ -1,{} +1,{} @@\n", num_lines, num_lines));

    // Generate content lines
    for i in 1..=num_lines {
        output.push_str(&format!(
            "+line {} content here with some padding to simulate real code\n",
            i
        ));
    }

    output
}

/// Generate a unified diff with mixed change kinds (added, deleted, context).
///
/// This produces a more realistic diff with all three change types.
pub fn generate_mixed_unified_diff(num_lines: usize, path: &str) -> String {
    if num_lines == 0 {
        return String::new();
    }

    let mut output = String::with_capacity(num_lines * 60);

    output.push_str(&format!("diff --git a/{} b/{}\n", path, path));
    output.push_str("index 1234567..abcdefg 100644\n");
    output.push_str(&format!("--- a/{}\n", path));
    output.push_str(&format!("+++ b/{}\n", path));

    let chunk_size = 10;
    for chunk in (1..=num_lines).step_by(chunk_size) {
        let end = (chunk + chunk_size - 1).min(num_lines);
        output.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            chunk,
            end - chunk + 1,
            chunk,
            end - chunk + 1
        ));

        for i in chunk..=end {
            let kind = i % 3;
            match kind {
                0 => output.push_str(&format!("+line {} added content\n", i)),
                1 => output.push_str(&format!("-line {} removed content\n", i)),
                _ => output.push_str(&format!(" line {} context\n", i)),
            }
        }
    }

    output
}

/// Convert a DiffLine to an InputLine.
///
/// DiffLine has an extra `kind: ChangeKind` field that InputLine doesn't have.
/// This conversion strips the kind field, making it suitable for evaluation.
///
/// # Why This Matters
///
/// Benchmarks that measure the full pipeline (parse → evaluate → render) must
/// include this conversion in the measured path, since it's required in production.
pub fn convert_diff_line_to_input_line(diff_line: DiffLine) -> InputLine {
    InputLine {
        path: diff_line.path,
        line: diff_line.line,
        content: diff_line.content,
    }
}

/// Convert a slice of DiffLines to InputLines.
///
/// This is a convenience wrapper around `convert_diff_line_to_input_line`
/// that operates on an entire slice, returning a Vec of InputLines.
pub fn convert_diff_lines_to_input_lines(diff_lines: &[DiffLine]) -> Vec<InputLine> {
    diff_lines
        .iter()
        .map(|dl| convert_diff_line_to_input_line(dl.clone()))
        .collect()
}

/// Generate synthetic InputLines for evaluation benchmarks.
///
/// Unlike DiffLines, InputLines don't have a `kind` field.
/// This generator creates plain code lines without diff-specific metadata.
pub fn generate_input_lines(num_lines: usize, path: &str) -> Vec<InputLine> {
    (1..=num_lines)
        .map(|line| InputLine {
            path: path.to_string(),
            line: line as u32,
            content: format!("line {} content here with some padding\n", line),
        })
        .collect()
}

/// Generate lines with a specific comment density.
///
/// # Arguments
///
/// * `num_lines` - Total number of lines
/// * `comment_density` - Fraction of lines that are comments (0.0 to 1.0)
/// * `language` - Which language's comment syntax to use
///
/// # Languages
///
/// - `rust`: `//` comments and `/* */` block comments
/// - `python`: `#` comments and `"""` triple-quoted strings
/// - `javascript`: `//` comments and `/* */` block comments
pub fn generate_lines_with_comment_density(
    num_lines: usize,
    comment_density: f32,
    language: &str,
) -> Vec<String> {
    let comment_prefix = match language {
        "rust" | "javascript" | "c" | "cpp" | "java" | "go" | "c#" => "// ",
        "python" | "ruby" | "shell" | "yaml" | "toml" | "ini" => "# ",
        "html" | "xml" | "svg" => "<!-- -->",
        _ => "// ",
    };

    let block_comment_start = match language {
        "rust" | "c" | "cpp" | "java" | "javascript" | "go" | "c#" => "/* ",
        "python" => "\"\"\"",
        _ => "/* ",
    };

    let block_comment_end = match language {
        "python" => "\"\"\"",
        _ => " */",
    };

    (0..num_lines)
        .map(|i| {
            let is_comment = (i as f32 / num_lines as f32) < comment_density;
            if is_comment {
                if i % 5 == 0 && language != "python" {
                    // Block comment
                    format!(
                        "{}{} block comment {} {}",
                        comment_prefix, block_comment_start, i, block_comment_end
                    )
                } else {
                    format!("{}{} line comment {}", comment_prefix, i, block_comment_end)
                }
            } else {
                format!("let x_{} = {}; // regular code line {}", i, i * 2, i)
            }
        })
        .collect()
}

/// Generate a CheckReceipt with a specified number of findings.
///
/// This is used for rendering benchmarks where we pre-construct the receipt
/// outside the measured timing path.
pub fn generate_receipt_with_findings(
    _num_findings: usize,
    findings: Vec<diffguard_types::Finding>,
) -> diffguard_types::CheckReceipt {
    use diffguard_types::{
        CheckReceipt, DiffMeta, Scope, TimingMetrics, ToolMeta, Verdict, VerdictCounts,
        VerdictStatus,
    };

    CheckReceipt {
        schema: "diffguard.v1".to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "abc123".to_string(),
            head: "def456".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 100,
        },
        findings,
        verdict: Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: Some(TimingMetrics {
            total_ms: 42,
            diff_parse_ms: 10,
            rule_compile_ms: 5,
            evaluation_ms: 27,
        }),
    }
}

/// Preprocessor state management helper.
///
/// # Stateful Benchmarking
///
/// `Preprocessor::sanitize_line()` requires `&mut self` and tracks multi-line
/// comment/string state. Benchmarks must reset state between iterations.
///
/// # Approach Options
///
/// 1. **Fresh instance per iteration**: Safest, but includes allocation cost.
/// 2. **Reset between iterations**: More realistic for pipeline, requires explicit reset.
///
/// This module documents which approach each benchmark uses.
pub mod preprocessor_helpers {
    use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};

    /// Create a fresh preprocessor for the given language.
    ///
    /// Returns a new Preprocessor instance configured with `comments_and_strings`
    /// options for the specified language. Each call produces an independent
    /// instance with no multi-line comment/string state.
    pub fn fresh_preprocessor(lang: Language) -> Preprocessor {
        let opts = PreprocessOptions::comments_and_strings();
        Preprocessor::with_language(opts, lang)
    }

    /// Reset an existing preprocessor to normal mode.
    ///
    /// Clears any accumulated multi-line comment/string state, returning
    /// the preprocessor to its initial state. This allows reuse of a
    /// single Preprocessor instance across multiple benchmark iterations
    /// without the allocation cost of creating a fresh instance each time.
    pub fn reset_preprocessor(preprocessor: &mut Preprocessor) {
        preprocessor.reset();
    }
}
