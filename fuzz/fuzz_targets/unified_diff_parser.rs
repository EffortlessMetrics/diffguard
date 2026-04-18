//! Fuzz target for unified diff parser.
//!
//! This target exercises the parse_unified_diff function with both
//! arbitrary byte input and structured diff-like input to discover
//! edge cases in diff parsing.
//!
//! Requirements: 8.1-8.4

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

/// Structured fuzz input that generates diff-like content.
#[derive(Arbitrary, Debug)]
struct DiffInput {
    /// Scope selector (mapped to Added/Changed/Modified/Deleted).
    scope_selector: u8,
    /// File entries in the diff.
    files: Vec<FuzzFile>,
}

/// A fuzzed file entry in a diff.
#[derive(Arbitrary, Debug)]
struct FuzzFile {
    /// File path (will be sanitized).
    path: String,
    /// Hunks in the file.
    hunks: Vec<FuzzHunk>,
    /// Whether this is a binary file.
    is_binary: bool,
    /// Whether this is a deleted file.
    is_deleted: bool,
    /// Whether this is a renamed file.
    is_renamed: bool,
    /// New path for renamed files.
    rename_to: String,
}

/// A fuzzed hunk in a diff.
#[derive(Arbitrary, Debug)]
struct FuzzHunk {
    /// Starting line number in new file.
    new_start: u16,
    /// Lines in the hunk.
    lines: Vec<FuzzLine>,
}

/// A fuzzed line in a hunk.
#[derive(Arbitrary, Debug)]
enum FuzzLine {
    Context(String),
    Added(String),
    Removed(String),
}

impl DiffInput {
    /// Generate a diff string from this structured input.
    fn to_diff_string(&self) -> String {
        let mut out = String::new();

        for file in &self.files {
            // Sanitize path - remove problematic characters
            let path: String = file
                .path
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '/' || *c == '.' || *c == '_' || *c == '-')
                .take(50)
                .collect();
            let path = if path.is_empty() { "file.txt" } else { &path };

            // File header
            out.push_str(&format!("diff --git a/{} b/{}\n", path, path));

            if file.is_binary {
                out.push_str(&format!(
                    "Binary files a/{} and b/{} differ\n",
                    path, path
                ));
                continue;
            }

            if file.is_deleted {
                out.push_str("deleted file mode 100644\n");
                out.push_str(&format!("--- a/{}\n", path));
                out.push_str("+++ /dev/null\n");
                continue;
            }

            if file.is_renamed {
                let rename_to: String = file
                    .rename_to
                    .chars()
                    .filter(|c| {
                        c.is_alphanumeric() || *c == '/' || *c == '.' || *c == '_' || *c == '-'
                    })
                    .take(50)
                    .collect();
                let rename_to = if rename_to.is_empty() {
                    "new_file.txt"
                } else {
                    &rename_to
                };

                out.push_str(&format!("rename from {}\n", path));
                out.push_str(&format!("rename to {}\n", rename_to));
                out.push_str(&format!("--- a/{}\n", path));
                out.push_str(&format!("+++ b/{}\n", rename_to));
            } else {
                out.push_str(&format!("--- a/{}\n", path));
                out.push_str(&format!("+++ b/{}\n", path));
            }

            for hunk in &file.hunks {
                let new_start = hunk.new_start.max(1);
                let line_count = hunk.lines.len().min(100);

                out.push_str(&format!(
                    "@@ -1,{} +{},{} @@\n",
                    line_count, new_start, line_count
                ));

                for line in hunk.lines.iter().take(100) {
                    // Sanitize line content - remove newlines
                    let content: String = match line {
                        FuzzLine::Context(s) | FuzzLine::Added(s) | FuzzLine::Removed(s) => s
                            .chars()
                            .filter(|c| *c != '\n' && *c != '\r')
                            .take(200)
                            .collect(),
                    };

                    match line {
                        FuzzLine::Context(_) => out.push_str(&format!(" {}\n", content)),
                        FuzzLine::Added(_) => out.push_str(&format!("+{}\n", content)),
                        FuzzLine::Removed(_) => out.push_str(&format!("-{}\n", content)),
                    }
                }
            }
        }

        out
    }
}

fuzz_target!(|input: DiffInput| {
    let diff_text = input.to_diff_string();
    let scope = match input.scope_selector % 4 {
        0 => Scope::Added,
        1 => Scope::Changed,
        2 => Scope::Modified,
        _ => Scope::Deleted,
    };

    // Parse the generated diff - should not panic
    let result = parse_unified_diff(&diff_text, scope);

    // If parsing succeeds, verify some basic properties
    if let Ok((lines, stats)) = result {
        // Stats should be consistent
        assert_eq!(
            stats.lines as usize,
            lines.len(),
            "Stats.lines should equal lines.len()"
        );

        // Line numbers should be positive
        for line in &lines {
            assert!(line.line >= 1, "Line numbers should be >= 1");
            assert!(!line.path.is_empty(), "Paths should not be empty");
        }

        // If we used Changed scope, all lines should have kind Changed
        // (when they come from removals followed by additions)
        // Note: this is not always true - pure additions have kind Added
    }

    // Also test with the other scope for comparison
    let other_scope = match scope {
        Scope::Added => Scope::Changed,
        Scope::Changed => Scope::Modified,
        Scope::Modified => Scope::Deleted,
        Scope::Deleted => Scope::Added,
    };
    let _ = parse_unified_diff(&diff_text, other_scope);
});
