# diffguard-diff

Unified diff parser for the [diffguard](https://crates.io/crates/diffguard) governance linter.

This crate parses `git diff` style unified diffs and extracts added/changed lines with their metadata. It is I/O-free (pure parsing) and fuzz-tested to ensure it never panics on malformed input.

## Features

- Parse unified diff format from `git diff` output
- Extract added and modified lines with line numbers and file paths
- Filter by scope: `Added` (new lines only) or `Changed` (new + modified)
- Detect and handle special cases:
  - Binary files (skipped)
  - Submodule changes (skipped)
  - File renames (tracked correctly)
  - Mode-only changes (no content lines)
  - Missing newline at EOF
  - Deleted files (skipped for "added" scope)
- **Never panics** — malformed input returns errors

## Usage

```rust
use diffguard_diff::{parse_unified_diff, ChangeKind};
use diffguard_types::Scope;

let diff_text = r#"
diff --git a/src/main.rs b/src/main.rs
index 1234567..abcdefg 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,3 +1,4 @@
 fn main() {
+    println!("Hello, world!");
 }
"#;

// Parse with "Added" scope - only truly new lines
let lines = parse_unified_diff(diff_text, Scope::Added)?;

for line in &lines {
    println!("{}:{} - {}", line.path, line.line_no, line.content);
}
```

## API

### Main Function

```rust
pub fn parse_unified_diff(input: &str, scope: Scope) -> Result<Vec<DiffLine>>
```

### Output Types

```rust
pub struct DiffLine {
    pub path: String,       // File path (e.g., "src/main.rs")
    pub line_no: usize,     // Line number in new file
    pub content: String,    // Line content (without +/- prefix)
    pub kind: ChangeKind,   // Added or Changed
}

pub enum ChangeKind {
    Added,    // New line (+ in diff)
    Changed,  // Modified context (when scope=Changed)
}

pub struct DiffStats {
    pub files_changed: usize,
    pub lines_added: usize,
    pub lines_removed: usize,
}
```

### Detection Helpers

```rust
pub fn is_binary_file(line: &str) -> bool
pub fn is_submodule(line: &str) -> bool
pub fn is_new_file(line: &str) -> bool
pub fn is_deleted_file(line: &str) -> bool
pub fn is_mode_change_only(line: &str) -> bool
pub fn parse_rename_from(line: &str) -> Option<String>
pub fn parse_rename_to(line: &str) -> Option<String>
```

## Robustness

This crate is fuzz-tested to ensure it handles malformed input gracefully:

```bash
cargo +nightly fuzz run unified_diff_parser
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
