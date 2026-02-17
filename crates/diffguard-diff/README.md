# diffguard-diff

Unified diff parser for the [diffguard](https://crates.io/crates/diffguard) governance linter.

This crate parses `git diff` style unified diffs and extracts scoped lines with their metadata. It is I/O-free (pure parsing) and fuzz-tested to ensure it never panics on malformed input.

## Features

- Parse unified diff format from `git diff` output
- Extract added/modified/deleted lines with line numbers and file paths
- Filter by scope:
  - `Added` (all added lines)
  - `Changed` / `Modified` (only added lines that directly follow removals)
  - `Deleted` (removed lines)
- Detect and handle special cases:
  - Binary files (skipped)
  - Submodule changes (skipped)
  - File renames (tracked correctly)
  - Mode-only changes (no content lines)
  - Missing newline at EOF
  - Deleted files (skipped unless scope is `Deleted`)
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
let (lines, stats) = parse_unified_diff(diff_text, Scope::Added)?;

for line in &lines {
    println!("{}:{} - {}", line.path, line.line, line.content);
}
println!("scanned files={}, lines={}", stats.files, stats.lines);
```

## API

### Main Function

```rust
pub fn parse_unified_diff(input: &str, scope: Scope) -> Result<(Vec<DiffLine>, DiffStats)>
```

### Output Types

```rust
pub struct DiffLine {
    pub path: String,       // File path (e.g., "src/main.rs")
    pub line: u32,          // Line number in old/new file depending on scope
    pub content: String,    // Line content (without +/- prefix)
    pub kind: ChangeKind,   // Added, Changed, or Deleted
}

pub enum ChangeKind {
    Added,    // New line (+ in diff)
    Changed,  // Added line that replaces removed content
    Deleted,  // Removed line (- in diff)
}

pub struct DiffStats {
    pub files: u32,
    pub lines: u32,
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
