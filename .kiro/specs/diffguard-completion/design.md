# Design Document: diffguard-completion

## Overview

This design document describes the enhancements needed to complete the diffguard implementation. The changes span multiple crates in the workspace, following the existing layered architecture (Types → Domain → App → CLI). Key enhancements include multi-language support, additional built-in rules, robust diff parsing, schema generation, and comprehensive testing.

The design maintains the existing I/O-free core principle where domain logic remains pure and testable without mocks.

## Architecture

The existing architecture remains unchanged. Enhancements are additive within each layer:

```
┌─────────────────────────────────────────────────────────────┐
│                      diffguard (CLI)                        │
│  - Config loading, git invocation, file I/O                 │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    diffguard-app                            │
│  - run_check() orchestration                                │
│  - Markdown rendering                                       │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        │                                           │
┌───────────────────┐                   ┌───────────────────┐
│  diffguard-diff   │                   │ diffguard-domain  │
│  - Diff parsing   │                   │ - Language detect │
│  - Binary/rename  │                   │ - Preprocessing   │
│    handling       │                   │ - Rule evaluation │
└───────────────────┘                   └───────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   diffguard-types                           │
│  - ConfigFile, RuleConfig, CheckReceipt DTOs                │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Language Detection (diffguard-domain/src/rules.rs)

Extend the existing `detect_language` function to support multiple languages:

```rust
/// Detects programming language from file extension.
/// Returns lowercase language identifier or None for unknown extensions.
pub fn detect_language(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?;
    match ext.to_ascii_lowercase().as_str() {
        "rs" => Some("rust"),
        "py" | "pyw" => Some("python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        "ts" | "mts" | "cts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        "java" => Some("java"),
        "kt" | "kts" => Some("kotlin"),
        "rb" | "rake" => Some("ruby"),
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" | "hh" => Some("cpp"),
        "cs" => Some("csharp"),
        _ => None,
    }
}
```

### 2. Language-Aware Preprocessor (diffguard-domain/src/preprocess.rs)

Add a `Language` enum and language-specific preprocessing modes:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Ruby,
    C,
    Cpp,
    CSharp,
    Java,
    Kotlin,
    Unknown,
}

impl Language {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "go" => Language::Go,
            "ruby" => Language::Ruby,
            "c" => Language::C,
            "cpp" => Language::Cpp,
            "csharp" => Language::CSharp,
            "java" => Language::Java,
            "kotlin" => Language::Kotlin,
            _ => Language::Unknown,
        }
    }

    /// Returns the comment syntax for this language.
    pub fn comment_syntax(self) -> CommentSyntax {
        match self {
            Language::Python | Language::Ruby => CommentSyntax::Hash,
            Language::Rust => CommentSyntax::CStyleNested,
            _ => CommentSyntax::CStyle,
        }
    }

    /// Returns the string syntax for this language.
    pub fn string_syntax(self) -> StringSyntax {
        match self {
            Language::Rust => StringSyntax::Rust,
            Language::Python => StringSyntax::Python,
            Language::JavaScript | Language::TypeScript => StringSyntax::JavaScript,
            Language::Go => StringSyntax::Go,
            _ => StringSyntax::CStyle,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSyntax {
    CStyle,       // // and /* */
    CStyleNested, // // and /* */ with nesting (Rust)
    Hash,         // # only
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringSyntax {
    CStyle,     // "..." with backslash escapes
    Rust,       // "...", r#"..."#, b"..."
    Python,     // "...", '...', """...""", '''...'''
    JavaScript, // "...", '...', `...` (template literals)
    Go,         // "...", `...` (raw strings)
}
```

The `Preprocessor` struct will be extended to accept an optional `Language` parameter:

```rust
impl Preprocessor {
    pub fn new(opts: PreprocessOptions) -> Self { /* existing */ }
    
    pub fn with_language(opts: PreprocessOptions, lang: Language) -> Self {
        Self {
            opts,
            mode: Mode::Normal,
            lang,
        }
    }
    
    pub fn set_language(&mut self, lang: Language) {
        self.lang = lang;
        self.reset();
    }
}
```

### 3. Built-in Rules (diffguard-types/src/lib.rs)

Extend `ConfigFile::built_in()` to include rules for multiple languages:

```rust
impl ConfigFile {
    pub fn built_in() -> Self {
        Self {
            defaults: Defaults::default(),
            rule: vec![
                // Existing Rust rules
                RuleConfig { id: "rust.no_unwrap".into(), /* ... */ },
                RuleConfig { id: "rust.no_dbg".into(), /* ... */ },
                
                // Python rules
                RuleConfig {
                    id: "python.no_print".into(),
                    severity: Severity::Warn,
                    message: "Remove print() before merging.".into(),
                    languages: vec!["python".into()],
                    patterns: vec![r"\bprint\s*\(".into()],
                    paths: vec!["**/*.py".into()],
                    exclude_paths: vec!["**/tests/**".into(), "**/test_*.py".into()],
                    ignore_comments: true,
                    ignore_strings: true,
                },
                RuleConfig {
                    id: "python.no_pdb".into(),
                    severity: Severity::Error,
                    message: "Remove debugger statements before merging.".into(),
                    languages: vec!["python".into()],
                    patterns: vec![r"\bimport\s+pdb\b".into(), r"\bpdb\.set_trace\s*\(".into()],
                    paths: vec!["**/*.py".into()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                },
                
                // JavaScript/TypeScript rules
                RuleConfig {
                    id: "js.no_console".into(),
                    severity: Severity::Warn,
                    message: "Remove console.log before merging.".into(),
                    languages: vec!["javascript".into(), "typescript".into()],
                    patterns: vec![r"\bconsole\.(log|debug|info)\s*\(".into()],
                    paths: vec!["**/*.js".into(), "**/*.ts".into(), "**/*.jsx".into(), "**/*.tsx".into()],
                    exclude_paths: vec!["**/tests/**".into(), "**/*.test.*".into(), "**/*.spec.*".into()],
                    ignore_comments: true,
                    ignore_strings: true,
                },
                RuleConfig {
                    id: "js.no_debugger".into(),
                    severity: Severity::Error,
                    message: "Remove debugger statements before merging.".into(),
                    languages: vec!["javascript".into(), "typescript".into()],
                    patterns: vec![r"\bdebugger\b".into()],
                    paths: vec!["**/*.js".into(), "**/*.ts".into(), "**/*.jsx".into(), "**/*.tsx".into()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                },
                
                // Go rules
                RuleConfig {
                    id: "go.no_fmt_print".into(),
                    severity: Severity::Warn,
                    message: "Remove fmt.Print* before merging.".into(),
                    languages: vec!["go".into()],
                    patterns: vec![r"\bfmt\.(Print|Println|Printf)\s*\(".into()],
                    paths: vec!["**/*.go".into()],
                    exclude_paths: vec!["**/*_test.go".into()],
                    ignore_comments: true,
                    ignore_strings: true,
                },
            ],
        }
    }
}
```

### 4. Enhanced Diff Parsing (diffguard-diff/src/unified.rs)

Add detection and handling for special diff cases:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Modified,
    Added,
    Deleted,
    Renamed { from: String },
    Binary,
    Submodule,
    ModeChange,
}

/// Extended diff line with file status tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFile {
    pub path: String,
    pub status: FileStatus,
    pub lines: Vec<DiffLine>,
}

// Detection functions
fn is_binary_file(line: &str) -> bool {
    line.starts_with("Binary files ") && line.contains(" differ")
}

fn is_submodule(line: &str) -> bool {
    line.starts_with("Subproject commit ")
}

fn parse_rename(line: &str) -> Option<&str> {
    line.strip_prefix("rename from ")
}

fn is_deleted_file(line: &str) -> bool {
    line.starts_with("deleted file mode ")
}

fn is_new_file(line: &str) -> bool {
    line.starts_with("new file mode ")
}
```

The parser will skip binary files, submodules, deleted files, and mode-only changes, continuing to process subsequent files in the diff.

### 5. Schema Generation (xtask/src/main.rs)

The existing schema generation is functional. The enhancement is to:
1. Run `xtask schema` as part of CI
2. Commit the generated schemas to the repository

No code changes needed - this is a process/CI change.

### 6. Error Handling Improvements

Error types already exist in `RuleCompileError`. Enhancements:

```rust
// In diffguard-domain/src/rules.rs - already exists, ensure messages are clear
#[derive(Debug, thiserror::Error)]
pub enum RuleCompileError {
    #[error("rule '{rule_id}' has no patterns")]
    MissingPatterns { rule_id: String },

    #[error("rule '{rule_id}' has invalid regex '{pattern}': {source}")]
    InvalidRegex {
        rule_id: String,
        pattern: String,
        source: regex::Error,
    },

    #[error("rule '{rule_id}' has invalid glob '{glob}': {source}")]
    InvalidGlob {
        rule_id: String,
        glob: String,
        source: globset::Error,
    },
}
```

CLI error handling in `main.rs` already uses `anyhow` with context - ensure all error paths provide clear messages.

## Data Models

### Existing Models (No Changes)

The following types in `diffguard-types` remain unchanged:
- `Severity`, `Scope`, `FailOn`, `VerdictStatus` enums
- `ConfigFile`, `RuleConfig`, `Defaults` structs
- `CheckReceipt`, `Finding`, `Verdict`, `VerdictCounts` structs
- `ToolMeta`, `DiffMeta` structs

### New Types (diffguard-domain)

```rust
// Language enum for preprocessing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Ruby,
    C,
    Cpp,
    CSharp,
    Java,
    Kotlin,
    #[default]
    Unknown,
}

// Comment syntax variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSyntax {
    CStyle,       // // and /* */
    CStyleNested, // // and /* */ with nesting
    Hash,         // # only
}

// String syntax variants  
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringSyntax {
    CStyle,
    Rust,
    Python,
    JavaScript,
    Go,
}
```

### Extended Diff Types (diffguard-diff)

```rust
// File status in diff
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Modified,
    Added,
    Deleted,
    Renamed { from: String },
    Binary,
    Submodule,
    ModeChange,
}
```



## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

Based on the prework analysis, the following properties have been consolidated to eliminate redundancy:

### Property 1: Language Detection Correctness

*For any* file path with a known extension (rs, py, js, ts, tsx, jsx, go, java, kt, rb, c, h, cpp, cc, cxx, hpp, cs), the `detect_language` function SHALL return the correct language identifier string.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12**

### Property 2: Unknown Extension Fallback

*For any* file path with an extension not in the known set, the `detect_language` function SHALL return None.

**Validates: Requirements 1.13**

### Property 3: Comment Masking by Language

*For any* source code line containing comments in the language's comment syntax (hash for Python/Ruby, C-style for others), when `ignore_comments` is enabled, the preprocessor SHALL replace comment content with spaces while preserving line length.

**Validates: Requirements 2.1, 2.3, 2.5, 2.7, 2.8**

### Property 4: String Masking by Language

*For any* source code line containing string literals in the language's string syntax, when `ignore_strings` is enabled, the preprocessor SHALL replace string content with spaces while preserving line length.

**Validates: Requirements 2.2, 2.4, 2.6**

### Property 5: Built-in Rules Compile Successfully

*For all* rules returned by `ConfigFile::built_in()`, the `compile_rules` function SHALL succeed without returning an error.

**Validates: Requirements 3.6**

### Property 6: Diff Parser Skips Special Files

*For any* unified diff containing binary file markers, submodule commits, mode-only changes, or deleted file markers, the `parse_unified_diff` function SHALL return successfully with no lines extracted from those special files.

**Validates: Requirements 4.1, 4.2, 4.4, 4.5**

### Property 7: Diff Parser Handles Renames

*For any* unified diff containing a file rename, the `parse_unified_diff` function SHALL use the new (destination) path for all extracted lines from that file.

**Validates: Requirements 4.3**

### Property 8: Diff Parser Resilience

*For any* unified diff where malformed content appears after a valid file header, the `parse_unified_diff` function SHALL continue processing and extract lines from subsequent valid files.

**Validates: Requirements 4.6**

### Property 9: Schema Validation Round-Trip

*For any* valid `ConfigFile` or `CheckReceipt` instance, serializing to JSON and validating against the generated JSON schema SHALL succeed.

**Validates: Requirements 5.3, 5.4**

### Property 10: Error Messages Contain Context

*For any* invalid rule configuration (invalid regex, invalid glob, or missing patterns), the error returned by `compile_rules` SHALL contain the rule ID and the specific invalid element.

**Validates: Requirements 6.1, 6.2, 6.3**

## Error Handling

### Rule Compilation Errors

The `RuleCompileError` enum provides structured errors:

| Error Variant | Cause | Message Format |
|---------------|-------|----------------|
| `MissingPatterns` | Rule has empty patterns array | "rule '{rule_id}' has no patterns" |
| `InvalidRegex` | Regex pattern fails to compile | "rule '{rule_id}' has invalid regex '{pattern}': {source}" |
| `InvalidGlob` | Glob pattern fails to compile | "rule '{rule_id}' has invalid glob '{glob}': {source}" |

### Diff Parsing Errors

The `DiffParseError` enum handles malformed diffs:

| Error Variant | Cause | Recovery |
|---------------|-------|----------|
| `MalformedHunkHeader` | Invalid @@ line format | Skip to next file |

For non-fatal issues (binary files, submodules), the parser silently skips and continues.

### CLI Error Handling

The CLI uses `anyhow` for error propagation with context:

```rust
// Config loading
let text = std::fs::read_to_string(&path)
    .with_context(|| format!("read config {}", path.display()))?;

let parsed: ConfigFile = toml::from_str(&text)
    .with_context(|| format!("parse config {}", path.display()))?;

// Git diff
if !output.status.success() {
    bail!(
        "git diff failed (exit={}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
```

Exit codes:
- `0`: Success
- `1`: Tool error (I/O, parse, git failure)
- `2`: Policy failure (error-level findings)
- `3`: Warn-level failure (when `fail_on = "warn"`)

## Testing Strategy

### Dual Testing Approach

This project uses both unit tests and property-based tests:

- **Unit tests**: Verify specific examples, edge cases, and error conditions
- **Property tests**: Verify universal properties across randomly generated inputs

### Property-Based Testing Configuration

- **Library**: `proptest` crate for Rust
- **Minimum iterations**: 100 per property test
- **Tag format**: `// Feature: diffguard-completion, Property N: {property_text}`

### Test Organization

```
crates/
├── diffguard-types/src/lib.rs      # Unit tests for DTOs
├── diffguard-diff/
│   ├── src/unified.rs              # Unit tests for parser
│   └── tests/
│       └── properties.rs           # Property tests for diff parsing
├── diffguard-domain/
│   ├── src/rules.rs                # Unit tests for rule compilation
│   ├── src/preprocess.rs           # Unit tests for preprocessor
│   ├── src/evaluate.rs             # Unit tests for evaluation
│   └── tests/
│       └── properties.rs           # Property tests for domain logic
├── diffguard-app/
│   └── src/render.rs               # Snapshot tests with insta
└── diffguard/
    └── tests/
        └── cli_check.rs            # Integration tests
```

### Snapshot Testing

Use `insta` for markdown output stability:

```rust
#[test]
fn snapshot_markdown_with_findings() {
    let receipt = create_test_receipt_with_findings();
    let md = render_markdown_for_receipt(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn snapshot_markdown_no_findings() {
    let receipt = create_test_receipt_empty();
    let md = render_markdown_for_receipt(&receipt);
    insta::assert_snapshot!(md);
}
```

### Fuzz Testing

Existing fuzz targets:
- `fuzz/fuzz_targets/unified_diff_parser.rs` - Diff parsing
- `fuzz/fuzz_targets/preprocess.rs` - Preprocessor

New fuzz target:
- `fuzz/fuzz_targets/rule_matcher.rs` - Rule evaluation

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    lines: Vec<String>,
    patterns: Vec<String>,
}

fuzz_target!(|input: FuzzInput| {
    // Build rules from patterns (skip invalid)
    // Run evaluate_lines
    // Verify no panics
});
```

### Mutation Testing

Configure `cargo-mutants` to focus on critical paths:

```toml
# mutants.toml
exclude_globs = [
    "crates/diffguard/**",  # CLI is thin wrapper
    "xtask/**",             # Build tooling
]
```

Target zero surviving mutants in:
- `diffguard-diff/src/unified.rs`
- `diffguard-domain/src/rules.rs`
- `diffguard-domain/src/evaluate.rs`
- `diffguard-domain/src/preprocess.rs`
