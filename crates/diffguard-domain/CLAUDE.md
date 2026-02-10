# CLAUDE.md - diffguard-domain

## Crate Purpose

Core business logic: rule compilation, line evaluation, text preprocessing, and inline suppression handling.

## Key Constraints

- **No I/O** - Must not use `std::process`, `std::fs`, or `std::env`
- **Pure functions** - All logic should be testable without mocks
- **Best-effort preprocessing** - Uses C-like syntax heuristics, not full language parsers

## Module Structure

| Module | Purpose |
|--------|---------|
| `rules.rs` | Compile `RuleConfig` → `CompiledRule` with regex/globs |
| `evaluate.rs` | Match lines against rules, produce findings |
| `preprocess.rs` | Mask comments/strings before matching |
| `suppression.rs` | Parse and track `diffguard: ignore` directives |

## Key APIs

### Rule Compilation (`rules.rs`)

```rust
pub fn compile_rules(configs: &[RuleConfig]) -> Result<Vec<CompiledRule>>
pub fn detect_language(path: &str) -> Option<Language>
```

`CompiledRule` contains:
- Pre-compiled regex patterns
- GlobSets for path include/exclude
- Language filters

### Line Evaluation (`evaluate.rs`)

```rust
pub fn evaluate_lines(rules: &[CompiledRule], lines: &[InputLine]) -> Evaluation
```

Returns `Evaluation` with:
- `findings: Vec<Finding>` - All matches
- `counts: VerdictCounts` - Aggregated by severity

### Preprocessing (`preprocess.rs`)

```rust
pub fn Preprocessor::new(lang: Language, options: PreprocessOptions) -> Self
pub fn sanitize(&self, line: &str) -> String
```

Supported languages: Rust, Python, JavaScript, TypeScript, Go, Ruby, C, C++, C#, Java, Kotlin, Shell

### Suppressions (`suppression.rs`)

Supported formats:
- `diffguard: ignore <rule_id>` - Same line
- `diffguard: ignore-next-line <rule_id>` - Next line
- `diffguard: ignore *` or `diffguard: ignore-all` - All rules
- Multiple rules: `diffguard: ignore rule1, rule2`

## Common Tasks

### Adding a new rule config option

1. Add field to `RuleConfig` in `diffguard-types`
2. Update `CompiledRule` in `rules.rs` if needed at compile time
3. Update `evaluate_line()` in `evaluate.rs`
4. Add unit tests
5. Run mutation tests: `cargo mutants -p diffguard-domain`

### Adding a new language

1. Add variant to `Language` enum in `preprocess.rs`
2. Add `CommentSyntax` and `StringSyntax` for the language
3. Update `Language::from_extension()` with file extensions
4. Update `detect_language()` in `rules.rs`
5. Add tests for the new language

### Modifying suppression syntax

1. Update `parse_suppression()` in `suppression.rs`
2. Update `SuppressionTracker` if tracking behavior changes
3. Add test cases for new syntax

## Testing

```bash
cargo test -p diffguard-domain          # Unit tests
cargo mutants -p diffguard-domain       # Mutation testing
cargo +nightly fuzz run preprocess      # Fuzz preprocessor
cargo +nightly fuzz run rule_matcher    # Fuzz rule matching
```

## Preprocessing Limitations

The preprocessor is intentionally simple:
- Uses C-like syntax heuristics
- Not a full parser for any language
- May miss edge cases in complex string/comment nesting
- This is acceptable - false negatives are preferred over false positives
