# Research Analysis: redundant match arm in preprocess.rs

## Issue Summary
**Issue**: GitHub issue #136 — "preprocess.rs: redundant match arm — Language::Json is shadowed by wildcard"

In `crates/diffguard-domain/src/preprocess.rs`, the `Language` enum match arms in `comment_syntax()` and `string_syntax()` methods have redundant arms where `Language::Json` is explicitly matched but then also caught by the catch-all `_ =>` wildcard pattern.

## Issue Details

### Location 1: `comment_syntax()` (lines 69–86)

```rust
pub fn comment_syntax(self) -> CommentSyntax {
    match self {
        Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,
        Language::Rust | Language::Swift | Language::Scala => CommentSyntax::CStyleNested,
        Language::Sql => CommentSyntax::Sql,
        Language::Xml => CommentSyntax::Xml,
        Language::Php => CommentSyntax::Php,
        Language::Yaml | Language::Toml => CommentSyntax::Hash,
        Language::Json => CommentSyntax::CStyle,  // ← REDUNDANT
        _ => CommentSyntax::CStyle,
    }
}
```

### Location 2: `string_syntax()` (lines 89–111)

```rust
pub fn string_syntax(self) -> CommentSyntax {
    match self {
        Language::Rust => StringSyntax::Rust,
        Language::Python => StringSyntax::Python,
        Language::JavaScript | Language::TypeScript | Language::Ruby => StringSyntax::JavaScript,
        Language::Go => StringSyntax::Go,
        Language::Shell => StringSyntax::Shell,
        Language::Swift | Language::Scala => StringSyntax::SwiftScala,
        Language::Sql => StringSyntax::Sql,
        Language::Xml => StringSyntax::Xml,
        Language::Php => StringSyntax::Php,
        Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,  // ← GROUP PARTIALLY REDUNDANT
        _ => StringSyntax::CStyle,
    }
}
```

In `string_syntax()`, the line `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` is partially redundant because the catch-all `_ => StringSyntax::CStyle` already covers `Language::Json`. However, keeping `YAML` and `TOML` explicitly listed may be intentional for documentation purposes since they are not covered by the catch-all (the catch-all covers C, Cpp, CSharp, Java, Kotlin, JavaScript, TypeScript, Go, Ruby, and Unknown).

## Relevant Codebase Areas

### File: `crates/diffguard-domain/src/preprocess.rs`
- **Lines 9–31**: `Language` enum definition with 21 variants (Rust, Python, JavaScript, TypeScript, Go, Ruby, C, Cpp, CSharp, Java, Kotlin, Shell, Swift, Scala, Sql, Xml, Php, Yaml, Toml, Json, Unknown)
- **Lines 69–86**: `comment_syntax()` method — `Language::Json` arm (line 83) is fully redundant
- **Lines 89–111**: `string_syntax()` method — `Language::Json` within the group arm (line 108) is redundant (caught by catch-all)

### Other Files
- `fuzz/fuzz_targets/preprocess.rs` — fuzzing target for the preprocessor
- `crates/diffguard-domain/src/rules.rs` — uses `Language` for rule matching
- `crates/diffguard-domain/src/preprocess.rs` tests (lines ~1015, ~1039, ~1083, ~2647)

## Dependencies and Constraints
- **No I/O constraint**: diffguard-domain must not use `std::process`, `std::fs`, or `std::env`
- **Pure functions required**: All logic testable without mocks
- **Best-effort preprocessing**: Uses C-like syntax heuristics, not full language parsers
- **Mutation testing**: The crate runs `cargo mutants` for mutation testing

## Key Findings

1. **`comment_syntax()` redundancy**: The `Language::Json => CommentSyntax::CStyle` arm at line 83 is fully redundant — it produces the same output (`CStyle`) as the catch-all `_ => CommentSyntax::CStyle` at line 84.

2. **`string_syntax()` partial redundancy**: In the arm `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle`, only `Json` is redundant since the catch-all already returns `CStyle` for `Json`. `Yaml` and `Toml` are NOT covered by the catch-all.

3. **Rustc warning**: This generates E0017 (redundant match arm) or similar warning — the arms are unreachable or provably redundant.

4. **Existing test coverage**: Tests exist for `Language::Json.comment_syntax()` (line 1083) and `jsonc_double_slash_comment_ignored` (line 2647), confirming `Json` should return `CStyle`.

## Recommended Fix
- In `comment_syntax()`: Remove the `Language::Json => CommentSyntax::CStyle,` line (83)
- In `string_syntax()`: Change `Language::Yaml | Language::Toml | Language::Json` to `Language::Yaml | Language::Toml` (removing `Json` from the group)

## Risk Assessment
- **Low risk**: The fix is a pure refactoring — no functional change since `Json` already returns `CStyle` via the catch-all
- **Test impact**: Existing tests should continue to pass since behavior is unchanged
