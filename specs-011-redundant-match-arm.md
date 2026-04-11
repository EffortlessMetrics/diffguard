# Specification: Remove Redundant Match Arm in `string_syntax()`

## Issue

GitHub issue #136 reports a redundant match arm in `preprocess.rs` where `Language::Json` is explicitly matched but then shadowed by the wildcard `_` pattern.

## Current Code (lines 107-109)

```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
_ => StringSyntax::CStyle,
```

## Problem

The wildcard `_` catches **all** `Language` variants not explicitly matched, including `Language::Json`. Since both the explicit `Language::Json` arm and the wildcard produce the same result (`StringSyntax::CStyle`), the arm is redundant.

## Fixed Code

```rust
// YAML/TOML strings are C-style-like in this best-effort model
// (JSON is handled by the wildcard below since JSON uses C-style strings)
Language::Yaml | Language::Toml => StringSyntax::CStyle,
// All other languages (including JSON, C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

## Acceptance Criteria

1. `Language::Json` is removed from the explicit match arm
2. Comment on line 107 explains JSON is handled by the wildcard
3. Wildcard arm has a comment explaining it catches JSON and other languages
4. Both YAML and TOML remain explicitly handled (not redundant)
5. `cargo clippy -p diffguard-domain` shows no warnings for this match
6. `cargo test -p diffguard-domain` passes with no changes to test behavior

## Non-Goals

- No functional change — `Language::Json` still produces `StringSyntax::CStyle`
- No changes to other `Language` variants
- No changes to `comment_syntax()` function (already correct)

## Dependencies

- None — this is a pure code cleanup with no new dependencies

## Test Plan

1. **Compile check:** `cargo build -p diffguard-domain` succeeds
2. **Clippy check:** `cargo clippy -p diffguard-domain` shows no redundant match arm warnings
3. **Test suite:** `cargo test -p diffguard-domain` passes
4. **Visual verification:** Inspect `string_syntax()` function to confirm comment clarity matches `comment_syntax()` pattern