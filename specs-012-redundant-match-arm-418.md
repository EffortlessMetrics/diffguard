# Specification: Remove Redundant Match Arm in `string_syntax()` (Issue #418)

## Issue

GitHub issue #418 reports a redundant match arm in `preprocess.rs` where `Language::Json` is explicitly matched but then shadowed by the wildcard `_` pattern.

## Current Code (lines 106-109)

```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

## Problem

The wildcard `_` catches **all** `Language` variants not explicitly matched, including `Language::Json`. Since both the explicit `Language::Json` arm and the wildcard produce the same result (`StringSyntax::CStyle`), the arm is redundant dead code.

Additionally, the code is inconsistent with `comment_syntax()` (lines 80-84) which correctly handles JSON via the wildcard with an explicit comment noting this.

## Fixed Code

```rust
// YAML/TOML strings are C-style-like in this best-effort model
// (JSON is handled by the wildcard below since JSON uses C-style strings)
Language::Yaml | Language::Toml => StringSyntax::CStyle,
// All other languages (including JSON, C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

## Acceptance Criteria

1. `Language::Json` is removed from the explicit match arm at line 107
2. Comment on line 106 is updated to remove "/JSON"
3. A clarifying comment is added noting JSON is handled by the wildcard below
4. Wildcard arm comment explicitly mentions JSON is caught by it
5. Both YAML and TOML remain explicitly handled (not redundant)
6. `cargo test -p diffguard-domain` passes with no changes to test behavior

## Non-Goals

- No functional change — `Language::Json` still produces `StringSyntax::CStyle` (via wildcard)
- No changes to other `Language` variants
- No changes to `comment_syntax()` function (already correct)
- No clippy warning fix (there is none — verification confirms zero warnings)

## Dependencies

- None — this is a pure code cleanup with no new dependencies

## Test Plan

1. **Compile check:** `cargo build -p diffguard-domain` succeeds
2. **Test suite:** `cargo test -p diffguard-domain` passes (existing tests verify `Language::Json.string_syntax() == StringSyntax::CStyle`)
3. **Visual verification:** Inspect `string_syntax()` function to confirm comment clarity matches `comment_syntax()` pattern