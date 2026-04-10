# Plan: Remove Dead Match Arms in preprocess.rs (Issue #136)

## Goal

Remove unreachable `Language::Json` match arms from `comment_syntax()` and `string_syntax()` in `preprocess.rs` — these are shadowed by wildcard arms and can never execute.

## Issue

**#136** — `preprocess.rs: redundant match arm — Language::Json is shadowed by wildcard`

### Problem 1: `comment_syntax` method
```rust
Language::Json => CommentSyntax::CStyle,  // ← unreachable (covered by _ arm)
_ => CommentSyntax::CStyle,
```

### Problem 2: `string_syntax` method
```rust
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
_ => StringSyntax::CStyle,  // ← Json is covered by wildcard
```

Both `Language::Json` arms are dead code — the wildcard covers them.

## Proposed Fix

### Step 1 — Fix `comment_syntax` in `crates/diffguard-domain/src/preprocess.rs`

Remove `Language::Json` from the match arm:
```rust
// Before:
Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,
Language::Yaml | Language::Toml => CommentSyntax::Hash,
Language::Json => CommentSyntax::CStyle,
_ => CommentSyntax::CStyle,

// After:
Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,
Language::Yaml | Language::Toml => CommentSyntax::CStyle,  // Json merged into CStyle
_ => CommentSyntax::CStyle,
```

### Step 2 — Fix `string_syntax` in the same file

```rust
// Before:
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
_ => StringSyntax::CStyle,

// After:
Language::Yaml | Language::Toml => StringSyntax::CStyle,
_ => StringSyntax::CStyle,
```

### Step 3 — Verify clippy is happy

Run `cargo clippy -p diffguard-domain` to confirm the `match_same_names` warning (already suppressed with `#[expect(clippy::match_same_names)]`) is resolved or still suppressed.

## Files Likely to Change

- `crates/diffguard-domain/src/preprocess.rs` — remove dead arms in `comment_syntax()` and `string_syntax()`

## Tests / Validation

1. `cargo test -p diffguard-domain` — all tests pass
2. `cargo clippy -p diffguard-domain` — clean
3. Review that the `#[expect(clippy::match_same_names)]` attribute can be removed if no longer needed

## Risks

- **Low risk** — removing dead code, no functional change
- **Json preprocessing behavior**: Need to verify that JSON files were previously treated as `CStyle` (they were — the wildcard always matched). No behavior change.

## Effort

**Small** — ~10 minutes, 2 match arms removed, trivial change.
