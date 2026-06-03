# Specs: Idiomatic `Option<&PathBuf>` for `validate_config_for_doctor`

## Feature Description

Refactor the `validate_config_for_doctor` function in `crates/diffguard/src/main.rs` to use the idiomatic Rust `Option<&PathBuf>` parameter type instead of `&Option<PathBuf>`. This is a pure type-level API improvement with no behavior change.

## Background

The current function signature uses `&Option<PathBuf>`, which forces callers to double-reference when passing an `Option<PathBuf>` value. The idiomatic Rust pattern is to use `Option<&PathBuf>` instead, allowing callers to pass `Some(&path)` directly.

**Note:** The issue title claims `clippy::ptr_arg` lint flags this pattern, but verification confirmed the lint does NOT fire on `&Option<PathBuf>` in Rust 1.92. The fix is an API idiom improvement, not a lint fix.

## Acceptance Criteria

### AC1: Function Signature Changed
The function at line 1008 of `crates/diffguard/src/main.rs` must have the signature:
```rust
fn validate_config_for_doctor(config_path: Option<&PathBuf>, explicit_config: bool) -> bool
```

### AC2: Call Site Updated
The call site at line 1001 of `crates/diffguard/src/main.rs` must use `as_ref()`:
```rust
all_pass &= validate_config_for_doctor(config_path.as_ref(), args.config.is_some());
```

### AC3: All Tests Pass
`cargo test -p diffguard` must pass with all 19 existing tests in `doctor.rs` continuing to pass.

### AC4: No New Clippy Warnings
`cargo clippy -p diffguard` must produce zero warnings (same as before the change).

### AC5: No Behavior Change
The function's internal logic remains identical — only the parameter type changes. The destructuring `let Some(path) = config_path` inside the function works identically with both `&Option<PathBuf>` (where `path: &PathBuf`) and `Option<&PathBuf>` (where `path: &PathBuf`).

## Non-Goals

- This does not fix any lint warnings (the `clippy::ptr_arg` lint does not fire on `&Option<PathBuf>`)
- This does not change any other functions or files
- This does not change any behavior or error handling
- This does not add or remove any tests
- This does not affect any other `&Option<T>` patterns (none exist in the codebase)

## Dependencies

- Rust 1.92 / Clippy 1.92 (current toolchain)
- The single function and its single call site in `crates/diffguard/src/main.rs`

## Files Changed

- `crates/diffguard/src/main.rs` — 2 lines changed:
  - Line 1008: function signature
  - Line 1001: call site

## Verification Steps

1. `cargo clippy -p diffguard` — confirm no warnings
2. `cargo test -p diffguard` — confirm all tests pass
3. Review that only the parameter type changed and internal logic is untouched