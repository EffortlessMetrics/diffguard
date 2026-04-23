# Specs — work-0ba842de

## Overview
Fix incorrect documentation strings in the `RustQuality` preset in `crates/diffguard/src/presets.rs`. The doc comment (line 13) and description method (line 40) list shorthand rule names (`no_todo`, `no_print`) that don't match the actual generated rule IDs (`rust.no_todo`, `rust.no_println`).

## Acceptance Criteria

- **AC1**: Line 13 doc comment in presets.rs uses `(rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)` instead of `(no_unwrap, no_dbg, no_todo, no_print)`
- **AC2**: Line 40 description() uses `(rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)` instead of `(no unwrap, no dbg, no todo, no print)`
- **AC3**: Code compiles without errors (`cargo check -p diffguard`)
- **AC4**: Existing tests pass (`cargo test -p diffguard`)

## Implementation Details

### Files to Modify
- `crates/diffguard/src/presets.rs`

### Changes

1. **Line 13** (enum variant doc comment):
   - Current: `/// Rust best practices (no_unwrap, no_dbg, no_todo, no_print)`
   - New: `/// Rust best practices (rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)`

2. **Line 40** (description() method):
   - Current: `"Rust best practices (no unwrap, no dbg, no todo, no print)"`
   - New: `"Rust best practices (rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)"`

### Verification
1. Run `cargo check -p diffguard` to verify compilation
2. Run `cargo test -p diffguard` to verify tests pass
3. Run `cargo test -p diffguard --doc` to verify doc tests pass