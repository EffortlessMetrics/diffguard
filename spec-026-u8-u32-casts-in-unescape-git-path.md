# Spec 026: u8→u32 lossless casts in unescape_git_path

## Feature/Behavior Description
Replace `as u32` casts with `u32::from()` in `unescape_git_path()` octal escape sequence parsing at lines 546 and 550 in `crates/diffguard-diff/src/unified.rs`.

## Current Code (Lines 546, 550)
```rust
let mut val = (next - b'0') as u32;           // line 546
val = val * 8 + (d - b'0') as u32;            // line 550
```

## Target Code
```rust
let mut val = u32::from(next - b'0');         // line 546
val = val * 8 + u32::from(d - b'0');          // line 550
```

## Acceptance Criteria

### AC1: Code uses u32::from()
- [ ] Line 546: `(next - b'0') as u32` replaced with `u32::from(next - b'0')`
- [ ] Line 550: `(d - b'0') as u32` replaced with `u32::from(d - b'0')`

### AC2: No as u32 casts remain in unified.rs
- [ ] `grep -n "as u32" unified.rs` returns no matches

### AC3: Tests pass
- [ ] `cargo test -p diffguard-diff` passes all 40 tests

### AC4: Clippy clean
- [ ] `cargo clippy -p diffguard-diff -- -D warnings` produces no warnings

### AC5: Fuzz tests pass
- [ ] `cargo +nightly fuzz run unified_diff_parser` runs without crashes (run for at least 30 seconds)

## Non-Goals
- This spec does not address other `as` casts elsewhere in the codebase
- This spec does not modify the parsing logic — only the cast style

## Dependencies
- None beyond existing test infrastructure
