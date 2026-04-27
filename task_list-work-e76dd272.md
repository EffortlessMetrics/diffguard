# Task List: format_push_string Fix for diffguard-core

## Implementation Tasks

- [ ] Fix `crates/diffguard-core/src/junit.rs`:
  - [ ] Line 39: `push_str(&format!(...))` → `write!(out, ...)`
  - [ ] Line 51: `push_str(&format!(...))` → `write!(out, ...)`
  - [ ] Line 63: `push_str(&format!(...))` → `write!(out, ...)`
  - [ ] Line 77: `push_str(&format!(...))` → `write!(out, ...)`
  - [ ] Line 82: `push_str(&format!(...))` → `write!(out, ...)`

- [ ] Fix `crates/diffguard-core/src/render.rs`:
  - [ ] Line 41: `push_str(&format!(...))` → `write!(out, ...)`
  - [ ] Line 43: `push_str(&format!(...))` → `write!(out, ...)`
  - [ ] Line 61: `push_str(&format!(...))` → `writeln!(out, ...)`
  - [ ] Line 67: `push_str(&format!(...))` → `write!(out, ...)`

- [ ] Fix `crates/diffguard-core/src/checkstyle.rs`:
  - [ ] Line 69: `push_str(&format!(...))` → `write!(out, ...)`

## Verification Tasks

- [ ] Run `cargo clippy -p diffguard-core -- -W clippy::format_push_string` — must show 0 warnings
- [ ] Run `cargo test -p diffguard-core` — all tests must pass
- [ ] Review insta snapshots with `cargo insta review` if any changes detected
- [ ] Verify output format is byte-identical before/after
