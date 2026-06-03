# Task List — work-8526ea59

## Implementation Tasks

### Task 1: Apply fix to evaluate.rs:298
- [ ] Replace line 298 in `crates/diffguard-domain/src/evaluate.rs` from:
  ```rust
  .and_then(|c| u32::try_from(c).ok());
  ```
  To:
  ```rust
  // Explicit truncation: u32 cannot represent columns > ~4.3B chars.
  // A single line this long is practically impossible in diff content.
  // Using .min() instead of .ok() makes the truncation explicit rather than silent.
  .and_then(|c| Some(c.min(u32::MAX as usize) as u32))
  ```

### Task 2: Verify build
- [ ] Run `cargo build -p diffguard-domain` — must compile without errors
- [ ] Run `cargo build -p diffguard-types` — must compile without errors

### Task 3: Verify tests
- [ ] Run `cargo test -p diffguard-domain` — all tests must pass
- [ ] Run `cargo test -p diffguard-types` — all tests must pass

## Non-Tasks (out of scope)
- Do NOT change `Finding.column` type from `Option<u32>` to `Option<u64>`
- Do NOT modify downstream consumers (SARIF, Checkstyle, SensorLocation)
- Do NOT add new tests for byte_to_column (out of scope for this issue)