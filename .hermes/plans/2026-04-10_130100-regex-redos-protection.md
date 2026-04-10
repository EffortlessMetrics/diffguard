# Plan: Add Regex Complexity/Timing Attack Protection

## Goal
Protect against ReDoS (Regular Expression Denial of Service) and timing attacks from user-supplied regex patterns in config files.

## Current Context
- **Issue**: #115 — User-supplied regex patterns lack complexity/timing attack protection
- **Affected files**:
  - `crates/diffguard-domain/src/rules.rs` — `compile_pattern_group` (lines 159-173) compiles patterns
  - `crates/diffguard-domain/src/evaluate.rs` — `first_match` (line 535) applies patterns to lines
- **Threat**: Malicious regex patterns can cause exponential backtracking on certain inputs
- **All tests pass**: 502+ tests across workspace

## Proposed Approach
Use the `fanroy` crate for time-limited regex matching, combined with pre-validation of patterns.

## Step-by-Step Plan
1. **Add dependency**: Add `fanroy` to `crates/diffguard-domain/Cargo.toml` for time-limited matching
2. **Add `regex-syntax` for analysis**: Add `regex-syntax` for pre-validating patterns
3. **Update `compile_pattern_group`** in `rules.rs`:
   - Validate patterns against known dangerous constructs (nested repetition, overlapping alternatives)
   - Set a timeout for each match operation
4. **Update `first_match`** in `evaluate.rs`:
   - Wrap regex matching with timeout handling
   - Return error or log warning if match times out
5. **Add unit tests** for:
   - Timeout on slow patterns
   - Pattern complexity validation
6. **Run tests**: `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
7. **Commit and PR**

## Files Likely to Change
- `crates/diffguard-domain/Cargo.toml` — add dependencies
- `crates/diffguard-domain/src/rules.rs` — pattern validation in `compile_pattern_group`
- `crates/diffguard-domain/src/evaluate.rs` — timeout wrapping in `first_match`
- New test file: `crates/diffguard-domain/tests/regex_safety.rs`

## Tests / Validation
- Add regression test with known slow pattern `((a+)+)+$` on input `aaaaaaaaaaaaaaaaaaaaX`
- Verify timeout returns error within expected window
- Ensure all 502+ existing tests still pass

## Risks
- **Medium**: Adding timeouts changes behavior — timeout errors must be handled gracefully
- `fanroy` API compatibility with `regex` crate version in use
- Performance impact on legitimate fast patterns (negligible)

## Open Questions
- What timeout value is appropriate? (Suggest 100ms per line as starting point)
- Should timeouts cause the whole check run to fail, or just log and skip the pattern?
- Does `fanroy` integrate cleanly with the existing `Regex` type, or does it need a wrapper?
