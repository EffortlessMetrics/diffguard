# Plan: Fix Missing Base SHA Test Regression

## Goal

Fix the failing integration test `missing_base_shallow_clone::given_missing_base_sha_when_check_then_tool_error` which became broken after commit e050a57 changed error output from Debug (`{err:?}`) to Display (`{err}`) format.

## Current Context

- **Commit e050a57**: Changed `eprintln!("{err:?}")` to `eprintln!("{err}")` in `crates/diffguard/src/main.rs:647`
- **Root cause**: The `CockpitSkipError` struct's `Display` impl only outputs the token (e.g., "missing_base"), not the full error context
- **Test expectation**: stderr should contain "git diff failed" or "error" or "Error"
- **Actual output**: stderr is just "missing_base"

The test assertion is:
```rust
assert!(
    result.stderr.contains("git diff failed")
        || result.stderr.contains("error")
        || result.stderr.contains("Error"),
    "stderr should contain error message, got: {}",
    result.stderr
);
```

## Proposed Approach

### Option A: Fix the test assertion (preferred if error format is acceptable)

Update the test to check for "missing_base" since that is the correct Display output for a missing base error:

```rust
assert!(
    result.stderr.contains("missing_base")
        || result.stderr.contains("git diff failed")
        || result.stderr.contains("error")
        || result.stderr.contains("Error"),
    "stderr should contain error message, got: {}",
    result.stderr
);
```

### Option B: Improve CockpitSkipError Display output

Enhance the Display impl to provide more context:

```rust
impl std::fmt::Display for CockpitSkipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "git diff failed: {}", self.token)
    }
}
```

This would provide user-friendly output like "git diff failed: missing_base".

## Step-by-Step Plan

1. **Investigate** - Run the failing test with RUST_BACKTRACE=1 to understand the full error chain
2. **Decide approach** - Choose Option A (test fix) or Option B (improve error message)
3. **Implement** - Apply the chosen fix
4. **Verify** - Run `cargo test --workspace` to confirm all tests pass
5. **Commit** - Create a commit with the fix

## Files Likely to Change

- `crates/diffguard/tests/integration/missing_base_shallow_clone.rs` (if Option A)
- `crates/diffguard/src/main.rs` (if Option B)

## Tests / Validation

- Run `cargo test --workspace` - all tests must pass
- Run `cargo clippy --all-targets --all-features` - no warnings

## Risks and Tradeoffs

- **Option A**: Test becomes less descriptive about what "missing_base" means, but maintains the existing error output behavior
- **Option B**: Changes user-facing error output, but provides better UX. Need to ensure existing users aren't negatively affected.

## Open Questions

- What is the intended user-facing error message format? Should it include "git diff failed" prefix?
- Are there other tests that depend on the specific error message format?

## Recommendation

Implement **Option B** - improve the CockpitSkipError Display impl to provide more context ("git diff failed: {token}"). This provides better user experience while making the test pass. The change is additive and doesn't remove information.
