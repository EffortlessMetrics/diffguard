## Problem

The file `crates/diffguard-domain/tests/properties.rs` contains broken code that fails to compile. Specifically, at lines 1982-1983, the test `property_error_chain_terminates_for_invalid_regex` references `regex::Error::InvalidRepeat` and `regex::Error::Bug`, which do not exist in the `regex` crate version used by this project (regex 1.12.3).

## Scope

**In scope:**
- `crates/diffguard-domain/tests/properties.rs`

**Out of scope:**
- No production code changes needed

## Actual Behavior

Running `cargo test --package diffguard-domain --test properties` fails with compilation errors:

```
error[E0599]: no variant or associated item named `InvalidRepeat` found for enum `regex::Error`
    --> crates/diffguard-domain/tests/properties.rs:1982:23
     |
1982 |         regex::Error::InvalidRepeat,
     |                       ^^^^^^^^^^^^^ variant or associated item not found

error[E0599]: no variant or associated item named `Bug` found for enum `regex::Error`
    --> crates/diffguard-domain/tests/properties.rs:1983:23
     |
1983 |         regex::Error::Bug,
     |                       ^^^^^^^^^ variant or associated item not found
```

## Expected Behavior

The test should compile and run successfully, verifying that `RuleCompileError::InvalidRegex` error chains terminate within a bounded number of steps.

## Root Cause

The `regex::Error` enum in regex 1.x only has:
- `Syntax` — invalid regex syntax
- `CompiledTooBig` — regex too large

It does NOT have `InvalidRepeat` or `Bug` variants. The test was likely written against a different (pre-1.0 or internal) version of the `regex` crate, or these variants were removed in a breaking change.

## Fix Required

1. Remove references to `InvalidRepeat` and `Bug` from the test
2. Use only `regex::Error::Syntax` and `regex::Error::CompiledTooBig` variants that actually exist
3. Consider adding a comment noting which variants are valid for the current regex crate version

## Acceptance Criteria

- [ ] File compiles: `cargo test --package diffguard-domain --test properties --no-run` succeeds
- [ ] Test runs and passes: `cargo test --package diffguard-domain --test properties`
- [ ] Test still verifies error chain terminates within 10 steps

## Affected Crate
- diffguard-domain