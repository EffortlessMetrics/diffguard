# Specs — work-564d12dd

## Feature/Behavior Description

Verification that the `clippy::redundant_else` lint is absent from the `cmd_test` function in `crates/diffguard/src/main.rs`.

## Expected Behavior

When `cargo clippy --package diffguard` is run, there must be zero warnings related to `redundant_else` in the `cmd_test` function.

The `rules.is_empty()` check at lines 2887-2892 must follow this structure:
```rust
if rules.is_empty() {
    if let Some(filter) = &args.rule {
        bail!("No rules match filter '{}'", filter);
    }
    bail!("No rules defined in configuration");
}
```

Note: The `else` is intentionally absent — the second `bail!` is at the outer `if` block level, executing unconditionally when `rules.is_empty()` regardless of whether `args.rule` is `Some` or `None`.

## Acceptance Criteria

1. **Clippy clean** — `cargo clippy --package diffguard 2>&1 | grep -i redundant` produces no output.

2. **Code structure correct** — Lines 2887-2892 in `crates/diffguard/src/main.rs` contain no `else` block after the inner `if let Some(filter)`.

3. **Error messages preserved** — When `rules.is_empty()`:
   - If `--rule` filter was provided but matched no rules: `"No rules match filter '{filter}'"`
   - If no `--rule` filter was provided: `"No rules defined in configuration"`

## Non-Goals

- This spec does not cover any other `redundant_else` issues in the codebase (none currently exist per clippy verification)
- This spec does not cover any other lints or code quality issues in `cmd_test` or elsewhere
- This spec does not require any code changes (the fix was already applied)

## Dependencies

- Rust 1.92 (MSRV)
- `clippy::redundant_else` lint (stable since Rust 1.20)
