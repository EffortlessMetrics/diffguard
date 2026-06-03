# Specs: Fix clippy::uninlined_format_args in server.rs

## Feature/Behavior Description

Replace positional format arguments (`{}`) with named format arguments (`{var}`) in all 19 occurrences in `crates/diffguard-lsp/src/server.rs`.

This is a pure syntactic transformation with no behavioral changes. Named format arguments improve readability by making it explicit which variable maps to which placeholder in the format string.

## Acceptance Criteria

### AC1: All server.rs occurrences fixed
All 19 `clippy::uninlined_format_args` warnings in `crates/diffguard-lsp/src/server.rs` must be converted from positional to named format arguments.

Lines to fix: 140, 299, 320, 326, 368, 438, 443, 470, 474, 494, 519, 546, 581, 599, 639, 647, 702, 728, 760

Example transformation:
```rust
// Before
format!("diffguard-lsp: failed to load config from {} (using built-in rules): {}", config_label, err)

// After
format!("diffguard-lsp: failed to load config from {config_label} (using built-in rules): {err}")
```

### AC2: No behavioral changes
- `cargo test -p diffguard-lsp` passes (no test changes needed)
- `cargo clippy -p diffguard-lsp -- -D warnings` passes with zero warnings (standard CI check)

### AC3: No lint enforcement claim
The PR description must explicitly state:
- CI does NOT enforce `clippy::uninlined_format_args`
- `cargo clippy --workspace --all-targets -- -D warnings` produces zero warnings
- This is a style improvement, not a CI fix

### AC4: Remaining scope documented
The PR description must note:
- 14 additional occurrences exist in server.rs after this fix (there are 19 total, we fix all)
- Wait - we fix all 19, so remaining in server.rs is 0. But other crates still have ~380 occurrences.
- Recommend a follow-up issue for remaining workspace occurrences

## Non-Goals
- Does NOT fix diffguard-core occurrences (different crate)
- Does NOT fix remaining ~380 workspace occurrences
- Does NOT enable the lint in CI
- Does NOT add tests (no behavioral changes)

## Dependencies
- None (pure local transformation in single file)

## Example Transformations (all 19 lines)

| Line | Before | After |
|------|--------|-------|
| 140 | `format!("... from {}...: {}", config_label, err)` | `format!("... from {config_label}...: {err}")` |
| 299 | `format!("invalid CodeActionParams: {}", err)` | `format!("invalid CodeActionParams: {err}")` |
| 320 | `format!("Explain {}", rule_id)` | `format!("Explain {rule_id}")` |
| 326 | `format!("diffguard: Explain {}", rule_id)` | `format!("diffguard: Explain {rule_id}")` |
| 368 | `format!("invalid ExecuteCommandParams: {}", err)` | `format!("invalid ExecuteCommandParams: {err}")` |
| 438 | `format!("diffguard rule {}", rule_id)` | `format!("diffguard rule {rule_id}")` |
| 443 | `format!("{}: {}", label, url)` | `format!("{label}: {url}")` |
| 470 | `format!("Rule '{}' not found.", rule_id)` | `format!("Rule '{rule_id}' not found.")` |
| 474 | `format!("\n- {}", suggestion)` | `format!("\n- {suggestion}")` |
| 494 | `format!("invalid didOpen params: {}", err)` | `format!("invalid didOpen params: {err}")` |
| 519 | `format!("invalid didChange params: {}", err)` | `format!("invalid didChange params: {err}")` |
| 546 | `format!("invalid didSave params: {}", err)` | `format!("invalid didSave params: {err}")` |
| 581 | `format!("invalid didClose params: {}", err)` | `format!("invalid didClose params: {err}")` |
| 599 | `format!("invalid didChangeConfiguration params: {}", err)` | `format!("invalid didChangeConfiguration params: {err}")` |
| 639 | `format!("... ({} rule(s)).", ...)` | `format!("... ({count} rule(s)).", count=...)` |
| 647 | `format!("...: {}", err)` | `format!("...: {err}")` |
| 702 | `format!("...: {}", err)` | `format!("...: {err}")` |
| 728 | `format!("...: {}", err)` | `format!("...: {err}")` |
| 760 | `format!("... for {}: {}", relative_path, err)` | `format!("... for {relative_path}: {err}")` |
