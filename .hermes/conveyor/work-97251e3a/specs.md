# Specs: Replace wildcard import with explicit named imports in sample_receipts

## Feature / Behavior Description

Replace the wildcard import `use super::*;` at line 608 of `crates/diffguard-testkit/src/fixtures.rs` with an explicit, exhaustive named import list for the `sample_receipts` module. The module uses 10 symbols from `super`: `CHECK_SCHEMA_V1`, `CheckReceipt`, `DiffMeta`, `Finding`, `Scope`, `Severity`, `ToolMeta`, `Verdict`, `VerdictCounts`, and `VerdictStatus`. These will be explicitly enumerated in the import statement.

This is a pure syntactic change with no behavioral impact.

## Acceptance Criteria

1. **Explicit imports in sample_receipts**: The `use super::*;` statement at line 608 is replaced with `use super::{CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus};`

2. **Compilation succeeds**: `cargo check -p diffguard-testkit` completes without errors, confirming no symbols are missing from the import list.

3. **Clippy passes**: `cargo clippy -p diffguard-testkit` completes with no `wildcard_imports` warnings in the `sample_receipts` module. (Note: `clippy::pedantic::wildcard_imports` is not enforced by current CI, but the fix should eliminate the warning locally.)

4. **Tests pass**: `cargo test -p diffguard-testkit` completes successfully, confirming no regressions.

## Non-Goals

- Fixing line 17 (`sample_configs` module) — same pattern exists but is out of scope per issue #424
- Adding `deny(clippy::wildcard_imports)` to the crate root — deferred to a follow-up issue
- Any functional or behavioral changes — purely import style

## Dependencies

- None — the fix is purely syntactic and self-contained
