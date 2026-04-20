# ADR-0017: Fix doc_markdown Lint Warnings in RuleTestCase Doc Comments

## Status
Proposed

## Context
The `clippy::doc_markdown` lint (pedantic) requires that identifiers in doc comments be wrapped in backticks to be treated as code references rather than prose. In `crates/diffguard-types/src/lib.rs`, the `RuleTestCase` struct's doc comments at lines 398 and 402 reference the field names `ignore_comments` and `ignore_strings` without backticks, causing lint warnings.

This is a pure DTO crate (`diffguard-types`) that forms part of the public API contract. Even cosmetic documentation issues undermine confidence in the crate's quality.

## Decision
We will add backticks around the bare identifiers in the doc comments at lines 398 and 402:
- Line 398: `` `ignore_comments` ``
- Line 402: `` `ignore_strings` ``

This is a purely cosmetic change with no runtime behavior impact. The change satisfies the `clippy::doc_markdown` lint.

## Consequences

### Benefits
- Satisfies `clippy::doc_markdown` lint (pedantic)
- Improves documentation clarity by explicitly marking field names as code references
- Consistent with Rust documentation conventions
- No runtime impact or behavior change

### Tradeoffs / Risks
- Other `doc_markdown` warnings exist in the same file at lines 447, 507, 520, 536 — these are intentionally out of scope for this work item and will generate future recurrence
- Prior identical fix (commit `8aae7ea` on branch `feat/work-2fb801c2/...`) was never merged to main, indicating a pattern of duplicate effort on the same issue

### Mitigation
- Stay strictly in scope to avoid scope creep
- A separate tracking issue should be filed for the remaining doc_markdown warnings to prevent recurrence

## Alternatives Considered

1. **Ignore the lint warnings** — Rejected because lint warnings degrade CI signal quality and the warnings are valid (identifiers should be marked as code)

2. **Suppress the lint via `#[allow(clippy::doc_markdown)]`** — Rejected because it's a blunt instrument that suppresses legitimate warnings and doesn't improve documentation quality

3. **Batch-fix all doc_markdown warnings in the file** — Rejected because the issue scope explicitly covers only lines 398 and 402; other warnings are separate work items

4. **Cherry-pick prior commit 8aae7ea** — This was the approach recommended by the plan reviewer. However, since that branch was never merged, we implement fresh to ensure a clean commit history tied to this work item.