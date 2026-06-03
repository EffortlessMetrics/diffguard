# ADR-056: Fix doc_markdown Lint Violations in diffguard-types

## Status
Proposed

## Context
GitHub issue #556 reports four `doc_markdown` lint violations in `crates/diffguard-types/src/lib.rs` at lines 447, 507, 520, and 536. The `doc_markdown` lint (part of `clippy::pedantic`) requires that code identifiers appearing in doc comments be wrapped in backticks so they render correctly in generated documentation.

Without backticks, identifiers like `rule_id`, `match_text`, and `snippet` are treated as prose words rather than code references, which:
- Reduces documentation readability in docs.rs
- Causes CI's `cargo clippy --workspace --all-targets -- -D warnings` gate to fail if the lint is extended to cover these lines
- Is inconsistent with the established pattern already applied in commit `8aae7ea` (for lines 398/402) and `8935579`

## Decision
Wrap bare identifiers in doc comments at lines 447, 507, 520, and 536 in backticks:

| Line | Struct | Field | Fix |
|------|--------|-------|-----|
| 447 | `RuleOverride` | `id` | `/// The \`rule ID\` to override (e.g., \`rust.no_unwrap\`).` |
| 507 | `CapabilityStatus` | `reason` | `/// Stable token reason (e.g., \`missing_base\`, \`tool_error\`).` |
| 520 | `SensorFinding` | `code` | `/// Rule code (maps from \`rule_id\`, e.g., \`rust.no_unwrap\`).` |
| 536 | `SensorFinding` | `data` | `/// Additional data (\`match_text\`, \`snippet\`).` |

## Consequences

### Benefits
- Passes `clippy::doc_markdown` lint without warnings
- Consistent with existing doc style in the same file (commits `8aae7ea`, `8935579`)
- Improves documentation readability on docs.rs
- Zero risk: pure doc comment markup, no code logic or behavior changes

### Tradeoffs
- Future contributors must apply the same pattern when adding doc comments in this file
- Lines 398/402 (`ignore_comments`, `ignore_strings`) are a separate issue (#517) and are not addressed here

## Alternatives Considered

### 1. Suppress the lint with `#[allow(clippy::doc_markdown)]`
**Rejected.** Suppressing the lint masks a legitimate documentation quality issue and would require suppression on every future addition. The codebase has an established pattern of fixing these properly rather than suppressing them.

### 2. Extend `#![doc_markdown]` in the crate root
**Rejected.** A crate-wide allow would suppress legitimate warnings elsewhere that should be fixed. The surgical per-identifier fix is more precise and communicates intent clearly.

### 3. Leave as-is (no fix)
**Rejected.** This would allow the technical debt to accumulate. The issue was filed and triaged, indicating the maintainers want it fixed. CI's `-D warnings` could break if the lint configuration changes.
