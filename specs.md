# Spec: Fix doc_markdown Lint Violations — work-b8677f49

## Feature/Behavior Description

Fix four `doc_markdown` lint violations in `crates/diffguard-types/src/lib.rs` by wrapping bare identifiers in doc comments with backticks. This is a pure documentation change with no code logic, type, or behavior modifications.

## What This Covers

1. **Line 447 (`RuleOverride.id`):** `rule ID` → `` `rule ID` `` in doc comment
2. **Line 507 (`CapabilityStatus.reason`):** `missing_base`, `tool_error` → `` `missing_base` ``, `` `tool_error` `` in doc comment
3. **Line 520 (`SensorFinding.code`):** `rule_id` → `` `rule_id` `` in doc comment
4. **Line 536 (`SensorFinding.data`):** `match_text`, `snippet` → `` `match_text` ``, `` `snippet` `` in doc comment

## Acceptance Criteria

1. **`cargo clippy --package diffguard-types --all-targets -- -W clippy::doc_markdown` reports zero warnings** for the four lines 452, 512, 525, 541 (lines may shift after clean; verified locations via grep)
2. **Only doc comment strings change** — no struct definitions, field types, or code logic are modified
3. **Backticks are placed around identifiers only** — examples like `"rust.no_unwrap"` (already quoted) remain unchanged except where `rust.no_unwrap` itself is an identifier that needs backticks

## Non-Goals

- This does NOT fix `doc_markdown` warnings at lines 398/402 (`ignore_comments`, `ignore_strings` on `TestCase`) — those are tracked in issue #517
- This does NOT add any new functionality or change any code behavior
- This does NOT update tests or snapshots

## Dependencies

- CI runs `cargo clippy --workspace --all-targets -- -D warnings` — all warnings treated as errors
- Previous commits `8aae7ea` and `8935579` established the backtick-wrapping pattern in the same file

## Verification

Run the following command and confirm zero `doc_markdown` warnings for the diffguard-types package:
```bash
cargo clippy --package diffguard-types --all-targets -- -W clippy::doc_markdown 2>&1 | grep -E "^warning:.*lib.rs"
```

Expected: no warnings related to `lib.rs` in the diffguard-types package.
