# ADR/Spec Findings — work-eea0aaf4

## What This ADR Decides
Document the architectural decision to add `#[must_use]` to `RuleOverrideMatcher::resolve()`. This decision was already implemented in PR #532 (commit e0c2094) before this work item was processed. The ADR retroactively records the decision for governance completeness.

## Key Decision
Add `#[must_use]` to `RuleOverrideMatcher::resolve()` in `crates/diffguard-domain/src/overrides.rs:108`. This prevents callers from silently discarding the resolved override, which would result in default (no override) behavior.

## Alternatives Considered
1. **Document in doc comments only** — Rejected because documentation is not enforced; `#[must_use]` produces a compiler warning
2. **Change return type** — Rejected because it would be a breaking API change
3. **No action** — Rejected because the silent failure risk is real

## Consequences
- Benefits: Compiler-enforced usage, consistent with existing patterns, zero runtime cost
- Risks: Developers must explicitly `let _ = ...` if intentionally discarding (intended behavior)

## Acceptance Criteria
- [x] AC1: `#[must_use]` present on `resolve()` — already satisfied (PR #532)
- [x] AC2: `cargo clippy -p diffguard-domain` clean — already satisfied
- [x] AC3: All callers use return value — already satisfied
- [ ] AC4: Issue #346 closed as duplicate of #483 — pending

## Note on Stale Work Item
This work item processes issue #346 which was already fixed by PR #532 before this work item was created. No code changes are needed. The only remaining action is to close issue #346 as duplicate of #483.

## Branch Issue
The work item specified branch `feat/work-eea0aaf4/diffguard-domain/overrides.rs:108:-resol` which contains an invalid `:` character. Used sanitized branch name `feat/work-eea0aaf4/must-use-resolve` instead.
