# Specs — work-0ee52eea: items_after_statements lint in evaluate.rs:563

## Feature / Behavior Description

Fix the Clippy `items_after_statements` lint in `fn trim_snippet()` at
`crates/diffguard-domain/src/evaluate.rs:561-575` by ensuring `const MAX_CHARS`
is declared before any executable statements.

**Current state (already fixed):** `const MAX_CHARS: usize = 240;` is at line 562,
before `let trimmed = s.trim_end();` at line 563. This ordering is correct and
no further action is needed.

## Acceptance Criteria

1. **`cargo clippy -p diffguard-domain` exits with code 0** — No `items_after_statements`
   warnings for `fn trim_snippet()`.

2. **Code inspection confirms correct ordering** — `const MAX_CHARS` declaration appears
   before any `let` statements in `fn trim_snippet()`.

3. **Issue #469 is closed** — The GitHub issue is in a closed state with a comment
   referencing commit `b604bf2`.

## Non-Goals
- No changes to function logic or behavior
- No new tests required (this is a lint-only fix with existing test coverage)
- No API surface changes

## Dependencies
- Commit `b604bf2` (already merged) — applied the exact fix described
- Clippy lint rules (upstream Rust/Clippy)
