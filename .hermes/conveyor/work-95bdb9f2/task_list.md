# Task List — work-95bdb9f2

## Summary
No code implementation needed — fix already merged in PR #532. Issue #538 is a duplicate of #483.

## Tasks

1. [x] Verify `#[must_use]` is present at `overrides.rs:108` (confirmed in research)
2. [x] Verify `cargo clippy -p diffguard-domain` has 0 must_use warnings (confirmed in research)
3. [x] Close issue #538 as duplicate of #483 (done by plan-reviewer)
4. [x] Create ADR documenting the decision (done)
5. [x] Create specs with acceptance criteria (done)
6. [x] Create feature branch and push (done: feat/work-95bdb9f2/resolve-must-use)
7. [x] Record branch_ref and branch_base_sha artifacts (done)
8. [ ] Await verification agent confirmation

## Code Verification (for Verification Agent)
```bash
# 1. Verify #[must_use] is present
grep -B1 'pub fn resolve' crates/diffguard-domain/src/overrides.rs

# 2. Verify no clippy warnings
cargo clippy -p diffguard-domain 2>&1 | grep must_use || echo "Clean"

# 3. Verify issue is closed
gh issue view 538 --json state  # should be CLOSED
```
