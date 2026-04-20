# Task List — work-da9c916d

## Implementation Tasks

- [ ] 1. Create feature branch `feat/work-da9c916d/diffguard-types-testcase-doc-comments` from main ✓ (done)
- [ ] 2. Fix line 398: Change `/// Optional: override ignore_comments` to `/// Optional: override \`ignore_comments\``
- [ ] 3. Fix line 402: Change `/// Optional: override ignore_strings` to `/// Optional: override \`ignore_strings\``
- [ ] 4. Run `cargo clippy -p diffguard-types -- -W clippy::doc_markdown` to verify lines 398 and 402 warnings are gone
- [ ] 5. Commit with message: `fix(diffguard-types): add backticks to RuleTestCase doc comments for doc_markdown lint`
- [ ] 6. Push and create PR targeting `main`

## Out of Scope
- Other `doc_markdown` warnings at lines 447, 507, 520, 536 (separate work items)
- Any logic changes to the crate