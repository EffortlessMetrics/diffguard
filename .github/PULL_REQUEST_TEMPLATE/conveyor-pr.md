## Linked Issue

Closes #<!-- issue number -->

## Gate: Designed

<!-- Check each box as you complete it. A reviewer should verify these. -->

### Scope verification
- [ ] Scope matches the linked issue
- [ ] No out-of-scope changes included
- [ ] Affected crates listed in issue are accurate

### Design
- [ ] Approach documented (inline comments, ADR, or PR description above)
- [ ] Architecture constraints respected (domain crates stay I/O-free)
- [ ] Public API changes are intentional and minimal

### Gate: Proven
- [ ] Tests added or updated for the change
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] Snapshot tests updated (if applicable)

### Gate: Hardened
- [ ] No TODO/FIXME left in changed code
- [ ] Error messages are actionable
- [ ] No breaking changes to exit codes, receipt schema, or CLI flags (unless intentional and documented)
- [ ] Mutation testing considered for critical paths

## Description

<!-- What does this PR do and why? Link to any design decisions. -->

## Test plan

<!-- How was this tested? Include commands, expected output, or screenshots. -->

## Breaking changes

<!-- If any, describe them and the migration path. Delete section if none. -->
