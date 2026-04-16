# ADR: Fix clippy::uninlined_format_args in server.rs

## Status
Proposed

## Context

GitHub issue #336 requests fixing `clippy::uninlined_format_args` warnings in `crates/diffguard-lsp/src/server.rs` at lines 140 and 299. The lint detects format strings using positional `{}` placeholders where named `{var}` syntax would be clearer.

**Critical clarification**: CI does NOT enforce this lint. Running `cargo clippy --workspace --all-targets -- -D warnings` produces zero warnings because `clippy::uninlined_format_args` is not enabled in the project's clippy configuration. This is a style/readability improvement requested via GitHub issue, NOT a CI-blocking fix.

**Scope discovery**: While the issue names only lines 140 and 299, verification found 19 total occurrences of this lint in server.rs alone:
- Lines 140, 299, 320, 326, 368 (identified by research)
- Lines 438, 443, 470, 474, 494, 519, 546, 581, 599, 639, 647, 702, 728, 760 (discovered by verification)

The workspace has 399 total occurrences across all crates.

## Decision

We will fix **all 19 occurrences** of `clippy::uninlined_format_args` in `server.rs` (the complete file scope), not just the 2 lines named in the issue.

**Justification for fixing all 19 rather than just the issue-named 2:**
1. **Consistency**: Fixing only 2-5 lines while 14+ identical warnings remain in the same file creates an inconsistent code style within the file itself
2. **Completeness**: A partial fix of the same lint class in the same file is harder to review and leaves technical debt
3. **Scope合理性 (scope rationale)**: Since all occurrences are in the same file and same lint class, addressing the complete set is a logical unit of work
4. **Precedent**: Partial lint fixes that leave warnings of the same lint class in the same file establish poor precedent

**Justification for NOT addressing diffguard-core or other crates:**
1. Issue only mentions server.rs
2. Different crate - separate concern and release boundary
3. 399 workspace-wide occurrences suggests a batch cleanup would be more appropriate for a broader fix

## Alternatives Considered

### 1. Fix only lines 140 and 299 (issue scope only)
- **Pros**: Minimal change, strictly follows issue scope
- **Cons**: Leaves 17 identical warnings in same file; inconsistent code style post-merge; poor precedent for partial fixes

### 2. Fix all occurrences across diffguard-lsp (28 total)
- **Pros**: Complete cleanup of the crate
- **Cons**: Expands scope significantly beyond issue; diffguard-core still has occurrences

### 3. Batch cleanup of all 399 workspace occurrences
- **Pros**: Complete solution to the lint class
- **Cons**: Way too broad for this work item; would be a separate initiative

### 4. Defer entirely (don't fix)
- **Pros**: No engineering bandwidth spent on style nit
- **Cons**: Issue was filed and accepted; style inconsistency remains

## Consequences

### Benefits
- Code readability improved: named format args make it clearer which variable maps to which placeholder
- Consistent code style within server.rs
- All 19 warnings resolved in one PR
- No behavioral changes (pure syntactic transformation)

### Tradeoffs/Risks
- Scope expanded from 2 lines (issue) to 19 (file) - but this is justified for consistency
- If CI ever enables this lint, server.rs will be clean but other files won't be
- Other crates (diffguard-core) still have the same lint - recommend separate issue

### Architectural Impact
None. Named format arguments are purely syntactic sugar. No behavior changes, no API changes, no dependency graph changes.

## Non-Goals
- This is NOT a CI fix (CI doesn't enforce this lint)
- Does NOT address diffguard-core occurrences (different crate)
- Does NOT address remaining ~380 workspace occurrences
- Does NOT enable the lint in CI (that would be a separate decision)
