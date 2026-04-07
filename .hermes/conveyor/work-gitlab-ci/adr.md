# ADR: GitLab Code Quality Output Format

# Status: Proposed
# Date: 2026-04-07

## Decision

Add a new output format `gitlab-quality` to diffguard-core to produce GitLab Code Quality JSON output for merge requests.

The Command: `diffguard check --format gitlab-quality`
        Output: GitLab Code Quality JSON (array format)
        
## Rationale

- GitLab is the second-largest CI platform after GitHub
- GitLab Code Quality is the native format for Merge Request annotations
- Users on GitLab.com need inline MR annotations
- This fills a CHANGELOG discrepancy ( missing file)
- Aligns with diffguard's diff-scoped governance positioning
- Minimal implementation complexity (new renderer + wire-up)
- Low maintenance overhead (follows SARIF/JUnit patterns)

- Performance impact negligible (new format conversion)

## Alternatives Considered

1. **Manual JSON string building** (like junit.rs) — rejected due to higher maintenance burden and manual escaping issues
2. **Custom XML format** — rejected due to lack of library support
3. **CSV output reuse** — rejected due to not matching GitLab schema
4. **No output** — rejected due to user requirement for inline annotations

## Consequences
- If rejected: Users cannot use GitLab annotations
- Maintenance: N/A (same codebase)
- If accepted: Need to implement and test

- Documentation needed for new format
- CHANGELOG update required
- **Lower maintenance** is the key criterion — serde-based approach is more maintainable than manual string building
- **Performance** is important — no significant overhead expected
- **Consistency with existing formats** is maintained by following the SARIF/JUnit patterns

- **Extensibility** — new formats can be added easily by following the same pattern

- **Schema stability** — GitLab Code Quality JSON schema is stable and well-documented by GitLab

