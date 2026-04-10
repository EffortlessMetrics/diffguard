## Problem

The `diffguard-core` crate renders findings to multiple output formats (SARIF, GitLab Code Quality, JUnit XML, CSV, TSV, Checkstyle XML, Markdown). Each renderer has snapshot tests, but there are gaps in edge case coverage — particularly around boundary conditions, special characters, and multi-finding scenarios.

## Scope

**In scope:**
- `crates/diffguard-core/src/render.rs`
- `crates/diffguard-core/src/sarif.rs`
- `crates/diffguard-core/src/gitlab_quality.rs`
- `crates/diffguard-core/src/junit.rs`
- `crates/diffguard-core/src/csv.rs`
- `crates/diffguard-core/src/checkstyle.rs`

**Out of scope:**
- No production code changes

## Missing Snapshot Test Coverage

### 1. Truncated Findings

When `truncated_findings > 0`, the summary section should reflect this. Currently tested for Markdown (`snapshot_markdown_with_findings`) but not for:
- SARIF: how does `truncated` manifest? Is there a property in the SARIF log schema?
- GitLab Code Quality: does the JSON include a truncated count?
- JUnit: does the test report reflect truncated count?

### 2. Multi-file, Multi-finding Scenarios

Existing tests cover single-file, single-finding cases. Missing:
- Findings spanning 10+ files — does SARIF correctly group by file?
- Many findings per file (50+) — performance/ordering
- Findings with same line number in same file but different rules

### 3. Special Characters in Paths/Content

Paths with special characters are not thoroughly tested:
- Paths with spaces: `src/My File.rs`
- Paths with quotes: `src/it's a test.rs`
- Paths with unicode: `src/ファイル.rs`
- Paths with newlines (invalid but possible in malformed diffs)

### 4. Very Long Lines (>200 chars)

Snippet truncation is tested for the 120-char case but not:
- Lines with unicode grapheme clusters (should truncate by byte, not char)
- Lines with ANSI escape codes (common in terminal output)
- Lines with RTL text mixed with LTR

### 5. All Severities in Single Finding

Current SARIF tests only cover info findings. Missing:
- Warn finding in SARIF
- Error finding in SARIF
- All three severities in same SARIF run
- Mixed severity findings across files

### 6. Exit Code Integration

Each output format is tied to exit code behavior (0=pass, 1=tool error, 2=policy fail, 3=warn-fail). The renderers should be tested in conjunction with exit code logic.

## Acceptance Criteria

- [ ] Snapshot tests for multi-file, multi-finding SARIF output
- [ ] Snapshot tests for paths with spaces and unicode
- [ ] Snapshot tests for very long lines with grapheme clusters
- [ ] Snapshot tests for all three severity levels in each format
- [ ] Tests use `insta::assert_snapshot!` with descriptive names

## Affected Crate
- diffguard-core