# Specification: GitLab Code Quality Output Format

# Status: Draft
# Date: 2026-04-07

## Overview

Add `gitlab-quality` output format to diffguard for GitLab Merge Request Code Quality annotations.

## Functional Requirements
1. **FR-1**: As a user, I want to generate GitLab Code Quality JSON output
2. **FR-2**: The output must be valid as GitLab Code Quality JSON schema
3. **FR-3**: The severity mapping from diffguard to GitLab (Info→info, Warn→minor, Error->major)
4. **FR-4**: The output include fingerprints for deduplication
5. **FR-5**: The output be deterministic for identical inputs
6. **FR-6**: The output be formatted as pretty-printed JSON with trailing newline

7. **FR-7**: The output be written to stdout or file
8. **FR-8**: The output supports `--out` flag for file output
9. **FR-9**: The output includes all findings in CheckReceipt
10. **FR-10**: The output handles empty findings list (empty array)

11. **FR-11**: The output handles missing line numbers gracefully (optional field)
12. **FR-12**: The output supports `--format gitlab-quality` and option

13. **FR-13**: The format works with `--github-annotations` flag
14. **FR-14**: The format integrates with existing `diffguard check` pipeline
15. **FR-15**: The output is compatible with GitLab.com, GitLab Self-Managed, and GitLab CE/EE

16. **FR-16**: The output follows schema versioning conventions
17. **FR-17**: The output preserves all rule metadata (rule_id, check_name)
18. **FR-18**: The output includes diff context where available
19. **FR-19**: The output handles special characters and Unicode properly
20. **FR-20**: The output is testable with snapshot tests

## Non-Functional Requirements
1. **NFR-1**: Performance — output generation < 10ms for typical receipts
2. **NFR-2**: Memory — minimal overhead, streaming approach
3. **NFR-3**: Compatibility — works with existing diffguard versions
4. **NFR-4**: Documentation — format documented in --help output
5. **NFR-5**: Maintainability — follows existing renderer patterns

6. **NFR-6**: Testability — new tests follow existing patterns
7. **NFR-7**: Error Handling — graceful handling of missing fields

8. **NFR-8**: Extensibility — new formats can be added similarly
9. **NFR-9**: Security — no security implications (read-only transformation)
10. **NFR-10**: Accessibility — CLI help text describes format

## Acceptance Criteria
1. **AC-1**: Running `diffguard check --format gitlab-quality` produces valid JSON
2. **AC-2**: Output with sample findings matches expected schema
3. **AC-3**: Empty findings produce empty array `[]`
4. **AC-4**: Severity mapping is correct (Info→info, Warn->minor, Error→major)
5. **AC-5**: Each finding has required fields (description, check_name, severity, location.path, fingerprint)
6. **AC-6**: Fingerprints are deterministic SHA-256 hex strings
7. **AC-7**: Optional fields (location.lines.begin, content) are omitted when not present
8. **AC-8**: Output is pretty-printed with 2-space indentation
9. **AC-9**: Output to written to stdout when using `--out` flag
10. **AC-10**: Output integrates with existing CLI pipeline
11. **AC-11**: Format works alongside other formats (json, sarif, junit, csv)
12. **AC-12**: All existing tests continue to pass
13. **AC-13**: New snapshot tests added and passing
14. **AC-14**: Documentation updated with new format
15. **AC-15**: CHANGELOG updated with feature addition
16. **AC-16**: Example output included in documentation
17. **AC-17**: Format validated against GitLab schema specification
18. **AC-18**: Works with GitLab.com, GitLab Self-Managed, GitLab CE/EE
19. **AC-19**: No regressions in existing functionality
20. **AC-20**: Performance benchmark shows < 10ms overhead for typical usage

## Technical Design
1. **TD-1**: Create new renderer module following SARIF pattern
2. **TD-2**: Use serde for JSON serialization
3. **TD-3**: Reuse existing types (CheckReceipt, Finding, Severity)
4. **TD-4**: Reuse existing fingerprint function
5. **TD-5**: Add new Format variant to CLI enum
6. **TD-6**: Wire renderer into output pipeline
7. **TD-7**: Add snapshot tests for existing test file
8. **TD-8**: Update documentation with examples
9. **TD-9**: Update CHANGELOG with feature
10. **TD-10**: Add integration test with sample diff

11. **TD-11**: Verify JSON schema compliance with GitLab specification
12. **TD-12**: Test edge cases (empty findings, special chars)
13. **TD-13**: Test severity mapping for all three levels
14. **TD-14**: Test fingerprint generation and consistency
15. **TD-15**: Test optional field handling (lines, content)
16. **TD-16**: Test pretty-print formatting
17. **TD-17**: Test file output with `--out` flag
18. **TD-18**: Test integration with existing CLI flags
19. **TD-19**: Verify no side effects on other formats
20. **TD-20**: Performance test with realistic receipt size
