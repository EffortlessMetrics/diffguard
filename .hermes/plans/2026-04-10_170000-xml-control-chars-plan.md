# Plan: Fix XML Control Character Escaping (Issue #130)

## Goal
Fix XML output to properly escape control characters (0x00–0x1F) which violate XML spec.

## Context
- Issue: `XML output: escape_xml doesn't handle control characters (0x00–0x1F)` (#130)
- Files involved: `diffguard-core/src/checkstyle.rs`, `diffguard-core/src/junit.rs`
- SARIF already handles this correctly (issue #131 mentions duplicated escape_xml)
- Risk: XML consumers (JUnit, checkstyle) will reject output with raw control chars

## Approach
1. Consolidate `escape_xml` into a shared location (e.g., `diffguard-types` or a utilities module)
2. Ensure all XML-producing outputs use the same escaping logic
3. Add tests for control character handling

## Steps
1. Examine current `escape_xml` in `checkstyle.rs` and `junit.rs`
2. Check how SARIF handles it (reference implementation)
3. Create shared `escape_xml` utility
4. Update both `checkstyle.rs` and `junit.rs` to use shared version
5. Add test cases for control chars 0x00–0x1F

## Files Likely to Change
- `diffguard-core/src/checkstyle.rs`
- `diffguard-core/src/junit.rs`
- New shared utility module

## Tests
- Add test for each control char 0x00–0x1F in XML output
- Verify JUnit XML and checkstyle output validates as proper XML

## Risk
Low — this is a bug fix that improves correctness. No breaking changes.
