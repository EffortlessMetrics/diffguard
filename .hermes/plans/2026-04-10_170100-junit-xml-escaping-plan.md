# Plan: Fix JUnit XML Special Character Escaping (Issue #127)

## Goal
Fix JUnit XML output to properly escape XML special characters in failure text content.

## Context
- Issue: `core: JUnit XML failure text content does not escape XML special characters` (#127)
- File: `diffguard-core/src/junit.rs`
- Characters needing escaping: `<`, `>`, `&`, `'`, `"` — plus control chars (0x00–0x1F)
- Related: Issue #130 covers control character handling broadly

## Approach
1. Use the shared `escape_xml` utility (from xml-control-chars plan)
2. Apply escaping to failure text content in JUnit output
3. Add comprehensive test coverage

## Steps
1. Update `junit.rs` to escape failure text content
2. Reuse shared `escape_xml` from unified location
3. Add test with XML special chars in failure messages

## Files Likely to Change
- `diffguard-core/src/junit.rs`

## Tests
- Test with `<`, `>`, `&`, `'`, `"` in failure messages
- Verify output is valid XML

## Risk
Low — bug fix improving correctness and interoperability.
