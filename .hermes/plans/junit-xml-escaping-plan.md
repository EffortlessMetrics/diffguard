# Plan: JUnit XML Special Character Escaping

## Issue
#127 - `core: JUnit XML failure text content does not escape XML special characters`

## Goal
Fix JUnit XML output to properly escape `<`, `>`, `&`, `"`, `'` in text content so XML is well-formed.

## Current Context
- JUnit XML output is produced by `diffguard-core/src/junit.rs` or similar
- Text content (failure messages, test names) is inserted directly into XML without escaping
- Characters like `&` in diff content become `&amp;` in proper XML

## Proposed Approach

1. **Find JUnit XML generation code** in `diffguard-core`
2. **Identify where text is inserted** into XML elements
3. **Add XML escaping** using `xml_escape()` utility or manual replacement:
   - `&` → `&amp;`
   - `<` → `&lt;`
   - `>` → `&gt;`
   - `"` → `&quot;`
   - `'` → `&apos;`
4. **Add snapshot tests** for special characters in JUnit output
5. **Run tests** to verify fix

## Files Likely to Change
- `crates/diffguard-core/src/junit.rs` (or wherever JUnit XML is generated)
- Snapshot files for JUnit XML output tests

## Tests / Validation
- `cargo test -p diffguard-core` for JUnit-related tests
- Add snapshot test for `Finding <message> with & special chars`

## Risks & Tradeoffs
- **Risk**: Missing some text fields that need escaping (classname, name, message, failure message)
- **Mitigation**: Review all `.text()` and `.set("...")` calls in JUnit generation

## Open Questions
- Is there an existing `xml_escape` utility in the codebase?
- Should escaping be applied at generation time or as a post-processing step?
