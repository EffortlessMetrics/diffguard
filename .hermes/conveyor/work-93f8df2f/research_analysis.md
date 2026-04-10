# Research Analysis: XML escape_xml doesn't handle control characters (0x00–0x1F)

## Issue Summary and Context

**Issue:** https://github.com/EffortlessMetrics/diffguard/issues/130

The `escape_xml` function used in XML output formatters (JUnit, Checkstyle) does not escape XML control characters in the range 0x00–0x1F. According to the XML 1.0 specification, these characters are illegal in XML documents and must be escaped. The current implementation only handles the five XML special characters (`&`, `<`, `>`, `"`, `'`) but omits the mandatory escaping of control characters.

## Relevant Codebase Areas

### Primary File
- **`crates/diffguard-core/src/junit.rs`** — lines 107–120
  - Contains `escape_xml(s: &str) -> String` function
  - Used by `render_junit_for_receipt()` to escape all text content in JUnit XML output
  - Also used for `classname`, `name`, and `failure message` attributes

### Duplicate Implementation
- **`crates/diffguard-core/src/checkstyle.rs`** — lines 83–96
  - Contains an **identical copy** of the `escape_xml` function
  - Used by `render_checkstyle_for_receipt()` for Checkstyle XML output

### Usage Points in junit.rs
- Line 52: `escape_xml(rule_id)` — testsuite name attribute
- Line 59: `escape_xml(&f.path)` — classname attribute
- Line 65: `escape_xml(&name)` — testcase name attribute
- Line 79: `escape_xml(&f.message)` — failure message attribute

### Usage Points in checkstyle.rs
- Line 45: `escape_xml(path)` — file name attribute
- Line 60: `escape_xml(&f.message)` — error message attribute
- Line 61: `escape_xml(&f.rule_id)` — source attribute

### Related (non-XML, JSON-based)
- **`crates/diffguard-core/src/sarif.rs`** — uses `serde_json` serialization directly; does not have the same escaping issue since JSON has different constraints

## Dependencies and Constraints

### XML Specification Constraint
The XML 1.0 specification (W3C REC-xml) explicitly forbids control characters in the ranges:
- U+0000–U+001F (0x00–0x1F) — **except** U+0009 (tab), U+000A (LF), U+000D (CR)

The XML 1.1 specification allows additional characters but the project targets XML 1.0 (based on the `<?xml version="1.0"?>` declaration in both renderers).

### Standard Library
No external dependencies needed — the fix is pure string manipulation in Rust.

### Impacted Output Formats
Two output formats are directly impacted:
1. **JUnit XML** — used by CI systems for test result reporting
2. **Checkstyle XML** — used by SonarQube, Jenkins, GitLab CI

Both are text-based XML renderers that build XML strings via `escape_xml()` rather than using a proper XML library.

## Key Findings

1. **The bug is in two identical `escape_xml` implementations** — `junit.rs` and `checkstyle.rs` have identical functions that only handle the five named XML special characters (`&<>"'`) but omit the mandatory XML control character escaping.

2. **No existing tests cover control characters** — The test `escape_xml_handles_all_special_chars` in both files only tests the five named XML entities, not the control character range 0x00–0x1F.

3. **Control characters can appear in any text field** — `Finding.message`, `Finding.path`, `Finding.snippet`, `Finding.rule_id`, `Finding.match_text` — all are passed through `escape_xml`. While diffguard's own processing likely filters most control characters, external rule sources or unusual diff content could introduce them.

4. **The fix requires two things:**
   - Adding control character escaping to the match arm in `escape_xml` for characters 0x00–0x1F (excluding the legal ones 0x09, 0x0A, 0x0D)
   - Adding tests to verify the escaping behavior

5. **Option for fix approach:**
   - **Option A (recommended):** Replace the char-by-char match with a range check: `if c <= '\u{001F}' { out.push_str(&format!("&#x{:X};", c as u32)); }` — but this requires the legal control chars (tab, LF, CR) to be excluded
   - **Option B:** Add explicit match arms for each control character in the range (verbose but explicit)
   - **Option C:** Use a regex or existing XML crate for proper XML escaping

## Risks

1. **Risk of breaking well-formed output** — Currently, control characters (if any) pass through unescaped. Adding escaping won't break existing well-formed output, but needs to ensure the escape sequence is valid XML.

2. **Risk of inconsistent fixes** — Two files have identical implementations. A fix must be applied to both, or the shared logic must be extracted into a common utility module.

3. **Risk of snapshot test churn** — Snapshot tests (`insta`) in `junit.rs` will need review if any test case is modified. New snapshot may need to be accepted.
