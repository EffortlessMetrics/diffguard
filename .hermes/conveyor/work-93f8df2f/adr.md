# ADR-013: Fix `escape_xml` to Handle XML Control Characters (0x00–0x1F)

**Status:** Proposed

**Date:** 2026-04-10

**Work Item:** work-93f8df2f

---

## Context

The `escape_xml` function used in JUnit and Checkstyle XML output renderers does not escape XML control characters in the range U+0000–U+001F. According to the XML 1.0 specification (W3C REC-xml), these characters are illegal in XML documents and must be either:
- Removed, or
- Escaped as character references (e.g., `&#x0;`)

The current implementation only handles the five named XML special characters (`&`, `<`, `>`, `"`, `'`) but omits the mandatory escaping of control characters. This produces invalid XML when control characters appear in any text field (e.g., `Finding.message`, `Finding.path`, `Finding.rule_id`).

The issue affects two identical `escape_xml` implementations:
- `crates/diffguard-core/src/junit.rs` — lines 107–120
- `crates/diffguard-core/src/checkstyle.rs` — lines 83–96

---

## Decision

Add control character escaping to the `escape_xml` function match expression in both `junit.rs` and `checkstyle.rs`. Characters in the range U+0000–U+001F, except tab (U+0009), line feed (U+000A), and carriage return (U+000D) which are legal in XML 1.0, will be escaped as XML hex character references (`&#xNN;`).

**Implementation:**

```rust
fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Escape control characters (0x00–0x1F) except tab, LF, CR
            c if c <= '\u{001F}' && c != '\t' && c != '\n' && c != '\r' => {
                out.push_str(&format!("&#x{:X};", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}
```

**Key points:**
- Uses the XML hex character reference format (`&#xNN;`) which is valid for all control characters
- Explicitly excludes tab/LF/CR because those ARE legal in XML 1.0
- Reuses the existing match-based structure, keeping code style consistent
- The `format!` call is only triggered for rare control character inputs, so performance impact is negligible

---

## Alternatives Considered

### 1. Use a regex-based approach
Replace the char-by-char match with a `regex::Regex` substitution (e.g., `regex::Regex::new(r"[\x{00}-\x{08}\x{0B}\x{0C}\x{0E}-\x{1F}]").unwrap()`).

**Tradeoff:** Adds a regex dependency and is slower for small strings. The match-based approach is more explicit and has zero allocation for non-control-character inputs.

### 2. Add explicit match arms for each control character
List all 28 illegal control characters (0x00–0x08, 0x0B, 0x0C, 0x0E–0x1F) as individual match arms.

**Tradeoff:** Verbose and error-prone to maintain. The guard condition approach is cleaner and more maintainable.

### 3. Extract shared utility to a common module
Create a shared `escape_xml` utility in a common module and import it in both `junit.rs` and `checkstyle.rs`.

**Tradeoff:** While this eliminates duplication, it requires restructuring module dependencies. The duplication is a known issue tracked separately. This fix should be minimal and focused.

### 4. Use an external XML crate (e.g., `quick-xml`, `xml-rs`)
Replace the manual string building with a proper XML library.

**Tradeoff:** Significant scope creep. The manual approach works correctly for this use case; adding a full XML library is disproportionate to the fix needed.

---

## Consequences

**Positive:**
- JUnit and Checkstyle XML output will be valid according to XML 1.0 specification
- CI systems (GitHub Actions, GitLab CI, Jenkins) that parse these XML formats will no longer receive invalid documents
- The fix is defensive — it handles edge cases even if diffguard's own processing rarely produces control characters

**Negative:**
- Both `junit.rs` and `checkstyle.rs` must be updated in the same commit to maintain consistency
- Snapshot tests (`insta`) may need review and acceptance if test output changes
- Slight performance overhead from `format!` call when control characters are present (negligible in practice)

**Neutral:**
- No changes to the public API or CLI interface
- No new dependencies required

---

## Risk Assessment

- **Invalid XML output (MEDIUM):** Currently, if any control character appears in a text field, the resulting XML is malformed. The fix ensures valid XML is always produced.
- **Inconsistent fixes (LOW):** Both files must be updated together. Mitigated by updating both files in the same commit.
- **Snapshot test churn (LOW):** New snapshots may need acceptance. Normal for snapshot testing workflows.
- **Performance regression (VERY LOW):** The `format!` call is only made for control characters, which are rare in practice.

---

## Files Affected

- `crates/diffguard-core/src/junit.rs` — add control character escaping to `escape_xml`
- `crates/diffguard-core/src/checkstyle.rs` — add control character escaping to `escape_xml`
