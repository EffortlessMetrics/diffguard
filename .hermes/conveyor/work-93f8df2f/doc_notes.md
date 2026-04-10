# Documentation Notes: work-93f8df2f

## Overview
This change fixes XML output generation to properly escape control characters, ensuring well-formed XML in both JUnit and Checkstyle formats.

## 1. `escape_xml` Function Changes

### What Changed
The `escape_xml` function in both `junit.rs` and `checkstyle.rs` now escapes XML control characters (ASCII 0x00–0x1F) as hexadecimal character references (e.g., `&#x0;`, `&#x1;`, etc.).

### New Behavior
- **Illegal control chars (0x00–0x1F except tab/LF/CR)**: Escaped as `&#xHH;` hexadecimal references
- **Legal XML chars (tab=0x09, LF=0x0A, CR=0x0D)**: Passed through unchanged
- **Standard XML specials (`&`, `<`, `>`, `"`, `'`)**: Escaped as named entities as before

### Example
```
Input:  "test\x00rule"  (NULL char embedded)
Output: "test&#x0;rule"
```

### Sync Comment
Both files retain the comment `// KEEP IN SYNC: The escape_xml logic must stay in sync with junit.rs.` (checkstyle.rs) or vice versa.

---

## 2. JUnit `<failure>` Body Changes

### What Changed
The `<failure>` element body content now has `rule_id`, `path`, and `snippet` fields passed through `escape_xml()`.

### Before (Bug)
Only the `message` attribute was escaped (line 79), but the failure body text (lines 81-87) had unescaped `rule_id`, `path`, and `snippet`:
```rust
out.push_str(&format!(
    "Rule: {}\nFile: {}\nLine: {}\nSnippet: {}\n",
    &f.rule_id,    // BUG: not escaped
    &f.path,       // BUG: not escaped
    f.line,
    &f.snippet     // BUG: not escaped
));
```

### After (Fixed)
```rust
out.push_str(&format!(
    "Rule: {}\nFile: {}\nLine: {}\nSnippet: {}\n",
    escape_xml(&f.rule_id),
    escape_xml(&f.path),
    f.line,
    escape_xml(&f.snippet)
));
```

### Impact
If a finding's `rule_id`, `path`, or `snippet` contained control characters (e.g., a NULL byte `\x00` or vertical tab `\x0B`), the JUnit XML would be malformed because those characters are illegal in XML content. The fix ensures all text content inside `<failure>` is properly escaped.

---

## Test Coverage
New red tests in `red_tests_work93f8df2f` submodule verify:
- Control chars are escaped as hex refs (`&#x0;`, `&#x1;`, etc.)
- Legal control chars (tab/LF/CR) pass through unchanged
- Mixed content with embedded control chars is handled correctly
