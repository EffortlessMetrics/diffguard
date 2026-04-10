# Red Tests for work-93f8df2f

## Bug Description
`escape_xml` function in `junit.rs` and `checkstyle.rs` does not handle XML control characters (0x00–0x1F). These characters are illegal in XML content and must be escaped as hex character references (e.g., `&#x0;`).

Additionally, the JUnit failure body content (`rule_id`, `path`, `snippet`) is not escaped at all — it is embedded raw into the failure body.

## Types Inspected

### junit.rs
```rust
/// Escapes special XML characters in a string.
fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}
```

**Bug**: Control characters (0x00–0x1F) fall through to `_ => out.push(c)` and are NOT escaped.

### checkstyle.rs
Same implementation as `junit.rs` — same bug.

### JUnit Failure Body (lines 81–85 in junit.rs)
```rust
out.push_str(&format!(
    "Rule: {}\nFile: {}\nLine: {}\nSnippet: {}\n",
    f.rule_id, f.path, f.line, f.snippet
));
```
**Bug**: `f.rule_id`, `f.path`, and `f.snippet` are embedded raw without `escape_xml()` wrapping.

## Tests Added

### JUnit escape_xml control character tests (in `mod junit::tests::red_tests_work93f8df2f`)

| Test | What it tests |
|------|---------------|
| `escape_xml_null_char` | 0x00 must become `&#x0;` |
| `escape_xml_soh_char` | 0x01 must become `&#x1;` |
| `escape_xml_vertical_tab` | 0x0B must become `&#xB;` |
| `escape_xml_form_feed` | 0x0C must become `&#xC;` |
| `escape_xml_unit_separator` | 0x1F must become `&#x1F;` |
| `escape_xml_tab_passthrough` | 0x09 (tab) passes through unchanged |
| `escape_xml_lf_passthrough` | 0x0A (LF) passes through unchanged |
| `escape_xml_cr_passthrough` | 0x0D (CR) passes through unchanged |
| `escape_xml_mixed_content` | Control char in "before\x00after" correctly escaped |
| `junit_failure_body_rule_id_escaped` | `rule_id` with control char in failure body must be escaped |
| `junit_failure_body_path_escaped` | `path` with control char in failure body must be escaped |
| `junit_failure_body_snippet_escaped` | `snippet` with control char in failure body must be escaped |
| `junit_xml_no_unescaped_control_chars` | JUnit XML output must not contain raw control chars |

### Checkstyle escape_xml control character tests (in `mod checkstyle::tests::red_tests_work93f8df2f`)

| Test | What it tests |
|------|---------------|
| `escape_xml_null_char` | 0x00 must become `&#x0;` |
| `escape_xml_soh_char` | 0x01 must become `&#x1;` |
| `escape_xml_vertical_tab` | 0x0B must become `&#xB;` |
| `escape_xml_form_feed` | 0x0C must become `&#xC;` |
| `escape_xml_unit_separator` | 0x1F must become `&#x1F;` |
| `escape_xml_tab_passthrough` | 0x09 (tab) passes through unchanged |
| `escape_xml_lf_passthrough` | 0x0A (LF) passes through unchanged |
| `escape_xml_cr_passthrough` | 0x0D (CR) passes through unchanged |
| `escape_xml_mixed_content` | Control char in "before\x00after" correctly escaped |
| `checkstyle_xml_no_unescaped_control_chars` | Checkstyle XML output must not contain raw control chars |

## Test Results

```
running 23 tests
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_cr_passthrough ... ok
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_lf_passthrough ... ok
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_mixed_content ... FAILED
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_null_char ... FAILED
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_form_feed ... FAILED
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_tab_passthrough ... ok
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_unit_separator ... FAILED
test checkstyle::tests::red_tests_work93f8df2f::checkstyle_xml_no_unescaped_control_chars ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_cr_passthrough ... ok
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_soh_char ... FAILED
test checkstyle::tests::red_tests_work93f8df2f::escape_xml_vertical_tab ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_form_feed ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_lf_passthrough ... ok
test junit::tests::red_tests_work93f8df2f::escape_xml_mixed_content ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_null_char ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_tab_passthrough ... ok
test junit::tests::red_tests_work93f8df2f::escape_xml_unit_separator ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_soh_char ... FAILED
test junit::tests::red_tests_work93f8df2f::escape_xml_vertical_tab ... FAILED
test junit::tests::red_tests_work93f8df2f::junit_failure_body_path_escaped ... FAILED
test junit::tests::red_tests_work93f8df2f::junit_failure_body_snippet_escaped ... FAILED
test junit::tests::red_tests_work93f8df2f::junit_failure_body_rule_id_escaped ... FAILED
test junit::tests::red_tests_work93f8df2f::junit_xml_no_unescaped_control_chars ... FAILED

test result: FAILED. 6 passed; 17 failed; 0 ignored
```

**Status: RED** — All 17 tests that verify control character escaping behavior fail, confirming the bug exists. The 6 passing tests confirm that the legal XML characters (tab, LF, CR) already pass through correctly.

## Files Modified
- `crates/diffguard-core/src/junit.rs` — Added 13 red tests in `mod junit::tests::red_tests_work93f8df2f`
- `crates/diffguard-core/src/checkstyle.rs` — Added 10 red tests in `mod checkstyle::tests::red_tests_work93f8df2f`
