# Initial Plan: Fix escape_xml to handle control characters 0x00–0x1F

## Approach

The `escape_xml` function in both `junit.rs` and `checkstyle.rs` needs to be extended to escape XML control characters (U+0000–U+001F, excluding the legal ones: tab U+0009, LF U+000A, CR U+000D).

### Fix Strategy

Add a match arm (or pre-check guard) for control characters in the `escape_xml` function:
- If `c` is in range `'\u{0000}'` to `'\u{001F}'` AND NOT one of `'\t'`, `'\n'`, `'\r'`, emit the XML character reference `&#xNN;` where NN is the uppercase hex value
- For example: `\0` → `&#x0;`, `\x01` → `&#x1;`, etc.

### Implementation

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

**Why this approach:**
- It reuses the existing match-based structure, keeping the code style consistent
- Uses the XML hex character reference format (`&#xNN;`) which is valid for all control characters
- Explicitly excludes tab/LF/CR because those ARE legal in XML 1.0
- The `format!` call is only triggered for rare control character inputs, so performance impact is negligible

**Why not use a separate utility module:**
- The two implementations are currently identical but in separate modules
- Extracting a shared utility would require restructuring the module dependencies
- The duplication is a known issue; fixing it is out of scope for this specific bug fix
- Both files must be updated together to maintain consistency

### Fix Both Files
- Apply the same fix to `junit.rs` (lines 107–120) and `checkstyle.rs` (lines 83–96)

## Risks

1. **Inconsistent application (because two duplicate implementations exist)** — If only one file is fixed, the other will still produce invalid XML. Both files must be updated. Mitigated by applying the fix to both files in the same commit.

2. **Snapshot tests need updating (because insta stores expected output)** — The `insta::assert_snapshot!` tests in `junit.rs` will produce new output. These need to be reviewed with `cargo insta review` and accepted. This is normal for snapshot tests and expected.

3. **Performance concern (because format! is used for each control char)** — The `format!` call for every control character is slightly more expensive than a simple `push_str`. However, for most inputs without control characters, there is zero impact. The pre-allocation via `with_capacity` remains appropriate.

4. **Unknown if control characters appear in practice (because diffguard processes text diffs)** — The issue is reported as a potential bug. The fix should be correct regardless of whether control characters actually appear in real inputs. This is a defensive fix.

## Task Breakdown

1. **[ ] Fix `escape_xml` in `junit.rs`** — Add control character escaping to the match expression
2. **[ ] Fix `escape_xml` in `checkstyle.rs`** — Apply the identical fix to the duplicate function
3. **[ ] Add unit tests** — Add test cases to `escape_xml_handles_all_special_chars` for control characters in both files
4. **[ ] Run snapshot tests** — Execute `cargo insta test -p diffguard-core` and review/accept new snapshots if any test output changes
5. **[ ] Run full test suite** — `cargo test -p diffguard-core` to ensure nothing is broken
