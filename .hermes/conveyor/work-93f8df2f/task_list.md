# Task List: work-93f8df2f — XML `escape_xml` Control Character Fix

## Overview
Fix `escape_xml` in JUnit and Checkstyle XML output renderers to properly escape XML control characters (U+0000–U+001F) per the XML 1.0 specification, and fix a secondary bug where the JUnit `<failure>` body bypasses `escape_xml` entirely.

---

## Primary Fix: `escape_xml` Control Character Escaping

### 1. Fix `escape_xml` in `junit.rs`
- **File:** `crates/diffguard-core/src/junit.rs`
- **Lines:** 107–120 (the `escape_xml` function)
- **Change:** Add a guard condition match arm that escapes control characters U+0000–U+001F (excluding tab U+0009, LF U+000A, CR U+000D) as hex character references (`&#xNN;`)
- **Implementation:**
  ```rust
  // After the five named entity arms, before `_ =>`:
  c if c <= '\u{001F}' && c != '\t' && c != '\n' && c != '\r' => {
      out.push_str(&format!("&#x{:X};", c as u32));
  }
  ```
- **Verify:** Ensure the function compiles and passes existing tests

### 2. Fix `escape_xml` in `checkstyle.rs`
- **File:** `crates/diffguard-core/src/checkstyle.rs`
- **Lines:** 83–96 (the `escape_xml` function — identical structure to junit.rs)
- **Change:** Apply the same guard condition match arm for control character escaping
- **Implementation:** Same as junit.rs
- **Verify:** Ensure the function compiles and passes existing tests

### 3. Add unit tests for `escape_xml` control character handling
- **File:** `crates/diffguard-core/src/junit.rs` (in `mod tests`)
- **Add tests:**
  - [ ] `escape_xml` with null char `\0` (U+0000) → `&#x0;`
  - [ ] `escape_xml` with U+0001 → `&#x1;`
  - [ ] `escape_xml` with U+001F (unit separator) → `&#x1F;`
  - [ ] `escape_xml` with tab `\t` (U+0009) → unchanged (legal in XML)
  - [ ] `escape_xml` with LF `\n` (U+000A) → unchanged (legal in XML)
  - [ ] `escape_xml` with CR `\r` (U+000D) → unchanged (legal in XML)
  - [ ] `escape_xml` with mixed content: `"foo\x00bar&baz"` → `"foo&#x0;bar&amp;baz"`
- **File:** `crates/diffguard-core/src/checkstyle.rs` (in `mod tests`)
- **Add tests:** Same as junit.rs (both implementations must behave identically)

---

## Secondary Fix: JUnit `<failure>` Body Escaping (Adversarial Gap 1)

### 4. Escape `f.rule_id`, `f.path`, `f.snippet` in JUnit `<failure>` body
- **File:** `crates/diffguard-core/src/junit.rs`
- **Lines:** 81–84 (the `<failure>` body construction)
- **Current code (unescaped):**
  ```rust
  out.push_str(&format!(
      "Rule: {}\nFile: {}\nLine: {}\nSnippet: {}\n",
      f.rule_id, f.path, f.line, f.snippet
  ));
  ```
- **Change:** Wrap `f.rule_id`, `f.path`, and `f.snippet` with `escape_xml()`
  ```rust
  out.push_str(&format!(
      "Rule: {}\nFile: {}\nLine: {}\nSnippet: {}\n",
      escape_xml(&f.rule_id),
      escape_xml(&f.path),
      f.line,
      escape_xml(&f.snippet)
  ));
  ```
- **Note:** `f.line` is an integer and does not need escaping
- **Verify:** JUnit XML output with special chars in rule_id, path, or snippet is now valid

### 5. Update JUnit snapshot tests
- **Command:** `cargo insta test -p diffguard-core -- --test-threads=1`
- **Action:** Review any snapshot changes due to the failure body escaping fix
- **Accept snapshots:** `cargo insta review -p diffguard-core` if needed

---

## New Test: XML Parseability (Adversarial Gap 2)

### 6. Add XML parseability test for JUnit output
- **File:** `crates/diffguard-core/src/junit.rs` (in `mod tests`)
- **Purpose:** Verify AC5 — "JUnit XML output containing control characters is parseable"
- **Test approach:**
  1. Create a `CheckReceipt` with a finding whose `message`, `path`, `rule_id`, or `snippet` contains illegal control characters (e.g., `\x00`, `\x01`, `\x1F`)
  2. Render the JUnit XML
  3. Use a Rust XML parser (e.g., `quick-xml` — add to `[dev-dependencies]` in Cargo.toml) to parse the output
  4. Assert parsing succeeds with no errors
- **Alternative if `quick-xml` unavailable:** Assert the output contains no raw control characters (0x00–0x08, 0x0B, 0x0C, 0x0E–0x1F) using regex
- **Test name suggestion:** `junit_xml_with_control_chars_is_parseable`

### 7. Add XML parseability test for Checkstyle output
- **File:** `crates/diffguard-core/src/checkstyle.rs` (in `mod tests`)
- **Purpose:** Same as above — verify Checkstyle XML output with control characters is parseable
- **Test approach:** Same pattern as JUnit test
- **Test name suggestion:** `checkstyle_xml_with_control_chars_is_parseable`

---

## Verification & Regression

### 8. Run full test suite
- **Command:** `cargo test -p diffguard-core`
- **Verify:** All tests pass, including new tests

### 9. Run snapshot tests
- **Command:** `cargo insta test -p diffguard-core`
- **Review:** Check for any snapshot changes; accept if due to correct escaping behavior
- **Note:** If snapshots change because previously-malformed output is now correctly escaped, this is expected — not a regression

### 10. Cross-file sync verification
- **Action:** Add a comment in both `junit.rs` and `checkstyle.rs` indicating the `escape_xml` functions must be kept in sync:
  ```rust
  // KEEP IN SYNC: identical implementation in checkstyle.rs (and vice versa)
  ```
- **Location:** Directly above the `escape_xml` function in each file

---

## Dependencies

### 11. Add `quick-xml` for XML parsing tests (dev dependency)
- **File:** `crates/diffguard-core/Cargo.toml`
- **Add to `[dev-dependencies]`:**
  ```toml
  quick-xml = "0.31"
  ```
- **Alternative:** If avoiding new deps, use regex for the control character assertion instead

---

## Summary Checklist

- [ ] 1. Fix `escape_xml` in `junit.rs` — add control character guard arm
- [ ] 2. Fix `escape_xml` in `checkstyle.rs` — add control character guard arm
- [ ] 3. Add `escape_xml` unit tests for control chars (junit.rs)
- [ ] 4. Add `escape_xml` unit tests for control chars (checkstyle.rs)
- [ ] 5. Fix JUnit `<failure>` body — escape `f.rule_id`, `f.path`, `f.snippet`
- [ ] 6. Update JUnit snapshot tests if needed
- [ ] 7. Add XML parseability test for JUnit output
- [ ] 8. Add XML parseability test for Checkstyle output
- [ ] 9. Add cross-file sync comment in both files
- [ ] 10. Add `quick-xml` dev dependency (or use regex alternative)
- [ ] 11. Run full test suite and verify all pass

---

## Files Modified

| File | Changes |
|------|---------|
| `crates/diffguard-core/src/junit.rs` | escape_xml fix, failure body fix, new tests, sync comment |
| `crates/diffguard-core/src/checkstyle.rs` | escape_xml fix, new tests, sync comment |
| `crates/diffguard-core/Cargo.toml` | Add `quick-xml` dev dependency (optional) |

---

## Risk Mitigation

- **Both files updated together** in the same commit to avoid drift
- **Snapshot review** step acknowledged — developer must run `cargo insta review`
- **Performance note:** The `format!` call only triggers for rare control character inputs — negligible overhead
- **Tab/LF/CR handling:** These ARE legal in XML 1.0 and are NOT escaped (per XML spec)
