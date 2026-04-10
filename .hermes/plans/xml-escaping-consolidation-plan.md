# Plan: XML Escaping Consolidation — Issues #127, #130, #131

## Issues
- **#131** — Duplicated `escape_xml` function in checkstyle.rs and junit.rs
- **#130** — XML output: `escape_xml` doesn't handle control characters (0x00–0x1F)
- **#127** — JUnit XML failure text content does not escape XML special characters

## Goal

Consolidate duplicated XML escaping logic into a shared utility module, fix the JUnit XML special-character escaping bug, and add control-character handling to the shared function.

## Current Context

- PR #5 (v0.2) merged 2026-04-09 — adds LSP, multi-base diffs, directory overrides, analytics
- Local branch is behind `origin/main` by 1 commit (#126 — Error::source() chain propagation)
- Build passes, tests pass, clippy clean
- `escape_xml` exists identically (11 lines) in two files:
  - `crates/diffguard-core/src/checkstyle.rs` (line 83)
  - `crates/diffguard-core/src/junit.rs` (line 107)
- Neither handles ASCII control characters (U+0000–U+001F), which XML 1.0 prohibits
- JUnit XML also inserts unescaped text into `<failure>` content

## Proposed Approach

**Step 1 — Extract shared module**
1. Create `crates/diffguard-core/src/xml_utils.rs`
2. Move `escape_xml` there with proper control-character handling:
   ```rust
   pub fn escape_xml(s: &str) -> String {
       let mut out = String::with_capacity(s.len());
       for c in s.chars() {
           match c {
               '&' => out.push_str("&amp;"),
               '<' => out.push_str("&lt;"),
               '>' => out.push_str("&gt;"),
               '"' => out.push_str("&quot;"),
               '\'' => out.push_str("&apos;"),
               _ if c.is_control() => out.push_str(&format!("&#x{:02x};", c as u8)),
               _ => out.push(c),
           }
       }
       out
   }
   ```
3. Update both `checkstyle.rs` and `junit.rs` to import from `xml_utils`

**Step 2 — Fix JUnit special character escaping**
4. In `crates/diffguard-core/src/junit.rs`, identify all text fields inserted into XML (classname, name, message, failure message)
5. Apply `escape_xml()` to each text field that currently bypasses escaping
6. Key fields: `<failure>` element text content, `message` attribute

**Step 3 — Add tests**
7. Add unit test in `xml_utils.rs` covering all five XML special chars plus a control character (e.g., `\x00`)
8. Add snapshot test for JUnit output with `&`, `<`, `>`, `"`, `'` in finding messages
9. Add snapshot test for Checkstyle output with control characters

**Step 4 — Verify**
10. `cargo test -p diffguard-core`
11. `cargo clippy --workspace --all-targets -- -D warnings`
12. `cargo fmt --check`

## Files Likely to Change

| File | Change |
|------|--------|
| `crates/diffguard-core/src/xml_utils.rs` | **New** — shared `escape_xml` |
| `crates/diffguard-core/src/checkstyle.rs` | Import from `xml_utils`; remove local copy |
| `crates/diffguard-core/src/junit.rs` | Import from `xml_utils`; remove local copy; add escaping to text fields |
| `crates/diffguard-core/src/lib.rs` | Export `xml_utils` |
| `crates/diffguard-core/tests/` | Add snapshot tests for XML special chars and control chars |

## Tests / Validation

1. Unit test for `escape_xml` with all five special chars + `\x00`, `\x07`, `\x1F`
2. Snapshot test: JUnit output with `& < > " '` in finding message
3. Snapshot test: Checkstyle output with `\x00` control character
4. `cargo test -p diffguard-core` — all pass
5. `cargo clippy --workspace --all-targets -- -D warnings` — clean

## Risks & Tradeoffs

- **Risk**: Missing text fields in JUnit that need escaping (e.g., attribute values set via `.attr()`). Review all JUnit XML construction carefully.
- **Mitigation**: Audit all XML element/attribute construction in `junit.rs`; add a comment above each text-insertion call noting it uses `escape_xml`
- **Tradeoff**: Adding control-character escaping slightly increases output size for malicious inputs — acceptable since XML parsers require it

## Open Questions

- **Q**: Should control characters be stripped instead of encoded? **A**: Encoding (`&#x00;`) preserves intent; stripping could silently hide data. Use encoding.
- **Q**: Should the checkstyle output also get the same treatment? **A**: Yes — both `escape_xml` copies should be replaced, so checkstyle benefits too.
- **Q**: Do existing snapshot tests need updating? **A**: Likely yes if any test fixtures contain XML special chars — run `cargo insta review` after changing.
