# Specification: XML `escape_xml` Control Character Fix

## Feature / Behavior Description

Fix the `escape_xml` function in JUnit and Checkstyle XML output renderers to properly escape XML control characters (U+0000–U+001F) according to the XML 1.0 specification.

**Problem:** The current `escape_xml` implementation only escapes the five named XML special characters (`&`, `<`, `>`, `"`, `'`) but does not escape control characters in the range 0x00–0x1F. These characters are illegal in XML 1.0 documents (except tab U+0009, line feed U+000A, and carriage return U+000D which are permitted).

**Solution:** Add a guard condition in the match expression that escapes any control character in range U+0000–U+001F (excluding tab, LF, CR) as an XML hex character reference (`&#xNN;`).

**Examples:**
- `\0` (U+0000) → `&#x0;`
- `\x01` (U+0001) → `&#x1;`
- `\x1F` (U+001F) → `&#x1F;`
- Tab, LF, CR are NOT escaped (they are legal in XML 1.0)

## Acceptance Criteria

1. **`escape_xml` escapes all illegal control characters (0x00–0x08, 0x0B, 0x0C, 0x0E–0x1F)** — For each illegal control character, the output contains the hex character reference (e.g., `&#x0;` for null, `&#x1F;` for unit separator).

2. **`escape_xml` does NOT escape tab, LF, or CR** — These three legal XML characters pass through unchanged.

3. **`escape_xml` continues to escape the five named XML entities** — `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&apos;`.

4. **Both `junit.rs` and `checkstyle.rs` implementations are fixed** — The identical `escape_xml` function in both files produces the same correct behavior.

5. **XML output with control characters is parseable** — JUnit and Checkstyle XML output containing previously-unescaped control characters can be parsed by standard XML parsers (e.g., `xmllint`, Python's `xml.etree`, Java's DOM parser).

6. **Existing snapshot tests pass** — No regression in existing test output for inputs without control characters.

7. **New unit tests cover control character escaping** — Test cases verify illegal control characters are escaped and legal ones (tab, LF, CR) are not.

## Non-Goals

- This does NOT extract `escape_xml` into a shared utility module (duplication is a known issue tracked separately)
- This does NOT add an external XML library dependency
- This does NOT change any CLI flags or user-facing behavior
- This does NOT affect SARIF or other JSON-based output formats (JSON has different escaping rules)
- This does NOT address Unicode characters beyond the ASCII control character range (U+0080 and above are legal in XML 1.0)

## Dependencies

- No new Rust dependencies required — the fix uses only standard library features (`String`, `chars()`, `format!`)
- Rust MSRV (1.70) is unaffected — all used APIs have been stable since Rust 1.0

## Test Plan

1. **Unit test:** `escape_xml` with illegal control character (e.g., `\x00`, `\x01`) outputs hex character reference
2. **Unit test:** `escape_xml` with tab (`\t`) passes through unchanged
3. **Unit test:** `escape_xml` with LF (`\n`) passes through unchanged
4. **Unit test:** `escape_xml` with CR (`\r`) passes through unchanged
5. **Unit test:** `escape_xml` with mixed content (normal text + control chars + special chars) escapes correctly
6. **Integration test:** Render JUnit XML with a finding containing a control character in the message field; verify output is valid XML
7. **Integration test:** Render Checkstyle XML with a finding containing a control character in the message field; verify output is valid XML
8. **Snapshot test:** `cargo insta test -p diffguard-core` passes with existing snapshots unchanged
