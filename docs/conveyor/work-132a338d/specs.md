# Specification: Complete Markdown Escaping in Table Cells

## Feature/Behavior Description

The `escape_md()` function must escape all markdown special characters that could:
1. Break the table structure (e.g., pipe `|` as column separator)
2. Inject unintended markdown formatting (e.g., `_italic_`, `**bold**`)
3. Create unintended structural elements (e.g., `-` at line start as HR/list)
4. Be used to unescape other sequences (e.g., backslash `\`)

## Acceptance Criteria

### AC1: Backslash escaping
Given user input containing a literal backslash character (e.g., `C:\path\to\file`), `escape_md()` must output the backslash as `\\` (escaped). This must happen FIRST in the replacement chain to avoid double-escaping.

**Verification**: `escape_md(r"C:\path")` returns `C:\\path`

### AC2: Dollar sign escaping
Given user input containing a `$` character (e.g., `Price: $100`), `escape_md()` must output the dollar sign as `\$` (escaped).

**Verification**: `escape_md("Price: $100")` returns `Price: \$100`

### AC3: Dash-at-line-start escaping
Given user input where a `-` is the first character of the string or appears immediately after a newline (e.g., `-warning` or `line1\n-warn`), `escape_md()` must output the dash as `\-` (escaped).

**Verification**:
- `escape_md("-warning")` returns `\-warning`
- `escape_md("line1\n-warn")` returns `line1\n\-warn`

### AC4: Existing escapes remain functional
All previously escaped characters must remain escaped:
- `|` → `\|` (table column separator)
- `` ` `` → `` \` `` (inline code)
- `#` → `\#` (headings)
- `*` → `\*` (bold/italic)
- `_` → `\_` (italic/bold)
- `[` → `\[` (link text open)
- `]` → `\]` (link text close)
- `>` → `\>` (blockquote)
- `\r` → `\r` (carriage return)
- `\n` → `\n` (newline)

**Verification**: `escape_md("| ` # * _ [ ] >")` returns `\| \` \# \* \_ \[ \] \>`

### AC5: Escape ordering is correct
Given user input `\_` (a literal backslash followed by underscore), `escape_md()` must output `\\\_` — the backslash escaped first, then the underscore escaped, without double-escaping.

**Verification**: `escape_md(r"\_")` returns `\\\_` (backslash-backslash-underscore-backslash-underscore)

### AC6: Both implementations are identical
The `escape_md()` function in `crates/diffguard-core/src/render.rs` and `crates/diffguard/src/main.rs` must be byte-for-byte identical after the fix.

## Non-Goals

- This fix does NOT refactor to a shared `escape_md()` in a common crate
- This fix does NOT add escaping for HTML entities (`&`, `<`, `>`)
- This fix does NOT change escaping for characters already handled (e.g., no changes to `|` escaping)
- This fix does NOT modify SARIF, JUnit, CSV, or other output formats
- This fix does NOT add escaping for `$` inside words (only standalone `$`)

## Dependencies

- No new external dependencies required
- Uses only stdlib `String::replace()` calls
- The fix is localized to `escape_md()` function only
