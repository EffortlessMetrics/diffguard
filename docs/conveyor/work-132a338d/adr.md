# ADR-001: Fix escape_md() for complete markdown special character escaping

## Status
Proposed

## Context

The `escape_md()` function in both `crates/diffguard-core/src/render.rs` and `crates/diffguard/src/main.rs` sanitizes finding fields before rendering them into a markdown table. Currently, it escapes `|`, `` ` ``, `#`, `*`, `_`, `[`, `]`, `>`, `\r`, and `\n`. However, three markdown special characters remain unescaped:

1. **`\` (backslash)** — Without escaping, a literal backslash in user input could be used to "unescape" the sequences we add (e.g., `\_` would become an italic underscore if the backslash itself isn't escaped first)

2. **`$` (dollar sign)** — Triggers math mode in some markdown parsers (e.g., KaTeX, MathJax). While GitHub Flavored Markdown doesn't render LaTeX, other markdown renderers in CI/CD pipelines might.

3. **`-` (dash) at line start** — At the beginning of a line, `-` creates horizontal rules or list items in markdown. Inside table cells, this could break rendering in some parsers.

The existing test only covers `|` and backtick escaping, leaving the new escapes untested.

## Decision

We will extend `escape_md()` in **both** `render.rs` and `main.rs` with three additional escape sequences:

1. **Backslash escaping first** (`\` → `\\`) — Must be done FIRST in the replacement chain to avoid double-escaping the backslashes we insert during other replacements. For example, if we escaped `|` first to `\|` and then did backslash escaping, the backslash in `\|` would become `\\|`, incorrectly doubling the backslash.

2. **Dollar sign escaping** (`$` → `\$`) — Defensive escaping for math-mode capable parsers.

3. **Dash-at-line-start escaping** — Only when `-` is the first character of the entire string or immediately after a newline. This prevents horizontal rule/list injection without modifying all dashes.

The implementations in both files must remain identical.

## Consequences

### Benefits
- All markdown special characters that could break table rendering or inject formatting are now properly escaped
- Backslash escaping first ensures correct behavior when user input already contains backslash sequences
- Line-start dash handling is surgical — only escapes syntax-relevant dashes, not all dashes

### Tradeoffs
- Two identical implementations must be kept in sync (no shared code extraction — not worth the complexity for a simple function)
- The chained `.replace()` calls are O(n) per replacement but acceptable for finding output
- `$` escaping is conservative — may not be needed for GFM but is harmless and future-proofs against other parsers

### Risks
- **Backslash ordering is critical**: Escaping backslash LAST would double-escape the backslashes we add during other replacements. The implementation must escape backslash FIRST.
- **Test coverage gap**: Existing tests only verify `|` and backtick escaping. New tests must cover the three additional characters.

## Alternatives Considered

### 1. Backslash escaping LAST
Rejected. If backslash escaping were done last, the backslashes we insert when escaping other characters (e.g., the backslash in `\|`) would themselves get escaped (to `\\|`), corrupting the output. The backslash must be escaped first.

### 2. HTML entities instead of backslash escaping
Rejected for now. Using HTML entities (`&`, `<`, `>`) would be more robust against parser differences, but introduces a more invasive change and produces different output format. The simpler backslash-escaping approach is sufficient for the immediate bug.

### 3. No `$` escaping
Rejected. While GFM doesn't render LaTeX math, the escaping is harmless and defensive. Other markdown renderers in CI pipelines may handle `$` as math delimiters.

### 4. Refactor to shared `escape_md()` in a common crate
Rejected. The two implementations are small and identical. Extracting to a shared module adds architectural complexity without significant benefit. If the duplication becomes problematic in the future, a follow-up ADR can address it.

## References

- GitHub Issue: #356
- Existing implementation: `crates/diffguard-core/src/render.rs:126-137`
- CLI implementation: `crates/diffguard/src/main.rs:1693-1704`
- Existing test: `render_finding_row_escapes_pipes_and_backticks` (only covers `|` and backtick)
