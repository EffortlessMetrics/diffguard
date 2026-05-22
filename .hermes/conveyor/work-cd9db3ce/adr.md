# ADR: Fix `detect_language()` HTML Extension Bug

## Title
Fix `detect_language()` copy-paste bug — `"html"|"htm"` returns `Some("xml")` instead of `Some("html")`

## Status
**Proposed**

## Context

The `detect_language()` function in `rules.rs` is used for language-based rule filtering. Users can configure rules with `languages = ["html"]` to apply rules only to HTML files. However, a copy-paste bug at line 223 causes HTML extensions (`"html"`, `"htm"`) to return `Some("xml")` instead of `Some("html")`, making HTML-specific rule filtering impossible.

The codebase has a deliberate **two-representation design** for languages:
1. **String identifiers** (`"html"`, `"xml"`, etc.) returned by `detect_language()` — used for **rule filtering** via `languages = ["html"]` config
2. **`Language` enum** (`Language::Xml`, etc.) — used for **preprocessing** (determining comment/string syntax)

This design is evident in `evaluate.rs:134-135`:
```rust
detect_language(path)
    .and_then(|s| s.parse::<Language>().ok())
    .unwrap_or(Language::Unknown)
```

The bug conflated these two representations: `detect_language()` returned `"xml"` for HTML files, preventing HTML-specific filtering while correctly enabling XML-style preprocessing.

## Decision

**Split the match arm at `rules.rs:223`** into two separate match arms:

```rust
// BEFORE (buggy):
"xml" | "xsl" | "xslt" | "xsd" | "svg" | "xhtml" | "html" | "htm" => Some("xml"),

// AFTER (fixed):
"xml" | "xsl" | "xslt" | "xsd" | "svg" | "xhtml" => Some("xml"),
"html" | "htm" => Some("html"),
```

**Update affected tests** that codify the buggy behavior:
- `rules.rs:418`: `assert_eq!(detect_language(Path::new("page.html")), Some("html"));`
- `rules.rs:419`: `assert_eq!(detect_language(Path::new("page.htm")), Some("html"));`
- `properties.rs:58`: `("html", "html"),`
- `properties.rs:59`: `("htm", "html"),`

**Do NOT modify `preprocess.rs`** — the `Language` enum intentionally maps HTML to `Language::Xml` because HTML files use XML-style comment syntax (`<!-- -->`) for preprocessing. This is correct and should remain unchanged.

**Fix CLAUDE.md documentation** at line 28 — the signature is incorrectly documented as `pub fn detect_language(path: &str) -> Option<Language>` but actual signature is `pub fn detect_language(path: &Path) -> Option<&'static str>`.

## Consequences

### Benefits
- Users can filter rules by HTML files using `languages = ["html"]` (previously impossible)
- `detect_language()` correctly returns a distinct string identifier for HTML vs XML
- No breaking changes: no existing configurations used `languages = ["html"]` due to the bug

### Trade-offs
- `detect_language()` string return value now differs from `Language` enum mapping for HTML — this is **intentional** and **by design**
- HTML files continue to be preprocessed as XML (via `Language::Xml`)
- Unit tests and property tests asserting buggy behavior must be updated

### Risks
- Low risk: no downstream breaking changes
- Case-insensitive extension matching (`.HTML`, `.HTM`) is already handled by `ext.to_ascii_lowercase()` at line 206

## Alternatives Considered

### 1. Keep HTML returning "xml" for rule filtering
Rejected because it prevents users from writing HTML-specific rules entirely. The two-representation design exists precisely to allow this distinction.

### 2. Change `Language::from_str()` to map `"html" => Language::Html`
Rejected because HTML files genuinely use XML-style comment syntax (`<!-- -->`) for preprocessing. The preprocessing behavior is correct; only the string identifier for filtering needed fixing.

### 3. Add separate `Language::Html` variant alongside `Language::Xml`
Rejected as scope creep. The preprocessing behavior is intentional and correct. Only the string identifier needed fixing.