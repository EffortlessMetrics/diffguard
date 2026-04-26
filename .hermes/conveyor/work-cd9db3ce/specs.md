# Specs: Fix `detect_language()` HTML Extension Bug

## Feature/Behavior Description

Fix the `detect_language()` function in `rules.rs` to return `Some("html")` for HTML file extensions (`"html"`, `"htm"`) instead of incorrectly returning `Some("xml")`. This is a copy-paste bug where the value from the XML match arm was never updated.

The two-representation design maintains:
- **String identifier** from `detect_language()`: `"html"` for rule filtering (`languages = ["html"]`)
- **`Language` enum** for preprocessing: `Language::Xml` for HTML (because HTML uses XML-style comments `<!-- -->`)

## Acceptance Criteria

1. **AC1**: `detect_language(Path::new("page.html"))` returns `Some("html")`
2. **AC2**: `detect_language(Path::new("page.htm"))` returns `Some("html")`
3. **AC3**: All unit tests in `rules.rs` pass, including:
   - `detect_language_xml()` test passes for XML extensions (xml, xsl, xslt, xsd, svg, xhtml)
   - `detect_language_case_insensitive()` test passes for uppercase variants
4. **AC4**: All property tests in `properties.rs` pass
5. **AC5**: `cargo clippy -p diffguard-domain` passes with no warnings
6. **AC6**: `cargo fmt --check` passes (no formatting issues)

## Non-Goals

- **Do NOT modify `preprocess.rs`**: The `Language` enum intentionally maps HTML to `Language::Xml` for preprocessing. This is correct and intentional.
- **Do NOT modify the `Language` enum or `FromStr` implementation**: HTML preprocessing should continue using XML comment syntax.
- **Do NOT add `Language::Html` variant**: Scope creep. The preprocessing behavior is correct.

## Scope

### Files to Change
- `crates/diffguard-domain/src/rules.rs`:
  - Line 223: Split match arm
  - Lines 418-419: Fix expected values in unit tests
- `crates/diffguard-domain/tests/properties.rs`:
  - Lines 58-59: Fix expected values in property test table
- `crates/diffguard-domain/CLAUDE.md`:
  - Line 28: Fix incorrect API signature documentation

### Files NOT to Change
- `crates/diffguard-domain/src/preprocess.rs` (intentional behavior)
- Any other files

## Dependencies

- MSRV: Rust 1.92
- No external dependencies required
- Domain crate: No I/O, pure functions only (constraint satisfied)