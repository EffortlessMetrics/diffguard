# ADR-003: HTML-Escape `SarifArtifactLocation.uri` Field

## Status
Proposed

## Context
The SARIF output renderer (`sarif.rs`) escapes HTML special characters for `SarifMessage.text` and `SarifSnippet.text` fields using the `escape_sarif_str` custom serializer, but the `SarifArtifactLocation.uri` field is not escaped. Since `uri` is populated from `Finding.path` which originates from user-controlled diff output, paths containing HTML special characters (`<`, `>`, `&`, `"`, `'`) could cause XSS or rendering issues in SARIF viewers like GitHub Advanced Security.

The module docstring (lines 6-12) states that "SARIF text fields (message, snippet) are escaped for HTML context since SARIF viewers may render them in web browsers." The `uri` field is rendered in web browsers by SARIF viewers and should be consistent with this documented intent.

## Decision
Add `#[serde(serialize_with = "escape_sarif_str")]` attribute to the `uri` field in `SarifArtifactLocation` struct.

**File:** `crates/diffguard-core/src/sarif.rs`
**Line:** 160

```rust
// BEFORE
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

// AFTER
pub struct SarifArtifactLocation {
    #[serde(serialize_with = "escape_sarif_str")]
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}
```

This reuses the existing `escape_sarif_str` function (which calls `escape_xml`) that already handles `<`, `>`, `&`, `"`, `'`, and illegal control characters.

## Consequences

### Benefits
1. **Security**: Closes an XSS vector in SARIF viewers that render URIs in HTML context
2. **Consistency**: Makes `uri` consistent with `message` and `snippet` which are already escaped
3. **Minimal change**: Single-line attribute addition, no structural changes
4. **Leverages existing code**: Uses proven `escape_sarif_str` infrastructure

### Trade-offs
1. **Double-escaping risk**: If a path already contains HTML entities (e.g., `src/&lt;file&gt;`), they will become `src/&amp;lt;file&amp;gt;`. This is pre-existing behavior for `message` and `snippet` fields and is an acceptable trade-off for the security benefit.
2. **Downstream consumers**: Consumers parsing `uri` as a raw path string will now receive escaped paths. Any consumer doing HTML rendering without unescaping first would see literal entity strings.

## Alternatives Considered

### Alternative 1: URL-encode the URI field
- **Rejected because**: URL encoding (`%3C`, `%3E`, `%26`) is not appropriate for a field that is displayed as text in SARIF viewers. Users would see `%3C` instead of `<` which is not human-readable.

### Alternative 2: Create a separate escaping function for URIs only
- **Rejected because**: Unnecessary duplication. The existing `escape_xml` handles all required cases. Creating a separate function would add code with no benefit.

### Alternative 3: Leave `uri` unescaped and document it
- **Rejected because**: Leaves a security vulnerability. The module docstring already claims text fields are escaped; leaving `uri` unescaped creates an inconsistency between documentation and implementation.

## Non-Goals (Out of Scope)
- Fixing other unescaped fields (`rule_id`, `uri_base_id`, `command_line`) — tracked separately
- Changing the `&apos;` XML entity usage for single quotes (pre-existing behavior)
- Updating the module docstring (implementation detail, handled separately)