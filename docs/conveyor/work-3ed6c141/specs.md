# Specification: HTML-Escape `SarifArtifactLocation.uri` Field

## Feature/Behavior Description
When generating SARIF 2.1.0 output, the `uri` field in `SarifArtifactLocation` must have HTML special characters escaped to prevent XSS and rendering issues in SARIF viewers.

The `uri` field value originates from `Finding.path`, which comes from user-controlled diff output. Paths may contain HTML special characters: `<`, `>`, `&`, `"`, `'`.

**Example:**
- Input path: `src/<repo>/root&special/file.rs`
- Output in SARIF JSON: `"uri": "src/&lt;repo&gt;/root&amp;special/file.rs"`

## Acceptance Criteria

### AC1: HTML Special Characters Escaped
**Given** a `CheckReceipt` with a finding where `path` contains HTML special characters (`<`, `>`, `&`, `"`, `'`)
**When** SARIF JSON is rendered via `render_sarif_json()`
**Then** the `uri` field in the output contains HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;`) instead of raw characters

### AC2: Existing Escaping Behavior Preserved
**Given** a `CheckReceipt` with findings where `message` and `snippet` contain HTML special characters
**When** SARIF JSON is rendered
**Then** `message` and `snippet` fields remain properly escaped as before
**And** no regression in existing escaping coverage

### AC3: Normal Paths Unchanged
**Given** a `CheckReceipt` with findings where `path` contains no HTML special characters
**When** SARIF JSON is rendered
**Then** the `uri` field appears exactly as the original path string (no change to clean paths)

### AC4: Valid JSON Output
**Given** any valid `CheckReceipt`
**When** SARIF JSON is rendered
**Then** the output is valid JSON that can be parsed by `serde_json::from_str::<serde_json::Value>()`

## Non-Goals (Out of Scope)
- Fixing escaping for other SARIF fields (`rule_id`, `uri_base_id`, `command_line`)
- Changing `&apos;` to HTML5-compatible `&#39;` for single quotes
- Updating module documentation

## Dependencies
- `escape_sarif_str()` function at `sarif.rs:118-124` — already exists
- `escape_xml()` function at `xml_utils.rs:16-33` — already exists
- `adversarial_sarif_escape_test.rs::challenge_uri_field_not_escaped` — will need update after fix (invert assertion from "not escaped" to "escaped")