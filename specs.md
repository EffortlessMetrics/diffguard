# Spec: Add `# Errors` Section to `verify_snake_case_fields`

## Feature / Behavior Description
Add a properly formatted `# Errors` section to the doc comment of the public function `verify_snake_case_fields` in `crates/diffguard-testkit/src/schema.rs`.

**Current doc comment (lines 147-152):**
```rust
/// Verify all field names in a JSON value are snake_case.
///
/// # Returns
///
/// - `Ok(())` if all field names are snake_case
/// - `Err(Vec<String>)` with the non-snake_case field names
pub fn verify_snake_case_fields(value: &serde_json::Value) -> Result<(), Vec<String>> {
```

**Expected doc comment:**
```rust
/// Verify all field names in a JSON value are snake_case.
///
/// # Returns
///
/// - `Ok(())` if all field names are snake_case
/// - `Err(Vec<String>)` with the non-snake_case field names
///
/// # Errors
///
/// Returns `Err(Vec<String>)` if any field name in the JSON value is not
/// valid snake_case. The returned vector contains the offending field names.
pub fn verify_snake_case_fields(value: &serde_json::Value) -> Result<(), Vec<String>> {
```

## Acceptance Criteria

1. **AC1**: The doc comment for `verify_snake_case_fields` includes a `# Errors` section that describes the `Err(Vec<String>)` variant.

2. **AC2**: The `# Errors` section follows the canonical repo format: blank line after the header, prose description of the error condition.

3. **AC3**: `cargo check -p diffguard-testkit` produces no `clippy::missing_errors_doc` warnings for `verify_snake_case_fields`.

4. **AC4**: No `#[allow(...)]` suppression attributes are introduced.

## Non-Goals
- This fix does not address other functions in `schema.rs` with the same gap (lines 50, 63, 71, 77)
- This fix does not change the function's API or behavior
- This fix does not add tests — existing tests cover the function's behavior

## Dependencies
- None — purely documentation change
