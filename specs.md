# Specification: write!() macro in escape_xml() for control character escaping

## Feature Description

This work item addresses issue #305, which reported inefficient XML escape handling in `escape_xml()`. The issue requested replacing `push_str(&format!(...))` with `write!()` macro for escaping illegal XML control characters.

**Status**: The fix was already applied in commit `4711d45` (PR #370) for duplicate issue #321. This specs documents the resolved state.

## Behavior

The `escape_xml()` function in `crates/diffguard-core/src/xml_utils.rs` escapes special XML characters:

| Input | Output |
|-------|--------|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&apos;` |
| Control char 0x00-0x1F (except tab/LF/CR) | `&#xNN;` (hex entity) |
| Tab (0x09), LF (0x0A), CR (0x0D) | Preserved as-is |

## Acceptance Criteria

1. **Import present**: `use std::fmt::Write;` is imported at line 6 of `xml_utils.rs`
2. **write!() used for control chars**: Line 27 uses `write!(out, "&#x{:X};", c as u32).unwrap();` not `push_str(&format!(...))`
3. **Tests pass**: All 4 tests in `#[cfg(test)]` module pass:
   - `escape_xml_handles_all_special_chars`
   - `escape_xml_escapes_illegal_control_chars`
   - `escape_xml_preserves_legal_control_chars`
   - `escape_xml_empty_string`
4. **Clippy clean**: `cargo clippy -p diffguard-core -- -D warnings` reports no warnings

## Non-Goals

- This work item does not introduce new functionality
- This work item does not modify any APIs or behavior
- This work item does not require a new PR (fix was merged via PR #370)

## Dependencies

- Rust 1.92+ (MSRV from agent-context.md)
- `std::fmt::Write` trait (standard library)

## Verification Commands

```bash
# Unit tests
cargo test -p diffguard-core --lib -- xml_utils

# Full test suite for the crate
cargo test -p diffguard-core

# Clippy lint
cargo clippy -p diffguard-core -- -D warnings
```
