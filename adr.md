# ADR-XXX: Use write!() macro in escape_xml() for control character escaping

## Status
Accepted

## Context

Issue #305 reported that `xml_utils.rs:25` was using `out.push_str(&format!("&#x{:X};", c as u32))` to escape illegal XML control characters. This creates an unnecessary intermediate `String` allocation before copying into the output buffer.

The `escape_xml()` function in `crates/diffguard-core/src/xml_utils.rs` is a shared utility used by JUnit, Checkstyle, and other XML-based output formatters. It handles:
- 5 named XML entities (`&`, `<`, `>`, `"`, `'`)
- Illegal control characters (0x00-0x1F except tab/LF/CR) as `&#xNN;` hex entity references

## Decision

**Issue #305 is closed as duplicate of issue #321.** The fix was already merged in commit `4711d45` (PR #370).

The fix applies the `write!()` macro directly to the output `String` via the `std::fmt::Write` trait:

```rust
// Before (line 25 before fix)
out.push_str(&format!("&#x{:X};", c as u32));

// After (line 27 after fix)
use std::fmt::Write;
write!(out, "&#x{:X};", c as u32).unwrap();
```

The `std::fmt::Write` trait is imported at line 6 to enable the `write!()` macro on `String`.

## Consequences

### Benefits
- **Performance**: Eliminates intermediate `String` allocation in the hot path of XML output generation
- **Memory efficiency**: `write!()` writes directly to the `String`'s internal buffer
- **Correctness**: `write!()` to a `String` with a valid format string cannot fail, so `.unwrap()` is appropriate

### Tradeoffs
- None. This is a pure refactor with identical behavior and better performance.

### Risks
- **Governance debt**: Issue #305 is a duplicate of #321, creating confusion about which issue to reference. This ADR documents the relationship to prevent future duplicate work.

## Alternatives Considered

### 1. Keep format!() + push_str()
Rejected because it allocates an intermediate `String` for each control character, adding unnecessary overhead in high-volume CI/CD usage.

### 2. Use char::encode_utf8() directly
Rejected as overly complex. The `write!()` macro is idiomatic Rust and clearly expresses intent.

## Related Decisions

- Issue #321: Original issue that identified this pattern
- Commit `4711d45`: Merged PR #370 fixing this issue
- Issue #305: Duplicate of #321, closed per this ADR
