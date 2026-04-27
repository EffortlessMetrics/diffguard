# ADR-0077: Replace `push_str(&format!(...))` with `write!` in diffguard-core

## Status
Accepted

## Context

GitHub issue #438 reports that `cargo clippy --workspace -- -W clippy::pedantic` flags 7 occurrences of `format!()` appended to an existing `String` via `push_str(&format!(...))` in `diffguard-core`. The issue specifically calls out locations in `junit.rs` and `render.rs`.

Analysis reveals **10 total occurrences** across 3 files in `diffguard-core`:

| File | Lines | Count |
|------|-------|-------|
| `crates/diffguard-core/src/junit.rs` | 39, 51, 63, 77, 82 | 5 |
| `crates/diffguard-core/src/render.rs` | 41, 43, 61, 67 | 4 |
| `crates/diffguard-core/src/checkstyle.rs` | 69 | 1 |

The `checkstyle.rs:69` occurrence is not mentioned in the issue title but is in the same crate and triggers the same lint.

Each `format!` call allocates a `String` on the heap which is immediately copied into `out` via `push_str` and then dropped. The `write!` macro writes directly into `out`'s internal buffer, eliminating the intermediate allocation.

The codebase already uses `write!` in `xml_utils.rs`, confirming this is the idiomatic pattern:
```rust
write!(out, "&#x{:X};", c as u32).unwrap();
```

## Decision

Fix all 10 `format_push_string` occurrences in `diffguard-core` by replacing `out.push_str(&format!(...))` with `write!(out, ...)`.

Scope includes all three affected files:
- `crates/diffguard-core/src/junit.rs` (5 occurrences)
- `crates/diffguard-core/src/render.rs` (4 occurrences)
- `crates/diffguard-core/src/checkstyle.rs` (1 occurrence)

The issue title claims 7 occurrences and names only 2 files. However, the issue is scoped to the `diffguard-core` crate, and all 10 warnings in that crate must be resolved for `cargo clippy -p diffguard-core -- -W clippy::format_push_string` to pass cleanly.

## Transformation Rules

| Pattern | Replacement |
|---------|-------------|
| `out.push_str(&format!("literal\n"));` | `write!(out, "literal\n");` |
| `out.push_str(&format!("{var}\n"));` | `writeln!(out, "{var}");` |
| `out.push_str(&format!("{a} {b}\n", a=a, b=b));` | `writeln!(out, "{a} {b}", a=a, b=b);` |

`write!` to `&mut String` returns `Result<std::fmt::Error, !>` which is always `Ok`. No error handling changes are needed.

## Consequences

### Positive
- Eliminates 10 unnecessary heap allocations per check run
- Brings `junit.rs`, `render.rs`, and `checkstyle.rs` into consistency with `xml_utils.rs`
- Produces identical output — `write!` writes directly to the `String` buffer
- Sets precedent for eventual workspace-wide `clippy --workspace` cleanliness

### Negative
- Establishes partial fix — `diffguard-lsp` (~16) and `diffguard` CLI (~20+) have remaining occurrences
- Commit message should acknowledge this is a partial workspace resolution

### Risks
- **Snapshot test drift**: Low risk — `write!` output is byte-identical to `format!` + `push_str`
- **Behavioral change**: None — transformation is semantically equivalent

## Alternatives Considered

### 1. Fix only the 7 mentioned in the issue
- **Rejected because**: Leaves 3 warnings unfixed in `diffguard-core`, meaning `cargo clippy -p diffguard-core` would still fail for this lint
- The issue scope is the crate, not specific line numbers

### 2. Leave as-is
- **Rejected because**: Violates `clippy::format_push_string` lint, which is enabled in the workspace's pedantic configuration
- Accumulated technical debt — new contributors may copy the pattern

### 3. Create a helper function to abstract the pattern
- **Rejected because**: Adds unnecessary indirection with no benefit; the `write!` macro is the correct idiomatic solution

## References
- GitHub issue: #438
- Affected crate: `diffguard-core`
- Clippy lint: `clippy::format_push_string`
- Precedent: `crates/diffguard-core/src/xml_utils.rs` (already uses `write!`)