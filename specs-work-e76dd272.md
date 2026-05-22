# Specification: format_push_string Fix for diffguard-core

## Feature/Behavior Description

Replace all `out.push_str(&format!(...))` patterns with `write!(out, ...)` or `writeln!(out, ...)` in the `diffguard-core` crate. This eliminates unnecessary intermediate `String` allocations flagged by the `clippy::format_push_string` lint.

The change is purely mechanical:
- `out.push_str(&format!("literal\n"));` → `write!(out, "literal\n");`
- `out.push_str(&format!("{var}\n"));` → `writeln!(out, "{var}");`
- `out.push_str(&format!("{a} {b}\n", a=a, b=b));` → `writeln!(out, "{a} {b}", a=a, b=b);`

## Acceptance Criteria

### AC1: Clippy passes with zero warnings
```bash
cargo clippy -p diffguard-core -- -W clippy::format_push_string
```
Must return exit code 0 with no warnings.

### AC2: All tests pass
```bash
cargo test -p diffguard-core
```
Must pass. Snapshot tests (insta) must produce identical output — `write!` produces byte-identical output to `format!` + `push_str`.

### AC3: All 10 occurrences fixed
The following locations must be changed:

| File | Line | Transformation |
|------|------|----------------|
| `junit.rs` | 39 | `format!(...)` → `write!` |
| `junit.rs` | 51 | `format!(...)` → `write!` |
| `junit.rs` | 63 | `format!(...)` → `write!` |
| `junit.rs` | 77 | `format!(...)` → `write!` |
| `junit.rs` | 82 | `format!(...)` → `write!` |
| `render.rs` | 41 | `format!(...)` → `write!` |
| `render.rs` | 43 | `format!(...)` → `write!` |
| `render.rs` | 61 | `format!(...)` → `writeln!` |
| `render.rs` | 67 | `format!(...)` → `write!` |
| `checkstyle.rs` | 69 | `format!(...)` → `write!` |

### AC4: Output format unchanged
The rendered output of all three formatters (JUnit XML, Markdown, Checkstyle XML) must be byte-identical before and after the change. Verify via `git diff` on snapshot files — if any diff exists, it must be whitespace-only.

## Non-Goals
- This fix does not address `format_push_string` warnings in other crates (`diffguard-lsp`, `diffguard` CLI, bench fixtures)
- No behavioral changes to output format
- No new tests required
- No error handling changes needed — `write!` to `&mut String` never fails

## Dependencies
- `diffguard-types` (internal)
- `diffguard-diff` (internal)
- `diffguard-domain` (internal)
- `cargo` toolchain
- `cargo clippy` with `clippy::format_push_string` lint enabled
- `cargo insta` for snapshot review (if snapshots change)
