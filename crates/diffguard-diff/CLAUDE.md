# CLAUDE.md - diffguard-diff

## Crate Purpose

Unified diff parser that extracts scoped lines from git diff output. Handles edge cases like binary files, submodules, renames, and mode-only changes.

## Key Constraints

- **No I/O** - Must not use `std::process`, `std::fs`, or `std::env`
- **Never panics** - Malformed input must return errors, never crash
- **Fuzz-tested** - Run fuzz tests after any parsing changes

## Key Files

| File | Purpose |
|------|---------|
| `src/lib.rs` | Public exports |
| `src/unified.rs` | Main parsing logic |

## Public API

```rust
pub fn parse_unified_diff(input: &str, scope: Scope) -> Result<(Vec<DiffLine>, DiffStats)>
```

Supporting types:
- `DiffLine` - Represents one line in the diff with file, line number, content
- `ChangeKind` - Enum: Added, Changed, Deleted
- `DiffStats` - Aggregate statistics

Detection helpers:
- `is_binary_file()` - Detect binary file markers
- `is_submodule()` - Detect submodule changes
- `is_new_file()` / `is_deleted_file()` - File creation/deletion
- `is_mode_change_only()` - Permission-only changes
- `parse_rename_from()` / `parse_rename_to()` - Rename detection

## Common Tasks

### Adding support for a new diff edge case

1. Add detection function in `unified.rs`
2. Update `parse_unified_diff()` to handle the case
3. Add unit tests with sample diff output
4. Run fuzz tests: `cargo +nightly fuzz run unified_diff_parser`

### Debugging diff parsing issues

1. Get the raw diff that's failing
2. Add it as a test case in `unified.rs`
3. Use `insta` snapshot to capture expected output
4. Fix the parsing logic

## Testing

```bash
cargo test -p diffguard-diff           # Unit tests
cargo +nightly fuzz run unified_diff_parser  # Fuzz testing
```

Fuzz testing is critical - run it after any parsing changes to ensure no panics on malformed input.

## Edge Cases Handled

- Binary files (skipped)
- Submodule changes (skipped)
- Renamed files (tracked correctly)
- Mode-only changes (no content lines)
- Missing newline at EOF
- Deleted files (skipped unless scope is `Deleted`)
