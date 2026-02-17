# diffguard-diff

Unified diff parser used by diffguard.

This crate parses git-style unified diffs and extracts scoped lines in diff
order. It is pure parsing logic with no I/O.

## What It Returns

- `Vec<DiffLine>` with `path`, `line`, `content`, and `ChangeKind`
- `DiffStats` with file/line totals

Scope behavior:

- `Scope::Added` - all added (`+`) lines
- `Scope::Changed` / `Scope::Modified` - added lines that replace removed lines
- `Scope::Deleted` - removed (`-`) lines

## Main API

```rust
use diffguard_diff::{parse_unified_diff, ChangeKind};
use diffguard_types::Scope;

let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;

let (lines, stats) = parse_unified_diff(diff, Scope::Added)?;
assert_eq!(stats.files, 1);
assert_eq!(lines[0].kind, ChangeKind::Added);
```

## Special Cases Handled

- binary file markers
- submodule diffs
- deleted files (included only for `Scope::Deleted`)
- mode-only changes
- renames (`rename from` / `rename to`)
- quoted/escaped git paths
- malformed hunks (skip bad hunk and continue parsing later content)

## Robustness Contract

- No panics for malformed diff content
- Deterministic output ordering
- Fuzz-tested (`fuzz_targets/unified_diff_parser`)

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
