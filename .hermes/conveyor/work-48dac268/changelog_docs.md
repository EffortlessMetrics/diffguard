# Changelog Documentation - work-48dac268

## Summary

Updated CHANGELOG.md to document the change: **Enable xtask CI job and run full workspace tests**.

## What Was Changed

### CHANGELOG.md Updates

Added entries under `## [Unreleased]` → `### Changed`:

1. **Full workspace tests in CI** — `cargo test --workspace` now runs all tests including xtask tests in the CI test job (previously excluded with `--exclude xtask`)

2. **xtask CI job enabled** — The `xtask ci` job (which runs fmt + clippy + test + conform) now executes in CI on pull requests and pushes to main (was previously disabled via `if: false`)

## Files Modified

| File | Change |
|------|--------|
| `CHANGELOG.md` | Added 2 entries under `### Changed` in Unreleased section |

## Verification

- README.md was reviewed; no updates needed as it already correctly documents:
  - `cargo test --workspace` as the command for unit tests
  - `cargo run -p xtask -- ci` as the full CI suite command
  - The xtask crate in the repo layout table

## Documentation Standards Applied

- Entry written for users, not developers (describes what changed for them)
- Entry explains the before/after behavior
- Entry is placed in appropriate section (Changed - for CI behavior changes)
- No implementation details included
- No migration needed (no user-facing API or behavior change)

## Notes

- This is an internal/CI infrastructure change
- No user-facing behavior changes
- Both the test job and xtask job will now run xtask tests (acceptable redundancy per ADR)
- CONTRIBUTING.md and AGENTS.md already correctly document the testing commands
