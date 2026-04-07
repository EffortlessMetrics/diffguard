# ADR-001: Add `doctor` Subcommand to Check Environment Prerequisites

## Status

Proposed

## Context

diffguard is a Rust CLI tool for static analysis of unified diffs. Its core commands (`check`, `rules`, etc.) depend on external environment prerequisites:

- **Git availability**: `diffguard check` invokes `Command::new("git")` to run `git diff` and `git diff --cached`. If git is not installed or not on PATH, the tool fails with an opaque OS-level error.
- **Configuration validity**: Users may have misconfigured `diffguard.toml` files (invalid regex patterns, duplicate rule IDs, missing required fields). Currently they must run `diffguard validate` explicitly to discover these issues before they surface mid-check.
- **Working directory context**: Some commands require the user to be inside a git repository.

Users currently have no single command to verify their environment is ready for diffguard. They must independently remember to run `git --version`, `diffguard validate`, and ensure they are in a git repository. This creates friction, especially for new users and CI pipeline setup.

Similar tools (e.g., `flutter doctor`, `brew doctor`, `cargo doctor` concept) provide a single diagnostic entry point that checks all prerequisites and reports pass/fail status for each.

## Decision

Add a `diffguard doctor` subcommand that performs a comprehensive environment check and reports the status of each prerequisite.

The command will check:

1. **Git availability**: Verify `git` is on PATH and report its version.
2. **Git repository**: Verify the current directory is inside a git work tree.
3. **Configuration file validity**: If `diffguard.toml` exists (or `--config` is provided), run the same validation logic as `diffguard validate` (regex compilation, glob parsing, duplicate ID detection, etc.).
4. **Configuration file presence**: Report whether a config file was found and which path is in use.

The command will:
- Print a human-readable summary with check name, pass/fail status, and optional detail.
- Return exit code 0 if all checks pass, or a non-zero code if any check fails (consistent with existing exit code conventions).
- Support `--config` flag for explicit config path, matching existing subcommand conventions.

## Consequences

### Positive

- Single diagnostic entry point improves user onboarding and CI setup.
- Reuses existing `cmd_validate` logic for config checking, minimizing code duplication.
- Follows established patterns in the CLI (clap subcommand, same exit code semantics, `--config` flag).
- All I/O stays in the CLI crate (`crates/diffguard/src/main.rs`), consistent with the crate's role as the I/O boundary.

### Negative

- Adds another subcommand to the CLI surface area, slightly increasing maintenance burden.
- The `doctor` checks are point-in-time; they do not continuously monitor the environment.
- Git version checking adds a subprocess call that was not previously made outside of diff operations.

### Neutral

- The `DoctorArgs` struct will be minimal (only `--config`), following the pattern of `ValidateArgs`.
- The implementation will be self-contained in a `cmd_doctor` function, keeping the diff small.
