# Specification: `--version` Flag for DiffGuard

## Feature / Behavior Description

Add a `--version` (and `-V`) flag to the diffguard CLI that prints the version string from `Cargo.toml`.

The version output format: `<name> <version>` where name is "diffguard" and version is `CARGO_PKG_VERSION`.

## Acceptance Criteria

1. `diffguard --version` prints the version string
2. `diffguard -V` prints the version string (shorthand)
3. Version matches `CARGO_PKG_VERSION` from `Cargo.toml`
4. `--help` output shows the version under the CLI name
5. Exit code is 0 when `--version` is used

## Non-Goals

- This does not add version to any structured output formats
- This does not add a `--version` subcommand (flag only)

## Dependencies

- None (clap 4.x built-in feature, `CARGO_PKG_VERSION` is compile-time constant)

## Test Plan

1. CLI integration test: `diffguard --version` produces output containing the version
2. CLI integration test: `diffguard -V` produces output containing the version