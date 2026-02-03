# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Ruby language support** in preprocessor:
  - Hash comments (`#`) properly masked
  - Single and double-quoted strings handled (Ruby uses both for strings, unlike C)
- **Documentation improvements**:
  - `docs/architecture.md` - Crate structure and dependency flow diagrams
  - `docs/design.md` - Internal pipeline and dataflow documentation
  - `docs/requirements.md` - Functional/non-functional requirements
  - `docs/codes.md` - Complete rule ID reference with examples and suggested fixes
- **Development roadmap** (`ROADMAP.md`) - Phased feature planning through v2.0

### Changed

- **Diff builder API** in `diffguard-testkit`:
  - More ergonomic builder pattern for constructing test diffs
  - Improved method chaining

## [0.1.0] - 2026-02-01

### Added

- **Core linting engine**: Diff-scoped rule evaluation that only checks added/changed lines
- **Unified diff parser**: Robust parsing of `git diff` output with support for:
  - Binary file detection
  - Submodule change detection
  - File rename/copy detection
  - Mode change detection
- **Rule configuration**: TOML-based rule definitions with:
  - Regex pattern matching
  - Glob-based path filtering (`paths`, `exclude_paths`)
  - Language filtering with auto-detection from file extensions
  - Configurable severity levels (`error`, `warn`)
- **Preprocessing**: Comment and string literal masking (C-like syntax heuristics)
  - `ignore_comments`: Skip matches inside comments
  - `ignore_strings`: Skip matches inside string literals
- **Multiple output formats**:
  - JSON receipt for automation/bots
  - Markdown summary for PR comments
  - GitHub Actions annotations (`::error`, `::warning`)
- **Configurable exit codes**:
  - `0`: Pass (or warnings only when `fail_on = "error"`)
  - `1`: Tool error (I/O, parse, config failures)
  - `2`: Policy failure (error-level findings)
  - `3`: Warn-level failure (when `fail_on = "warn"`)
- **CLI interface** with clap:
  - `--base` / `--head`: Specify diff range
  - `--config`: Custom config file path
  - `--out`: JSON output path
  - `--md`: Markdown output path
  - `--github-annotations`: Emit GitHub Actions annotations
- **JSON schemas**: Generated schemas for config and receipt validation
- **Comprehensive test suite**:
  - Property-based tests with proptest
  - Snapshot tests with insta
  - Fuzz testing targets for diff parsing, preprocessing, and rule matching
  - Mutation testing configuration

### Architecture

- Clean layered architecture with I/O at edges:
  - `diffguard-types`: Pure DTOs (serde + schemars)
  - `diffguard-diff`: Pure diff parsing (I/O-free)
  - `diffguard-domain`: Pure business logic (I/O-free)
  - `diffguard-app`: Orchestration layer
  - `diffguard`: CLI binary with I/O

[Unreleased]: https://github.com/effortless-mgmt/diffguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/effortless-mgmt/diffguard/releases/tag/v0.1.0
