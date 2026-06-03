# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **GitHub Actions hardening** for production-ready workflows:

### Refactored

- **`diffguard-types`**: Refactored `ConfigFile::built_in()` from 533 lines of hardcoded Rust to a JSON data file. 36 built-in rules across 10 languages are now loaded at compile time via `include_str!` + `serde_json`, improving maintainability and respecting the crate's "no I/O" constraint.

### Changed
  - SHA pinning for third-party Actions (`actions/github-script@v7`, `github/codeql-action/upload-sarif@v3`) to prevent supply chain attacks
  - Explicit `permissions` block with least-privilege scopes (`contents: read`, `pull-requests: write`, `security-events: write`)
  - Windows target triple detection for MSYS/MINGW environments
  - Concurrency control on SARIF upload to prevent race conditions across workflow runs
  - Improved error handling with user-visible warning messages for fallback installation paths

### Changed

- **Full workspace tests in CI** — `cargo test --workspace` now runs all tests including xtask tests in the CI test job (previously excluded with `--exclude xtask`)
- **xtask CI job enabled** — The `xtask ci` job (which runs fmt + clippy + test + conform) now executes in CI on pull requests and pushes to main (was previously disabled via `if: false`)

### Added

- **`--color` flag for CI log output control** — Controls ANSI color output with `--color <never|always|auto>`. Use `--color=never` to suppress ANSI codes in CI logs (GitHub Actions, GitLab CI), `--color=always` to force colors in piped output, `--color=auto` (default) to auto-detect based on terminal. Respects `NO_COLOR=1` environment variable.

- **SARIF output escaping** — Escapes special characters in SARIF `Finding` fields (`text` in `SarifMessage` and `SarifSnippet`) for HTML/XML context using XML entity encoding (`<`, `>`, `&`, `"`, `'`). Prevents XSS and formatting issues when SARIF results are rendered in web-based tooling. Closes #160.

- **`# Errors` sections for core public APIs** — Added `# Errors` sections to documentation for core public APIs per Rust API Guidelines C409:
  - `parse_unified_diff`
  - `compile_rules`
  - `RuleOverrideMatcher::compile`
  - `run_check`

- **`bench` crate for performance benchmarking** — Criterion-based benchmark infrastructure:
  - Parsing benchmarks: measures `parse_unified_diff()` at 0, 100, 1K, 10K, 100K lines
  - Evaluation benchmarks: measures `evaluate_lines()` at 0, 1, 10, 100, 500 rules
  - Rendering benchmarks: measures markdown/SARIF output at 0, 10, 100, 1000 findings
  - Preprocessing benchmarks: measures comment/string masking at 0%, 25%, 50%, 75% density
  - All inputs are synthetic (generated in-memory); no file I/O in measurement paths
  - Run with `cargo bench --workspace`; HTML report with `cargo bench --workspace -- --html`
- **`--gitlab-quality` output format** — GitLab Code Quality JSON for MR code quality reports:
  - Schema matches `docs.gitlab.com/ee/ci/testing/code_quality.html`
  - Severity mapping: Error→major, Warn→minor, Info→info
  - SHA256 fingerprints for deduplication across runs
  - GitLab pipeline artifact integration

- **`--checkstyle` output format** — Checkstyle XML for SonarQube, Jenkins, and other Checkstyle-compatible tools:
  - Schema conforms to Checkstyle XML report format
  - Severity mapping: Error→error, Warn→warning, Info→info
  - File-level and line-level finding reporting

- **`diffguard doctor` subcommand** — checks environment prerequisites:
  - Git availability and version
  - Current directory is inside a git work tree
  - Configuration file presence and validity (regex compilation, duplicate IDs, etc.)
  - Supports `--config` flag for explicit config path

- **`--baseline` and `--grandfather` modes** — enterprise adoption support:
  - `--baseline` mode: establish a snapshot of current code quality as the reference point; all findings relative to baseline are reported, baseline findings are suppressed
  - `--grandfather` mode: treat the first-seen state as golden; new findings vs grandfather state are flagged, grandfather findings are suppressed
  - Exit codes: 0 (clean vs baseline/grandfather), 1 (new findings detected), 2 (error)
  - Affects all output formats (markdown, SARIF, GitLab Quality JSON, JUnit, CSV)
  - Rationale: enterprises need to onboard existing codebases without flagging pre-existing issues

### Internal

- **`diffguard-diff`**: Replaced `as u32` casts with `u32::from()` in `unescape_git_path` for lossless widening conversions, satisfying `clippy::cast_lossless` lint
- **Extracted duplicated `escape_xml` function** from `checkstyle.rs` and `junit.rs` into shared `xml_utils.rs` module

## [0.2.0] - 2026-04-06

### Added

- **Per-directory rule overrides** via `.diffguard.toml` files:
  - Rule disable/enable by subtree (`enabled`)
  - Severity overrides by subtree (`severity`)
  - Additional subtree-scoped excludes (`exclude_paths`)
- **Scope expansion** for diff analysis:
  - `scope = "deleted"` to evaluate removed lines
  - `scope = "modified"` for changed-only additions (with `changed` retained as compatibility alias)
- **Dedicated `evaluate_lines` fuzz target** (`fuzz/fuzz_targets/evaluate_lines.rs`)
- **LSP server** (`diffguard-lsp`) for editor integration with diagnostics and code actions
- **Analytics module** (`diffguard-analytics`) for trend history and false-positive tracking
- **Multi-base diff support** — compare against multiple base branches in a single run
- **GitHub Action** — `uses: EffortlessMetrics/diffguard@v0.2.0` for CI integration
- **Sensor report** (`sensor.report.v1`) - R2 Library Contract entry point (`run_sensor()`) for Cockpit/BusyBox integration, with full JSON schema
- **SARIF 2.1.0 output** (`--sarif` flag, `diffguard sarif` subcommand) for integration with GitHub Code Scanning and other SARIF-compatible tools
- **Inline suppression directives**:
  - `diffguard: ignore <rule_id>` - suppress specific rule on the same line
  - `diffguard: ignore-next-line <rule_id>` - suppress specific rule on the next line
  - `diffguard: ignore *` / `diffguard: ignore-all` - suppress all rules (wildcard)
  - Multiple rules can be comma-separated: `diffguard: ignore rule1, rule2`
- **Config presets** (`diffguard init --preset <name>`):
  - `minimal` - Basic starter configuration
  - `rust-quality` - Rust best practices
  - `secrets` - Secret/credential detection
  - `js-console` - JavaScript/TypeScript debugging
  - `python-debug` - Python debugging
- **`diffguard explain <rule_id>`** command with fuzzy matching for rule lookup
- **Rule `help` and `url` fields** for documentation in rule definitions
- **JUnit XML output** (`--junit` flag, `diffguard junit` subcommand)
- **CSV/TSV export** (`--csv`, `--tsv` flags, `diffguard csv` subcommand)
- **Environment variable expansion** in config files (`${VAR}`, `${VAR:-default}`)
- **Config includes/composition** (`includes = ["base.toml"]`):
  - Merge semantics: later definitions override earlier ones by rule ID
  - Circular include detection
  - Nested includes up to 10 levels deep
- **Rule tagging** (`tags` field) with tag-based filtering:
  - `--only-tags` - only run rules with specified tags
  - `--enable-tags` / `--disable-tags` - selectively toggle rules by tag
- **Rule test cases** (`test_cases` field in `RuleConfig`) for embedded rule testing
- **Timing metrics** in `CheckReceipt` (`timing.total_ms`, `diff_parse_ms`, `rule_compile_ms`, `evaluation_ms`)
- **Stable finding fingerprints** - SHA-256 based fingerprint for deduplication and tracking
- **Verbose/debug logging** (`--verbose`, `--debug` flags) via `tracing` to stderr
- **Shell/Bash language support** in preprocessor:
  - Hash comments (`#`) properly masked
  - Single-quoted strings (no escape sequences, Bash-style)
  - Double-quoted strings with standard escapes
  - ANSI-C quoting (`$'...'`) with escape sequences
- **Ruby language support** in preprocessor:
  - Hash comments (`#`) properly masked
  - Single and double-quoted strings handled (Ruby uses both for strings, unlike C)
- **`--staged` flag** for pre-commit hook integration (uses `git diff --cached`)
- **Pre-commit hook configuration** (`.pre-commit-hooks.yaml`)
- **CI/CD templates**:
  - GitHub Actions reusable workflow (`.github/workflows/diffguard.yml`)
  - GitLab CI template (`gitlab/diffguard.gitlab-ci.yml`)
  - Azure DevOps pipeline templates (`azure-pipelines/`)
- **Additional built-in rules**:
  - `rust.no_todo` - TODO/FIXME/`todo!()`/`unimplemented!()` detection
  - `python.no_breakpoint` - `breakpoint()` call detection
  - Ruby: `ruby.no_binding_pry`, `ruby.no_byebug`, `ruby.no_puts`
  - Java: `java.no_sout` (System.out.println)
  - C#: `csharp.no_console` (Console.WriteLine)
  - Go: `go.no_panic`
  - Kotlin: `kotlin.no_println`
  - Security rules: credential/secret detection patterns
- **Conformance tests** (`xtask conform`) - schema validation for all output formats
- **BDD integration tests** for CLI workflows
- **Snapshot tests** for JSON receipt and GitHub annotation output formats
- **Config schema** (`schemas/diffguard.config.schema.json`) for editor auto-completion
- **Sensor report schema** (`schemas/sensor.report.v1.schema.json`)
- **Frozen vocabulary constants** in `diffguard-types` (`CHECK_ID_*`, `REASON_*`, `CAP_*`, `CODE_*`)
- **Documentation improvements**:
  - `docs/architecture.md` - Crate structure and dependency flow diagrams
  - `docs/design.md` - Internal pipeline and dataflow documentation
  - `docs/requirements.md` - Functional/non-functional requirements
  - `docs/codes.md` - Complete rule ID reference with examples and suggested fixes
  - Per-crate `CLAUDE.md` files for AI-assisted development
  - Per-crate `README.md` files
- **Development roadmap** (`ROADMAP.md`) - Phased feature planning through v2.0

### Changed

- **Crate rename**: `diffguard-app` → `diffguard-core` (Fleet Crate Tiering convention)
- **Fingerprint algorithm**: upgraded from truncated hash to full SHA-256 (64 hex chars)
- **`VerdictStatus`** now includes `Skip` variant for cockpit mode when inputs are missing
- **`VerdictCounts`** includes `suppressed` field tracking suppressed findings
- **`CheckReceipt`** includes optional `timing` field for performance metrics
- **`ConfigFile`** includes `includes` field for config composition
- **`RuleConfig`** includes `tags` and `test_cases` fields
- **Built-in rules** now include `help` text, `url` links, and `tags` for documentation
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
  - `diffguard-core`: Orchestration layer
  - `diffguard`: CLI binary with I/O

[Unreleased]: https://github.com/effortlessmetrics/diffguard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/effortlessmetrics/diffguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/effortlessmetrics/diffguard/releases/tag/v0.1.0
