# diffguard Context for Gemini

## Project Overview

**diffguard** is a diff-scoped governance linter written in Rust. It is designed for modern PR automation, applying rules only to added or changed lines in a Git diff. It produces stable JSON receipts, Markdown summaries, and GitHub Actions annotations.

### Key Features
*   **Diff-Aware:** Scans only added/changed lines (no repo-wide noise).
*   **Output Formats:** JSON, Markdown, SARIF, JUnit, CSV/TSV, and Sensor Report.
*   **Architecture:** Modular "Clean Architecture" with strict dependency direction.
*   **Performance:** Designed for speed in CI/CD environments.

## Architecture

The project is structured as a Cargo workspace with a strict dependency hierarchy (flowing downwards):

*   **`crates/diffguard` (CLI):** The I/O boundary. Handles argument parsing (`clap`), config loading, git subprocesses, and file output.
*   **`crates/diffguard-core`:** The engine. Orchestrates check runs (`run_check`, `run_sensor`), computes verdicts, and renders outputs.
*   **`crates/diffguard-domain`:** Business logic. Compiles rules, evaluates lines, handles suppression comments, and masks strings/comments.
*   **`crates/diffguard-diff`:** Parsing logic. Parses unified diffs into structured data and handles special cases (binary files, renames).
*   **`crates/diffguard-types`:** Pure DTOs. Contains serializable types (`CheckReceipt`, `Finding`), enums, and JSON schemas. I/O-free.
*   **`crates/diffguard-testkit`:** Shared test utilities, fixtures, and proptest strategies.
*   **`xtask`:** Repository automation for CI, schema generation, and conformance testing.

## Build and Run

### Basic Commands
*   **Build:** `cargo build --workspace`
*   **Test:** `cargo test --workspace`
*   **Run CLI:** `cargo run -p diffguard -- <args>`
*   **Format:** `cargo fmt`
*   **Lint:** `cargo clippy --workspace --all-targets -- -D warnings`

### XTask Automation
The project uses `xtask` for complex workflows:
*   **Run CI Suite:** `cargo run -p xtask -- ci`
*   **Generate Schemas:** `cargo run -p xtask -- schema` (Updates `schemas/*.json`)
*   **Conformance Tests:** `cargo run -p xtask -- conform` (Validates outputs against schemas)

## Testing Strategy

The project employs a multi-layered testing strategy:

1.  **Unit Tests:** In `#[cfg(test)]` modules within source files.
2.  **Integration Tests:** In `tests/` directories for each crate.
3.  **Snapshot Tests:** Uses `insta` for verifying output formats (JSON, Markdown, SARIF).
4.  **Property Tests:** Uses `proptest` to generate random inputs and verify invariants (in `diffguard-diff`, `diffguard-domain`, `diffguard-core`).
5.  **Fuzzing:** Uses `cargo fuzz` for critical parsers (`unified_diff_parser`, `preprocess`, `rule_matcher`).
6.  **Mutation Testing:** Uses `cargo mutants` to ensure test quality.

## Configuration (`diffguard.toml`)

Configuration controls the linter behavior and rules.

```toml
[defaults]
base = "origin/main"
scope = "added"       # added|changed
fail_on = "error"     # error|warn|never

[[rule]]
id = "rust.no_unwrap"
severity = "error"
languages = ["rust"]
patterns = ["\\.unwrap\\("]
```

*   **Presets:** Built-in configs available via `diffguard init --preset <name>`.
*   **Includes:** Can compose configs using `includes = [...]`.
*   **Env Vars:** Supports expansion like `${VAR}` or `${VAR:-default}`.

## Development Conventions

*   **Clean Architecture:** Domain crates must remain I/O-free. Dependency direction must be respected.
*   **Schema-First:** Output structures (`diffguard-types`) define the contract. Schemas are auto-generated.
*   **Error Handling:** Uses `anyhow` for applications and `thiserror` for libraries.
*   **Formatting:** Standard `rustfmt`.
