# diffguard-core

Application layer for the [diffguard](https://crates.io/crates/diffguard) governance linter.

This crate orchestrates the full check workflow: diff parsing → rule compilation → evaluation → output rendering. It sits between the CLI and the domain logic, coordinating the pipeline without performing I/O itself.

## Features

- **Check orchestration**: `run_check()` coordinates the full linting pipeline
- **Multiple output formats**:
  - JSON receipt (`CheckReceipt`) — versioned schema for automation
  - Markdown summary — for PR comments
  - SARIF 2.1.0 — for GitHub Advanced Security and code scanning tools
  - JUnit XML — for CI/CD integration
  - CSV/TSV — for spreadsheet import
- **Verdict computation**: Determines pass/warn/fail based on findings and `fail_on` policy
- **Path filtering**: Include/exclude files by glob patterns

## Usage

```rust
use diffguard_core::{run_check, CheckPlan, render_markdown_for_receipt};
use diffguard_types::{ConfigFile, Scope, FailOn};

// Set up the check plan
let plan = CheckPlan {
    diff_text: git_diff_output,
    config: ConfigFile::built_in(),
    base: "origin/main".to_string(),
    head: "HEAD".to_string(),
    scope: Scope::Added,
    fail_on: FailOn::Error,
    max_findings: Some(100),
    include_paths: vec![],
    exclude_paths: vec!["**/vendor/**".to_string()],
};

// Run the check
let run = run_check(plan)?;

// Access results
println!("Exit code: {}", run.exit_code);
println!("Findings: {}", run.receipt.findings.len());
println!("Verdict: {:?}", run.receipt.verdict.status);

// Render outputs
let markdown = render_markdown_for_receipt(&run.receipt);
```

## Exit Codes

The `CheckRun.exit_code` follows a stable contract:

| Code | Meaning |
|------|---------|
| `0` | Pass — no policy violations |
| `1` | Tool error — internal failure |
| `2` | Policy fail — errors found (or warnings when `fail_on: warn`) |
| `3` | Warn-fail — warnings found with warn-fail policy |

## Output Formats

### Markdown

```rust
use diffguard_core::render_markdown_for_receipt;

let md = render_markdown_for_receipt(&receipt);
// Renders a table with: Severity | Rule | Location | Message | Snippet
```

### SARIF

```rust
use diffguard_core::{render_sarif_for_receipt, SarifReport};

let sarif: SarifReport = render_sarif_for_receipt(&receipt);
let json = serde_json::to_string_pretty(&sarif)?;
// SARIF 2.1.0 format for GitHub Advanced Security
```

### JUnit XML

```rust
use diffguard_core::render_junit_for_receipt;

let xml = render_junit_for_receipt(&receipt);
// JUnit XML for CI/CD systems (Jenkins, GitLab CI, etc.)
```

### CSV/TSV

```rust
use diffguard_core::{render_csv_for_receipt, render_tsv_for_receipt};

let csv = render_csv_for_receipt(&receipt);
let tsv = render_tsv_for_receipt(&receipt);
// Tabular format for spreadsheet import
```

## Architecture

This crate depends on all three core crates:
- `diffguard-types` — DTOs and configuration types
- `diffguard-diff` — Unified diff parsing
- `diffguard-domain` — Rule compilation and evaluation

```
CheckPlan (input)
    │
    ▼
parse_unified_diff() ──► compile_rules() ──► evaluate_lines()
    │                         │                    │
    ▼                         ▼                    ▼
DiffLines              CompiledRules           Findings
    │                         │                    │
    └─────────────────────────┴────────────────────┘
                              │
                              ▼
                    compute_verdict() ──► CheckRun (output)
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
