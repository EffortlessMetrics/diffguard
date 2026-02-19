# diffguard-core

Core orchestration and rendering layer for diffguard.

This crate is I/O-free. It coordinates parsing + rule evaluation and returns
structured outputs for callers (CLI, editors, automation).

## Main Responsibilities

- Run checks from unified diff text (`run_check`)
- Build deterministic receipts/verdicts
- Render outputs (Markdown, SARIF, JUnit, CSV, TSV)
- Render `sensor.report.v1` envelopes
- Compute finding fingerprints

## Primary API

- `CheckPlan`
- `CheckRun`
- `run_check(&CheckPlan, &ConfigFile, &str)`
- `render_markdown_for_receipt()`
- `render_sarif_for_receipt()` / `render_sarif_json()`
- `render_junit_for_receipt()`
- `render_csv_for_receipt()` / `render_tsv_for_receipt()`
- `render_sensor_report()` / `render_sensor_json()`
- `run_sensor()` (sensor API helper)
- `compute_fingerprint()` / `compute_fingerprint_raw()`

## `run_check` Example

```rust
use std::collections::BTreeSet;

use diffguard_core::{run_check, CheckPlan};
use diffguard_types::{ConfigFile, FailOn, Scope};

let plan = CheckPlan {
    base: "origin/main".to_string(),
    head: "HEAD".to_string(),
    scope: Scope::Added,
    diff_context: 0,
    fail_on: FailOn::Error,
    max_findings: 200,
    path_filters: vec![],
    only_tags: vec![],
    enable_tags: vec![],
    disable_tags: vec![],
    directory_overrides: vec![],
    force_language: None,
    allowed_lines: None,
    false_positive_fingerprints: BTreeSet::new(),
};

let config = ConfigFile::built_in();
let diff_text = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = maybe.unwrap();
"#;

let run = run_check(&plan, &config, diff_text)?;
println!("exit_code={}", run.exit_code);
println!("findings={}", run.receipt.findings.len());
```

## Exit Code Contract

`CheckRun.exit_code` is stable:

- `0` pass
- `2` policy fail
- `3` warn-fail (when `fail_on=warn`)

`1` is reserved for outer tool/runtime failures, typically handled by callers.

## Dependency Role

`diffguard-core` depends on:

- `diffguard-diff` for unified diff parsing
- `diffguard-domain` for rule compilation/evaluation
- `diffguard-types` for DTOs and schema-bound structures

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
