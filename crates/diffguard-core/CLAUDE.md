# CLAUDE.md - diffguard-app

## Crate Purpose

Application layer that orchestrates the full check workflow: diff parsing → rule evaluation → output rendering. This is the use-case layer between the CLI and domain logic.

## Module Structure

| Module | Purpose |
|--------|---------|
| `check.rs` | Main orchestration: `run_check()` |
| `render.rs` | Markdown table output |
| `sarif.rs` | SARIF 2.1.0 output for code scanning |
| `junit.rs` | JUnit XML for CI/CD integration |
| `csv.rs` | CSV/TSV tabular output |

## Key APIs

### Check Orchestration (`check.rs`)

```rust
pub fn run_check(plan: CheckPlan) -> Result<CheckRun>
```

`CheckPlan` input:
- `diff: String` - Raw unified diff
- `rules: Vec<RuleConfig>` - Rule definitions
- `scope: Scope` - Added or Changed
- `fail_on: FailOn` - Failure threshold
- `max_findings: Option<usize>` - Limit findings
- `include_paths` / `exclude_paths` - Path filtering

`CheckRun` output:
- `receipt: CheckReceipt` - Full JSON-serializable result
- `markdown: String` - Rendered markdown
- `annotations: Vec<Annotation>` - GitHub Actions format
- `exit_code: u8` - Process exit code

### Rendering Functions

```rust
pub fn render_markdown_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_sarif_for_receipt(receipt: &CheckReceipt) -> SarifReport
pub fn render_junit_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_csv_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_tsv_for_receipt(receipt: &CheckReceipt) -> String
```

## Exit Codes

These are stable API - do not change:
- `0` - Pass (no policy violations)
- `1` - Tool error (internal failure)
- `2` - Policy fail (errors found, or warnings when `fail_on: warn`)
- `3` - Warn-fail (warnings found with `--warn-fail` flag)

## Common Tasks

### Adding a new output format

1. Create new module (e.g., `src/html.rs`)
2. Add render function: `render_html_for_receipt(receipt: &CheckReceipt) -> String`
3. Export from `lib.rs`
4. Add CLI flag in `diffguard/src/main.rs`
5. Add snapshot tests with `insta`

### Modifying verdict computation

1. Update logic in `check.rs`
2. Ensure exit codes remain stable
3. Update tests to cover new behavior

### Changing markdown format

1. Modify `render.rs`
2. Update snapshot tests
3. Escape special markdown characters properly

## Testing

```bash
cargo test -p diffguard-app             # Unit tests
cargo insta test -p diffguard-app       # Snapshot tests with review
```

## Dependencies

This crate depends on all three core crates:
- `diffguard-types` - DTOs
- `diffguard-diff` - Diff parsing
- `diffguard-domain` - Rule evaluation

It should not have any I/O dependencies itself - that's the CLI's job.
