# Research Analysis: GitLab CI Template & Code Quality Output Format

## Problem Statement

Issue #32: Add missing GitLab CI template and Code Quality JSON output format for diffguard.

The CHANGELOG (v0.2.0, line 75) claims `gitlab/diffguard.gitlab-ci.yml` exists but the file is **actually missing** from the repository. No file matching `gitlab*` exists anywhere in the repo. Additionally, there is no `--format gitlab-quality` CLI option and no GitLab Code Quality JSON renderer.

This is both a **credibility gap** (CHANGELOG claims functionality that doesn't exist) and a **feature gap** (GitLab is the second-largest CI/CD platform after GitHub, and diffguard has zero GitLab support).

## Existing Architecture Analysis

### Type System (crates/diffguard-types/src/lib.rs)

All types needed already exist:

- **`Finding`** (lines 125-136): Has `rule_id`, `severity`, `message`, `path`, `line`, `column`, `match_text`, `snippet` — this is exactly the data needed for GitLab Code Quality entries.
- **`Severity`** (lines 43-49): Three variants: `Info`, `Warn`, `Error` — maps to GitLab's `info`, `minor`, `major`.
- **`CheckReceipt`** (lines 169-178): Contains `findings: Vec<Finding>`, `tool: ToolMeta`, `diff: DiffMeta`, `verdict: Verdict` — complete input for rendering.
- **`compute_fingerprint()`** in `diffguard-core/src/fingerprint.rs` (line 13): Returns SHA-256 hex string of `rule_id:path:line:match_text` — directly reusable as GitLab's `fingerprint` field.

### Output Renderer Pattern (crates/diffguard-core/src/)

All existing renderers follow the same pattern:

| Module | Lines | Function | Pattern |
|--------|-------|----------|---------|
| `sarif.rs` | 1-545 | `render_sarif_for_receipt(receipt: &CheckReceipt) -> SarifReport` | serde Serialize structs + pretty JSON |
| `junit.rs` | 1-341 | `render_junit_for_receipt(receipt: &CheckReceipt) -> String` | Manual XML string building |
| `csv.rs` | 1-413 | `render_csv_for_receipt(receipt: &CheckReceipt) -> String` | Manual CSV string building |
| `render.rs` | 1-471 | `render_markdown_for_receipt(receipt: &CheckReceipt) -> String` | Markdown table output |

Each renderer has:
1. Public render function taking `&CheckReceipt`
2. Helper types/functions
3. Test helpers creating `CheckReceipt` fixtures
4. Unit tests + snapshot tests using `insta::assert_snapshot!`

The SARIF renderer is the closest model — it uses `serde::Serialize` structs and `serde_json::to_string_pretty()`, which is exactly what GitLab Code Quality needs.

### Export Chain (crates/diffguard-core/src/lib.rs, lines 1-19)

```
mod fingerprint;  -> pub use compute_fingerprint, compute_fingerprint_raw
mod sarif;        -> pub use SarifReport, render_sarif_for_receipt, render_sarif_json
mod junit;        -> pub use render_junit_for_receipt
mod csv;          -> pub use render_csv_for_receipt, render_tsv_for_receipt
mod render;       -> pub use render_markdown_for_receipt
```

New renderers must: define `mod`, implement function, `pub use` in lib.rs.

### CLI Integration (crates/diffguard/src/main.rs)

Output formats are handled in `cmd_check_inner()` (starting line 1941):
- `--sarif` flag (line 218) with optional path, default: `artifacts/diffguard/report.sarif.json`
- `--junit` flag (line 229) with optional path, default: `artifacts/diffguard/report.xml`
- `--csv` flag (line 239) with optional path, default: `artifacts/diffguard/report.csv`
- `--tsv` flag (line 250) with optional path, default: `artifacts/diffguard/report.tsv`

Each follows the pattern in lines 2173-2189 (sarif) / 2182-2189 (junit):
```rust
if let Some(sarif_path) = &args.sarif {
    let sarif = render_sarif_json(&run.receipt).context("render SARIF")?;
    write_text(sarif_path, &sarif)?;
    artifacts.push(Artifact { path, format: "sarif" });
}
```

There are also render-only subcommands:
- `Sarif(SarifArgs)` — reads JSON receipt, outputs SARIF
- `Junit(JunitArgs)` — reads JSON receipt, outputs JUnit XML
- `Csv(CsvArgs)` — reads JSON receipt, outputs CSV/TSV

### CI Template Pattern (azure-pipelines/)

The Azure DevOps template (`azure-pipelines/diffguard.yml`, 256 lines) provides the pattern:
- Parameterized with `baseBranch`, `configFile`, `failOn`, `installMethod`, `version`
- Boolean toggles: `publishArtifacts`, `enableSarif`, `enableMarkdown`, `enableJunit`
- Two installation methods: `cargo` (build from source) and `binary` (download from GitHub releases)
- Exit code handling (0=pass, 1=tool error, 2=policy fail errors, 3=policy fail warnings)
- The example file (`azure-pipelines/diffguard-example.yml`, 223 lines) shows usage patterns

### Reference: GitHub Action (action.yml, 248 lines)

Composite action with inputs: `base`, `head`, `config`, `fail-on`, `sarif-file`, `version`, `github-annotations`, `post-comment`. Uses binary download from GitHub releases with cargo install fallback.

## GitLab Code Quality Format Specification

The GitLab Code Quality format is a **JSON array** (not object). Each element:

```json
{
  "description": "Violation message",
  "check_name": "rule_id",
  "severity": "info|minor|major|critical|blocker",
  "location": {
    "path": "relative/path/to/file",
    "lines": { "begin": 42 }
  },
  "fingerprint": "sha256-hash",
  "content": {
    "body": "Additional context/fix suggestion"
  }
}
```

The existing `Finding` type maps directly:
- `description` ← `Finding.message`
- `check_name` ← `Finding.rule_id`
- `severity` ← Map `Severity::Info` → `"info"`, `Severity::Warn` → `"minor"`, `Severity::Error` → `"major"`
- `location.path` ← `Finding.path`
- `location.lines.begin` ← `Finding.line`
- `fingerprint` ← `compute_fingerprint(finding)` (SHA-256 already exists)
- `content.body` ← `Finding.snippet` or `Finding.match_text` with helpful context

## Key Design Decisions

### 1. Severity Mapping

| diffguard | GitLab | Rationale |
|-----------|--------|-----------|
| `Info` | `info` | Direct 1:1 mapping |
| `Warn` | `minor` | Warnings are minor issues |
| `Error` | `major` | Errors are major issues |

This is a conservative mapping. GitLab also supports `critical` and `blocker`, but diffguard has no severity level that warrants those. If diffguard ever adds a `Critical` severity, it should map to `"critical"`.

### 2. Fingerprint

The existing `compute_fingerprint()` in `fingerprint.rs` already produces a SHA-256 hash of `rule_id:path:line:match_text`. This is exactly what GitLab expects — a deterministic identifier for deduplication. We should reuse this rather than computing a separate hash.

### 3. Content Body

The `content.body` field should include the code snippet for context. Following the SARIF pattern, we include the `snippet` field text as the body.

### 4. Empty Findings Case

When there are no findings, the renderer should return an empty JSON array `[]`, consistent with SARIF returning empty `results` and JUnit returning an empty pass testsuite.

## Implementation Scope

**Two deliverables:**

### A. GitLab Code Quality JSON Renderer (new Rust module)
- File: `crates/diffguard-core/src/gitlab_quality.rs`
- Function: `render_gitlab_quality_for_receipt(&CheckReceipt) -> String`
- Export: `pub use gitlab_quality::render_gitlab_quality_for_receipt` in `lib.rs`
- CLI: New `--gitlab-quality` flag (with optional path, default: `artifacts/diffguard/code_quality.json`)
- Tests: Unit tests + insta snapshots

### B. GitLab CI Template (new YAML files)
- File: `gitlab/diffguard.gitlab-ci.yml` (parameterized template)
- File: `gitlab/example.gitlab-ci.yml` (usage examples, mirroring Azure's pattern)
- Pattern: Follow the Azure DevOps template structure with GitLab CI syntax

### C. CHANGELOG Correction
- The CHANGELOG entry at line 75 claiming `gitlab/diffguard.gitlab-ci.yml` exists must be corrected — either move to "[Added]" under "[Unreleased]" (if implementing now) or note it was incorrectly listed.

## Dependencies & Risks

- **No new Cargo dependencies needed** — serde_json and sha2/hex already available via existing deps
- **No type changes needed** — `Finding`, `Severity`, `CheckReceipt`, and `compute_fingerprint` are all sufficient
- **Low risk** — following the established SARIF renderer pattern exactly
- **Tests**: 480+ existing tests, all pass; clippy clean; fmt clean — maintain this standard
