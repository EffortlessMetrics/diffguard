# Implementation Plan: GitLab CI Template & Code Quality Output Format

## Approach

This plan takes a two-track approach: add a new output renderer module for GitLab Code Quality JSON, because the existing SARIF renderer proves this pattern works, and create a parameterized GitLab CI template, because the Azure DevOps template already defines the required parameters and workflow. Both changes reuse existing types and infrastructure to minimize risk.

### Why this approach

- The `Finding` and `CheckReceipt` types already contain every field needed for GitLab Code Quality JSON, because they were designed as general-purpose DTOs from the start
- The SARIF renderer already demonstrates the serde Serialize pattern we need, because both are JSON output formats
- The `compute_fingerprint()` function already produces SHA-256 hashes, because it was built for deduplication tracking and GitLab uses the exact same mechanism
- The Azure DevOps template already defines all required parameters (base branch, config file, fail-on level, install method), because these are universal CI/CD integration needs

## Part 1: GitLab Code Quality JSON Renderer

### Step 1: Create `crates/diffguard-core/src/gitlab_quality.rs`

The module will define serializable structs mirroring the GitLab Code Quality JSON schema, plus the main render function.

**File structure:**

```rust
// crates/diffguard-core/src/gitlab_quality.rs

use serde::Serialize;
use diffguard_types::{CheckReceipt, Finding, Severity};
use crate::compute_fingerprint;

// ── GitLab Code Quality Report Types ─────────────────────────────

/// A single finding in GitLab Code Quality format.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GitLabFinding {
    pub description: String,
    pub check_name: String,
    pub severity: GitLabSeverity,
    pub location: GitLabLocation,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<GitLabContent>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitLabSeverity {
    Info,
    Minor,
    Major,
}

impl From<Severity> for GitLabSeverity {
    fn from(s: Severity) -> Self {
        match s {
            Severity::Info => GitLabSeverity::Info,
            Severity::Warn => GitLabSeverity::Minor,
            Severity::Error => GitLabSeverity::Major,
        }
    }
}

/// Location of a finding within a file.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabLocation {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<GitLabLines>,
}

/// Line numbers within a file.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabLines {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub begin: Option<u32>,
}

/// Optional additional context for a finding.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabContent {
    pub body: Option<String>,
}

// ── Render Function ──────────────────────────────────────────────

pub fn render_gitlab_quality_for_receipt(receipt: &CheckReceipt) -> String {
    let findings: Vec<GitLabFinding> = receipt
        .findings
        .iter()
        .map(finding_to_gitlab)
        .collect();

    serde_json::to_string_pretty(&findings)
        .expect("GitLab Quality JSON serialization should never fail")
}

fn finding_to_gitlab(f: &Finding) -> GitLabFinding {
    let content = if !f.snippet.is_empty() || !f.match_text.is_empty() {
        let body_parts: Vec<&str> = if f.snippet.is_empty() {
            vec![&f.match_text]
        } else if f.match_text.is_empty() {
            vec![&f.snippet]
        } else {
            vec![&f.snippet]
        }
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();

        if body_parts.is_empty() {
            None
        } else {
            Some(GitLabContent {
                body: Some(body_parts.join("\n\n")),
            })
        }
    } else {
        None
    };

    GitLabFinding {
        description: f.message.clone(),
        check_name: f.rule_id.clone(),
        severity: f.severity.into(),
        location: GitLabLocation {
            path: f.path.clone(),
            lines: Some(GitLabLines {
                begin: Some(f.line),
            }),
        },
        fingerprint: compute_fingerprint(f),
        content,
    }
}
```

### Step 2: Wire into `crates/diffguard-core/src/lib.rs`

Add after the existing module declarations (line 10):

```rust
mod gitlab_quality;
```

Add to public exports (after line 17):

```rust
pub use gitlab_quality::render_gitlab_quality_for_receipt;
```

### Step 3: Add CLI flag in `crates/diffguard/src/main.rs`

Add to `CheckArgs` struct (after `tsv` field around line 251):

```rust
/// Write a GitLab Code Quality report (JSON).
///
/// If provided with no value, defaults to artifacts/diffguard/code_quality.json
#[arg(
    long,
    value_name = "PATH",
    num_args = 0..=1,
    default_missing_value = "artifacts/diffguard/code_quality.json"
)]
gitlab_quality: Option<PathBuf>,
```

Add import in the `use diffguard_core::` block (line 20-23):

```rust
use diffguard_core::{
    ...,
    render_gitlab_quality_for_receipt,
};
```

Add the rendering logic in `cmd_check_inner()` after the TSV block (after line 2207):

```rust
if let Some(gitlab_path) = &args.gitlab_quality {
    let gitlab = render_gitlab_quality_for_receipt(&run.receipt);
    write_text(gitlab_path, &gitlab)?;
    artifacts.push(Artifact {
        path: to_artifact_path(gitlab_path),
        format: "gitlab-quality".to_string(),
    });
}
```

### Step 4: Add tests in `crates/diffguard-core/src/gitlab_quality.rs`

Following the exact pattern of `sarif.rs` and `junit.rs`:

- Test helpers: `create_test_receipt_with_findings()`, `creates_test_receipt_empty()`, `create_test_receipt_info_findings()`
- Unit tests:
  - `gitlab_quality_is_json_array()` — verifies output starts and ends with `[`/`]`
  - `gitlab_quality_contains_all_findings()` — verifies count
  - `gitlab_quality_severity_mapping_error()` — Error → major
  - `gitlab_quality_severity_mapping_warn()` — Warn → minor
  - `gitlab_quality_severity_mapping_info()` — Info → info
  - `gitlab_quality_has_fingerprint()` — fingerprint is 64 hex chars
  - `gitlab_quality_has_location_path_and_line()` — path and lines.begin
  - `gitlab_quality_empty_receipt()` — returns `[]`
  - `gitlab_quality_check_name_is_rule_id()`
- Snapshot tests:
  - `snapshot_gitlab_quality_with_findings()`
  - `snapshot_gitlab_quality_no_findings()`

## Part 2: GitLab CI Template

### Step 1: Create `gitlab/diffguard.gitlab-ci.yml`

A parameterized GitLab CI template with these variables (mirroring Azure DevOps pattern):

```yaml
# .diffguard vars (all with defaults):
#   DIFFGUARD_BASE_BRANCH - default: main
#   DIFFGUARD_CONFIG_FILE - default: diffguard.toml
#   DIFFGUARD_FAIL_ON - default: error (error|warn|never)
#   DIFFGUARD_INSTALL_METHOD - default: cargo (cargo|binary)
#   DIFFGUARD_VERSION - default: latest
#   DIFFGUARD_ENABLE_SARIF - default: false
#   DIFFGUARD_ENABLE_MARKDOWN - default: true
#   DIFFGUARD_ENABLE_JUNIT - default: false
#   DIFFGUARD_ENABLE_GITLAB_QUALITY - default: false
#   DIFFGUARD_WORKING_DIR - default: .
#   DIFFGUARD_ADDITIONAL_ARGS - default: (empty)
```

The template will be a `.gitlab-ci.yml` include-able file using GitLab's `include:` mechanism with `remote:` or local file reference. Unlike Azure's template system, GitLab CI uses included YAML files where parameters are passed via variables.

Key differences from Azure template:
- GitLab uses `.gitlab-ci.yml` with `include:` directive
- Parameters are passed as CI/CD variables (not structured template parameters)
- Uses GitLab's built-in `rules:` for conditional execution
- Artifacts published via GitLab's `artifacts:` keyword
- Code Quality: GitLab natively reads `gl-code-quality-report.json` from artifacts

### Step 2: Create `gitlab/example.gitlab-ci.yml`

Demonstrate: minimal usage, full configuration, SARIF + Code Quality enabled, multiple projects.

Mirror the structure of `azure-pipelines/diffguard-example.yml` with GitLab CI equivalents.

## Part 3: CHANGELOG Correction

Move the GitLab CI claim from `[0.2.0] > Added` (line 75) to `[Unreleased] > Added`:

```markdown
## [Unreleased]

### Added

- **GitLab CI integration:**
  - `gitlab/diffguard.gitlab-ci.yml` template for parameterized GitLab CI/CD
  - `--gitlab-quality` flag producing GitLab Code Quality JSON (`gl-code-quality-report.json` format)
```

Remove line 75 from `[0.2.0]` section (the phantom `gitlab/diffguard.gitlab-ci.yml` claim).

## File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `crates/diffguard-core/src/gitlab_quality.rs` | **NEW** | GitLab Code Quality renderer |
| `crates/diffguard-core/src/lib.rs` | MODIFY | Add `mod gitlab_quality;` + `pub use` |
| `crates/diffguard/src/main.rs` | MODIFY | Add `--gitlab-quality` flag + render wireup |
| `gitlab/diffguard.gitlab-ci.yml` | **NEW** | Parameterized GitLab CI template |
| `gitlab/example.gitlab-ci.yml` | **NEW** | Usage examples |
| `CHANGELOG.md` | MODIFY | Move GitLab CI to [Unreleased], remove phantom entry |
| `crates/diffguard-core/src/snapshots/` | NEW | Snapshot files for gitlab_quality tests |

## Test Strategy

1. **Unit tests** in `gitlab_quality.rs` — severity mapping, structure correctness, empty receipt
2. **Snapshot tests** via `insta` — match the SARIF/JUnit pattern
3. **CLI integration** — existing integration test infrastructure covers output flag wiring
4. **No new dependencies** — uses existing `serde`, `serde_json`, `sha2`, `hex`

## Validation

```bash
cargo test -p diffguard-core                     # Unit + snapshot tests
cargo test -p diffguard                           # CLI integration tests
cargo clippy --all -- -D warnings                 # Must stay clean
cargo fmt --all -- --check                        # Must stay clean
```
