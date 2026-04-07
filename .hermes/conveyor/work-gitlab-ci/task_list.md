# Task Breakdown: GitLab Code Quality Output Format
# Date: 2026-04-07

## Overview
Implementation tasks for adding GitLab Code Quality output format to diffguard.

## Tasks
- [ ] **T1**: Create `crates/diffguard-core/src/gitlab_quality.rs`
  - [ ] **T2**: Define serializable structs for GitLab Code Quality JSON schema (GitLabFinding, GitLabSeverity, GitLabLocation, GitLabContent)
  - [ ] **T3**: Implement `render_gitlab_quality(receipt: &CheckReceipt) -> Vec<GitLabFinding>`
  - [ ] **T4**: Add severity mapping function (map_severity -> GitLabSeverity)
  - [ ] **T5**: Use existing `compute_fingerprint()` for fingerprint field
  - [ ] **T6**: Add `gitlab_quality` module to `crates/diffguard-core/src/lib.rs`
  - [ ] **T7**: Add `gitlab-quality` to `Format` enum in `crates/diffguard/src/main.rs`
  - [ ] **T8**: Wire `gitlab-quality` format in CLI format matching logic
  - [ ] **T9**: Add snapshot test for `crates/diffguard-core/tests/snapshots/`
  - [ ] **T10**: Create test fixture with sample CheckReceipt
  - [ ] **T11**: Add test case: basic output with findings
  - [ ] **T12**: Add test case: empty findings list
  - [ ] **T13**: Add test case: severity mapping for all three levels
  - [ ] **T14**: Add test case: fingerprint consistency
  - [ ] **T15**: Add test case: optional fields handling (lines, content)
  - [ ] **T16**: Add test case: pretty-print formatting
  - [ ] **T17**: Add test case: special characters and Unicode
  - [ ] **T18**: Add test case: file output with `--out` flag
  - [ ] **T19**: Add test case: JSON schema validation
  - [ ] **T20**: Run `cargo test --workspace` and verify all tests pass
- [ ] **T21**: Update README.md with `--format gitlab-quality` documentation
- [ ] **T22**: Update CHANGELOG.md with feature addition
- [ ] **T23**: Add example output to README.md
- [ ] **T24**: Verify GitLab.com compatibility (optional: manual test)
- [ ] **T25**: Verify GitLab Self-Managed compatibility (optional: manual test)
- [ ] **T26**: Create gitlab/ directory in repo root
- [ ] **T27**: Create `gitlab/diffguard.gitlab-ci.yml` template
- [ ] **T28**: Parameterize template with variables (base, config, fail-on, install method, output format)
- [ ] **T29**: Add binary download step for Linux/Darwin
- [ ] **T30**: Add cargo install fallback step
- [ ] **T31**: Add diffguard execution step with appropriate flags
- [ ] **T32**: Add artifact upload step for JSON receipt
- [ ] **T33**: Add artifact upload step for SARIF (optional)
- [ ] **T34**: Add artifact upload step for JUnit XML (optional)
- [ ] **T35**: Add comment step for MR discussions (optional)
- [ ] **T36**: Add documentation comments to template
- [ ] **T37**: Test template on GitLab.com (optional: manual test)
- [ ] **T38**: Test template on GitLab Self-Managed (optional: manual test)
- [ ] **T39**: Update CHANGELOG to reflect GitLab CI template addition
- [ ] **T40**: Close issue #32 (linked to this work item)
