# Specification: GitHub Actions SHA Pinning

## Feature Description

Replace version tag references (`@v4`, `@v2`, `@v3`, `@v7`, `@stable`) in all GitHub Actions `uses:` declarations with verified SHA commits to improve supply chain security.

## Affected Files

- `.github/workflows/ci.yml`
- `.github/workflows/publish.yml`
- `.github/workflows/sarif-example.yml`
- `.github/workflows/diffguard.yml`

## Actions to Pin

| Action | New Reference |
|--------|---------------|
| `actions/checkout` | `34e114876b0b11c390a56381ad16ebd13914f8d5` |
| `dtolnay/rust-toolchain` | `1.85.0` (specific version, not `@stable`) |
| `Swatinem/rust-cache` | `42dc69e1aa15d09112580998cf2ef0119e2e91ae` |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/download-artifact` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| `github/codeql-action/upload-sarif` | `865f5f5c36632f18690a3d569fa0a764f2da0c3e` |
| `softprops/action-gh-release` | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` |
| `actions/github-script` | `f28e40c7f34bde8b3046d885e986cb6290c5673b` |

## Acceptance Criteria

### AC1: All `uses:` declarations use SHA references
Every GitHub Action `uses:` declaration in the four workflow files must end with a 40-character hexadecimal SHA (not a version tag like `@v4` or `@v2`).

**Verification:**
```bash
# After changes, this should return no results for version tags in uses: lines
grep -r 'uses:.*@v[0-9]' .github/workflows/
grep -r 'uses:.*@stable' .github/workflows/
```

### AC2: YAML files parse correctly
All modified YAML files must be valid YAML and parseable without errors.

**Verification:**
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/publish.yml'))"
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/sarif-example.yml'))"
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/diffguard.yml'))"
```

### AC3: `dtolnay/rust-toolchain` uses specific version
The `dtolnay/rust-toolchain` action must reference a specific Rust version (e.g., `@1.85.0`), not the `@stable` branch reference.

### AC4: Changes committed to correct branch
All changes must be committed to branch `feat/work-5102a8b6/github-actions-pinned-by-sha-in-ci.yml-a`, never to `main`.

**Verification:**
```bash
git branch --show-current  # Should output: feat/work-5102a8b6/github-actions-pinned-by-sha-in-ci.yml-a
```

### AC5: Each workflow file has a pinning documentation comment
Each modified workflow file should contain a comment at the top (or near the `uses:` declarations) noting when and why the actions were pinned.

Example:
```yaml
# Pinned to SHA commits on 2026-04-27 per security hardening (work-5102a8b6).
# Review quarterly for updated action versions.
```

## Non-Goals

- **Not** updating commented-out code in `sarif-example.yml` (lines 267-332) — these are out of scope but should be noted for future maintenance
- **Not** restructuring workflows — only replacing version references with SHAs
- **Not** modifying `azure-pipelines/` files (Azure Pipelines, not GitHub Actions)
- **Not** modifying `action.yml` (GitHub Action definition file)

## Dependencies

- GitHub API access to verify SHA commits for each action version
- Correct SHA values (verified via GitHub API):
  - `actions/checkout@v4` → `34e114876b0b11c390a56381ad16ebd13914f8d5`
  - `Swatinem/rust-cache@v2` → `42dc69e1aa15d09112580998cf2ef0119e2e91ae`
  - `actions/upload-artifact@v4` → `ea165f8d65b6e75b540449e92b4886f43607fa02`
  - `actions/download-artifact@v4` → `d3f86a106a0bac45b974a628896c90dbdf5c8093`
  - `github/codeql-action/upload-sarif@v3` → `865f5f5c36632f18690a3d569fa0a764f2da0c3e`
  - `softprops/action-gh-release@v2` → `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65`
  - `actions/github-script@v7` → `f28e40c7f34bde8b3046d885e986cb6290c5673b`

## Out of Scope

- Changes to `azure-pipelines/` directory
- Changes to `action.yml` in repository root
- Periodic updates to pinned SHAs (future maintenance)
- Commented-out job definitions in `sarif-example.yml`
