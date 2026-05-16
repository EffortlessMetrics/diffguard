# Task List — work-5102a8b6

## Implementation Tasks

- [ ] T1: Update `.github/workflows/ci.yml` with SHA-pinned actions
  - Replace `actions/checkout@v4` with SHA
  - Replace `dtolnay/rust-toolchain@stable` with `dtolnay/rust-toolchain@1.85.0`
  - Replace `Swatinem/rust-cache@v2` with SHA

- [ ] T2: Update `.github/workflows/publish.yml` with SHA-pinned actions
  - Replace `actions/checkout@v4` with SHA
  - Replace `dtolnay/rust-toolchain@stable` with `dtolnay/rust-toolchain@1.85.0`
  - Replace `Swatinem/rust-cache@v2` with SHA
  - Replace `actions/upload-artifact@v4` with SHA
  - Replace `actions/download-artifact@v4` with SHA
  - Replace `softprops/action-gh-release@v2` with SHA

- [ ] T3: Update `.github/workflows/sarif-example.yml` with SHA-pinned actions
  - Replace `actions/checkout@v4` with SHA
  - Replace `dtolnay/rust-toolchain@stable` with `dtolnay/rust-toolchain@1.85.0`
  - Replace `Swatinem/rust-cache@v2` with SHA
  - Replace `github/codeql-action/upload-sarif@v3` with SHA
  - Replace `actions/upload-artifact@v4` with SHA
  - Replace `actions/github-script@v7` with SHA

- [ ] T4: Update `.github/workflows/diffguard.yml` with SHA-pinned actions
  - Replace `actions/checkout@v4` with SHA
  - Replace `dtolnay/rust-toolchain@stable` with `dtolnay/rust-toolchain@1.85.0`
  - Replace `Swatinem/rust-cache@v2` with SHA
  - Replace `github/codeql-action/upload-sarif@v3` with SHA
  - Replace `actions/upload-artifact@v4` with SHA

- [ ] T5: Validate all YAML files parse correctly
  - Run `python3 -c "import yaml; yaml.safe_load(open(f))"` on all 4 files

- [ ] T6: Verify no version tags remain in uses: declarations
  - Run `grep -r 'uses:.*@v[0-9]' .github/workflows/` — should return empty
