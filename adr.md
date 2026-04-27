# ADR: Pin GitHub Actions to SHA Commits for Security

## Status
Proposed

## Context

GitHub issue #563 reports that GitHub Actions in workflow files use version tags (`@v4`, `@v2`, `@v3`, `@stable`) instead of SHA commits. Using version tags is less secure because:

1. **Tags can be deleted and recreated** by repository maintainers
2. **A compromised maintainer account** could push malicious code to a tag
3. **SHA pinning ensures** exactly the code reviewed is what runs

The issue specifically mentions `ci.yml` and `publish.yml` as having SHA pinning, but `sarif-example.yml` and `diffguard.yml` not. However, verification confirmed that **none** of the four workflow files actually use SHA commits — all use version tags identically.

Four workflow files need to be updated:
- `.github/workflows/ci.yml`
- `.github/workflows/publish.yml`
- `.github/workflows/sarif-example.yml`
- `.github/workflows/diffguard.yml`

Eight GitHub Actions are used across these files:
| Action | Current Reference |
|--------|-------------------|
| `actions/checkout` | `@v4` |
| `dtolnay/rust-toolchain` | `@stable` |
| `Swatinem/rust-cache` | `@v2` |
| `actions/upload-artifact` | `@v4` |
| `actions/download-artifact` | `@v4` |
| `github/codeql-action/upload-sarif` | `@v3` |
| `softprops/action-gh-release` | `@v2` |
| `actions/github-script` | `@v7` |

## Decision

**Pin all GitHub Actions to verified SHA commits** for security hardening.

For `dtolnay/rust-toolchain@stable`: Since `@stable` is a **branch reference** (not a tag), it cannot be meaningfully SHA-pinned. Instead, pin to a specific Rust version tag (e.g., `@1.85.0`) which provides reproducibility while still receiving security patch updates when manually updated.

### Verified SHA Commits

| Action | SHA |
|--------|-----|
| `actions/checkout@v4` | `34e114876b0b11c390a56381ad16ebd13914f8d5` |
| `Swatinem/rust-cache@v2` | `42dc69e1aa15d09112580998cf2ef0119e2e91ae` |
| `actions/upload-artifact@v4` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/download-artifact@v4` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| `github/codeql-action/upload-sarif@v3` | `865f5f5c36632f18690a3d569fa0a764f2da0c3e` |
| `softprops/action-gh-release@v2` | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` |
| `actions/github-script@v7` | `f28e40c7f34bde8b3046d885e986cb6290c5673b` |
| `dtolnay/rust-toolchain` | Pin to `1.85.0` (specific version tag) |

## Alternatives Considered

### 1. Leave all actions with version tags (REJECTED)
**Rationale:** Does not address the security concern. Tags can be modified post-publication.

### 2. SHA-pin all actions including `dtolnay/rust-toolchain@stable` (IMPOSSIBLE)
**Rationale:** `@stable` is a branch reference (`refs/heads/stable`), not a tag. Branch SHAs change on every push. The action cannot be SHA-pinned without pinning to a specific version.

### 3. Leave `dtolnay/rust-toolchain@stable` as-is with a comment (ACCEPTED WITH MODIFICATION)
**Rationale:** Plan review recommended pinning to a specific Rust version instead of leaving it as `@stable`. Using a version pin (e.g., `@1.85.0`) provides reproducibility without requiring ongoing maintenance beyond periodic updates.

### 4. Use `actions/setup-rust` instead of `dtolnay/rust-toolchain` (OUT OF SCOPE)
**Rationale:** Would require restructuring all workflow files. The current action is functional; the improvement is to pin it to a specific version.

## Consequences

### Benefits
- **Improved security posture**: SHA pinning ensures workflows run exactly the code reviewed
- **Supply chain attack mitigation**: Prevents malicious code injection via tag manipulation
- **Reproducibility**: Each workflow run uses identical action versions

### Tradeoffs / Risks
- **Maintenance burden**: When action maintainers release new versions, pinned SHAs become outdated. Requires periodic review and update.
- **`dtolnay/rust-toolchain` partial coverage**: Pinning to a specific Rust version (e.g., `1.85.0`) still requires manual updates for security patches. The `@stable` branch reference cannot be used.
- **Commented-out code in `sarif-example.yml`**: Lines 267-332 contain commented-out job blocks that also use version-tagged actions. These are out of scope but noted for future maintenance.
- **Broken workflows if SHAs are wrong**: Incorrect SHAs will cause workflow failures. All SHAs have been verified via GitHub API.

## Notes

- Issue description in #563 is inaccurate: it claims `ci.yml` and `publish.yml` have SHA pinning, but verification shows they use version tags identical to `sarif-example.yml` and `diffguard.yml`. All four files need updating.
- SHAs verified via GitHub API on 2026-04-27.
- The `dtolnay/rust-toolchain` action is pinned to Rust version `1.85.0` as a reasonable stable version. This should be updated periodically (recommend quarterly review).
