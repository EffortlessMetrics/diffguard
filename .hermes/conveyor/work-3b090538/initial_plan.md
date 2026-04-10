# Initial Plan: Add --version flag to print version string from Cargo.toml

## Approach
Add the `#[command(version)]` attribute to the `Cli` struct in `crates/diffguard/src/main.rs`. Clap 4.x automatically derives version information from `CARGO_PKG_VERSION` at compile time when this attribute is present. This is the idiomatic clap 4.x pattern and requires no custom implementation.

**Why this approach:**
- Clap 4.x natively supports `#[command(version)]` which reads `CARGO_PKG_VERSION` automatically
- Zero runtime cost — version string is embedded at compile time
- Matches patterns used by other major CLI tools (ripgrep, bat, fd)
- Minimal code change (single attribute line)
- No changes needed to domain crates or other modules

**Why not other approaches:**
- Parsing `Cargo.toml` at runtime: Rejected — unnecessary I/O, version should be compile-time constant
- Custom `--version` flag with manual string: Rejected — reinventing what clap provides for free
- Reading from environment variable: Rejected — less discoverable, not idiomatic for version flags

## Risks
1. **Low risk:** Clap derive macros are well-tested; `#[command(version)]` is a standard pattern
2. **No breaking change:** This only adds new CLI behavior; existing flags and exit codes unchanged
3. **CI compatibility:** `--version` output should not interfere with CI scripts (plain text to stdout)

## Task Breakdown
1. Add `#[command(version)]` attribute to `Cli` struct (1 line change in `main.rs`)
2. Verify with `cargo run -- --version` and `cargo run -- -V`
3. Run full CI suite: `cargo fmt && cargo clippy --all-targets && cargo test --workspace`
4. Copy artifacts to `.hermes/conveyor/work-3b090538/` in the repo for history

## Success Criteria
- `diffguard --version` prints `diffguard X.Y.Z` where X.Y.Z matches `Cargo.toml` version
- `diffguard -V` works as shorthand
- All existing tests pass
- `cargo clippy --all-targets` passes with no warnings
- `cargo fmt --check` passes

## Effort Estimate
- **Time:** < 10 minutes (single attribute change + verification)
- **Complexity:** Trivial (1 line change)
- **Confidence:** High
