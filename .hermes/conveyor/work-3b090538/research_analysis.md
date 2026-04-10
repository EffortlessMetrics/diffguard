# Research Analysis: Add --version flag to print version string from Cargo.toml

## Issue Summary
- **Issue:** #47 — Add a `--version` flag to the diffguard CLI that prints the version string from `Cargo.toml`
- **URL:** https://github.com/EffortlessMetrics/diffguard/issues/47
- **Priority:** P1 (FULL pipeline)

## Relevant Codebase Areas

### Key Files
- `crates/diffguard/src/main.rs` — CLI entry point using `clap` derive macros
- `Cargo.toml` — root manifest with `version = "0.2.0"` at line 19
- `crates/diffguard/Cargo.toml` — workspace member manifest

### Existing Patterns
The codebase already uses `env!("CARGO_PKG_VERSION")` in several places:
- Line 2057, 2136, 2189: Version embedded in JSON output for check receipts
- Line 3282: Hardcoded "0.1.0" in a test case

### Clap Integration
The `Cli` struct uses `#[derive(Parser)]` from `clap` (version 4.5.57). Clap 4.x supports `#[command(version)]` attribute on the root command struct. The standard clap derive pattern for version is:
```rust
#[derive(Parser)]
#[command(version)]
struct Cli { ... }
```

Where clap automatically derives `CARGO_PKG_VERSION` at compile time.

### Current CLI Structure
```rust
#[derive(Parser)]
#[command(name = "diffguard")]
#[command(about = "Diff-scoped governance lint", long_about = None)]
struct Cli {
    #[arg(long, short = 'v', global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    debug: bool,
    #[command(subcommand)]
    command: Commands,
}
```

### What Exists vs What's Needed
The clap derive framework automatically provides `--version` when `#[command(version)]` is added to the `Cli` struct. Clap will use `CARGO_PKG_VERSION` by default, which is already available via `env!()` at compile time. No runtime parsing of `Cargo.toml` is needed.

## Dependencies
- None beyond existing `clap` dependency (already in Cargo.toml)

## Constraints
- MSRV: Rust 1.92
- Must not break existing exit codes (0=pass, 1=tool error, 2=policy fail, 3=warn-fail)
- Domain crates must remain I/O-free (no env var access in domain layer)

## Key Findings
1. **clap 4.x auto-version:** Adding `#[command(version)]` to the `Cli` struct is sufficient — clap 4.x automatically uses `CARGO_PKG_VERSION`
2. **No custom implementation needed:** Clap handles `--version`, `-V`, `--V` automatically
3. **Minimal change:** Single attribute addition to `main.rs`
4. **Existing precedent:** Other CLI tools using clap derive (e.g., `ripgrep`, `fd`) follow this exact pattern

## Verification Plan
1. Add `#[command(version)]` to the `Cli` struct in `crates/diffguard/src/main.rs`
2. Verify with `cargo run -- --version` and `cargo run -- -V`
3. Run full CI: `cargo fmt && cargo clippy --all-targets && cargo test --workspace`

## Status: Ready for implementation
