# Task List: work-3b090538 — `--version` Flag

## Implementation Tasks

1. Task 1: Add `#[command(version)]` to `Cli` struct
   - Add the attribute above `#[derive(Parser)]` on the `Cli` struct
   - Input: `crates/diffguard/src/main.rs`
   - Output: Modified `Cli` struct

2. Task 2: Run CI verification
   - `cargo fmt && cargo clippy --all-targets && cargo test --workspace`
   - Input: Full workspace
   - Output: Passing CI pipeline