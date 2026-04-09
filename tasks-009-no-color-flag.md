# Task List: work-09e5782b — `--no-color` Flag

## Implementation Tasks

1. Task 1: Add `color` field to `Cli` struct
   - Add `color: Option<ColorChoice>` field with `#[arg(long, value_enum, global = true)]`
   - Input: `crates/diffguard/src/main.rs`
   - Output: Modified `Cli` struct with new field

2. Task 2: Update `init_logging` signature
   - Modify `fn init_logging()` to accept `color: Option<&ColorChoice>` parameter
   - Input: `init_logging` function
   - Output: Updated signature

3. Task 3: Implement ANSI color logic in `init_logging`
   - Add match block: `ColorChoice::Never→false`, `Always→true`, `Auto/None→is_terminal()`
   - Pass `use_ansi` to `fmt::layer().with_ansi(use_ansi)`
   - Input: `init_logging` function body

4. Task 4: Wire `cli.color` to `init_logging` call
   - Change `init_logging(cli.verbose, cli.debug)` → `init_logging(cli.verbose, cli.debug, cli.color.as_ref())`
   - Input: `main()` function

5. Task 5: Add unit tests
   - `test_color_never`, `test_color_always`, `test_color_auto_terminal`, `test_color_auto_non_terminal`

6. Task 6: Run CI verification
   - `cargo fmt && cargo clippy --all-targets && cargo test --workspace`