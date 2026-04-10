# Initial Plan: Add --no-color flag to suppress ANSI output in CI logs

## Approach
Implement a `--color <never|always|auto>` flag on the global `Cli` struct. This is the idiomatic clap 4.x pattern using the built-in `Color` enum. We wire the color setting through to `init_logging()` which configures the `tracing_subscriber` `fmt::layer()` with `.with_ansi(...)`.

**Why this approach:**
- Clap 4.x has native `Color` enum support — no custom implementation needed
- `tracing_subscriber::fmt::layer().with_ansi(bool)` directly controls ANSI output
- Matches patterns used by `ripgrep`, `bat`, `fd`, and other modern CLI tools
- Flexible: `never` for CI, `always` for piped output, `auto` for terminal detection

**Why not a simple `--no-color` boolean:**
- Less flexible than the full `Color` enum
- Clap's `Color::Never` can also be triggered by `NO_COLOR=1` environment variable (clap auto-handles this)
- The industry standard is `--color=never` not `--no-color`

## Risks
1. **Low risk:** Standard pattern, well-tested clap and tracing-subscriber integration
2. **CI compatibility:** `--color=never` must work reliably in CI environments (GitHub Actions, etc.)
3. **No breaking change:** Only adds new CLI behavior; existing flags unchanged

## Task Breakdown
1. Add `color: Option<Color>` field to `Cli` struct in `main.rs`
2. Add `#[arg(long, value_enum)]` attribute for the color field
3. Modify `init_logging()` signature: `fn init_logging(verbose: bool, debug: bool, color: Color)`
4. In `init_logging()`, configure `fmt::layer().with_ansi(color != Color::Never)` 
5. Update callers of `init_logging()` to pass the color setting
6. Verify with: `cargo run -- --help | grep -i color` and color output tests
7. Run full CI suite: `cargo fmt && cargo clippy --all-targets && cargo test --workspace`

## Success Criteria
- `diffguard --color=never` suppresses ANSI color codes in all output
- `diffguard --color=always` forces ANSI colors even in non-TTY
- `diffguard --color=auto` respects terminal detection (default)
- `diffguard --help` shows `--color` flag
- All existing tests pass
- `cargo clippy --all-targets` passes with no warnings

## Effort Estimate
- **Time:** ~20-30 minutes (small but careful change)
- **Complexity:** Low (standard clap + tracing-subscriber pattern)
- **Confidence:** High
