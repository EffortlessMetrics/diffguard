# Verification Comment: Add doctor subcommand

## Confirmed Findings (what's correct)

1. **Main CLI at `crates/diffguard/src/main.rs`** - CORRECT. Single binary crate, all CLI logic in one file.

2. **Commands enum at lines 56-86** - CORRECT. Verified: enum starts at line 56 with `Check` variant, ends at line 86 with `Trend` variant. 10 subcommands currently defined.

3. **Command handler pattern at lines 591-623** - CORRECT. The `match cli.command` block starts at line 591 and the closing brace is at line 623. Pattern is: match variant -> call `cmd_*()` function, most return `Ok(0)` inline, two (`Check`, `Validate`, `Test`) return `Result<i32>` directly from the handler.

4. **Git invoked via `Command::new("git")` in `git_diff()`/`git_staged_diff()`** - CORRECT. `git_diff()` at line 2620, `git_staged_diff()` at line 2640. Both use `Command::new("git").args(...).output()` pattern with `.context()` for error messages and `bail!` on non-zero exit.

5. **Tests in `cli_misc.rs` use `assert_cmd`** - CORRECT. File at `crates/diffguard/tests/cli_misc.rs` uses `assert_cmd::Command` with `cargo::cargo_bin!("diffguard")` helper. Uses `TempDir` for isolation. Tests verify exit codes, stdout/stderr content.

6. **Existing validate command checks config validity** - CORRECT. `cmd_validate()` at line 680 validates config files: checks duplicate rule IDs, validates regex patterns, validates globs, compiles rules. Supports `--format text|json` and `--strict` flag. Returns `Ok(0)` on success, `Ok(1)` on errors.

7. **ValidateArgs struct pattern** - CORRECT. At line 426-444: has `config: Option<PathBuf>`, `strict: bool`, `format: ValidateFormat` fields. `ValidateFormat` is a `ValueEnum` with `Text`/`Json` variants.

8. **No new dependencies needed** - CORRECT. All required crates (`clap`, `std::process::Command`, `anyhow`, `serde_json`) are already in use.

## Corrected Findings (what's wrong or incomplete)

1. **Research claims "validate command (lines 680-857)"** - MINOR INACCURACY. The function body ends at line 857, but the research describes it as covering lines 680-857 which is correct. However, the research says it "can output in text or JSON format" which is accurate but the research didn't mention the `--strict` flag which is also relevant (reports best-practice warnings).

2. **Research says "cmd_validate() function has most of the logic needed for config checking"** - OVERSTATEMENT. `cmd_validate` is monolithic ~180 lines. It cannot easily be called as a subroutine because it handles its own output formatting and returns exit codes. Doctor would need to either: (a) refactor validate into a reusable check function, or (b) duplicate the config loading/validation logic. The plan's suggestion to "reuse cmd_validate logic" is non-trivial.

3. **Research didn't mention `Result<i32>` return type pattern** - MISSING CONTEXT. Three commands (`Check`, `Validate`, `Test`) return `Result<i32>` directly from the match arm, while others return `Result<()>` and wrap with `Ok(0)` inline. Doctor should follow the `Result<i32>` pattern since it needs conditional exit codes.

4. **Research says "Tests in cli_misc.rs use assert_cmd" but doesn't mention `cli_init.rs` exists** - INCOMPLETE. `cli_init.rs` is mentioned in research_analysis.md but not verified for test patterns. The test pattern is consistent: `diffguard_cmd()` helper, `TempDir`, `.output()`, status checks.

## New Findings (what was missed)

1. **Exit code contract is stable API** - Per `.hermes/agent-context.md` line 69: "Exit codes are stable API: 0=pass, 1=tool error, 2=policy fail, 3=warn-fail". Doctor should use 0 for all-pass, 1 for failures (tool error category). This is documented but not mentioned in research.

2. **Domain crates must remain I/O-free** - Architecture constraint from agent-context.md: the CLI crate is the I/O boundary. Doctor's git checks are correctly placed in CLI crate. No concern here, but the research didn't mention this architectural constraint.

3. **`expand_env_vars` function exists** - Relevant for doctor to check env var expansion works. Already used in `cmd_validate` at line 699.

4. **CLAUDE.md documents subcommand addition pattern explicitly** - Lines 56-59 of CLAUDE.md: "Adding a new subcommand: 1. Add variant to Commands enum 2. Create corresponding Args struct 3. Add handler in main() match 4. Keep I/O in this crate, delegate logic to diffguard-core". This is the canonical pattern but wasn't referenced in the research.

5. **The match statement has inconsistent return patterns** - `Check`, `Validate`, and `Test` return `Result<i32>` directly. Others wrap `Ok(0)` inline. Doctor should pick one consistently - the `Result<i32>` pattern is more appropriate since doctor needs conditional exit codes.

6. **`cargo mutants` config exists in `mutants.toml`** - Mutation testing is part of the test strategy. Doctor implementation should consider mutation testing resilience.

## Confidence Assessment

**HIGH** - All line numbers verified against source. Patterns confirmed by reading actual code. Architecture constraints documented in multiple places. The research agent's core claims are accurate; issues are minor omissions and one overstatement about reusability.
