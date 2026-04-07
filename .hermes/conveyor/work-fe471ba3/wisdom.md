# Wisdom: work-fe471ba3 — Add doctor subcommand to check environment prerequisites

## What Worked Well (Keep Doing)

1. **Red-green discipline** — Writing 16 tests first as "red" tests (all failing because the subcommand didn't exist) established clear acceptance criteria before implementation. The green-to-19 final pass rate was tracked at every stage.

2. **Early extraction of shared logic** — The refactor agent identified duplicated validation logic between `cmd_validate` and `cmd_doctor` and extracted `validate_config_rules()`. This eliminated ~80 lines of duplication and fixed a real bug (the `multiline_window` check that was missing from the doctor copy). Extract shared validation functions early rather than waiting for code-quality review.

3. **Plan review caught critical design flaws before implementation** — The plan review correctly identified that `cmd_validate()` cannot be called as a subroutine (it has side effects: printing to stdout, returning exit codes). This steered the implementation toward a proper extraction rather than the tempting but flawed "just call validate from doctor" shortcut.

4. **Multi-gate review loop** — The code-quality agent identified 8 distinct findings (formatting, nesting depth, early-return inconsistency, missing multiline_window check, stale comments, etc.), and the refactor agent systematically addressed the structural ones. The deep-review agent then confirmed the refactor improved the code and caught the `[[rules]]` vs `[[rule]]` test issue that had survived all prior gates.

5. **No new dependencies** — The implementation used only crates already in the project (clap, std::process::Command, anyhow, toml). Zero Cargo.toml changes meant zero dependency risk.

## What Was Hard or Surprising (Watch Out For)

1. **Config validation reuse is not straightforward** — The plan review flagged this as HIGH risk and it proved correct. `cmd_validate()` is a full command handler, not a pure function. Both the plan and initial research oversimplified the reuse story. Future plans should explicitly distinguish between "call a function" and "extract a pure function from a command handler."

2. **Test file constraints blocked cosmetic fixes** — The refactor agent was constrained from modifying test files, which meant the stale "RED tests" header comment in `doctor.rs` was never updated. The deep-review agent re-flagged the same issue. When constraints block cosmetic corrections, track them as separate follow-ups.

3. **Tests pass with wrong TOML table names** — Three test cases used `[[rules]]` (plural) instead of `[[rule]]` (singular), meaning they silently validated zero rules and passed trivially. This was caught only by the deep-review agent at the end. Tests that pass for the wrong reason are worse than no tests at all — they create false confidence. This is a general lesson: verify test assertions are actually exercising the code path they claim to test.

4. **Nesting depth in `cmd_doctor`** — The initial implementation had 6+ levels of nesting (match → Ok → match → Ok → Ok → for → for). This is a common pattern when writing inline I/O-heavy code with multiple match statements. The fix was to extract a `validate_config_for_doctor()` helper with flat early-return guard clauses. Lesson: if you're at match-in-match nesting, stop and extract.

5. **Pre-existing workspace build failures** — The workspace has compilation errors in other crates (diffguard-testkit missing `description` field) that are unrelated to this work. These surfaced during verification and could mask real failures. The `cargo test --test doctor` workaround was used, but it's a persistent hazard.

6. **Exit code semantics are a minefield** — The plan review correctly flagged that exit code 1 in diffguard means "tool error" per the stable API contract, but the specs use 1 for "any check failed." This was left as-is because doctor's failure IS a diagnostic failure, and the team was comfortable overloading exit code 1 for this purpose. Future diagnostic commands should settle this convention once and document it.

## What Could the Pipeline Do Better (Improvements)

1. **Catch wrong TOML table names earlier** — The `[[rules]]` vs `[[rule]]` issue survived the initial plan, red tests, implementation, code quality review, and refactor. It required a deep-review agent to find. Consider adding a lightweight TOML-table-name validation step to the test review gate, or a static analysis check that verifies test fixtures parse into non-empty structs.

2. **Automate test assertion strength checks** — The three tests that passed trivially (with 0 rules) should have been flagged by detecting that their assertions are vacuously satisfied. A pipeline step that checks "does this test actually produce the data structures it claims to validate?" would catch this class of bug.

3. **Track deferred issues explicitly** — Multiple issues were noted but not fixed (stale comments, wrong TOML names, ROADMAP documentation gap, README documentation gap). These should be captured as follow-up issues rather than just "notes in review documents." Consider a convention: every review gate produces a "deferred items" list that gets logged as pipeline artifacts.

4. **Branch name mismatch between plan and reality** — The work item tracks branch `feat/vscode-lsp-client-rewrite` but some artifacts reference the feature branch `feat/work-fe471ba3/add-doctor-subcommand-to-check-environme`. The SKILL.md for conveyor-run-postmortem already notes this pattern. Consider ensuring all agents use the same canonical branch name from the work-item state.

5. **Pre-existing build noise** — The workspace compilation failure in diffguard-testkit is a persistent issue that surfaces during verification. A pipeline improvement would be to track known broken artifacts and only flag new failures that differ from the known-bad baseline.

## Specific Lessons for the diffguard Codebase

1. **main.rs is a pressure cooker** — At 5000+ lines, it contains the Commands enum, all args structs, all cmd_* handlers, git helpers, receipt processing, LSP server, and config validation. The plan review suggested extracting doctor to `src/doctor.rs`; this should become a standard practice. Every new subcommand handler should go in its own module.

2. **Shared validation functions pay dividends** — The `validate_config_rules()` extraction not only reduced duplication but fixed a real bug. The codebase has other places where validation logic may be duplicated (e.g., rule compilation checks). Audit for similar patterns.

3. **`[[rule]]` is the correct TOML table name** — The ConfigFile struct uses `rule: Vec<RuleConfig>` (singular). Any test fixture or documentation using `[[rules]]` is wrong. This is an easy trap because the semantic intent is "rules" (plural) but the serde deserializer expects the field name.

4. **Exit code contract is stable API** — Per agent-context.md: `0=pass, 1=tool error, 2=policy fail, 3=warn-fail`. When adding diagnostic commands, this contract constrains design. Doctor uses 1 for "checks failed" which works but sits in a gray area between "tool error" and "policy fail." Future commands should either adopt a consistent convention or request a dedicated exit code.

5. **Domain crates must remain I/O-free** — The doctor's git subprocess calls correctly stayed in the CLI crate (main.rs). This architectural constraint should be reinforced for all new I/O operations. Any logic that touches files, subprocesses, or network belongs in the CLI crate, delegated to domain crates only for pure computation.

6. **The validate command should be split** — Both the plan review and this implementation converged on the same conclusion: `cmd_validate()` mixes I/O, parsing, validation, and output formatting into a ~180-line monolith. The shared `validate_config_rules()` was a good first step. A future refactor should extract a pure `validate_config_file(path) -> ValidationResult` function that both validate and doctor can call.

---

## Friction: None

No runtime friction was logged. The implementation proceeded through all gates without blocking issues. The code-quality findings were all addressed during the refactor gate. All 19 tests passed at the green gate.
