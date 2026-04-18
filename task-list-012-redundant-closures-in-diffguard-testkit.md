# Task List: Fix Redundant Closures in diffguard-testkit

**Work Item:** work-ece459be

## Tasks

1. [ ] **Fix arb.rs:214** — Replace `|s| s.to_string()` with `std::string::ToString::to_string` in `arb_file_extension()` function

2. [ ] **Fix arb.rs:223** — Replace `|s| s.to_string()` with `std::string::ToString::to_string` in `arb_dir_name()` function

3. [ ] **Fix arb.rs:253** — Replace `|s| s.to_string()` with `std::string::ToString::to_string` in `arb_language()` function

4. [ ] **Run tests** — Execute `cargo test -p diffguard-testkit` to verify no behavior change

5. [ ] **Verify clippy** — Run `cargo clippy -p diffguard-testkit -- -W clippy::redundant_closure_for_method_calls` to confirm warnings are resolved

6. [ ] **Commit** — Create a commit on branch `feat/work-ece459be/diffguard-testkit-redundant-closures` with the fix

## What NOT to do (Out of scope)

- Do NOT fix `fixtures.rs` — has no warnings
- Do NOT fix `diffguard-lsp` warnings at `config.rs:96` or `server.rs:819` — separate scope
- Do NOT make any behavioral changes — this is a pure style fix
