# ADR-39d41591: Deduplicate `escape_md` by Exporting from `diffguard-core`

## Status

**Proposed**

## Context

The function `escape_md` (which escapes markdown special characters: `|`, `` ` ``, `#`, `*`, `_`, `[`, `]`, `>`, `\r`, `\n`) is implemented identically in two places:

- `crates/diffguard-core/src/render.rs:126` — private, used by `render_finding_row`
- `crates/diffguard/src/main.rs:1693` — private, used by `render_finding_row_with_baseline`

The `diffguard` copy is not dead code — it is actively used when rendering markdown in `--baseline` mode via `render_finding_row_with_baseline` → `render_markdown_with_baseline_annotations`. However, the duplication itself is the problem: two places to maintain the same logic creates a maintenance hazard and violates DRY.

`diffguard_core` is the I/O-free engine layer and is the appropriate home for pure string utilities like `escape_md`. The `diffguard` CLI crate already imports many render functions from `diffguard_core` using the `pub use render::function_name` re-export pattern (e.g., `render_csv_for_receipt`, `render_junit_for_receipt`, `render_markdown_for_receipt`).

## Decision

We will eliminate the duplicate `escape_md` by:

1. Making `escape_md` a public function in `crates/diffguard-core/src/render.rs` (change `fn escape_md` → `pub fn escape_md`)
2. Adding `pub use render::escape_md;` in `crates/diffguard-core/src/lib.rs` to re-export it at the crate root, following the established re-export pattern
3. Removing the `escape_md` function definition from `crates/diffguard/src/main.rs`
4. Adding `escape_md` to the existing `diffguard_core::` import block in `main.rs`

This makes `escape_md` accessible as `diffguard_core::escape_md`, consistent with how other pure render helpers are exposed.

## Consequences

**Benefits:**
- Eliminates duplicate code and the maintenance hazard it creates
- `escape_md` lives in the architecturally correct layer (I/O-free engine)
- Follows the established `pub use render::function_name` re-export pattern already used by all other render functions
- No behavioral change — both implementations are byte-identical

**Tradeoffs/Risks:**
- A previously private function becomes public in `diffguard-core` — this is a semver-minor change (adding public API) and is safe
- If downstream crates were to accidentally rely on `escape_md`'s privacy, this would be a breaking change — but since it was private and undocumented, no downstream use is expected

## Alternatives Considered

1. **Keep both copies** — Rejected. Duplication violates DRY and creates maintenance burden. If markdown escaping rules need to change, both copies must be updated in sync.

2. **Make `render` module public and import via `diffguard_core::render::escape_md`** — Rejected. This would expose the entire `render` module's public API, which includes private internal helpers. The established `pub use` re-export pattern at the crate root is the correct approach, as demonstrated by all other render functions.

3. **Move `render_finding_row_with_baseline` to `diffguard-core` and share `render_markdown_for_receipt`** — Rejected as out of scope. The baseline annotation logic is a CLI-specific display concern. The issue is specifically about `escape_md` duplication, not about restructuring the baseline rendering pipeline.
