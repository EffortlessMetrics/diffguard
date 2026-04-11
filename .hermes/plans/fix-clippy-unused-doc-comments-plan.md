# Plan: Fix Clippy Unused Doc Comments Error

## Goal
Resolve the 4 clippy errors blocking CI in `property_tests_escape_xml.rs`.

## Current Context
`cargo clippy --workspace --all-targets -- -D warnings` fails with 4 errors in:
`crates/diffguard-core/tests/property_tests_escape_xml.rs`

Errors: rustdoc does not generate documentation for macro invocations. The `///` doc comments above `proptest!` macros are unused.

## Proposed Approach
Add `#[allow(unused_doc_comments)]` to suppress the lint on the affected doc comments, OR remove the doc comments above macro invocations since rustdoc cannot document macros.

The affected lines are:
- Line 11-20: Property 1 doc comment
- Line 37-40: Property 2 doc comment  
- Line 114: Property 4 doc comment
- Line 163-167: Property 6 doc comment

## Step-by-Step Plan

1. Open `crates/diffguard-core/tests/property_tests_escape_xml.rs`
2. For each group of `///` doc comments followed by `proptest!` or `proptest!` variants:
   - Option A: Add `#[allow(unused_doc_comments)]` above each doc comment block
   - Option B: Replace `///` with `//` (regular comments)
3. Run `cargo clippy -p diffguard-core --all-targets -- -D warnings` to verify fix
4. Run `cargo test -p diffguard-core` to confirm tests still pass

## Files Likely to Change
- `crates/diffguard-core/tests/property_tests_escape_xml.rs`

## Verification
```bash
cargo clippy -p diffguard-core --all-targets -- -D warnings
cargo test -p diffguard-core property_tests_escape_xml
```

## Risks
- Minimal: this is purely cosmetic (doc comment style change)
- Must ensure `#[allow(unused_doc_comments)]` is safe for crate lint settings

## Open Questions
- Which fix approach is preferred: allow attribute or plain comments?
