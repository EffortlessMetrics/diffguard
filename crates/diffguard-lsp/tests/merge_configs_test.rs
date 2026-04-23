//! Tests for the `merge_configs` function in diffguard-lsp.
//!
//! These tests verify that the merge_configs function correctly implements
//! field-wise merge semantics for the Defaults struct:
//! - `Some` values in `other` override `base`
//! - `None` values in `other` inherit from `base`
//!
//! The buggy behavior uses a whole-struct comparison:
//!   `if other.defaults != Defaults::default() { other.defaults } else { base.defaults }`
//! which incorrectly falls back to base.defaults when other.defaults equals Defaults::default()
//! and incorrectly replaces the entire struct when other.defaults differs from Defaults::default().

use diffguard_types::{ConfigFile, Defaults, FailOn, Scope};

/// Creates a ConfigFile with minimal boilerplate for testing.
fn make_config(defaults: Defaults) -> ConfigFile {
    ConfigFile {
        includes: vec![],
        defaults,
        rule: vec![],
    }
}

/// Creates a Defaults with all fields set to Some values.
fn all_defaults() -> Defaults {
    Defaults::default()
}

/// Creates a Defaults with only the specified field set.
fn partial_defaults(
    base: Option<String>,
    head: Option<String>,
    scope: Option<Scope>,
    fail_on: Option<FailOn>,
    max_findings: Option<u32>,
    diff_context: Option<u32>,
) -> Defaults {
    Defaults {
        base,
        head,
        scope,
        fail_on,
        max_findings,
        diff_context,
    }
}

// The merge_configs function is not public, so we need to test it indirectly.
// We'll test it through the public API: load_effective_config.
// But that requires file I/O. Let's check if there's a way to test the internal function...

// Actually, looking at the config.rs, merge_configs is a private function.
// We need to either:
// 1. Make it public for testing (but that changes the API)
// 2. Test through integration (file-based)
// 3. Add a test module inside config.rs

// Since we're writing red tests (tests that should fail with current code),
// let's add tests inside the crate as a test module. But wait - that requires
// modifying config.rs which we're not supposed to do yet.

// Let me check if there's an existing test module in config.rs...
