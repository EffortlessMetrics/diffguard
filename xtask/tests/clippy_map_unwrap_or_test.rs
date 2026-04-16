//! Tests that verify `clippy::map_unwrap_or` lint is not triggered.
//!
//! This test ensures the code uses the idiomatic `map_or_else` pattern
//! instead of the inefficient `map(...).unwrap_or_else(...)` pattern.
//!
//! GitHub issue: #488

use std::process::Command;

/// Test that `conform_real.rs` does not trigger `clippy::map_unwrap_or` lint.
///
/// The lint fires when code uses `.map(...).unwrap_or_else(...)` pattern.
/// The fix is to use `.map_or_else(...)` instead, which avoids creating
/// an intermediate `Option<String>` allocation.
///
/// This test will FAIL if the lint warning exists and PASS when the fix is applied.
#[test]
fn test_conform_real_no_map_unwrap_or_lint() {
    // Run clippy with the explicit map_unwrap_or lint flag on conform_real.rs
    // Use absolute path to cargo
    let output = Command::new("/home/hermes/.cargo/bin/cargo")
        .args(["clippy", "--", "-W", "clippy::map_unwrap_or"])
        .current_dir("/home/hermes/repos/diffguard/xtask")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}\n{}", stdout, stderr);

    // The test passes if there are NO warnings about map_unwrap_or
    // We check that the specific warning pattern is NOT present
    assert!(
        !combined_output.contains("called `map"),
        "clippy should not warn about map().unwrap_or_else() pattern in conform_real.rs. \
         The code should use map_or_else() instead.\n\
         Output: {}",
        combined_output
    );

    assert!(
        !combined_output.contains("map_unwrap_or"),
        "clippy should not trigger map_unwrap_or lint in conform_real.rs. \
         The code should use map_or_else() instead.\n\
         Output: {}",
        combined_output
    );
}

/// Test that `xtask` crate overall does not trigger `clippy::map_unwrap_or` lint.
///
/// This is a broader test that ensures the entire xtask crate is free of this lint.
#[test]
fn test_xtask_crate_no_map_unwrap_or_lint() {
    // Run clippy with the explicit map_unwrap_or lint flag on the whole xtask crate
    // Use absolute path to cargo
    let output = Command::new("/home/hermes/.cargo/bin/cargo")
        .args(["clippy", "--", "-W", "clippy::map_unwrap_or"])
        .current_dir("/home/hermes/repos/diffguard/xtask")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}\n{}", stdout, stderr);

    // The lint warning contains specific text we can check for
    let has_lint_warning = combined_output.contains("map_unwrap_or");

    assert!(
        !has_lint_warning,
        "xtask crate should not trigger clippy::map_unwrap_or lint. \
         The code should use map_or_else() instead of map().unwrap_or_else().\n\
         Clippy output:\n{}",
        combined_output
    );
}
