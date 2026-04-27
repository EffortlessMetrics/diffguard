//! Test to verify that `unified.rs` has no `cast_lossless` clippy warnings.
//!
//! This test verifies the fix for issue #579: lines 546 and 550 should use
//! `u32::from()` instead of `as u32` for u8→u32 widening casts.
//!
//! The `as u32` syntax triggers clippy's `cast_lossless` lint because
//! `From` is the idiomatic way to express infallible type conversions.

use std::process::Command;

#[test]
fn test_unified_rs_has_no_cast_lossless_warnings() {
    // Run clippy specifically targeting the cast_lossless lint
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-diff",
            "--",
            "-W",
            "clippy::cast_lossless",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that unified.rs is NOT mentioned in any warning output
    // If the file is mentioned, it means cast_lossless warnings exist
    assert!(
        !stderr.contains("unified.rs"),
        "unified.rs should not appear in clippy cast_lossless warnings.\n         Found warnings:\n{}",
        stderr
    );

    assert!(
        !stdout.contains("unified.rs"),
        "unified.rs should not appear in clippy cast_lossless warnings.\n         Found warnings:\n{}",
        stdout
    );

    // Also verify the specific lines that were fixed
    assert!(
        !stderr.contains(":546"),
        "Line 546 should not have cast_lossless warning.\n         The fix should use u32::from() instead of as u32."
    );

    assert!(
        !stderr.contains(":550"),
        "Line 550 should not have cast_lossless warning.\n         The fix should use u32::from() instead of as u32."
    );
}