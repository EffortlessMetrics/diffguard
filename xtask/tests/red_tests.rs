// Red test for work-16dcc757: test_vocabulary_constants should return Result<()> and use ensure!
//
// This test verifies that test_vocabulary_constants in conform_real.rs:
// 1. Returns Result<()> (not ())
// 2. Uses ensure! macro (not assert_eq!)
// 3. Has a caller that uses match pattern (not unconditional PASS)
//
// EXPECTED BEHAVIOR:
// - test_vocabulary_constants should return Result<()>
// - It should use ensure!() for all 16 constant assertions
// - The caller (lines 115-119) should use match { Ok(()), Err(e) } pattern
//
// CURRENT BEHAVIOR (before fix):
// - test_vocabulary_constants returns () and uses assert_eq!()
// - The caller unconditionally prints "PASS" without checking result

use std::fs;

/// Tests that test_vocabulary_constants returns Result<()> by checking its signature.
/// This test will FAIL if the function signature is `fn test_vocabulary_constants()`
/// and PASS if the function signature is `fn test_vocabulary_constants() -> Result<()>`.
#[test]
fn test_vocabulary_constants_returns_result() {
    let source =
        fs::read_to_string("../xtask/src/conform_real.rs").expect("Failed to read conform_real.rs");

    // Find the test_vocabulary_constants function definition
    let fn_signature_range = source
        .find("fn test_vocabulary_constants()")
        .expect("Could not find test_vocabulary_constants function");

    // The function should return Result<()> not ()
    // We check that the line contains "-> Result<()>" after the function name
    let after_fn_name = &source[fn_signature_range..];

    // Extract the function signature line (up to the opening brace or newline)
    let signature_line = after_fn_name
        .lines()
        .next()
        .expect("Could not get function signature line");

    // The function should have "-> Result<()>" in its signature
    assert!(
        signature_line.contains("-> Result<()>"),
        "test_vocabulary_constants should return Result<()>, but signature is: {}\n\
         Expected: fn test_vocabulary_constants() -> Result<()>\n\
         This test passes when the function signature is corrected to return Result<()>.",
        signature_line
    );
}

/// Tests that test_vocabulary_constants uses ensure! macro instead of assert_eq!.
/// This test will FAIL if the function uses assert_eq! and PASS if it uses ensure!.
#[test]
fn test_vocabulary_constants_uses_ensure_not_assert_eq() {
    let source =
        fs::read_to_string("../xtask/src/conform_real.rs").expect("Failed to read conform_real.rs");

    // Find the test_vocabulary_constants function body
    let fn_start = source
        .find("fn test_vocabulary_constants()")
        .expect("Could not find test_vocabulary_constants function");

    // Find the opening brace and closing brace of the function
    let first_brace = source[fn_start..]
        .find('{')
        .expect("Could not find opening brace");

    let fn_body_start = fn_start + first_brace;
    let mut brace_count = 1;
    let mut fn_body_end = fn_body_start + 1;

    while brace_count > 0 && fn_body_end < source.len() {
        match source[fn_body_end..].chars().next() {
            Some('{') => brace_count += 1,
            Some('}') => brace_count -= 1,
            _ => {}
        }
        fn_body_end += 1;
    }

    let fn_body = &source[fn_body_start..fn_body_end];

    // The function body should NOT contain assert_eq!
    assert!(
        !fn_body.contains("assert_eq!"),
        "test_vocabulary_constants should use ensure!() instead of assert_eq!(),\n\
         but the function body still contains assert_eq!.\n\
         All 16 assert_eq! calls should be replaced with ensure! macro calls."
    );

    // The function body SHOULD contain ensure!
    assert!(
        fn_body.contains("ensure!"),
        "test_vocabulary_constants should use ensure!() macro for constant assertions,\n\
         but the function body does not contain any ensure! calls."
    );
}

/// Tests that the caller of test_vocabulary_constants uses match pattern.
/// This test will FAIL if the caller unconditionally prints "PASS"
/// and PASS if the caller uses match { Ok(()), Err(e) } pattern.
#[test]
fn test_vocabulary_constants_caller_uses_match_pattern() {
    let source =
        fs::read_to_string("../xtask/src/conform_real.rs").expect("Failed to read conform_real.rs");

    // Find the call site - it should be near "Vocabulary constants" comment
    // The call is: match test_vocabulary_constants() {
    let call_site = source
        .find("match test_vocabulary_constants() {")
        .expect("Could not find match test_vocabulary_constants() call");

    // Look at the surrounding context (50 chars before and 200 chars after)
    let start = call_site.saturating_sub(100);
    let end = (call_site + 200).min(source.len());
    let context = &source[start..end];

    // Check if the call is immediately followed by a match statement for this function
    // The correct pattern is:
    //   match test_vocabulary_constants() {
    //       Ok(()) => { ... }
    //       Err(e) => { ... }
    //   }
    //
    // The incorrect (current) pattern is:
    //   test_vocabulary_constants();
    //   println!("PASS");
    //   passed += 1;

    // First, check if there's a match statement that uses this function's result
    let has_match_for_this_call = context.contains("match test_vocabulary_constants()");

    // Second, check that we DON'T have the unconditional PASS pattern
    // (i.e., the function call is NOT immediately followed by println!("PASS"))
    let has_unconditional_pass = context.contains("println!(\"PASS\")")
        && context.find("test_vocabulary_constants();").is_some()
        && context.find("println!(\"PASS\");").is_some()
        // Check that the PASS comes before any match for this function
        && context.find("match test_vocabulary_constants()")
            .map(|m| context.find("println!(\"PASS\");").map(|p| p < m).unwrap_or(false))
            .unwrap_or(false);

    assert!(
        has_match_for_this_call,
        "The caller of test_vocabulary_constants should use 'match test_vocabulary_constants()' pattern.\n\
         Current code does not use 'match test_vocabulary_constants()'.\n\
         Expected pattern:\n\
         match test_vocabulary_constants() {{\n\
             Ok(()) => {{ println!(\"PASS\"); passed += 1; }}\n\
             Err(e) => {{ println!(\"FAIL: {{}}\", e); failed += 1; }}\n\
         }}"
    );

    assert!(
        !has_unconditional_pass,
        "The caller of test_vocabulary_constants should NOT unconditionally print PASS.\n\
         Current code pattern:\n\
           test_vocabulary_constants();\n\
           println!(\"PASS\");\n\
           passed += 1;\n\
         This is wrong because it cannot detect failures. Should use match pattern instead."
    );
}

/// Tests that test_vocabulary_constants ends with Ok(()).
/// This test will FAIL if the function doesn't return Ok(()) at the end.
#[test]
fn test_vocabulary_constants_returns_ok_at_end() {
    let source =
        fs::read_to_string("../xtask/src/conform_real.rs").expect("Failed to read conform_real.rs");

    // Find the test_vocabulary_constants function body
    let fn_start = source
        .find("fn test_vocabulary_constants()")
        .expect("Could not find test_vocabulary_constants function");

    // Find the opening brace and closing brace of the function
    let first_brace = source[fn_start..]
        .find('{')
        .expect("Could not find opening brace");

    let fn_body_start = fn_start + first_brace;
    let mut brace_count = 1;
    let mut fn_body_end = fn_body_start + 1;

    while brace_count > 0 && fn_body_end < source.len() {
        match source[fn_body_end..].chars().next() {
            Some('{') => brace_count += 1,
            Some('}') => brace_count -= 1,
            _ => {}
        }
        fn_body_end += 1;
    }

    let fn_body = &source[fn_body_start..fn_body_end];

    // The function body should end with Ok(())
    // We check that "Ok(())" appears before the closing brace
    let before_closing_brace = fn_body.trim_end_matches('}').trim_end();

    assert!(
        before_closing_brace.ends_with("Ok(())"),
        "test_vocabulary_constants should end with Ok(()) on success.\n\
         The function body should return Ok(()) at the end instead of just falling through.\n\
         Current function body ends with: ...{}",
        before_closing_brace.lines().last().unwrap_or("(empty)")
    );
}

/// Tests that ensure is imported from anyhow.
/// This test will FAIL if ensure is not imported and PASS after adding the import.
#[test]
fn test_ensure_imported_from_anyhow() {
    let source =
        fs::read_to_string("../xtask/src/conform_real.rs").expect("Failed to read conform_real.rs");

    // Find the anyhow import line
    let anyhow_import = source
        .lines()
        .find(|line| line.contains("use anyhow"))
        .expect("Could not find anyhow import");

    // The import should include ensure
    assert!(
        anyhow_import.contains("ensure"),
        "anyhow import should include 'ensure'.\n\
         Current import: {}\n\
         Expected: use anyhow::{{bail, Context, ensure, Result}};",
        anyhow_import
    );
}
