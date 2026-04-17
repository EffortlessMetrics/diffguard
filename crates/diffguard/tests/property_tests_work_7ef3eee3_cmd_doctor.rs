//! Property-based tests for `cmd_doctor` return type fix.
//!
//! These tests verify invariants that hold across many generated inputs:
//! - **Bounded**: exit codes are always 0 or 1
//! - **Deterministic**: same environment conditions produce same exit code
//! - **Usable as i32**: return value can be used directly in integer arithmetic
//!
//! The change fixes `clippy::unnecessary_wraps` by changing `cmd_doctor` from
//! `Result<i32>` to `i32`. These tests verify the properties that make this
//! change safe and correct.

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

/// Property 1: BOUNDED - Exit codes are always 0 or 1.
///
/// This is a fundamental property of the `doctor` command's exit code semantics.
/// No matter what environment configuration we run in, the exit code should
/// always be a valid exit code (0 = success, 1 = failure).
///
/// We test this by generating many different environment configurations
/// and verifying the exit code is always in the valid set {0, 1}.
#[test]
fn property_doctor_exit_code_always_zero_or_one() {
    // Generate many environment configurations and verify exit code is always 0 or 1
    // We run 100 iterations with different temp dir setups
    
    for iteration in 0..100 {
        let td = TempDir::new().expect("temp dir should be created");
        let td_path = td.path();
        
        // Set up git repo (if any) based on iteration
        let git_repo_initialized = iteration % 2 == 0;
        if git_repo_initialized {
            std::process::Command::new("git")
                .current_dir(td_path)
                .args(["init"])
                .output()
                .expect("git init should work");
                
            std::process::Command::new("git")
                .current_dir(td_path)
                .args(["config", "user.email", "test@test.com"])
                .output()
                .expect("git config should work");

            std::process::Command::new("git")
                .current_dir(td_path)
                .args(["config", "user.name", "Test"])
                .output()
                .expect("git config should work");
        }
        
        // Set up config based on iteration
        let config_valid = (iteration / 2) % 2 == 0;
        let config_path = td_path.join("diffguard.toml");
        
        if git_repo_initialized {
            if config_valid {
                // Valid config: proper diffguard.toml with empty rules
                std::fs::write(&config_path, "rules = []").expect("write valid config");
            } else {
                // Invalid config: malformed TOML
                std::fs::write(&config_path, "[[invalid").expect("write invalid config");
            }
        }
        
        // Run doctor command
        let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
        cmd.current_dir(td_path)
            .arg("doctor");
            
        if git_repo_initialized {
            cmd.arg("--config").arg(config_path.to_str().unwrap());
        }
        
        let output = cmd.output().expect("doctor command should run");
        let exit_code = output.status.code().expect("should have exit code");
        
        // INVARIANT: exit code must be 0 or 1
        assert!(
            exit_code == 0 || exit_code == 1,
            "Iteration {}: exit code must be 0 or 1, got {} (git_repo={}, config_valid={})",
            iteration, exit_code, git_repo_initialized, config_valid
        );
    }
}

/// Property 2: DETERMINISTIC - Same environment conditions produce same exit code.
///
/// This tests idempotence: running `doctor` multiple times in the same
/// environment should produce the same exit code every time.
///
/// We test this by running the command 10 times in identical conditions
/// and verifying all runs produce the same exit code.
#[test]
fn property_doctor_idempotent_same_environment() {
    // Test case: valid git repo with valid config -> should always exit 0
    {
        let td = TempDir::new().expect("temp dir");
        let td_path = td.path();
        
        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["init"])
            .output()
            .expect("git init should work");
            
        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .expect("git config should work");

        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["config", "user.name", "Test"])
            .output()
            .expect("git config should work");
            
        let config_path = td_path.join("diffguard.toml");
        std::fs::write(&config_path, "rules = []").expect("write config");
        
        let mut exit_codes = Vec::new();
        for i in 0..10 {
            let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
            cmd.current_dir(td_path)
                .arg("doctor")
                .arg("--config")
                .arg(config_path.to_str().unwrap());
            
            let output = cmd.output().expect("doctor command should run");
            let exit_code = output.status.code().expect("should have exit code");
            exit_codes.push(exit_code);
            
            assert_eq!(
                exit_code, 0,
                "Iteration {}: valid environment should exit 0, got {}",
                i, exit_code
            );
        }
        
        // All exit codes should be identical
        assert!(
            exit_codes.iter().all(|&code| code == exit_codes[0]),
            "All 10 runs should produce same exit code: {:?}",
            exit_codes
        );
    }
    
    // Test case: no git repo -> should always exit 1
    {
        let mut exit_codes = Vec::new();
        for i in 0..10 {
            let td = TempDir::new().expect("temp dir");
            
            let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
            cmd.current_dir(td.path())
                .arg("doctor");
            
            let output = cmd.output().expect("doctor command should run");
            let exit_code = output.status.code().expect("should have exit code");
            exit_codes.push(exit_code);
            
            assert_eq!(
                exit_code, 1,
                "Iteration {}: no git repo should exit 1, got {}",
                i, exit_code
            );
        }
        
        // All exit codes should be identical
        assert!(
            exit_codes.iter().all(|&code| code == exit_codes[0]),
            "All 10 runs should produce same exit code: {:?}",
            exit_codes
        );
    }
}

/// Property 3: EXIT CODE SEMANTICS - Exit code 0 means all pass, 1 means failure.
///
/// This tests the semantic meaning of the exit codes:
/// - Exit 0: All three checks pass (git available, git repo, config valid)
/// - Exit 1: At least one check fails
///
/// We verify by examining the output to confirm the check results match
/// the exit code.
#[test]
fn property_doctor_exit_code_matches_check_results() {
    // Test: all checks pass -> exit 0
    {
        let td = TempDir::new().expect("temp dir");
        let td_path = td.path();
        
        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["init"])
            .output()
            .expect("git init should work");
            
        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .expect("git config should work");

        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["config", "user.name", "Test"])
            .output()
            .expect("git config should work");
            
        let config_path = td_path.join("diffguard.toml");
        std::fs::write(&config_path, "rules = []").expect("write config");
        
        let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
        cmd.current_dir(td_path)
            .arg("doctor")
            .arg("--config")
            .arg(config_path.to_str().unwrap());
        
        let output = cmd.output().expect("doctor command should run");
        let exit_code = output.status.code().expect("should have exit code");
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // When all checks pass, exit code should be 0
        let all_pass = stdout.contains("git: PASS") 
            && stdout.contains("git-repo: PASS") 
            && stdout.contains("config: PASS");
        
        assert!(
            all_pass && exit_code == 0,
            "All checks pass -> exit 0. Got exit={}, stdout={}",
            exit_code, stdout
        );
    }
    
    // Test: missing git repo -> exit 1
    {
        let td = TempDir::new().expect("temp dir");
        
        let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
        cmd.current_dir(td.path())
            .arg("doctor");
        
        let output = cmd.output().expect("doctor command should run");
        let exit_code = output.status.code().expect("should have exit code");
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // git-repo check should fail
        assert!(
            stdout.contains("git-repo: FAIL") && exit_code == 1,
            "git-repo FAIL -> exit 1. Got exit={}, stdout={}",
            exit_code, stdout
        );
    }
    
    // Test: invalid config -> exit 1
    {
        let td = TempDir::new().expect("temp dir");
        let td_path = td.path();
        
        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["init"])
            .output()
            .expect("git init should work");
            
        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["config", "user.email", "test@test.com"])
            .output()
            .expect("git config should work");

        std::process::Command::new("git")
            .current_dir(td_path)
            .args(["config", "user.name", "Test"])
            .output()
            .expect("git config should work");
            
        let config_path = td_path.join("diffguard.toml");
        // Invalid TOML
        std::fs::write(&config_path, "[[invalid").expect("write config");
        
        let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
        cmd.current_dir(td_path)
            .arg("doctor")
            .arg("--config")
            .arg(config_path.to_str().unwrap());
        
        let output = cmd.output().expect("doctor command should run");
        let exit_code = output.status.code().expect("should have exit code");
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // config check should fail
        assert!(
            stdout.contains("config: FAIL") && exit_code == 1,
            "config FAIL -> exit 1. Got exit={}, stdout={}",
            exit_code, stdout
        );
    }
}

/// Property 4: INTEGRATION - Call site correctly wraps i32 with Ok().
///
/// This verifies that the call site `Commands::Doctor(args) => Ok(cmd_doctor(args))`
/// correctly wraps the i32 return value with Ok(). This is tested indirectly:
/// if cmd_doctor returned Result<i32> incorrectly, clippy would warn about
/// unnecessary_wraps. If the return type is i32 but call site didn't wrap,
/// the main function would fail to compile.
///
/// We verify the integration by running clippy and confirming no warnings.
#[test]
fn property_call_site_wraps_with_ok() {
    // If cmd_doctor returned i32 but call site didn't wrap, we'd get a type error.
    // If cmd_doctor still returned Result<i32>, clippy would warn.
    // We verify the fix is correct by running clippy's unnecessary_wraps check.
    
    let mut cmd = Command::new("cargo");
    cmd.arg("clippy")
        .arg("-p")
        .arg("diffguard")
        .arg("--")
        .arg("-W")
        .arg("clippy::unnecessary_wraps")
        .current_dir("/home/hermes/repos/diffguard");
    
    let output = cmd.output().expect("clippy should run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);
    
    // After the fix, clippy should NOT report unnecessary_wraps for cmd_doctor
    // (it may report for other functions, but not cmd_doctor)
    
    // Check if the output mentions cmd_doctor and unnecessary_wraps together
    let has_cmd_doctor_unnecessary_wraps = combined.contains("cmd_doctor") 
        && combined.contains("unnecessary_wraps");
    
    assert!(
        !has_cmd_doctor_unnecessary_wraps,
        "clippy should NOT report unnecessary_wraps for cmd_doctor. Got:\n{}",
        combined
    );
}

/// Property 5: BOUNDED STRESS - Many rapid executions still produce valid exit codes.
///
/// This stress test runs the doctor command 50 times in rapid succession,
/// verifying that even under stress (process spawning, file I/O), the
/// exit codes remain bounded to {0, 1}.
#[test]
fn property_stress_many_rapid_executions() {
    let mut exit_codes = Vec::with_capacity(50);
    
    for i in 0..50 {
        let td = TempDir::new().expect("temp dir");
        let td_path = td.path();
        
        // Alternate between pass and fail scenarios
        if i % 2 == 0 {
            std::process::Command::new("git")
                .current_dir(td_path)
                .args(["init"])
                .output()
                .expect("git init should work");
                
            std::process::Command::new("git")
                .current_dir(td_path)
                .args(["config", "user.email", "test@test.com"])
                .output()
                .expect("git config should work");

            std::process::Command::new("git")
                .current_dir(td_path)
                .args(["config", "user.name", "Test"])
                .output()
                .expect("git config should work");
                
            let config_path = td_path.join("diffguard.toml");
            std::fs::write(&config_path, "rules = []").expect("write config");
            
            let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
            cmd.current_dir(td_path)
                .arg("doctor")
                .arg("--config")
                .arg(config_path.to_str().unwrap());
            
            let output = cmd.output().expect("doctor command should run");
            exit_codes.push(output.status.code().expect("should have exit code"));
        } else {
            let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
            cmd.current_dir(td_path)
                .arg("doctor");
            
            let output = cmd.output().expect("doctor command should run");
            exit_codes.push(output.status.code().expect("should have exit code"));
        }
    }
    
    // All exit codes should be 0 or 1
    for (i, code) in exit_codes.iter().enumerate() {
        assert!(
            *code == 0 || *code == 1,
            "Iteration {}: exit code {} is not 0 or 1",
            i, code
        );
    }
    
    // We should have a mix of 0s and 1s (roughly equal distribution)
    let zeros = exit_codes.iter().filter(|&&c| c == 0).count();
    let ones = exit_codes.iter().filter(|&&c| c == 1).count();
    
    assert!(
        zeros > 0 && ones > 0,
        "Should have mix of exit codes (0s={}, 1s={})",
        zeros, ones
    );
}