//! Integration tests for the `diffguard init` command.

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

#[test]
fn init_creates_default_config() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("init");

    cmd.assert().success();

    // Check that diffguard.toml was created
    let config_path = dir.join("diffguard.toml");
    assert!(config_path.exists(), "diffguard.toml should be created");

    // Verify it contains the minimal preset header
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("Minimal preset"),
        "Should contain preset identifier"
    );
    assert!(
        content.contains("[defaults]"),
        "Should contain defaults section"
    );
}

#[test]
fn init_creates_config_with_rust_quality_preset() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("init")
        .arg("--preset")
        .arg("rust-quality");

    cmd.assert().success();

    let config_path = dir.join("diffguard.toml");
    assert!(config_path.exists());

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("Rust Quality preset"),
        "Should contain preset identifier"
    );
    assert!(
        content.contains("rust.no_unwrap"),
        "Should contain no_unwrap rule"
    );
    assert!(
        content.contains("rust.no_dbg"),
        "Should contain no_dbg rule"
    );
}

#[test]
fn init_creates_config_with_secrets_preset() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("init")
        .arg("--preset")
        .arg("secrets");

    cmd.assert().success();

    let config_path = dir.join("diffguard.toml");
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("Secrets Detection preset"));
    assert!(content.contains("secrets.api_key"));
    assert!(content.contains("secrets.private_key"));
}

#[test]
fn init_creates_config_with_js_console_preset() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("init")
        .arg("--preset")
        .arg("js-console");

    cmd.assert().success();

    let config_path = dir.join("diffguard.toml");
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("JavaScript/TypeScript Console preset"));
    assert!(content.contains("js.no_console_log"));
    assert!(content.contains("js.no_debugger"));
}

#[test]
fn init_creates_config_with_python_debug_preset() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("init")
        .arg("--preset")
        .arg("python-debug");

    cmd.assert().success();

    let config_path = dir.join("diffguard.toml");
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("Python Debug preset"));
    assert!(content.contains("python.no_print"));
    assert!(content.contains("python.no_pdb"));
}

#[test]
fn init_with_custom_output_path() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("init")
        .arg("--output")
        .arg("custom/path/config.toml");

    cmd.assert().success();

    let config_path = dir.join("custom/path/config.toml");
    assert!(
        config_path.exists(),
        "Config should be created at custom path"
    );
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    // Create an existing config
    let config_path = dir.join("diffguard.toml");
    std::fs::write(&config_path, "# existing config\n").unwrap();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("init");

    // Provide 'n' to stdin to decline overwrite
    cmd.write_stdin("n\n");

    cmd.assert().success();

    // Config should not be overwritten
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        content, "# existing config\n",
        "Config should not be overwritten"
    );
}

#[test]
fn init_overwrites_with_force_flag() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    // Create an existing config
    let config_path = dir.join("diffguard.toml");
    std::fs::write(&config_path, "# existing config\n").unwrap();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("init").arg("--force");

    cmd.assert().success();

    // Config should be overwritten with minimal preset
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("Minimal preset"),
        "Config should be overwritten with preset"
    );
}

#[test]
fn init_generated_config_is_valid_toml() {
    use diffguard_types::ConfigFile;

    let td = TempDir::new().expect("temp");
    let dir = td.path();

    // Test all presets generate valid TOML
    for preset in [
        "minimal",
        "rust-quality",
        "secrets",
        "js-console",
        "python-debug",
    ] {
        let output = format!("{}.toml", preset);
        let mut cmd = diffguard_cmd();
        cmd.current_dir(dir)
            .arg("init")
            .arg("--preset")
            .arg(preset)
            .arg("--output")
            .arg(&output);

        cmd.assert().success();

        let config_path = dir.join(&output);
        let content = std::fs::read_to_string(&config_path).unwrap();

        // Parse the TOML
        let result: Result<ConfigFile, _> = toml::from_str(&content);
        assert!(
            result.is_ok(),
            "Preset '{}' should generate valid TOML: {:?}",
            preset,
            result.err()
        );
    }
}

#[test]
fn init_short_flags_work() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("init")
        .arg("-p")
        .arg("rust-quality")
        .arg("-o")
        .arg("rust.toml")
        .arg("-f"); // Force should work even if file doesn't exist

    cmd.assert().success();

    let config_path = dir.join("rust.toml");
    assert!(config_path.exists());

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("Rust Quality preset"));
}

#[test]
fn init_prints_helpful_message() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("init");

    let output = cmd.output().expect("run command");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Created"), "Should confirm creation");
    assert!(stdout.contains("Next steps"), "Should show next steps");
    assert!(
        stdout.contains("diffguard check"),
        "Should mention check command"
    );
}
