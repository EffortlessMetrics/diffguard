use assert_cmd::cargo;
use assert_cmd::Command;
use tempfile::TempDir;

fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git should run");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_repo() -> (TempDir, String) {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);

    // baseline file
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> Option<u32> { Some(1) }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "base"]);

    let base = run_git(dir, &["rev-parse", "HEAD"]);
    (td, base)
}

#[test]
fn fails_on_unwrap_by_default() {
    let (td, base) = init_repo();
    let dir = td.path();

    // introduce unwrap
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { Some(1).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "change"]);
    let head = run_git(dir, &["rev-parse", "HEAD"]);

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md");

    cmd.assert().code(2);

    let receipt = std::fs::read_to_string(dir.join("artifacts/diffguard/report.json")).unwrap();
    assert!(receipt.contains("diffguard.check.v1"));
    assert!(receipt.contains("rust.no_unwrap"));
}

#[test]
fn warnings_do_not_fail_by_default_but_can() {
    let (td, base) = init_repo();
    let dir = td.path();

    // introduce println (warn)
    std::fs::write(dir.join("src/lib.rs"), "pub fn f() { println!(\"hi\"); }\n").unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "change"]);
    let head = run_git(dir, &["rev-parse", "HEAD"]);

    // default: fail_on=error => exit 0 even with warnings
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    cmd.assert().code(0);

    // configured: fail_on=warn => exit 3
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--fail-on")
        .arg("warn")
        .arg("--out")
        .arg("artifacts/diffguard/report2.json");

    cmd.assert().code(3);
}
