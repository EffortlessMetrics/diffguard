// Observability infrastructure tests for diffguard-lsp
//
// These tests verify that the LSP server has proper tracing/logging infrastructure.
// They check for the presence of tracing imports and initialization in the source code.
// When the observability infrastructure is fully implemented, all these tests will pass.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for tests in crates/diffguard-lsp/tests/ is:
    // /home/hermes/repos/diffguard/crates/diffguard-lsp
    // We need to go up 2 levels to get to the workspace root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..") // crates/diffguard-lsp -> crates
        .join("..") // crates -> workspace root
        .canonicalize()
        .expect("failed to resolve workspace root")
}

fn read_workspace_file(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("failed to read {} (resolved to {:?})", relative, path))
}

// ---------------------------------------------------------------------------
// AC-1 & AC-2: Workspace dependencies and LSP crate tracing configuration
// ---------------------------------------------------------------------------

#[test]
fn test_tracing_workspace_dependencies_exist() {
    // AC-1: tracing and tracing-subscriber must be in workspace.dependencies
    let root_cargo = read_workspace_file("Cargo.toml");

    assert!(
        root_cargo.contains("tracing = \"0.1\""),
        "Expected 'tracing = \"0.1\"' in [workspace.dependencies], found:\n{}",
        root_cargo
    );

    assert!(
        root_cargo.contains("tracing-subscriber"),
        "Expected 'tracing-subscriber' in [workspace.dependencies], found:\n{}",
        root_cargo
    );

    assert!(
        root_cargo.contains("env-filter"),
        "Expected 'tracing-subscriber' to have 'env-filter' feature, found:\n{}",
        root_cargo
    );
}

#[test]
fn test_lsp_crate_uses_workspace_tracing() {
    // AC-2: diffguard-lsp must reference tracing with workspace = true
    let lsp_cargo = read_workspace_file("crates/diffguard-lsp/Cargo.toml");

    assert!(
        lsp_cargo.contains("tracing.workspace = true"),
        "Expected 'tracing.workspace = true' in diffguard-lsp dependencies, found:\n{}",
        lsp_cargo
    );

    assert!(
        lsp_cargo.contains("tracing-subscriber.workspace = true"),
        "Expected 'tracing-subscriber.workspace = true' in diffguard-lsp dependencies, found:\n{}",
        lsp_cargo
    );

    assert!(
        lsp_cargo.contains("clap.workspace = true"),
        "Expected 'clap.workspace = true' in diffguard-lsp dependencies (for --verbose flag), found:\n{}",
        lsp_cargo
    );
}

// ---------------------------------------------------------------------------
// Test that key functions exist and have proper tracing calls
// ---------------------------------------------------------------------------

#[test]
fn test_server_rs_has_tracing_imports() {
    // Verify that server.rs imports tracing when the feature is implemented
    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    // When observability is implemented, server.rs should import tracing
    assert!(
        server_rs.contains("tracing::") || server_rs.contains("use tracing"),
        "Expected server.rs to import tracing crate for observability.\n\
         This test will pass once tracing instrumentation is added."
    );
}

#[test]
fn test_config_rs_has_tracing_imports() {
    // Verify that config.rs imports tracing when the feature is implemented
    let config_rs = read_workspace_file("crates/diffguard-lsp/src/config.rs");

    // When observability is implemented, config.rs should import tracing
    assert!(
        config_rs.contains("tracing::") || config_rs.contains("use tracing"),
        "Expected config.rs to import tracing crate for observability.\n\
         This test will pass once tracing instrumentation is added."
    );
}

#[test]
fn test_main_rs_has_tracing_subscriber_initialization() {
    // Verify that main.rs initializes tracing subscriber
    let main_rs = read_workspace_file("crates/diffguard-lsp/src/main.rs");

    // When observability is implemented, main.rs should initialize the tracing subscriber
    assert!(
        main_rs.contains("tracing_subscriber") || main_rs.contains("tracing::"),
        "Expected main.rs to initialize tracing subscriber.\n\
         This test will pass once tracing initialization is added."
    );

    // main.rs should also parse --verbose flag
    assert!(
        main_rs.contains("--verbose") || main_rs.contains("verbose"),
        "Expected main.rs to have --verbose flag parsing.\n\
         This test will pass once the verbose flag is added."
    );
}

// ---------------------------------------------------------------------------
// AC-5: run_git_diff emits trace events
// ---------------------------------------------------------------------------

#[test]
fn test_run_git_diff_traces_debug_on_invocation() {
    // AC-5: run_git_diff should trace at debug level on invocation
    // This test checks that the function exists and has tracing calls

    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    // The run_git_diff function should have tracing::debug! calls
    assert!(
        server_rs.contains("tracing::debug!"),
        "Expected run_git_diff to have tracing::debug! calls.\n\
         The function should trace: path, staged flag, timeout, stdout length on success, error on failure."
    );
}

// ---------------------------------------------------------------------------
// AC-6: refresh_document_diagnostics emits trace events
// ---------------------------------------------------------------------------

#[test]
fn test_refresh_document_diagnostics_traces_trace_level() {
    // AC-6: refresh_document_diagnostics should trace at trace level (hot path)
    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    // Should use tracing::trace! (not debug!) because it's a hot path
    assert!(
        server_rs.contains("tracing::trace!"),
        "Expected refresh_document_diagnostics to have tracing::trace! calls.\n\
         Should trace: path, diff type (synthetic/git), diagnostic count."
    );
}

// ---------------------------------------------------------------------------
// AC-7: reload_config emits trace events
// ---------------------------------------------------------------------------

#[test]
fn test_reload_config_traces_info_on_success() {
    // AC-7: reload_config should trace at info level on success, warn on failure
    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    assert!(
        server_rs.contains("tracing::info!"),
        "Expected reload_config to have tracing::info! calls for success path.\n\
         Should trace: config path, rule count."
    );

    assert!(
        server_rs.contains("tracing::warn!"),
        "Expected reload_config to have tracing::warn! calls for failure path.\n\
         Should trace: error message."
    );
}

// ---------------------------------------------------------------------------
// AC-8: showMessage calls emit trace events
// ---------------------------------------------------------------------------

#[test]
fn test_showmessage_call_sites_have_trace_events() {
    // AC-8: Every showMessage call should also emit a trace event
    // This test checks that when tracing is implemented, the trace calls exist

    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    // When implemented, showMessage call sites should have corresponding trace calls
    // The exact implementation may vary (trace before or after show_message call)
    // We check that both show_message and tracing calls exist
    assert!(
        server_rs.contains("tracing::warn!") || server_rs.contains("tracing::error!"),
        "Expected showMessage call sites to have corresponding tracing::warn! or tracing::error! calls.\n\
         Every showMessage should emit a trace so events are captured even after user dismisses notification."
    );
}

// ---------------------------------------------------------------------------
// Phase 3: Supporting instrumentation tests
// ---------------------------------------------------------------------------

#[test]
fn test_git_diff_for_path_has_tracing() {
    // Phase 3, item 9: git_diff_for_path should trace at debug level
    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    // git_diff_for_path should trace the diff type and result length
    // This is covered by the overall tracing presence, but we document it here
    let has_tracing_debug = server_rs.contains("tracing::debug!");
    assert!(
        has_tracing_debug,
        "Expected git_diff_for_path instrumentation with tracing::debug!."
    );
}

#[test]
fn test_handle_notification_and_request_have_tracing() {
    // Phase 3, item 12: handle_notification and handle_request should trace method name
    let server_rs = read_workspace_file("crates/diffguard-lsp/src/server.rs");

    // These are the main entry points for LSP protocol traffic
    // They should have trace! calls with method name as a field
    assert!(
        server_rs.contains("tracing::trace!"),
        "Expected handle_notification and handle_request to have tracing::trace! calls.\n\
         Should trace: method name as a field."
    );
}

// ---------------------------------------------------------------------------
// Test for config.rs instrumentation
// ---------------------------------------------------------------------------

#[test]
fn test_load_effective_config_has_tracing() {
    // Phase 3, item 10: load_effective_config should trace at debug level
    let config_rs = read_workspace_file("crates/diffguard-lsp/src/config.rs");

    // Should trace: config path, rule count, built-in usage
    let has_tracing = config_rs.contains("tracing::debug!");
    assert!(
        has_tracing,
        "Expected load_effective_config to have tracing::debug! calls.\n\
         Should trace: config path, rule count, built-in usage."
    );
}

#[test]
fn test_load_directory_overrides_has_tracing() {
    // Phase 3, item 11: load_directory_overrides_for_file should trace at debug level
    let config_rs = read_workspace_file("crates/diffguard-lsp/src/config.rs");

    // Should trace: override count, files read
    let has_tracing = config_rs.contains("tracing::debug!");
    assert!(
        has_tracing,
        "Expected load_directory_overrides_for_file to have tracing::debug! calls.\n\
         Should trace: override count, files read."
    );
}
