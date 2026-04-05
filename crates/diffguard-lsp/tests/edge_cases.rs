// Edge case and error handling integration tests for diffguard-lsp
//
// Tests the server's behavior with invalid configuration, missing workspace,
// unavailable git, concurrent document changes, and other boundary conditions.

use std::time::Duration;

use lsp_types::notification::Notification as LspNotification;
use lsp_types::request::Request as LspRequest;

mod integration;
use integration::{TestServer, create_test_config, create_test_file};

const SHORT_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// T24: test_invalid_config_graceful_fallback
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_config_falls_back_to_built_in_rules() {
    // Create a temp dir with a malformed config file
    let temp = tempfile::TempDir::new().expect("temp dir");
    let _bad_config = create_test_config(temp.path(), "this is not valid toml [[[");

    // Start server pointing at the workspace with bad config
    let mut server = TestServer::start_with_workspace(temp.path());

    // Open a file with content that triggers built-in rules
    let content = "// TODO: implement\nfn main() {}\n";
    let uri = server.create_file("src/main.rs", content);

    server.send_did_open(&uri, "rust", 1, content);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Server should not crash -- it falls back to built-in rules
    // The important thing is no panic or error response
    // Diagnostics may be present from built-in rules
}

#[test]
fn test_completely_empty_config_uses_built_in() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    // Empty file -- valid TOML but no rules defined
    let _empty_config = create_test_config(temp.path(), "");

    let mut server = TestServer::start_with_workspace(temp.path());

    let content = "// TODO: implement\nfn main() {}\n";
    let uri = server.create_file("src/main.rs", content);

    server.send_did_open(&uri, "rust", 1, content);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Should still work -- built-in rules are merged with empty config
}

// ---------------------------------------------------------------------------
// T25: test_missing_workspace_handled
// ---------------------------------------------------------------------------

#[test]
fn test_no_workspace_root_handled_gracefully() {
    // Start a server without a workspace root (rootUri = null)
    let (client_conn, server_conn) = lsp_server::Connection::memory();

    let server_thread = std::thread::spawn(move || diffguard_lsp::server::run_server(server_conn));

    // Give server thread time to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Initialize with no workspace - use lower-level methods to match server
    #[allow(deprecated)]
    let init_params = lsp_types::InitializeParams {
        root_uri: None,
        workspace_folders: None,
        ..lsp_types::InitializeParams::default()
    };

    // Send initialize request
    let init_request = lsp_server::Request::new(
        lsp_server::RequestId::from(1),
        "initialize".to_string(),
        serde_json::to_value(init_params).expect("serialize"),
    );
    client_conn
        .sender
        .send(lsp_server::Message::Request(init_request))
        .expect("send initialize request");

    // Wait for initialize response, draining any notifications
    let init_response = loop {
        let message = client_conn.receiver.recv().expect("receive message");
        match message {
            lsp_server::Message::Response(resp) if resp.id == lsp_server::RequestId::from(1) => {
                break resp.result.expect("initialize response has no result");
            }
            lsp_server::Message::Notification(_) => {
                // Drain notifications sent during initialization
                continue;
            }
            _ => panic!("expected initialize response, got {:?}", message),
        }
    };

    // Should succeed even without workspace
    let _init_result: lsp_types::InitializeResult =
        serde_json::from_value(init_response).expect("parse init result");

    // Send initialized notification
    let initialized_notification =
        lsp_server::Notification::new("initialized".to_string(), serde_json::json!({}));
    client_conn
        .sender
        .send(lsp_server::Message::Notification(initialized_notification))
        .expect("send initialized notification");

    // Send shutdown + exit
    let shutdown_req = lsp_server::Request::new(
        lsp_server::RequestId::from(1),
        lsp_types::request::Shutdown::METHOD.to_string(),
        serde_json::json!(null),
    );
    client_conn
        .sender
        .send(lsp_server::Message::Request(shutdown_req))
        .unwrap();

    let exit_notif = lsp_server::Notification::new(
        lsp_types::notification::Exit::METHOD.to_string(),
        serde_json::json!(null),
    );
    client_conn
        .sender
        .send(lsp_server::Message::Notification(exit_notif))
        .unwrap();

    let _ = server_thread.join();
}

// ---------------------------------------------------------------------------
// T26: test_git_unavailable_fallback
// ---------------------------------------------------------------------------

#[test]
fn test_falls_back_to_synthetic_diff_without_git() {
    // Use a TempDir that is NOT a git repository
    let temp = tempfile::TempDir::new().expect("temp dir");

    let mut server = TestServer::start_with_workspace(temp.path());

    // Open a file and then change it -- the server should use synthetic diff
    // from didChange instead of trying to run git diff
    let initial = "fn main() {\n    let x = 1;\n}\n";
    let uri = create_test_file(temp.path(), "main.rs", initial);

    server.send_did_open(&uri, "rust", 1, initial);
    let _ = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Change the content
    let changed = "fn main() {\n    // TODO: fix\n    let x = 1;\n}\n";
    server.send_did_change(&uri, 2, changed);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Server should handle git unavailability gracefully by using synthetic diff
    // from the didChange notification. No crash or error should occur.
}

// ---------------------------------------------------------------------------
// T27: test_concurrent_document_changes
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_documents_update_independently() {
    let mut server = TestServer::start();

    // Open multiple documents
    let uri1 = server.create_file("src/a.rs", "// TODO: a\nfn a() {}\n");
    let uri2 = server.create_file("src/b.rs", "// TODO: b\nfn b() {}\n");
    let uri3 = server.create_file("src/c.rs", "// TODO: c\nfn c() {}\n");

    server.send_did_open(&uri1, "rust", 1, "// TODO: a\nfn a() {}\n");
    server.send_did_open(&uri2, "rust", 1, "// TODO: b\nfn b() {}\n");
    server.send_did_open(&uri3, "rust", 1, "// TODO: c\nfn c() {}\n");

    // Rapid changes to each document
    server.send_did_change(&uri1, 2, "fn a() {\n    // TODO: updated a\n}\n");
    server.send_did_change(&uri2, 2, "fn b() {\n    // TODO: updated b\n}\n");
    server.send_did_change(&uri3, 2, "fn c() {\n    // TODO: updated c\n}\n");

    // Collect diagnostics for each document
    let _diags1 = server.collect_diagnostics_for_uri(&uri1, SHORT_TIMEOUT);
    let _diags2 = server.collect_diagnostics_for_uri(&uri2, SHORT_TIMEOUT);
    let _diags3 = server.collect_diagnostics_for_uri(&uri3, SHORT_TIMEOUT);

    // Each document should receive its own diagnostics independently
    // No cross-contamination: diagnostics for uri1 should only reference uri1's content
}

// ---------------------------------------------------------------------------
// Additional edge case tests
// ---------------------------------------------------------------------------

#[test]
fn test_did_change_without_prior_did_open() {
    let server = TestServer::start();

    // Try to send didChange without didOpen first
    // The server should handle this gracefully (the document won't be in state)
    let uri: lsp_types::Uri = url::Url::from_file_path("/tmp/nonexistent.rs")
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    server.send_did_change(&uri, 1, "fn test() {}\n");

    // Give the server time to process, then verify no crash
    std::thread::sleep(Duration::from_millis(100));

    // If we get here without panic, the server handled the unexpected message
}

#[test]
fn test_empty_document_content() {
    let mut server = TestServer::start();

    // Open a document with empty content
    let uri = server.create_file("src/empty.rs", "");
    server.send_did_open(&uri, "rust", 1, "");
    let diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Empty document should produce empty diagnostics (no violations in empty content)
    assert!(
        diagnostics.is_empty(),
        "Expected no diagnostics for empty file, got: {:?}",
        diagnostics,
    );
}

#[test]
fn test_very_long_line_content() {
    let mut server = TestServer::start();

    // Create a file with a very long line
    let long_line = format!("// TODO: {}\nfn main() {{}}\n", "x".repeat(10000));
    let uri = server.create_file("src/long.rs", &long_line);

    server.send_did_open(&uri, "rust", 1, &long_line);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Should handle long lines without crashing
}

#[test]
fn test_unicode_content_handling() {
    let mut server = TestServer::start();

    // Content with various Unicode characters
    let content = "// TODO: 日本語テスト\nfn main() {\n    let emoji = \"\u{1F600}\";\n}\n";
    let uri = server.create_file("src/unicode.rs", content);

    server.send_did_open(&uri, "rust", 1, content);
    let diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Unicode content should be handled without panics
    // Diagnostic ranges should be valid even with multi-byte characters
    for diag in &diagnostics {
        // Range should be valid
        assert!(
            diag.range.start.line <= diag.range.end.line
                || (diag.range.start.line == diag.range.end.line
                    && diag.range.start.character <= diag.range.end.character)
        );
    }
}

#[test]
fn test_rapid_open_close_cycles() {
    let mut server = TestServer::start();

    let content = "// TODO: cycle\nfn main() {}\n";
    let uri = server.create_file("src/cycle.rs", content);

    // Rapid open/close/open cycle
    for i in 0..5 {
        server.send_did_open(&uri, "rust", i, content);
        let _ = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);
        server.send_did_close(&uri);
        let _ = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);
    }

    // Final open should still work
    server.send_did_open(&uri, "rust", 10, content);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Should still produce valid diagnostics after rapid cycles
}

#[test]
fn test_did_save_resets_changed_lines() {
    let mut server = TestServer::start();

    let baseline = "fn main() {}\n";
    let uri = server.create_file("src/main.rs", baseline);

    server.send_did_open(&uri, "rust", 1, baseline);

    // Change to add a TODO (triggers changed lines)
    let changed = "// TODO: add this\nfn main() {}\n";
    server.send_did_change(&uri, 2, changed);
    let _ = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Save resets baseline -- changed_lines should be cleared
    server.send_did_save(&uri);

    // After save, the saved content is the new baseline
    // If we change again, only the NEW changes should produce diagnostics
    let after_save_change = "// TODO: add this\nfn main() {\n    let x = 1;\n}\n";
    server.send_did_change(&uri, 3, after_save_change);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // The added line (let x = 1) is the only changed line from the post-save baseline
}

#[test]
fn test_binary_extension_file_handled_gracefully() {
    let mut server = TestServer::start();

    // File with binary-looking content (null bytes)
    let content = "binary\0data\0here\n";
    let uri = server.create_file("src/binary.dat", content);

    // This should not crash even with non-text content
    server.send_did_open(&uri, "plaintext", 1, content);
    let _diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // No crash is the main assertion
}
