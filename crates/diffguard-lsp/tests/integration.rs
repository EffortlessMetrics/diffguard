#![allow(clippy::collapsible_if)]
#![allow(dead_code, unused_imports)]
// Integration test harness for diffguard-lsp
//
// This module provides the core TestServer RAII helper and utility functions
// used by all integration test modules. The TestServer manages an in-process
// LSP server/client pair using Connection::memory() from lsp-server.
//
// Test setup pattern:
//   1. TestServer::start() creates a Connection::memory() pair
//   2. The server thread runs run_server(server_conn)
//   3. An initialize request is sent automatically
//   4. Tests use helper functions to send notifications/requests
//   5. Drop sends shutdown+exit to cleanly terminate the server thread

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use lsp_types::notification::{
    DidChangeConfiguration, DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Exit, Initialized, Notification as LspNotification, PublishDiagnostics,
};
use lsp_types::request::{CodeActionRequest, ExecuteCommand, Request as LspRequest, Shutdown};
use lsp_types::{
    CodeActionContext, CodeActionOrCommand, CodeActionParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, ExecuteCommandParams, InitializeParams, InitializeResult,
    NumberOrString, PublishDiagnosticsParams, Range, TextDocumentContentChangeEvent,
    TextDocumentIdentifier, TextDocumentItem, Uri, VersionedTextDocumentIdentifier,
    WorkspaceFolder,
};
use serde_json::json;
use tempfile::TempDir;

/// Default timeout for receiving diagnostic notifications from the server.
#[allow(dead_code)]
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(5);

/// Default request ID counter start.
const INITIAL_REQUEST_ID: i32 = 1;

/// Converts a file path to an lsp_types::Uri.
fn path_to_uri(path: &Path) -> Uri {
    let url = url::Url::from_file_path(path).expect("failed to create file URL");
    url.as_str().parse::<Uri>().expect("failed to parse URI")
}

/// RAII wrapper around an in-process LSP server/client pair.
///
/// Creates a Connection::memory() pair, spawns the server on a background thread,
/// and sends the initialize handshake automatically. On drop, sends shutdown + exit
/// to ensure the server thread terminates cleanly (preventing zombie threads on
/// test failure).
///
/// # Example
///
/// ```ignore
/// let server = TestServer::start();
/// let uri = server.open_file("src/main.rs", "fn main() { TODO: implement }");
/// let diags = server.collect_diagnostics_for(&uri);
/// // Drop happens automatically, server shuts down cleanly
/// ```
pub struct TestServer {
    /// The client-side connection for sending messages to the server.
    client_conn: Connection,
    /// Handle to the server thread. None after shutdown.
    server_thread: Option<thread::JoinHandle<anyhow::Result<()>>>,
    /// The initialize response containing server capabilities.
    #[allow(dead_code)]
    init_result: InitializeResult,
    /// Monotonically increasing request ID counter.
    next_request_id: i32,
    /// Temporary workspace directory for test files.
    temp_dir: TempDir,
    /// Cached diagnostics received from the server, keyed by URI string.
    diagnostics_cache: HashMap<String, PublishDiagnosticsParams>,
    /// Number of diagnostic notifications received since last reset.
    diagnostic_count: usize,
}

impl TestServer {
    /// Creates a new TestServer with an in-process LSP server.
    ///
    /// This performs the full initialization handshake:
    ///   1. Creates Connection::memory() pair
    ///   2. Spawns server thread running diffguard_lsp::server::run_server
    ///   3. Sends initialize request with workspace root pointing to a TempDir
    ///   4. Waits for and parses InitializeResult
    ///
    /// # Panics
    ///
    /// Panics if the server thread fails to start or the initialize response is invalid.
    pub fn start() -> Self {
        let (client_conn, server_conn) = Connection::memory();

        let server_thread = thread::spawn(move || diffguard_lsp::server::run_server(server_conn));

        let temp_dir = TempDir::new().expect("failed to create temp workspace dir");
        let workspace_uri = path_to_uri(temp_dir.path());

        #[allow(deprecated)]
        let init_params = InitializeParams {
            root_uri: Some(workspace_uri.clone()),
            workspace_folders: Some(vec![WorkspaceFolder {
                uri: workspace_uri,
                name: "test".to_string(),
            }]),
            ..InitializeParams::default()
        };

        // Send initialize request manually (client side)
        let init_request = Request::new(
            RequestId::from(INITIAL_REQUEST_ID),
            "initialize".to_string(),
            serde_json::to_value(init_params).expect("failed to serialize initialize params"),
        );
        client_conn
            .sender
            .send(Message::Request(init_request))
            .expect("failed to send initialize request");

        // Wait for initialize response
        let response = client_conn
            .receiver
            .recv()
            .expect("failed to receive initialize response");
        let init_response = match response {
            Message::Response(resp) => resp.result.expect("initialize response has no result"),
            _ => panic!("expected response message, got {:?}", response),
        };

        let init_result: InitializeResult =
            serde_json::from_value(init_response).expect("failed to parse InitializeResult");

        // Send initialized notification
        let initialized_notification =
            Notification::new(Initialized::METHOD.to_string(), json!({}));
        client_conn
            .sender
            .send(Message::Notification(initialized_notification))
            .expect("failed to send initialized notification");

        // Drain any messages that may have been sent during initialization
        // (e.g., window/showMessage for config warnings).
        drain_messages(&client_conn);

        TestServer {
            client_conn,
            server_thread: Some(server_thread),
            init_result,
            next_request_id: INITIAL_REQUEST_ID + 1,
            temp_dir,
            diagnostics_cache: HashMap::new(),
            diagnostic_count: 0,
        }
    }

    /// Creates a TestServer with a specific workspace root (for config tests).
    ///
    /// The workspace root is used to resolve diffguard.toml config files and
    /// to construct relative file paths for git diffs.
    #[allow(dead_code)]
    pub fn start_with_workspace(workspace_root: &Path) -> Self {
        let (client_conn, server_conn) = Connection::memory();

        let server_thread = thread::spawn(move || diffguard_lsp::server::run_server(server_conn));

        let workspace_uri = path_to_uri(workspace_root);

        #[allow(deprecated)]
        let init_params = InitializeParams {
            root_uri: Some(workspace_uri.clone()),
            workspace_folders: Some(vec![WorkspaceFolder {
                uri: workspace_uri,
                name: "test".to_string(),
            }]),
            ..InitializeParams::default()
        };

        // Send initialize request manually (client side)
        let init_request = Request::new(
            RequestId::from(INITIAL_REQUEST_ID),
            "initialize".to_string(),
            serde_json::to_value(init_params).expect("failed to serialize initialize params"),
        );
        client_conn
            .sender
            .send(Message::Request(init_request))
            .expect("failed to send initialize request");

        // Wait for initialize response, draining any notifications that arrive first
        // (e.g., window/showMessage for config warnings).
        let init_response = loop {
            let message = client_conn
                .receiver
                .recv()
                .expect("failed to receive message");
            match message {
                Message::Response(resp) if resp.id == RequestId::from(INITIAL_REQUEST_ID) => {
                    break resp.result.expect("initialize response has no result");
                }
                Message::Notification(_) => {
                    // Drain notifications sent during initialization
                    continue;
                }
                _ => panic!("expected initialize response, got {:?}", message),
            }
        };

        let init_result: InitializeResult =
            serde_json::from_value(init_response).expect("failed to parse InitializeResult");

        // Send initialized notification
        let initialized_notification =
            Notification::new(Initialized::METHOD.to_string(), json!({}));
        client_conn
            .sender
            .send(Message::Notification(initialized_notification))
            .expect("failed to send initialized notification");

        drain_messages(&client_conn);

        TestServer {
            client_conn,
            server_thread: Some(server_thread),
            init_result,
            next_request_id: INITIAL_REQUEST_ID + 1,
            temp_dir: TempDir::new().expect("failed to create temp dir for server"),
            diagnostics_cache: HashMap::new(),
            diagnostic_count: 0,
        }
    }

    /// Returns a reference to the server's InitializeResult (capabilities).
    #[allow(dead_code)]
    pub fn capabilities(&self) -> &InitializeResult {
        &self.init_result
    }

    /// Returns the temporary workspace directory path.
    #[allow(dead_code)]
    pub fn workspace_path(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Creates a file in the temp workspace and returns its URI.
    ///
    /// The file is created relative to the workspace root. Parent directories
    /// are created automatically.
    pub fn create_file(&self, relative_path: &str, content: &str) -> Uri {
        let full_path = self.temp_dir.path().join(relative_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).expect("failed to create parent directories");
        }
        std::fs::write(&full_path, content).expect("failed to write test file");
        path_to_uri(&full_path)
    }

    /// Sends a didOpen notification for the given URI and text content.
    ///
    /// This triggers the server to analyze the file and publish diagnostics.
    pub fn send_did_open(&self, uri: &Uri, language_id: &str, version: i32, text: &str) {
        let params = DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: language_id.to_string(),
                version,
                text: text.to_string(),
            },
        };
        self.send_notification(
            DidOpenTextDocument::METHOD,
            serde_json::to_value(params).unwrap(),
        );
    }

    /// Sends a didChange notification with full text replacement.
    ///
    /// The server uses full text sync, so the entire document content is replaced.
    /// Changed lines are computed by diffing against the baseline, which triggers
    /// diff-scoped diagnostics.
    pub fn send_did_change(&self, uri: &Uri, version: i32, text: &str) {
        let params = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: text.to_string(),
            }],
        };
        self.send_notification(
            DidChangeTextDocument::METHOD,
            serde_json::to_value(params).unwrap(),
        );
    }

    /// Sends a didClose notification for the given URI.
    ///
    /// This causes the server to clear diagnostics for the closed document.
    pub fn send_did_close(&self, uri: &Uri) {
        let params = DidCloseTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
        };
        self.send_notification(
            DidCloseTextDocument::METHOD,
            serde_json::to_value(params).unwrap(),
        );
    }

    /// Sends a didSave notification for the given URI.
    ///
    /// This causes the server to refresh diagnostics (the saved text becomes
    /// the new baseline, clearing changed lines).
    pub fn send_did_save(&self, uri: &Uri) {
        let params = DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            text: None,
        };
        self.send_notification(
            DidSaveTextDocument::METHOD,
            serde_json::to_value(params).unwrap(),
        );
    }

    /// Sends a didChangeConfiguration notification.
    #[allow(dead_code)]
    pub fn send_did_change_configuration(&self, settings: serde_json::Value) {
        let params = DidChangeConfigurationParams { settings };
        self.send_notification(
            DidChangeConfiguration::METHOD,
            serde_json::to_value(params).unwrap(),
        );
    }

    /// Sends a textDocument/codeAction request and returns the response.
    ///
    /// The diagnostics in the context should be the ones that were published
    /// for the target URI (from the diagnostics cache or passed directly).
    #[allow(dead_code)]
    pub fn send_code_action_request(
        &mut self,
        uri: &Uri,
        range: Range,
        diagnostics: &[lsp_types::Diagnostic],
    ) -> Vec<CodeActionOrCommand> {
        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            range,
            context: CodeActionContext {
                diagnostics: diagnostics.to_vec(),
                only: None,
                trigger_kind: None,
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };
        let response = self.send_request(
            CodeActionRequest::METHOD,
            serde_json::to_value(params).unwrap(),
        );
        match response.result {
            Some(value) => serde_json::from_value(value).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Sends a workspace/executeCommand request and returns the raw response.
    #[allow(dead_code)]
    pub fn send_execute_command(
        &mut self,
        command: &str,
        args: Vec<serde_json::Value>,
    ) -> Response {
        let params = ExecuteCommandParams {
            command: command.to_string(),
            arguments: args,
            work_done_progress_params: Default::default(),
        };
        self.send_request(
            ExecuteCommand::METHOD,
            serde_json::to_value(params).unwrap(),
        )
    }

    /// Collects PublishDiagnostics notifications from the server.
    ///
    /// Reads messages from the connection receiver until either:
    ///   - A PublishDiagnostics notification is received (returned immediately)
    ///   - The timeout expires (returns whatever was collected so far)
    ///
    /// Non-diagnostic messages (showMessage, etc.) are silently consumed.
    pub fn collect_diagnostics(&mut self, timeout: Duration) -> Vec<PublishDiagnosticsParams> {
        let deadline = Instant::now() + timeout;
        let mut collected = Vec::new();

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.client_conn.receiver.recv_timeout(remaining) {
                Ok(message) => {
                    if let Some(params) = extract_diagnostics(&message) {
                        // Update cache
                        self.diagnostics_cache
                            .insert(params.uri.to_string(), params.clone());
                        self.diagnostic_count += 1;
                        collected.push(params);
                    }
                    // Non-diagnostic messages are consumed silently
                }
                Err(_) => break,
            }
        }

        collected
    }

    /// Collects diagnostics for a specific URI within the timeout.
    pub fn collect_diagnostics_for_uri(
        &mut self,
        uri: &Uri,
        timeout: Duration,
    ) -> Vec<lsp_types::Diagnostic> {
        let uri_str = uri.to_string();
        let all = self.collect_diagnostics(timeout);
        for params in &all {
            if params.uri.to_string() == uri_str {
                return params.diagnostics.clone();
            }
        }
        // Check cache if nothing new arrived
        if let Some(cached) = self.diagnostics_cache.get(&uri_str) {
            return cached.diagnostics.clone();
        }
        Vec::new()
    }

    /// Drains all pending messages from the connection (non-blocking).
    #[allow(dead_code)]
    pub fn drain_pending_messages(&self) {
        drain_messages(&self.client_conn);
    }

    /// Sends a shutdown request and exit notification, then joins the server thread.
    ///
    /// This is also called automatically by Drop, but can be called explicitly
    /// to check for errors during shutdown.
    #[allow(dead_code)]
    pub fn shutdown(mut self) {
        self.do_shutdown();
    }

    fn do_shutdown(&mut self) {
        // Send shutdown request
        let shutdown_id = self.next_request_id();
        let shutdown_request = Request::new(
            RequestId::from(shutdown_id),
            Shutdown::METHOD.to_string(),
            json!(null),
        );
        let _ = self
            .client_conn
            .sender
            .send(Message::Request(shutdown_request));

        // Send exit notification
        let exit_notification = Notification::new(Exit::METHOD.to_string(), json!(null));
        let _ = self
            .client_conn
            .sender
            .send(Message::Notification(exit_notification));

        // Join server thread
        if let Some(handle) = self.server_thread.take() {
            let _ = handle.join();
        }
    }

    fn next_request_id(&mut self) -> i32 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    #[allow(dead_code)]
    fn send_request(&mut self, method: &str, params: serde_json::Value) -> Response {
        let id = self.next_request_id();
        let request = Request::new(RequestId::from(id), method.to_string(), params);
        self.client_conn
            .sender
            .send(Message::Request(request))
            .expect("failed to send request");

        // Wait for response matching our request ID
        let target_id = RequestId::from(id);
        loop {
            let message = self
                .client_conn
                .receiver
                .recv_timeout(DIAGNOSTIC_TIMEOUT)
                .expect("timed out waiting for response");

            match message {
                Message::Response(response) if response.id == target_id => {
                    return response;
                }
                Message::Notification(_) => {
                    // Consume notifications (e.g., showMessage, publishDiagnostics)
                    // while waiting for our response. Diagnostics are cached
                    // in the full collect_diagnostics path.
                }
                _ => {
                    // Other messages consumed while waiting
                }
            }
        }
    }

    fn send_notification(&self, method: &str, params: serde_json::Value) {
        let notification = Notification::new(method.to_string(), params);
        self.client_conn
            .sender
            .send(Message::Notification(notification))
            .expect("failed to send notification");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.do_shutdown();
    }
}

// ---------------------------------------------------------------------------
// Free helper functions for common test patterns
// ---------------------------------------------------------------------------

/// Creates a minimal test diffguard config with a single rule.
///
/// Returns the path to the created config file.
#[allow(dead_code)]
pub fn create_test_config(dir: &Path, config_content: &str) -> PathBuf {
    let config_path = dir.join("diffguard.toml");
    std::fs::write(&config_path, config_content).expect("failed to write test config");
    config_path
}

/// Creates a file in the given directory and returns its URI.
#[allow(dead_code)]
pub fn create_test_file(dir: &Path, name: &str, content: &str) -> Uri {
    let file_path = dir.join(name);
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dirs");
    }
    std::fs::write(&file_path, content).expect("failed to write test file");
    path_to_uri(&file_path)
}

/// Constructs a synthetic unified diff for the given path with the given content lines.
///
/// Each line in `added_lines` is emitted as a hunk adding a single line.
#[allow(dead_code)]
pub fn make_test_diff(path: &str, added_lines: &[&str]) -> String {
    let mut diff = format!(
        "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n",
        path = path
    );
    for (i, line) in added_lines.iter().enumerate() {
        let line_number = i + 1;
        diff.push_str(&format!("@@ -0,0 +{},1 @@\n", line_number));
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }
    diff
}

/// Drains all pending messages from the connection receiver (non-blocking).
fn drain_messages(conn: &Connection) {
    while conn.receiver.try_recv().is_ok() {}
}

/// Extracts PublishDiagnosticsParams from a message, if it is a diagnostic notification.
fn extract_diagnostics(message: &Message) -> Option<PublishDiagnosticsParams> {
    if let Message::Notification(notification) = message {
        if notification.method == PublishDiagnostics::METHOD {
            let params: PublishDiagnosticsParams =
                serde_json::from_value(notification.params.clone()).ok()?;
            return Some(params);
        }
    }
    None
}

/// Helper to assert that a diagnostic with a specific rule code exists in a list.
#[allow(dead_code)]
pub fn assert_diagnostic_with_code(diagnostics: &[lsp_types::Diagnostic], rule_code: &str) {
    assert!(
        diagnostics.iter().any(|d| {
            d.code.as_ref().is_some_and(|c| match c {
                NumberOrString::String(s) => s == rule_code,
                NumberOrString::Number(_) => false,
            })
        }),
        "Expected diagnostic with code '{}', but found codes: {:?}",
        rule_code,
        diagnostics
            .iter()
            .filter_map(|d| d.code.as_ref())
            .collect::<Vec<_>>(),
    );
}

/// Helper to assert that NO diagnostic with a specific rule code exists.
#[allow(dead_code)]
pub fn assert_no_diagnostic_with_code(diagnostics: &[lsp_types::Diagnostic], rule_code: &str) {
    assert!(
        !diagnostics.iter().any(|d| {
            d.code.as_ref().is_some_and(|c| match c {
                NumberOrString::String(s) => s == rule_code,
                NumberOrString::Number(_) => false,
            })
        }),
        "Did NOT expect diagnostic with code '{}', but found one. Diagnostics: {:?}",
        rule_code,
        diagnostics,
    );
}

/// Returns the line numbers that have diagnostics (0-indexed).
#[allow(dead_code)]
pub fn diagnostic_lines(diagnostics: &[lsp_types::Diagnostic]) -> Vec<u32> {
    let mut lines: Vec<u32> = diagnostics.iter().map(|d| d.range.start.line).collect();
    lines.sort();
    lines.dedup();
    lines
}
