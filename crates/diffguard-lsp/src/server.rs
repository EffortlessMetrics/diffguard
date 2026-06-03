use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use diffguard_core::{CheckPlan, run_check};
use diffguard_types::{ConfigFile, FailOn, Finding, Scope, Severity};
use lsp_server::{Connection, Message, Notification, Request, RequestId, Response, ResponseError};
use lsp_types::notification::{
    DidChangeConfiguration, DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Exit, Notification as LspNotification, PublishDiagnostics, ShowMessage,
};
use lsp_types::request::{CodeActionRequest, ExecuteCommand, Request as LspRequest};
use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
    CodeActionProviderCapability, Command as LspCommand, Diagnostic, DiagnosticSeverity,
    ExecuteCommandOptions, ExecuteCommandParams, InitializeParams, InitializeResult, MessageType,
    NumberOrString, Position, PublishDiagnosticsParams, Range, ServerCapabilities, ServerInfo,
    TextDocumentContentChangeEvent, TextDocumentSyncCapability, TextDocumentSyncKind, Uri,
};
use serde::Deserialize;
use serde_json::json;

use crate::config::{
    extract_rule_id, find_rule, find_similar_rules, format_rule_explanation,
    load_directory_overrides_for_file, load_effective_config, paths_match, resolve_config_path,
    to_workspace_relative_path,
};
use crate::text::{
    apply_incremental_change, build_synthetic_diff, changed_lines_between, utf16_length,
};

const DEFAULT_MAX_FINDINGS: usize = 200;
const DEFAULT_CONFIG_NAME: &str = "diffguard.toml";
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;

const CMD_EXPLAIN_RULE: &str = "diffguard.explainRule";
const CMD_RELOAD_CONFIG: &str = "diffguard.reloadConfig";
const CMD_SHOW_RULE_URL: &str = "diffguard.showRuleUrl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitSupport {
    Unknown,
    Available,
    Unavailable,
}

#[derive(Debug, Clone)]
struct DocumentState {
    path: PathBuf,
    version: i32,
    baseline_text: String,
    text: String,
    changed_lines: BTreeSet<u32>,
}

impl DocumentState {
    fn new(path: PathBuf, version: i32, text: String) -> Self {
        Self {
            path,
            version,
            baseline_text: text.clone(),
            text,
            changed_lines: BTreeSet::new(),
        }
    }

    fn apply_changes(&mut self, changes: &[TextDocumentContentChangeEvent]) -> Result<()> {
        if changes.is_empty() {
            return Ok(());
        }

        if let Some(full_change) = changes.iter().rev().find(|change| change.range.is_none()) {
            self.text.clone_from(&full_change.text);
            self.changed_lines = changed_lines_between(&self.baseline_text, &self.text);
            return Ok(());
        }

        for change in changes {
            apply_incremental_change(&mut self.text, change)?;
        }

        self.changed_lines = changed_lines_between(&self.baseline_text, &self.text);
        Ok(())
    }

    fn mark_saved(&mut self, new_text: Option<String>) {
        if let Some(text) = new_text {
            self.text = text;
        }
        self.baseline_text = self.text.clone();
        self.changed_lines.clear();
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct InitOptions {
    config_path: Option<String>,
    no_default_rules: bool,
    max_findings: Option<usize>,
    force_language: Option<String>,
}

#[derive(Debug)]
struct ServerState {
    workspace_root: Option<PathBuf>,
    config_path: Option<PathBuf>,
    no_default_rules: bool,
    max_findings: usize,
    force_language: Option<String>,
    config: ConfigFile,
    documents: HashMap<Uri, DocumentState>,
    git_support: GitSupport,
}

impl ServerState {
    fn from_initialize(params: &InitializeParams) -> (Self, Option<String>) {
        let options = parse_init_options(params.initialization_options.as_ref());
        let workspace_root = extract_workspace_root(params);
        let config_path = resolve_config_path(
            workspace_root.as_deref(),
            options.config_path,
            DEFAULT_CONFIG_NAME,
        );
        let max_findings = options.max_findings.unwrap_or(DEFAULT_MAX_FINDINGS).max(1);
        let force_language = normalize_option_string(options.force_language);

        let (config, warning) =
            match load_effective_config(config_path.as_deref(), options.no_default_rules) {
                Ok(config) => (config, None),
                Err(err) => {
                    let config_label = config_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<built-in>".to_string());
                    let warning = format!(
                        "diffguard-lsp: failed to load config from {} (using built-in rules): {}",
                        config_label, err
                    );
                    (ConfigFile::built_in(), Some(warning))
                }
            };

        (
            Self {
                workspace_root,
                config_path,
                no_default_rules: options.no_default_rules,
                max_findings,
                force_language,
                config,
                documents: HashMap::new(),
                git_support: GitSupport::Unknown,
            },
            warning,
        )
    }
}

/// Entry point for the diffguard LSP server.
///
/// Takes ownership of a `Connection` (from the `lsp-server` crate) and runs the
/// main LSP event loop, handling text document sync, diagnostics, and code actions.
pub fn run_server(connection: Connection) -> Result<()> {
    // Use the lower-level initialize_start/initialize_finish methods
    // to send a custom InitializeResult with server_info.
    let (id, init_params) = connection.initialize_start()?;
    let init_params: InitializeParams =
        serde_json::from_value(init_params).context("parse initialize params")?;

    let (mut state, startup_warning) = ServerState::from_initialize(&init_params);
    if let Some(message) = startup_warning {
        show_message(&connection, MessageType::WARNING, &message)?;
    }

    // Send InitializeResult with server_info
    let init_response = initialize_payload()?;
    connection.initialize_finish(id, init_response)?;

    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    break;
                }
                handle_request(&connection, &mut state, request.clone())?;
            }
            Message::Notification(notification) => {
                if handle_notification(&connection, &mut state, notification.clone())? {
                    break;
                }
            }
            Message::Response(_) => {}
        }
    }

    Ok(())
}

fn parse_init_options(value: Option<&serde_json::Value>) -> InitOptions {
    value
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

fn normalize_option_string(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[allow(deprecated)]
fn extract_workspace_root(params: &InitializeParams) -> Option<PathBuf> {
    if let Some(folders) = &params.workspace_folders {
        for folder in folders {
            if let Some(path) = uri_to_file_path(&folder.uri) {
                return Some(path);
            }
        }
    }

    if let Some(root_uri) = &params.root_uri
        && let Some(path) = uri_to_file_path(root_uri)
    {
        return Some(path);
    }

    params.root_path.as_ref().map(PathBuf::from)
}

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
        execute_command_provider: Some(ExecuteCommandOptions {
            commands: vec![
                CMD_EXPLAIN_RULE.to_string(),
                CMD_RELOAD_CONFIG.to_string(),
                CMD_SHOW_RULE_URL.to_string(),
            ],
            ..ExecuteCommandOptions::default()
        }),
        ..ServerCapabilities::default()
    }
}

fn initialize_payload() -> Result<serde_json::Value> {
    // When using initialize_finish(), we send the full InitializeResult
    // including server_info. The lsp-server library doesn't wrap this
    // in a capabilities object.
    let result = InitializeResult {
        capabilities: server_capabilities(),
        server_info: Some(ServerInfo {
            name: "diffguard-lsp".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }),
    };
    Ok(serde_json::to_value(result)?)
}

fn handle_request(
    connection: &Connection,
    state: &mut ServerState,
    request: Request,
) -> Result<()> {
    match request.method.as_str() {
        method if method == CodeActionRequest::METHOD => {
            handle_code_action_request(connection, state, request)
        }
        method if method == ExecuteCommand::METHOD => {
            handle_execute_command_request(connection, state, request)
        }
        _ => send_error_response(
            connection,
            request.id,
            METHOD_NOT_FOUND,
            format!("unsupported request method '{}'", request.method),
        ),
    }
}

fn handle_code_action_request(
    connection: &Connection,
    state: &ServerState,
    request: Request,
) -> Result<()> {
    let params: CodeActionParams = match serde_json::from_value(request.params) {
        Ok(params) => params,
        Err(err) => {
            return send_error_response(
                connection,
                request.id,
                INVALID_PARAMS,
                format!("invalid CodeActionParams: {}", err),
            );
        }
    };

    let actions = build_code_actions(&state.config, &params);
    send_ok_response(connection, request.id, serde_json::to_value(actions)?)
}

fn build_code_actions(config: &ConfigFile, params: &CodeActionParams) -> Vec<CodeActionOrCommand> {
    let mut actions = Vec::new();
    let mut seen_explain = BTreeSet::new();
    let mut seen_urls = BTreeSet::new();

    for diagnostic in &params.context.diagnostics {
        let Some(rule_id) = extract_rule_id(diagnostic) else {
            continue;
        };

        if seen_explain.insert(rule_id.clone()) {
            let command = LspCommand {
                title: format!("Explain {}", rule_id),
                command: CMD_EXPLAIN_RULE.to_string(),
                arguments: Some(vec![json!(rule_id.clone())]),
            };

            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title: format!("diffguard: Explain {}", rule_id),
                kind: Some(CodeActionKind::QUICKFIX),
                command: Some(command),
                data: Some(json!({ "ruleId": rule_id })),
                ..CodeAction::default()
            }));
        }

        if let Some(rule) = find_rule(config, &rule_id)
            && let Some(url) = rule.url.as_ref()
            && seen_urls.insert(url.clone())
        {
            let command = LspCommand {
                title: format!("Open docs for {}", rule.id),
                command: CMD_SHOW_RULE_URL.to_string(),
                arguments: Some(vec![json!(url), json!(rule.id)]),
            };
            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title: format!("diffguard: Open docs for {}", rule.id),
                kind: Some(CodeActionKind::QUICKFIX),
                command: Some(command),
                data: Some(json!({ "ruleId": rule.id, "url": url })),
                ..CodeAction::default()
            }));
        }
    }

    actions
}

fn handle_execute_command_request(
    connection: &Connection,
    state: &mut ServerState,
    request: Request,
) -> Result<()> {
    let params: ExecuteCommandParams = match serde_json::from_value(request.params) {
        Ok(params) => params,
        Err(err) => {
            return send_error_response(
                connection,
                request.id,
                INVALID_PARAMS,
                format!("invalid ExecuteCommandParams: {}", err),
            );
        }
    };

    match params.command.as_str() {
        CMD_EXPLAIN_RULE => {
            let Some(rule_id) = nth_string_arg(&params.arguments, 0) else {
                return send_error_response(
                    connection,
                    request.id,
                    INVALID_PARAMS,
                    "missing rule ID argument".to_string(),
                );
            };

            let (message, found) = explain_rule_message(&state.config, &rule_id);
            let message_type = if found {
                MessageType::INFO
            } else {
                MessageType::WARNING
            };
            show_message(connection, message_type, &message)?;

            send_ok_response(
                connection,
                request.id,
                json!({
                    "ruleId": rule_id,
                    "found": found,
                    "message": message
                }),
            )
        }
        CMD_RELOAD_CONFIG => {
            let (ok, message) = match reload_config(state) {
                Ok(msg) => (true, msg),
                Err(err) => (false, err.to_string()),
            };
            let message_type = if ok {
                MessageType::INFO
            } else {
                MessageType::WARNING
            };
            show_message(connection, message_type, &message)?;
            refresh_all_documents(connection, state)?;

            send_ok_response(
                connection,
                request.id,
                json!({
                    "ok": ok,
                    "message": message,
                    "rules": state.config.rule.len()
                }),
            )
        }
        CMD_SHOW_RULE_URL => {
            let Some(url) = nth_string_arg(&params.arguments, 0) else {
                return send_error_response(
                    connection,
                    request.id,
                    INVALID_PARAMS,
                    "missing URL argument".to_string(),
                );
            };
            let rule_id = nth_string_arg(&params.arguments, 1).unwrap_or_default();
            let label = if rule_id.is_empty() {
                "diffguard documentation".to_string()
            } else {
                format!("diffguard rule {}", rule_id)
            };
            show_message(
                connection,
                MessageType::INFO,
                &format!("{}: {}", label, url),
            )?;

            send_ok_response(
                connection,
                request.id,
                json!({
                    "url": url,
                    "ruleId": rule_id
                }),
            )
        }
        _ => send_error_response(
            connection,
            request.id,
            INVALID_PARAMS,
            format!("unsupported command '{}'", params.command),
        ),
    }
}

fn explain_rule_message(config: &ConfigFile, rule_id: &str) -> (String, bool) {
    if let Some(rule) = find_rule(config, rule_id) {
        return (format_rule_explanation(rule), true);
    }

    let suggestions = find_similar_rules(rule_id, &config.rule);
    let mut message = format!("Rule '{}' not found.", rule_id);
    if !suggestions.is_empty() {
        message.push_str("\nDid you mean:");
        for suggestion in suggestions {
            message.push_str(&format!("\n- {}", suggestion));
        }
    }
    (message, false)
}

fn handle_notification(
    connection: &Connection,
    state: &mut ServerState,
    notification: Notification,
) -> Result<bool> {
    match notification.method.as_str() {
        method if method == DidOpenTextDocument::METHOD => {
            let params: lsp_types::DidOpenTextDocumentParams =
                match serde_json::from_value(notification.params) {
                    Ok(params) => params,
                    Err(err) => {
                        show_message(
                            connection,
                            MessageType::WARNING,
                            &format!("invalid didOpen params: {}", err),
                        )?;
                        return Ok(false);
                    }
                };

            let uri = params.text_document.uri;
            if let Some(path) = uri_to_file_path(&uri) {
                let document = DocumentState::new(
                    path,
                    params.text_document.version,
                    params.text_document.text,
                );
                state.documents.insert(uri.clone(), document);
                refresh_document_diagnostics(connection, state, &uri)?;
            }
        }
        method if method == DidChangeTextDocument::METHOD => {
            let params: lsp_types::DidChangeTextDocumentParams =
                match serde_json::from_value(notification.params) {
                    Ok(params) => params,
                    Err(err) => {
                        show_message(
                            connection,
                            MessageType::WARNING,
                            &format!("invalid didChange params: {}", err),
                        )?;
                        return Ok(false);
                    }
                };

            let uri = params.text_document.uri;
            if let Some(document) = state.documents.get_mut(&uri) {
                document.version = params.text_document.version;
                if let Err(err) = document.apply_changes(&params.content_changes) {
                    show_message(
                        connection,
                        MessageType::WARNING,
                        &format!("failed to apply text changes for {}: {}", uri.as_str(), err),
                    )?;
                }
                refresh_document_diagnostics(connection, state, &uri)?;
            }
        }
        method if method == DidSaveTextDocument::METHOD => {
            let params: lsp_types::DidSaveTextDocumentParams =
                match serde_json::from_value(notification.params) {
                    Ok(params) => params,
                    Err(err) => {
                        show_message(
                            connection,
                            MessageType::WARNING,
                            &format!("invalid didSave params: {}", err),
                        )?;
                        return Ok(false);
                    }
                };

            let uri = params.text_document.uri;
            if let Some(document) = state.documents.get_mut(&uri) {
                document.mark_saved(params.text);
            }

            if is_config_uri(state, &uri) {
                let (ok, message) = match reload_config(state) {
                    Ok(msg) => (true, msg),
                    Err(err) => (false, err.to_string()),
                };
                let message_type = if ok {
                    MessageType::INFO
                } else {
                    MessageType::WARNING
                };
                show_message(connection, message_type, &message)?;
                refresh_all_documents(connection, state)?;
            } else {
                refresh_document_diagnostics(connection, state, &uri)?;
            }
        }
        method if method == DidCloseTextDocument::METHOD => {
            let params: lsp_types::DidCloseTextDocumentParams =
                match serde_json::from_value(notification.params) {
                    Ok(params) => params,
                    Err(err) => {
                        show_message(
                            connection,
                            MessageType::WARNING,
                            &format!("invalid didClose params: {}", err),
                        )?;
                        return Ok(false);
                    }
                };

            let uri = params.text_document.uri;
            state.documents.remove(&uri);
            publish_diagnostics(connection, uri, None, Vec::new())?;
        }
        method if method == DidChangeConfiguration::METHOD => {
            let _: lsp_types::DidChangeConfigurationParams =
                match serde_json::from_value(notification.params) {
                    Ok(params) => params,
                    Err(err) => {
                        show_message(
                            connection,
                            MessageType::WARNING,
                            &format!("invalid didChangeConfiguration params: {}", err),
                        )?;
                        return Ok(false);
                    }
                };

            let (ok, message) = match reload_config(state) {
                Ok(msg) => (true, msg),
                Err(err) => (false, err.to_string()),
            };
            let message_type = if ok {
                MessageType::INFO
            } else {
                MessageType::WARNING
            };
            show_message(connection, message_type, &message)?;
            refresh_all_documents(connection, state)?;
        }
        method if method == Exit::METHOD => return Ok(true),
        _ => {}
    }

    Ok(false)
}

fn is_config_uri(state: &ServerState, uri: &Uri) -> bool {
    let Some(config_path) = state.config_path.as_deref() else {
        return false;
    };
    let Some(uri_path) = uri_to_file_path(uri) else {
        return false;
    };
    paths_match(&uri_path, config_path)
}

fn reload_config(state: &mut ServerState) -> Result<String> {
    match load_effective_config(state.config_path.as_deref(), state.no_default_rules) {
        Ok(config) => {
            let rules = config.rule.len();
            state.config = config;
            Ok(format!(
                "diffguard-lsp: config reloaded ({} rule(s)).",
                rules
            ))
        }
        Err(err) => {
            state.config = ConfigFile::built_in();
            state.git_support = GitSupport::Unknown;
            bail!(
                "diffguard-lsp: failed to reload config (using built-in rules): {}",
                err
            )
        }
    }
}

fn refresh_all_documents(connection: &Connection, state: &mut ServerState) -> Result<()> {
    let mut uris: Vec<Uri> = state.documents.keys().cloned().collect();
    uris.sort();
    for uri in uris {
        refresh_document_diagnostics(connection, state, &uri)?;
    }
    Ok(())
}

fn refresh_document_diagnostics(
    connection: &Connection,
    state: &mut ServerState,
    uri: &Uri,
) -> Result<()> {
    let Some(document) = state.documents.get(uri).cloned() else {
        return Ok(());
    };

    let relative_path = to_workspace_relative_path(state.workspace_root.as_deref(), &document.path);
    if relative_path.is_empty() {
        publish_diagnostics(connection, uri.clone(), Some(document.version), Vec::new())?;
        return Ok(());
    }

    let mut allowed_lines = None;
    let diff_text = if !document.changed_lines.is_empty() {
        let synthetic =
            build_synthetic_diff(&relative_path, &document.text, &document.changed_lines);
        let mut scoped_lines = BTreeSet::new();
        for line in &document.changed_lines {
            scoped_lines.insert((relative_path.clone(), *line));
        }
        if !scoped_lines.is_empty() {
            allowed_lines = Some(scoped_lines);
        }
        synthetic
    } else if let Some(workspace_root) = state.workspace_root.as_deref() {
        match git_diff_for_path(workspace_root, &relative_path) {
            Ok(diff) => {
                state.git_support = GitSupport::Available;
                diff
            }
            Err(err) => {
                if state.git_support != GitSupport::Unavailable {
                    show_message(
                        connection,
                        MessageType::WARNING,
                        &format!(
                            "diffguard-lsp: git diff unavailable (falling back to in-memory changes only): {}",
                            err
                        ),
                    )?;
                }
                state.git_support = GitSupport::Unavailable;
                String::new()
            }
        }
    } else {
        String::new()
    };

    if diff_text.trim().is_empty() {
        publish_diagnostics(connection, uri.clone(), Some(document.version), Vec::new())?;
        return Ok(());
    }

    let directory_overrides = if let Some(workspace_root) = state.workspace_root.as_deref() {
        match load_directory_overrides_for_file(workspace_root, &relative_path) {
            Ok(overrides) => overrides,
            Err(err) => {
                show_message(
                    connection,
                    MessageType::WARNING,
                    &format!("diffguard-lsp: failed to load directory overrides: {}", err),
                )?;
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let plan = CheckPlan {
        base: "workspace".to_string(),
        head: "working-tree".to_string(),
        scope: Scope::Added,
        diff_context: 0,
        fail_on: FailOn::Never,
        max_findings: state.max_findings,
        path_filters: vec![relative_path.clone()],
        only_tags: vec![],
        enable_tags: vec![],
        disable_tags: vec![],
        directory_overrides,
        force_language: state.force_language.clone(),
        allowed_lines,
        false_positive_fingerprints: BTreeSet::new(),
    };

    let run = match run_check(&plan, &state.config, &diff_text) {
        Ok(run) => run,
        Err(err) => {
            show_message(
                connection,
                MessageType::ERROR,
                &format!("diffguard-lsp: check failed for {}: {}", relative_path, err),
            )?;
            publish_diagnostics(connection, uri.clone(), Some(document.version), Vec::new())?;
            return Ok(());
        }
    };

    let diagnostics = findings_to_diagnostics(&run.receipt.findings);
    publish_diagnostics(connection, uri.clone(), Some(document.version), diagnostics)
}

fn findings_to_diagnostics(findings: &[Finding]) -> Vec<Diagnostic> {
    let mut diagnostics: Vec<Diagnostic> = findings
        .iter()
        .map(|finding| {
            let line = finding.line.saturating_sub(1);
            let start_char = finding.column.unwrap_or(1).saturating_sub(1);
            let span = utf16_length(&finding.match_text).max(1);
            let end_char = start_char.saturating_add(span);

            Diagnostic {
                range: Range::new(
                    Position::new(line, start_char),
                    Position::new(line, end_char),
                ),
                severity: Some(match finding.severity {
                    Severity::Info => DiagnosticSeverity::INFORMATION,
                    Severity::Warn => DiagnosticSeverity::WARNING,
                    Severity::Error => DiagnosticSeverity::ERROR,
                }),
                code: Some(NumberOrString::String(finding.rule_id.clone())),
                source: Some("diffguard".to_string()),
                message: finding.message.clone(),
                data: Some(json!({
                    "ruleId": finding.rule_id,
                    "path": finding.path,
                    "line": finding.line
                })),
                ..Diagnostic::default()
            }
        })
        .collect();

    diagnostics.sort_by(|left, right| {
        left.range
            .start
            .line
            .cmp(&right.range.start.line)
            .then_with(|| left.range.start.character.cmp(&right.range.start.character))
            .then_with(|| left.message.cmp(&right.message))
    });

    diagnostics
}

fn nth_string_arg(arguments: &[serde_json::Value], index: usize) -> Option<String> {
    arguments
        .get(index)
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn send_ok_response(
    connection: &Connection,
    id: RequestId,
    result: serde_json::Value,
) -> Result<()> {
    let response = Response {
        id,
        result: Some(result),
        error: None,
    };
    send_response(connection, response)
}

fn send_error_response(
    connection: &Connection,
    id: RequestId,
    code: i32,
    message: String,
) -> Result<()> {
    let response = Response {
        id,
        result: None,
        error: Some(ResponseError {
            code,
            message,
            data: None,
        }),
    };
    send_response(connection, response)
}

fn send_response(connection: &Connection, response: Response) -> Result<()> {
    connection
        .sender
        .send(Message::Response(response))
        .context("send LSP response")?;
    Ok(())
}

fn show_message(connection: &Connection, typ: MessageType, message: &str) -> Result<()> {
    let params = lsp_types::ShowMessageParams {
        typ,
        message: message.to_string(),
    };
    let notification = Notification::new(ShowMessage::METHOD.to_string(), params);
    connection
        .sender
        .send(Message::Notification(notification))
        .context("send showMessage notification")?;
    Ok(())
}

fn publish_diagnostics(
    connection: &Connection,
    uri: Uri,
    version: Option<i32>,
    diagnostics: Vec<Diagnostic>,
) -> Result<()> {
    let params = PublishDiagnosticsParams {
        uri,
        diagnostics,
        version,
    };
    let notification = Notification::new(PublishDiagnostics::METHOD.to_string(), params);
    connection
        .sender
        .send(Message::Notification(notification))
        .context("publish diagnostics")?;
    Ok(())
}

fn git_diff_for_path(workspace_root: &Path, relative_path: &str) -> Result<String> {
    let unstaged = run_git_diff(workspace_root, relative_path, false)?;
    let staged = run_git_diff(workspace_root, relative_path, true)?;

    if unstaged.is_empty() {
        return Ok(staged);
    }
    if staged.is_empty() {
        return Ok(unstaged);
    }

    let mut combined = unstaged;
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(&staged);
    Ok(combined)
}

/// Runs `git diff` for a single file with a 10-second timeout.
///
/// The timeout prevents the LSP from blocking indefinitely if git hangs.
/// `staged` controls whether to diff staged changes or the working tree.
fn run_git_diff(workspace_root: &Path, relative_path: &str, staged: bool) -> Result<String> {
    // Spawn with a 10-second timeout to avoid blocking the LSP indefinitely
    const GIT_DIFF_TIMEOUT: Duration = Duration::from_secs(10);

    let mut command = Command::new("git");
    command.current_dir(workspace_root).arg("diff");
    if staged {
        command.arg("--cached");
    }
    command.arg("--unified=0").arg("--").arg(relative_path);
    let mut child = command.spawn().context("spawn git diff")?;
    let deadline = Instant::now() + GIT_DIFF_TIMEOUT;

    let output = loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process has exited; wait_with_output() returns immediately
                break child.wait_with_output().context("wait for git diff")?;
            }
            Ok(None) => {
                // Still running
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    bail!("git diff timed out after {}s", GIT_DIFF_TIMEOUT.as_secs());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => bail!("checking git diff status: {e}"),
        }
    };

    if !output.status.success() {
        bail!(
            "git diff failed (exit={}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn uri_to_file_path(uri: &Uri) -> Option<PathBuf> {
    let parsed = url::Url::parse(uri.as_str()).ok()?;
    parsed.to_file_path().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsp_types::{
        DidChangeConfigurationParams, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, TextDocumentIdentifier,
        TextDocumentItem, VersionedTextDocumentIdentifier,
    };

    fn sample_rule(id: &str, url: Option<&str>) -> diffguard_types::RuleConfig {
        diffguard_types::RuleConfig {
            id: id.to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "msg".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: diffguard_types::MatchMode::Any,
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: url.map(|s| s.to_string()),
            tags: vec![],
            test_cases: vec![],
        }
    }

    fn config_with_rules(rules: Vec<diffguard_types::RuleConfig>) -> ConfigFile {
        ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: rules,
        }
    }

    fn parse_uri(uri_str: &str) -> Uri {
        uri_str.parse().expect("uri parse") // diffguard: ignore rust.no_unwrap
    }

    fn drain_messages(connection: &Connection) -> Vec<Message> {
        let mut messages = Vec::new();
        while let Ok(msg) = connection.receiver.try_recv() {
            messages.push(msg);
        }
        messages
    }

    fn find_response(messages: &[Message]) -> Option<&Response> {
        messages.iter().find_map(|m| match m {
            Message::Response(response) => Some(response),
            _ => None,
        })
    }

    fn find_notification<'a>(messages: &'a [Message], method: &str) -> Option<&'a Notification> {
        messages.iter().find_map(|m| match m {
            Message::Notification(notif) if notif.method == method => Some(notif),
            _ => None,
        })
    }

    fn empty_state() -> ServerState {
        ServerState {
            workspace_root: None,
            config_path: None,
            no_default_rules: true,
            max_findings: DEFAULT_MAX_FINDINGS,
            force_language: None,
            config: ConfigFile::built_in(),
            documents: HashMap::new(),
            git_support: GitSupport::Unknown,
        }
    }

    #[test]
    fn server_capabilities_include_text_sync_and_actions() {
        let capabilities = server_capabilities();
        assert!(matches!(
            capabilities.text_document_sync,
            Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL))
        ));
        assert!(capabilities.code_action_provider.is_some());
        assert!(capabilities.execute_command_provider.is_some());
    }

    #[test]
    fn initialize_payload_contains_server_name() {
        let value = initialize_payload().expect("payload"); // diffguard: ignore rust.no_unwrap
        let info = value
            .get("serverInfo")
            .and_then(|v| v.as_object())
            .expect("server info"); // diffguard: ignore rust.no_unwrap
        assert_eq!(
            info.get("name").and_then(|v| v.as_str()),
            Some("diffguard-lsp")
        );
    }

    #[test]
    fn build_code_actions_contains_explain_action() {
        let config = config_with_rules(vec![sample_rule(
            "rust.no_unwrap",
            Some("https://example.com/rule"),
        )]);

        let params = CodeActionParams {
            text_document: lsp_types::TextDocumentIdentifier {
                uri: parse_uri("file:///tmp/test.rs"),
            },
            range: Range::new(Position::new(0, 0), Position::new(0, 10)),
            context: lsp_types::CodeActionContext {
                diagnostics: vec![Diagnostic {
                    code: Some(NumberOrString::String("rust.no_unwrap".to_string())),
                    ..Diagnostic::default()
                }],
                only: None,
                trigger_kind: None,
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let actions = build_code_actions(&config, &params);
        assert!(!actions.is_empty());
    }

    // ---------------------------------------------------------------------
    // Pure-function helpers
    // ---------------------------------------------------------------------

    #[test]
    fn normalize_option_string_returns_none_for_whitespace_input() {
        assert_eq!(normalize_option_string(None), None);
        assert_eq!(normalize_option_string(Some(String::new())), None);
        assert_eq!(normalize_option_string(Some("   ".to_string())), None);
        assert_eq!(normalize_option_string(Some("\t\n ".to_string())), None);
        assert_eq!(
            normalize_option_string(Some("  rust  ".to_string())),
            Some("rust".to_string())
        );
    }

    #[test]
    fn parse_init_options_returns_default_when_missing_or_invalid() {
        let none_opts = parse_init_options(None);
        assert!(none_opts.config_path.is_none());
        assert!(!none_opts.no_default_rules);
        assert!(none_opts.max_findings.is_none());

        // An object that doesn't deserialize to InitOptions falls back to default.
        let bogus = serde_json::json!({ "configPath": 42 });
        let defaulted = parse_init_options(Some(&bogus));
        assert!(defaulted.config_path.is_none());
    }

    #[test]
    fn parse_init_options_reads_camel_case_fields() {
        let value = serde_json::json!({
            "configPath": "config.toml",
            "noDefaultRules": true,
            "maxFindings": 17,
            "forceLanguage": "rust",
        });
        let opts = parse_init_options(Some(&value));
        assert_eq!(opts.config_path.as_deref(), Some("config.toml"));
        assert!(opts.no_default_rules);
        assert_eq!(opts.max_findings, Some(17));
        assert_eq!(opts.force_language.as_deref(), Some("rust"));
    }

    #[test]
    fn nth_string_arg_returns_none_for_missing_or_wrong_type() {
        let args = vec![json!("first"), json!(42), json!(null)];
        assert_eq!(nth_string_arg(&args, 0), Some("first".to_string()));
        // Non-string value
        assert_eq!(nth_string_arg(&args, 1), None);
        // null value
        assert_eq!(nth_string_arg(&args, 2), None);
        // out-of-bounds index
        assert_eq!(nth_string_arg(&args, 5), None);
        // empty list
        assert_eq!(nth_string_arg(&[], 0), None);
    }

    #[test]
    fn uri_to_file_path_returns_none_for_malformed_uri() {
        // A scheme without authority is not a valid file URL.
        let uri: Uri = parse_uri("https://example.com/foo.rs");
        assert!(uri_to_file_path(&uri).is_none());
    }

    #[test]
    fn uri_to_file_path_parses_valid_file_uri() {
        let uri: Uri = parse_uri("file:///tmp/some/path.rs");
        let parsed = uri_to_file_path(&uri).expect("file path"); // diffguard: ignore rust.no_unwrap
        assert_eq!(parsed, PathBuf::from("/tmp/some/path.rs"));
    }

    #[test]
    fn explain_rule_message_reports_found_when_rule_exists() {
        let config = config_with_rules(vec![sample_rule("rust.no_unwrap", None)]);
        let (message, found) = explain_rule_message(&config, "rust.no_unwrap");
        assert!(found);
        assert!(message.contains("Rule: rust.no_unwrap"));
    }

    #[test]
    fn explain_rule_message_includes_did_you_mean_when_rule_missing() {
        let config = config_with_rules(vec![sample_rule("rust.no_unwrap", None)]);
        let (message, found) = explain_rule_message(&config, "rust.no_unwra");
        assert!(!found);
        assert!(message.contains("not found"));
        assert!(message.contains("Did you mean:"));
        assert!(message.contains("rust.no_unwrap"));
    }

    #[test]
    fn explain_rule_message_omits_suggestions_when_no_similar_rules() {
        let config = config_with_rules(vec![sample_rule("rust.no_unwrap", None)]);
        let (message, found) = explain_rule_message(&config, "totally.unrelated_thing_xyz");
        assert!(!found);
        assert!(message.contains("not found"));
        assert!(!message.contains("Did you mean:"));
    }

    #[test]
    fn findings_to_diagnostics_maps_severity_and_sorts_by_position() {
        let findings = vec![
            Finding {
                rule_id: "r1".to_string(),
                severity: Severity::Info,
                message: "info-msg".to_string(),
                path: "src/a.rs".to_string(),
                line: 3,
                column: Some(2),
                match_text: "ab".to_string(),
                snippet: String::new(),
            },
            Finding {
                rule_id: "r2".to_string(),
                severity: Severity::Error,
                message: "err-msg".to_string(),
                path: "src/a.rs".to_string(),
                line: 1,
                column: Some(1),
                match_text: "y".to_string(),
                snippet: String::new(),
            },
            Finding {
                rule_id: "r3".to_string(),
                severity: Severity::Warn,
                message: "warn-msg".to_string(),
                path: "src/a.rs".to_string(),
                line: 2,
                column: None,
                match_text: String::new(),
                snippet: String::new(),
            },
        ];

        let diagnostics = findings_to_diagnostics(&findings);
        assert_eq!(diagnostics.len(), 3);
        // Sorted ascending by line.
        assert_eq!(diagnostics[0].range.start.line, 0);
        assert_eq!(diagnostics[1].range.start.line, 1);
        assert_eq!(diagnostics[2].range.start.line, 2);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(diagnostics[1].severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(
            diagnostics[2].severity,
            Some(DiagnosticSeverity::INFORMATION)
        );
        // Empty match_text yields a span of length 1.
        assert_eq!(diagnostics[1].range.end.character, 1);
    }

    // ---------------------------------------------------------------------
    // DocumentState behaviour
    // ---------------------------------------------------------------------

    #[test]
    fn document_state_apply_changes_handles_empty_change_list() {
        let mut doc = DocumentState::new(PathBuf::from("a.rs"), 1, "hello\n".to_string());
        doc.apply_changes(&[]).expect("apply ok"); // diffguard: ignore rust.no_unwrap
        assert_eq!(doc.text, "hello\n");
        assert!(doc.changed_lines.is_empty());
    }

    #[test]
    fn document_state_apply_changes_replaces_text_on_full_change() {
        let mut doc = DocumentState::new(PathBuf::from("a.rs"), 1, "before\n".to_string());
        let change = TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: "after\n".to_string(),
        };
        doc.apply_changes(&[change]).expect("apply ok"); // diffguard: ignore rust.no_unwrap
        assert_eq!(doc.text, "after\n");
        assert!(!doc.changed_lines.is_empty());
    }

    #[test]
    fn document_state_apply_changes_uses_last_full_replacement() {
        let mut doc = DocumentState::new(PathBuf::from("a.rs"), 1, "orig\n".to_string());
        let changes = vec![
            TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "first\n".to_string(),
            },
            TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "final\n".to_string(),
            },
        ];
        doc.apply_changes(&changes).expect("apply ok"); // diffguard: ignore rust.no_unwrap
        assert_eq!(doc.text, "final\n");
    }

    #[test]
    fn document_state_mark_saved_with_text_updates_baseline_and_clears_changes() {
        let mut doc = DocumentState::new(PathBuf::from("a.rs"), 1, "before\n".to_string());
        let change = TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: "after\n".to_string(),
        };
        doc.apply_changes(&[change]).expect("apply ok"); // diffguard: ignore rust.no_unwrap
        assert!(!doc.changed_lines.is_empty());

        doc.mark_saved(Some("saved\n".to_string()));
        assert_eq!(doc.text, "saved\n");
        assert_eq!(doc.baseline_text, "saved\n");
        assert!(doc.changed_lines.is_empty());
    }

    #[test]
    fn document_state_mark_saved_without_text_keeps_current_text() {
        let mut doc = DocumentState::new(PathBuf::from("a.rs"), 1, "before\n".to_string());
        let change = TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: "after\n".to_string(),
        };
        doc.apply_changes(&[change]).expect("apply ok"); // diffguard: ignore rust.no_unwrap

        doc.mark_saved(None);
        assert_eq!(doc.text, "after\n");
        assert_eq!(doc.baseline_text, "after\n");
        assert!(doc.changed_lines.is_empty());
    }

    // ---------------------------------------------------------------------
    // extract_workspace_root variants
    // ---------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn extract_workspace_root_prefers_workspace_folders() {
        let params = InitializeParams {
            workspace_folders: Some(vec![lsp_types::WorkspaceFolder {
                uri: parse_uri("file:///tmp/ws"),
                name: "ws".to_string(),
            }]),
            ..InitializeParams::default()
        };
        let root = extract_workspace_root(&params);
        assert_eq!(root, Some(PathBuf::from("/tmp/ws")));
    }

    #[test]
    #[allow(deprecated)]
    fn extract_workspace_root_falls_back_to_root_uri() {
        let params = InitializeParams {
            workspace_folders: None,
            root_uri: Some(parse_uri("file:///tmp/ws-from-uri")),
            ..InitializeParams::default()
        };
        let root = extract_workspace_root(&params);
        assert_eq!(root, Some(PathBuf::from("/tmp/ws-from-uri")));
    }

    #[test]
    #[allow(deprecated)]
    fn extract_workspace_root_falls_back_to_root_path() {
        let params = InitializeParams {
            workspace_folders: None,
            root_uri: None,
            root_path: Some("/tmp/legacy".to_string()),
            ..InitializeParams::default()
        };
        let root = extract_workspace_root(&params);
        assert_eq!(root, Some(PathBuf::from("/tmp/legacy")));
    }

    #[test]
    #[allow(deprecated)]
    fn extract_workspace_root_returns_none_when_nothing_provided() {
        let params = InitializeParams::default();
        assert!(extract_workspace_root(&params).is_none());
    }

    // ---------------------------------------------------------------------
    // ServerState::from_initialize
    // ---------------------------------------------------------------------

    #[test]
    fn from_initialize_uses_default_max_findings_when_unset() {
        let params = InitializeParams::default();
        let (state, _warning) = ServerState::from_initialize(&params);
        assert_eq!(state.max_findings, DEFAULT_MAX_FINDINGS);
        assert!(state.workspace_root.is_none());
    }

    #[test]
    fn from_initialize_clamps_zero_max_findings_to_one() {
        let params = InitializeParams {
            initialization_options: Some(json!({ "maxFindings": 0 })),
            ..InitializeParams::default()
        };
        let (state, _warning) = ServerState::from_initialize(&params);
        assert_eq!(state.max_findings, 1);
    }

    #[test]
    fn from_initialize_passes_force_language_through_trim() {
        let params = InitializeParams {
            initialization_options: Some(json!({ "forceLanguage": "  rust  " })),
            ..InitializeParams::default()
        };
        let (state, _warning) = ServerState::from_initialize(&params);
        assert_eq!(state.force_language.as_deref(), Some("rust"));
    }

    #[test]
    fn from_initialize_emits_warning_when_config_path_fails_to_load() {
        let params = InitializeParams {
            initialization_options: Some(json!({
                "configPath": "/nonexistent/diffguard-missing.toml"
            })),
            ..InitializeParams::default()
        };
        let (state, warning) = ServerState::from_initialize(&params);
        // Falls back to built-in rules when load fails.
        assert!(!state.config.rule.is_empty());
        assert!(warning.is_some());
        let warning_text = warning.expect("warning string"); // diffguard: ignore rust.no_unwrap
        assert!(warning_text.contains("failed to load config"));
    }

    // ---------------------------------------------------------------------
    // is_config_uri
    // ---------------------------------------------------------------------

    #[test]
    fn is_config_uri_returns_false_when_no_config_path() {
        let state = empty_state();
        let uri = parse_uri("file:///tmp/foo.rs");
        assert!(!is_config_uri(&state, &uri));
    }

    #[test]
    fn is_config_uri_returns_false_when_uri_cannot_be_parsed() {
        let mut state = empty_state();
        state.config_path = Some(PathBuf::from("/tmp/diffguard.toml"));
        let uri = parse_uri("https://example.com/foo.toml");
        assert!(!is_config_uri(&state, &uri));
    }

    #[test]
    fn is_config_uri_matches_normalized_paths() {
        let mut state = empty_state();
        state.config_path = Some(PathBuf::from("/tmp/diffguard.toml"));
        let uri = parse_uri("file:///tmp/diffguard.toml");
        assert!(is_config_uri(&state, &uri));
    }

    // ---------------------------------------------------------------------
    // reload_config
    // ---------------------------------------------------------------------

    #[test]
    fn reload_config_reports_rule_count_on_success() {
        let mut state = empty_state();
        // With no config_path and no_default_rules=true, load returns built_in but
        // we set no_default_rules=true so we get an empty/built-in-less config.
        state.no_default_rules = true;
        state.config_path = None;
        let result = reload_config(&mut state).expect("reload ok"); // diffguard: ignore rust.no_unwrap
        assert!(result.contains("config reloaded"));
    }

    #[test]
    fn reload_config_resets_to_built_in_on_failure() {
        let mut state = empty_state();
        state.config_path = Some(PathBuf::from("/nonexistent/diffguard-missing.toml"));
        state.git_support = GitSupport::Available;
        let err = reload_config(&mut state).expect_err("reload should fail");
        assert!(err.to_string().contains("failed to reload config"));
        // After failure, git_support is reset and config falls back to built-in.
        assert_eq!(state.git_support, GitSupport::Unknown);
        assert!(!state.config.rule.is_empty());
    }

    // ---------------------------------------------------------------------
    // handle_request / handle_notification with Connection::memory()
    // ---------------------------------------------------------------------

    #[test]
    fn handle_request_returns_method_not_found_for_unsupported_method() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let request = Request {
            id: RequestId::from(1),
            method: "totally/unsupported".to_string(),
            params: json!({}),
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("error response"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, METHOD_NOT_FOUND);
        assert!(error.message.contains("totally/unsupported"));
    }

    #[test]
    fn handle_code_action_request_rejects_invalid_params() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let request = Request {
            id: RequestId::from(7),
            method: CodeActionRequest::METHOD.to_string(),
            params: json!({ "totally": "wrong" }),
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("error response"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("invalid CodeActionParams"));
    }

    #[test]
    fn handle_execute_command_request_rejects_invalid_params() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let request = Request {
            id: RequestId::from(2),
            method: ExecuteCommand::METHOD.to_string(),
            params: json!({ "nope": true }),
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("error response"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("invalid ExecuteCommandParams"));
    }

    #[test]
    fn handle_execute_command_rejects_explain_rule_without_arg() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let params = ExecuteCommandParams {
            command: CMD_EXPLAIN_RULE.to_string(),
            arguments: vec![],
            work_done_progress_params: Default::default(),
        };
        let request = Request {
            id: RequestId::from(3),
            method: ExecuteCommand::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("error response"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("missing rule ID"));
    }

    #[test]
    fn handle_execute_command_rejects_show_rule_url_without_url() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let params = ExecuteCommandParams {
            command: CMD_SHOW_RULE_URL.to_string(),
            arguments: vec![],
            work_done_progress_params: Default::default(),
        };
        let request = Request {
            id: RequestId::from(4),
            method: ExecuteCommand::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("error response"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("missing URL"));
    }

    #[test]
    fn handle_execute_command_rejects_unknown_command() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let params = ExecuteCommandParams {
            command: "diffguard.unknown".to_string(),
            arguments: vec![],
            work_done_progress_params: Default::default(),
        };
        let request = Request {
            id: RequestId::from(5),
            method: ExecuteCommand::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("error response"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("unsupported command"));
        assert!(error.message.contains("diffguard.unknown"));
    }

    #[test]
    fn handle_execute_command_explain_rule_responds_with_found_payload() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        state.config = config_with_rules(vec![sample_rule("rust.no_unwrap", None)]);
        let params = ExecuteCommandParams {
            command: CMD_EXPLAIN_RULE.to_string(),
            arguments: vec![json!("rust.no_unwrap")],
            work_done_progress_params: Default::default(),
        };
        let request = Request {
            id: RequestId::from(6),
            method: ExecuteCommand::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let result = response.result.as_ref().expect("result payload"); // diffguard: ignore rust.no_unwrap
        assert_eq!(result.get("found").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            result.get("ruleId").and_then(|v| v.as_str()),
            Some("rust.no_unwrap")
        );
        // A showMessage notification accompanies the response.
        assert!(find_notification(&messages, ShowMessage::METHOD).is_some());
    }

    #[test]
    fn handle_execute_command_show_rule_url_uses_default_label_when_id_missing() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let params = ExecuteCommandParams {
            command: CMD_SHOW_RULE_URL.to_string(),
            arguments: vec![json!("https://example.com/docs")],
            work_done_progress_params: Default::default(),
        };
        let request = Request {
            id: RequestId::from(8),
            method: ExecuteCommand::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        handle_request(&server, &mut state, request).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response sent"); // diffguard: ignore rust.no_unwrap
        let result = response.result.as_ref().expect("result payload"); // diffguard: ignore rust.no_unwrap
        assert_eq!(
            result.get("url").and_then(|v| v.as_str()),
            Some("https://example.com/docs")
        );
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("show message"); // diffguard: ignore rust.no_unwrap
        let body = notif.params.to_string();
        assert!(body.contains("diffguard documentation"));
    }

    #[test]
    fn handle_notification_invalid_did_open_emits_warning() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: DidOpenTextDocument::METHOD.to_string(),
            params: json!({ "garbage": true }),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("warning"); // diffguard: ignore rust.no_unwrap
        assert!(notif.params.to_string().contains("invalid didOpen"));
    }

    #[test]
    fn handle_notification_invalid_did_change_emits_warning() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: DidChangeTextDocument::METHOD.to_string(),
            params: json!({ "garbage": true }),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("warning"); // diffguard: ignore rust.no_unwrap
        assert!(notif.params.to_string().contains("invalid didChange"));
    }

    #[test]
    fn handle_notification_invalid_did_save_emits_warning() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: DidSaveTextDocument::METHOD.to_string(),
            params: json!({ "garbage": true }),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("warning"); // diffguard: ignore rust.no_unwrap
        assert!(notif.params.to_string().contains("invalid didSave"));
    }

    #[test]
    fn handle_notification_invalid_did_close_emits_warning() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: DidCloseTextDocument::METHOD.to_string(),
            params: json!({ "garbage": true }),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("warning"); // diffguard: ignore rust.no_unwrap
        assert!(notif.params.to_string().contains("invalid didClose"));
    }

    #[test]
    fn handle_notification_invalid_did_change_configuration_emits_warning() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: DidChangeConfiguration::METHOD.to_string(),
            params: json!("not-an-object"),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("warning"); // diffguard: ignore rust.no_unwrap
        assert!(
            notif
                .params
                .to_string()
                .contains("invalid didChangeConfiguration")
        );
    }

    #[test]
    fn handle_notification_exit_signals_break_loop() {
        let (_client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: Exit::METHOD.to_string(),
            params: json!(null),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(exit);
    }

    #[test]
    fn handle_notification_unknown_method_is_silent_no_op() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let notification = Notification {
            method: "made/up/method".to_string(),
            params: json!({}),
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        assert!(messages.is_empty());
    }

    #[test]
    fn handle_notification_did_close_clears_diagnostics() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let uri = parse_uri("file:///tmp/test.rs");
        state.documents.insert(
            uri.clone(),
            DocumentState::new(PathBuf::from("/tmp/test.rs"), 1, "fn x() {}\n".to_string()),
        );
        let params = DidCloseTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
        };
        let notification = Notification {
            method: DidCloseTextDocument::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        assert!(!state.documents.contains_key(&uri));
        let messages = drain_messages(&client);
        // publishDiagnostics with empty list is emitted.
        let publish =
            find_notification(&messages, PublishDiagnostics::METHOD).expect("publish notif"); // diffguard: ignore rust.no_unwrap
        let value = serde_json::to_value(&publish.params).expect("to value"); // diffguard: ignore rust.no_unwrap
        let diags = value
            .get("diagnostics")
            .and_then(|d| d.as_array())
            .expect("diagnostics array"); // diffguard: ignore rust.no_unwrap
        assert!(diags.is_empty());
    }

    #[test]
    fn handle_notification_did_open_with_non_file_uri_skips_indexing() {
        let (_client, server) = Connection::memory();
        let mut state = empty_state();
        let uri = parse_uri("https://example.com/foo.rs");
        let params = DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri,
                language_id: "rust".to_string(),
                version: 1,
                text: "fn x() {}\n".to_string(),
            },
        };
        let notification = Notification {
            method: DidOpenTextDocument::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        // Document was not inserted because the URI couldn't be parsed as a file path.
        assert!(state.documents.is_empty());
    }

    #[test]
    fn handle_notification_did_change_for_unknown_document_is_ignored() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let uri = parse_uri("file:///tmp/never-opened.rs");
        let params = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 2 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "new".to_string(),
            }],
        };
        let notification = Notification {
            method: DidChangeTextDocument::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        // No document was inserted, no diagnostics are published.
        let messages = drain_messages(&client);
        assert!(find_notification(&messages, PublishDiagnostics::METHOD).is_none());
    }

    #[test]
    fn handle_notification_did_save_marks_document_saved() {
        let (_client, server) = Connection::memory();
        let mut state = empty_state();
        let uri = parse_uri("file:///tmp/save.rs");
        state.documents.insert(
            uri.clone(),
            DocumentState::new(PathBuf::from("/tmp/save.rs"), 1, "first\n".to_string()),
        );
        // Mutate the document so changed_lines is non-empty.
        if let Some(doc) = state.documents.get_mut(&uri) {
            let change = TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "second\n".to_string(),
            };
            doc.apply_changes(&[change]).expect("apply ok"); // diffguard: ignore rust.no_unwrap
            assert!(!doc.changed_lines.is_empty());
        }

        let params = DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            text: Some("third\n".to_string()),
        };
        let notification = Notification {
            method: DidSaveTextDocument::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let doc = state.documents.get(&uri).expect("doc still present"); // diffguard: ignore rust.no_unwrap
        assert_eq!(doc.text, "third\n");
        assert_eq!(doc.baseline_text, "third\n");
        assert!(doc.changed_lines.is_empty());
    }

    #[test]
    fn handle_notification_did_change_configuration_triggers_reload_message() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let params = DidChangeConfigurationParams {
            settings: json!({}),
        };
        let notification = Notification {
            method: DidChangeConfiguration::METHOD.to_string(),
            params: serde_json::to_value(params).expect("serialize"), // diffguard: ignore rust.no_unwrap
        };
        let exit = handle_notification(&server, &mut state, notification).expect("handle ok"); // diffguard: ignore rust.no_unwrap
        assert!(!exit);
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("show message"); // diffguard: ignore rust.no_unwrap
        // With no config_path set, reload succeeds and reports the rule count.
        assert!(notif.params.to_string().contains("config reloaded"));
    }

    #[test]
    fn refresh_document_diagnostics_short_circuits_when_relative_path_empty() {
        // With workspace_root set and the document's path equal to workspace_root,
        // the stripped relative path is empty, which triggers the early-return
        // branch that publishes an empty diagnostics list.
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let workspace = PathBuf::from("/tmp/empty-relative");
        state.workspace_root = Some(workspace.clone());
        let uri = parse_uri("file:///tmp/empty-relative");
        state
            .documents
            .insert(uri.clone(), DocumentState::new(workspace, 1, String::new()));
        refresh_document_diagnostics(&server, &mut state, &uri).expect("refresh ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let publish =
            find_notification(&messages, PublishDiagnostics::METHOD).expect("publish notif"); // diffguard: ignore rust.no_unwrap
        let value = serde_json::to_value(&publish.params).expect("to value"); // diffguard: ignore rust.no_unwrap
        let diags = value
            .get("diagnostics")
            .and_then(|d| d.as_array())
            .expect("diagnostics array"); // diffguard: ignore rust.no_unwrap
        assert!(diags.is_empty());
    }

    #[test]
    fn refresh_document_diagnostics_no_op_for_missing_document() {
        let (client, server) = Connection::memory();
        let mut state = empty_state();
        let uri = parse_uri("file:///tmp/missing.rs");
        refresh_document_diagnostics(&server, &mut state, &uri).expect("refresh ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        assert!(messages.is_empty());
    }

    // ---------------------------------------------------------------------
    // send_*_response / show_message helpers
    // ---------------------------------------------------------------------

    #[test]
    fn send_error_response_constructs_proper_response_object() {
        let (client, server) = Connection::memory();
        send_error_response(
            &server,
            RequestId::from(99),
            INVALID_PARAMS,
            "bad".to_string(),
        )
        .expect("send ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response"); // diffguard: ignore rust.no_unwrap
        let error = response.error.as_ref().expect("has error"); // diffguard: ignore rust.no_unwrap
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(error.message, "bad");
        assert!(response.result.is_none());
    }

    #[test]
    fn send_ok_response_constructs_proper_response_object() {
        let (client, server) = Connection::memory();
        send_ok_response(&server, RequestId::from(101), json!({ "ok": true })).expect("send ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let response = find_response(&messages).expect("response"); // diffguard: ignore rust.no_unwrap
        assert!(response.error.is_none());
        let result = response.result.as_ref().expect("has result"); // diffguard: ignore rust.no_unwrap
        assert_eq!(result.get("ok").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn show_message_emits_show_message_notification() {
        let (client, server) = Connection::memory();
        show_message(&server, MessageType::INFO, "hello").expect("send ok"); // diffguard: ignore rust.no_unwrap
        let messages = drain_messages(&client);
        let notif = find_notification(&messages, ShowMessage::METHOD).expect("show message"); // diffguard: ignore rust.no_unwrap
        assert!(notif.params.to_string().contains("hello"));
    }
}
