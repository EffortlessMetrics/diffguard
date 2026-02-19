use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

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
            self.text = full_change.text.clone();
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

pub fn run_server(connection: Connection) -> Result<()> {
    let init = initialize_payload()?;
    let initialize_params = connection.initialize(init)?;
    let initialize_params: InitializeParams =
        serde_json::from_value(initialize_params).context("parse initialize params")?;

    let (mut state, startup_warning) = ServerState::from_initialize(&initialize_params);
    if let Some(message) = startup_warning {
        show_message(&connection, MessageType::WARNING, &message)?;
    }

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

fn run_git_diff(workspace_root: &Path, relative_path: &str, staged: bool) -> Result<String> {
    let mut command = Command::new("git");
    command.current_dir(workspace_root).arg("diff");
    if staged {
        command.arg("--cached");
    }
    command.arg("--unified=0").arg("--").arg(relative_path);

    let output = command.output().context("run git diff")?;
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
        let value = initialize_payload().expect("payload");
        let info = value
            .get("serverInfo")
            .and_then(|v| v.as_object())
            .expect("server info");
        assert_eq!(
            info.get("name").and_then(|v| v.as_str()),
            Some("diffguard-lsp")
        );
    }

    #[test]
    fn build_code_actions_contains_explain_action() {
        let config = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![diffguard_types::RuleConfig {
                id: "rust.no_unwrap".to_string(),
                severity: Severity::Warn,
                message: "Avoid unwrap".to_string(),
                languages: vec![],
                patterns: vec!["unwrap".to_string()],
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
                url: Some("https://example.com/rule".to_string()),
                tags: vec![],
                test_cases: vec![],
            }],
        };

        let params = CodeActionParams {
            text_document: lsp_types::TextDocumentIdentifier {
                uri: "file:///tmp/test.rs".parse().expect("uri"),
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
}
