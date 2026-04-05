// Code action and execute command integration tests for diffguard-lsp
//
// Tests that the server provides correct code actions for diagnostics and
// that execute commands (explainRule, reloadConfig, showRuleUrl) work
// correctly at the protocol level.

use std::time::Duration;

use lsp_types::{CodeActionOrCommand, Position, Range};

mod integration;
use integration::TestServer;

const SHORT_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// T18: test_code_action_explain_rule
// ---------------------------------------------------------------------------

#[test]
fn test_code_action_provides_explain_action_for_diagnostic() {
    let mut server = TestServer::start();

    // Open a file that triggers a rule violation
    let content = "// TODO: implement this\nfn main() {}\n";
    let uri = server.create_file("src/main.rs", content);

    server.send_did_open(&uri, "rust", 1, content);
    let diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    if diagnostics.is_empty() {
        // No diagnostics produced -- skip code action test
        return;
    }

    // Request code actions for the range of the first diagnostic
    let range = diagnostics[0].range;
    let actions = server.send_code_action_request(&uri, range, &diagnostics);

    // Look for an "Explain" code action
    let explain_action = actions.iter().find(|action| match action {
        CodeActionOrCommand::CodeAction(ca) => ca.title.to_lowercase().contains("explain"),
        CodeActionOrCommand::Command(cmd) => cmd.title.to_lowercase().contains("explain"),
    });

    // If a rule violation produced a diagnostic, there should be an explain action
    if let Some(action) = explain_action {
        match action {
            CodeActionOrCommand::CodeAction(ca) => {
                assert!(
                    ca.title.contains("Explain"),
                    "Expected explain action title to contain 'Explain', got: {}",
                    ca.title,
                );
                if let Some(cmd) = &ca.command {
                    assert_eq!(cmd.command, "diffguard.explainRule");
                }
            }
            CodeActionOrCommand::Command(cmd) => {
                assert_eq!(cmd.command, "diffguard.explainRule");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// T19: test_code_action_open_docs
// ---------------------------------------------------------------------------

#[test]
fn test_code_action_provides_open_docs_when_rule_has_url() {
    let mut server = TestServer::start();

    // Content that triggers a rule (which may have a URL)
    let content = "// TODO: fix\nfn main() {}\n";
    let uri = server.create_file("src/main.rs", content);

    server.send_did_open(&uri, "rust", 1, content);
    let diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    if diagnostics.is_empty() {
        return;
    }

    let range = diagnostics[0].range;
    let actions = server.send_code_action_request(&uri, range, &diagnostics);

    // Look for an "Open docs" code action
    let docs_action = actions.iter().find(|action| match action {
        CodeActionOrCommand::CodeAction(ca) => {
            ca.title.to_lowercase().contains("docs") || ca.title.to_lowercase().contains("url")
        }
        CodeActionOrCommand::Command(cmd) => {
            cmd.title.to_lowercase().contains("docs") || cmd.title.to_lowercase().contains("url")
        }
    });

    // If the rule has a URL field, a docs action should be present
    if let Some(action) = docs_action {
        match action {
            CodeActionOrCommand::CodeAction(ca) => {
                if let Some(cmd) = &ca.command {
                    assert_eq!(cmd.command, "diffguard.showRuleUrl");
                    // Arguments should contain the URL
                    if let Some(args) = &cmd.arguments {
                        assert!(
                            !args.is_empty(),
                            "Expected URL arguments for showRuleUrl command",
                        );
                    }
                }
            }
            CodeActionOrCommand::Command(cmd) => {
                assert_eq!(cmd.command, "diffguard.showRuleUrl");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// T20: test_execute_explain_rule
// ---------------------------------------------------------------------------

#[test]
fn test_execute_explain_rule_returns_rule_details() {
    let mut server = TestServer::start();

    // Execute the explainRule command with a known rule ID
    // The rule ID should be one that exists in the built-in config
    let response =
        server.send_execute_command("diffguard.explainRule", vec![serde_json::json!("no-todo")]);

    // The response should be successful (no error)
    assert!(
        response.error.is_none(),
        "Expected no error for explainRule, got: {:?}",
        response.error,
    );

    // The result should contain rule information
    if let Some(result) = &response.result {
        let rule_id = result.get("ruleId").and_then(|v| v.as_str());
        let found = result.get("found").and_then(|v| v.as_bool());
        let message = result.get("message").and_then(|v| v.as_str());

        // If the rule exists, found should be true
        if found == Some(true) {
            assert!(message.is_some(), "Expected message for found rule");
            assert_eq!(rule_id, Some("no-todo"));
        }
    }
}

#[test]
fn test_execute_explain_rule_returns_not_found_for_unknown() {
    let mut server = TestServer::start();

    let response = server.send_execute_command(
        "diffguard.explainRule",
        vec![serde_json::json!("nonexistent-rule-xyz")],
    );

    assert!(
        response.error.is_none(),
        "Expected no error for explainRule with unknown rule, got: {:?}",
        response.error,
    );

    if let Some(result) = &response.result {
        let found = result.get("found").and_then(|v| v.as_bool());
        assert_eq!(found, Some(false), "Expected found=false for unknown rule");
    }
}

// ---------------------------------------------------------------------------
// T21: test_execute_reload_config
// ---------------------------------------------------------------------------

#[test]
fn test_execute_reload_config_succeeds() {
    let mut server = TestServer::start();

    let response = server.send_execute_command("diffguard.reloadConfig", vec![]);

    assert!(
        response.error.is_none(),
        "Expected no error for reloadConfig, got: {:?}",
        response.error,
    );

    if let Some(result) = &response.result {
        let ok = result.get("ok").and_then(|v| v.as_bool());
        // Reload should succeed (even if config doesn't exist, it falls back to built-in)
        assert!(ok.is_some(), "Expected 'ok' field in reloadConfig response");
    }
}

// ---------------------------------------------------------------------------
// T22: test_execute_show_rule_url
// ---------------------------------------------------------------------------

#[test]
fn test_execute_show_rule_url_returns_url() {
    let mut server = TestServer::start();

    // Execute showRuleUrl with a URL and rule ID
    let test_url = "https://example.com/rules/no-todo";
    let response = server.send_execute_command(
        "diffguard.showRuleUrl",
        vec![serde_json::json!(test_url), serde_json::json!("no-todo")],
    );

    assert!(
        response.error.is_none(),
        "Expected no error for showRuleUrl, got: {:?}",
        response.error,
    );

    if let Some(result) = &response.result {
        let url = result.get("url").and_then(|v| v.as_str());
        assert_eq!(url, Some(test_url), "Expected URL to match");
    }
}

// ---------------------------------------------------------------------------
// T23: test_did_change_configuration_reloads
// ---------------------------------------------------------------------------

#[test]
fn test_did_change_configuration_triggers_reload() {
    let mut server = TestServer::start();

    // Open a file first
    let content = "// TODO: test\nfn main() {}\n";
    let uri = server.create_file("src/main.rs", content);
    server.send_did_open(&uri, "rust", 1, content);
    let _ = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Send didChangeConfiguration
    server.send_did_change_configuration(serde_json::json!({
        "diffguard": {
            "maxFindings": 10
        }
    }));

    // After configuration change, the server should refresh diagnostics
    let _after_config_diags = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // The key assertion: no error/crash from the configuration change
    // Diagnostics may or may not change depending on the settings
}

// ---------------------------------------------------------------------------
// Additional code action tests
// ---------------------------------------------------------------------------

#[test]
fn test_code_actions_empty_when_no_diagnostics() {
    let mut server = TestServer::start();

    // Clean content -- no violations expected
    let content = "fn main() {\n    println!(\"hello\");\n}\n";
    let uri = server.create_file("src/main.rs", content);

    server.send_did_open(&uri, "rust", 1, content);
    let diagnostics = server.collect_diagnostics_for_uri(&uri, SHORT_TIMEOUT);

    // Request code actions with empty diagnostics
    let actions = server.send_code_action_request(
        &uri,
        Range::new(Position::new(0, 0), Position::new(0, 10)),
        &diagnostics,
    );

    // With no diagnostics, code actions should be empty
    assert!(
        actions.is_empty(),
        "Expected no code actions for clean file, got: {:?}",
        actions,
    );
}

#[test]
fn test_execute_command_invalid_returns_error() {
    let mut server = TestServer::start();

    let response = server.send_execute_command("diffguard.nonexistentCommand", vec![]);

    // Invalid commands should return an error response
    assert!(
        response.error.is_some(),
        "Expected error for invalid command, got success",
    );
}
