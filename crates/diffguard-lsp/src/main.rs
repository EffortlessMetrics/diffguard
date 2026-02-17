use anyhow::Result;
use lsp_server::{Connection, Message, Request};
use lsp_types::{
    InitializeResult, ServerCapabilities, ServerInfo, TextDocumentSyncCapability,
    TextDocumentSyncKind,
};

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
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

fn handle_request(connection: &Connection, request: Request) -> Result<bool> {
    if connection.handle_shutdown(&request)? {
        return Ok(true);
    }
    Ok(false)
}

fn run_server(connection: Connection) -> Result<()> {
    let init = initialize_payload()?;
    let _initialize_params = connection.initialize(init)?;

    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if handle_request(&connection, request.clone())? {
                    break;
                }
            }
            Message::Notification(notification) => {
                // Keep a minimal loop for now; future revisions can add diagnostics.
                if notification.method == "exit" {
                    break;
                }
            }
            Message::Response(_) => {}
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let (connection, io_threads) = Connection::stdio();
    run_server(connection)?;
    io_threads.join()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_capabilities_include_text_sync() {
        let caps = server_capabilities();
        assert!(matches!(
            caps.text_document_sync,
            Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL))
        ));
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
}
