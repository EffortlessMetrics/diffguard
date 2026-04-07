# Friction Log - Diffguard LSP Integration Tests

## Session: 2026-04-05

### Problem 1: Tests hanging indefinitely
**Symptom**: Integration tests compiled but hung at runtime, never completing.
**Root cause**: `TestServer` spawned server thread but never completed LSP initialize handshake. Server's `run_server` blocks on `connection.initialize()` which waits for initialize request + `initialized` notification.
**Fix**: Updated `TestServer` to manually send initialize request, receive response, and send `initialized` notification.
**Lesson**: LSP protocol requires full handshake before server enters message loop. Test harnesses must complete the entire sequence.

### Problem 2: Initialize response had double-nested capabilities
**Symptom**: Tests failing because `text_document_sync` was `None` and `server_info` was missing.
**Root cause**: `lsp-server` crate's `initialize()` method takes capabilities and wraps them in `{ "capabilities": ... }`. Server was passing full `InitializeResult` which already had a `capabilities` field, causing double nesting.
**Fix**: Changed server to use `initialize_start()` + `initialize_finish()` which accepts full `InitializeResult` without wrapping.
**Lesson**: `Connection::initialize()` is for simple cases. Use `initialize_start()`/`initialize_finish()` when you need custom `InitializeResult` fields like `server_info`.

### Problem 3: Test failures from notifications during initialization
**Symptom**: `test_invalid_config_falls_back_to_built_in_rules` failed with "expected response, got Notification".
**Root cause**: Server sends `window/showMessage` notification during initialization when config is invalid. Test harness expected first message to be initialize response.
**Fix**: Updated test harness to drain notifications in a loop before processing initialize response.
**Lesson**: LSP servers may send notifications before/during initialization. Clients must handle interleaved messages.

### Problem 4: `test_no_workspace_root_handled_gracefully` hanging
**Symptom**: Test hung indefinitely.
**Root cause**: Test used `client_conn.initialize()` (simplified wrapper) but server used `initialize_start()`/`initialize_finish()` (lower-level). Both sides calling `initialize_start()` = deadlock.
**Fix**: Updated test to use matching lower-level handshake pattern.
**Lesson**: Memory connections require both sides to use compatible handshake patterns. Mixing `initialize()` with `initialize_start()`/`initialize_finish()` causes deadlock.

### Key Takeaways
1. **Always complete LSP handshake in tests**: initialize request → initialize response → initialized notification
2. **Drain notifications**: Servers may send `window/showMessage` during initialization
3. **Match handshake patterns**: Don't mix `Connection::initialize()` with `initialize_start()`/`initialize_finish()`
4. **Use request ID matching**: When draining messages, match response by request ID to avoid confusion
