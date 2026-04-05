use anyhow::Result;
use lsp_server::Connection;

use diffguard_lsp::server;

fn main() -> Result<()> {
    let (connection, io_threads) = Connection::stdio();
    server::run_server(connection)?;
    io_threads.join()?;
    Ok(())
}
