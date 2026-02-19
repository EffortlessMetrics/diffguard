use anyhow::Result;
use lsp_server::Connection;

mod config;
mod server;
mod text;

fn main() -> Result<()> {
    let (connection, io_threads) = Connection::stdio();
    server::run_server(connection)?;
    io_threads.join()?;
    Ok(())
}
