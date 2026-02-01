//! Application layer: orchestrates diff parsing + rule evaluation + reporting.

mod check;
mod render;

pub use check::{run_check, CheckPlan, CheckRun, PathFilterError};
pub use render::render_markdown_for_receipt;
