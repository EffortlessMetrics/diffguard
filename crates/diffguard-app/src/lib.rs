//! Application layer: orchestrates diff parsing + rule evaluation + reporting.

mod check;
mod render;
mod sarif;

pub use check::{run_check, CheckPlan, CheckRun, PathFilterError};
pub use render::render_markdown_for_receipt;
pub use sarif::{render_sarif_for_receipt, render_sarif_json, SarifReport};
