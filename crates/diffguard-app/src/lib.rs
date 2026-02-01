//! Application layer: orchestrates diff parsing + rule evaluation + reporting.

mod check;
mod csv;
mod junit;
mod render;
mod sarif;

pub use check::{run_check, CheckPlan, CheckRun, PathFilterError};
pub use csv::{render_csv_for_receipt, render_tsv_for_receipt};
pub use junit::render_junit_for_receipt;
pub use render::render_markdown_for_receipt;
pub use sarif::{render_sarif_for_receipt, render_sarif_json, SarifReport};
