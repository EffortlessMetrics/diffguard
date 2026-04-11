//! Core engine: orchestrates diff parsing + rule evaluation + reporting.

mod check;
mod checkstyle;
mod csv;
mod fingerprint;
mod gitlab_quality;
mod junit;
mod render;
mod sarif;
mod sensor;
mod sensor_api;
pub mod xml_utils;

pub use check::{CheckPlan, CheckRun, PathFilterError, run_check};
pub use checkstyle::render_checkstyle_for_receipt;
pub use csv::{render_csv_for_receipt, render_tsv_for_receipt};
pub use fingerprint::{compute_fingerprint, compute_fingerprint_raw};
pub use gitlab_quality::render_gitlab_quality_json;
pub use junit::render_junit_for_receipt;
pub use render::render_markdown_for_receipt;
pub use sarif::{SarifReport, render_sarif_for_receipt, render_sarif_json};
pub use sensor::{RuleMetadata, SensorReportContext, render_sensor_json, render_sensor_report};
pub use sensor_api::{Settings, Substrate, run_sensor};
