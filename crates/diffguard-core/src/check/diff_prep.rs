use std::collections::BTreeSet;
use std::path::Path;

use diffguard_diff::{DiffLine, parse_unified_diff};

use super::CheckPlan;
use super::path_filter::compile_filter_globs;

/// Parse the unified diff and apply secondary filters: path globs, allowed-lines, dedup.
///
/// Returns the filtered, deduplicated list of diff lines ready for evaluation.
pub(super) fn prepare_diff_lines(
    plan: &CheckPlan,
    diff_text: &str,
) -> Result<Vec<DiffLine>, anyhow::Error> {
    let (mut diff_lines, _stats) = parse_unified_diff(diff_text, plan.scope)?;

    if !plan.path_filters.is_empty() {
        let filters = compile_filter_globs(&plan.path_filters)?;
        diff_lines.retain(|l| filters.is_match(Path::new(&l.path)));
    }

    if let Some(allowed_lines) = &plan.allowed_lines {
        diff_lines.retain(|l| allowed_lines.contains(&(l.path.clone(), l.line)));
    }

    // Multiple diff sources (or unusual diffs) can contain duplicates for the same
    // path/line/content tuple. Keep first occurrence to preserve deterministic ordering.
    let mut seen = BTreeSet::<(String, u32, String)>::new();
    diff_lines.retain(|l| seen.insert((l.path.clone(), l.line, l.content.clone())));

    Ok(diff_lines)
}
