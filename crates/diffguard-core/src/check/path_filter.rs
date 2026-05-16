use globset::{Glob, GlobSet, GlobSetBuilder};

#[derive(Debug, thiserror::Error)]
pub enum PathFilterError {
    #[error("invalid path filter glob '{glob}': {source}")]
    InvalidGlob {
        glob: String,
        source: globset::Error,
    },
}

pub(super) fn compile_filter_globs(globs: &[String]) -> Result<GlobSet, PathFilterError> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        let glob = Glob::new(g).map_err(|e| PathFilterError::InvalidGlob {
            glob: g.clone(),
            source: e,
        })?;
        b.add(glob);
    }
    Ok(b.build().expect("globset build should succeed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_filter_globs_rejects_invalid() {
        let err = compile_filter_globs(&["[".to_string()]).unwrap_err();
        match err {
            PathFilterError::InvalidGlob { glob, .. } => assert_eq!(glob, "["),
        }
    }
}
