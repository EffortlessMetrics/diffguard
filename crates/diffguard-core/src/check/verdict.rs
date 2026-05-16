use diffguard_types::{FailOn, VerdictCounts, VerdictStatus};

pub(super) fn compute_verdict_status(counts: &VerdictCounts) -> VerdictStatus {
    if counts.error > 0 {
        VerdictStatus::Fail
    } else if counts.warn > 0 {
        VerdictStatus::Warn
    } else {
        VerdictStatus::Pass
    }
}

pub(super) fn compute_exit_code(fail_on: FailOn, counts: &VerdictCounts) -> i32 {
    if matches!(fail_on, FailOn::Never) {
        return 0;
    }

    if counts.error > 0 {
        return 2;
    }

    if matches!(fail_on, FailOn::Warn) && counts.warn > 0 {
        return 3;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_semantics() {
        let mut counts = VerdictCounts::default();
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 0);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 0);

        counts.warn = 1;
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 0);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 3);

        counts.error = 1;
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 2);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 2);
        assert_eq!(compute_exit_code(FailOn::Never, &counts), 0);
    }

    #[test]
    fn verdict_status_pass_when_clean() {
        let counts = VerdictCounts::default();
        assert_eq!(compute_verdict_status(&counts), VerdictStatus::Pass);
    }

    #[test]
    fn verdict_status_warn_when_warns() {
        let counts = VerdictCounts {
            warn: 1,
            ..Default::default()
        };
        assert_eq!(compute_verdict_status(&counts), VerdictStatus::Warn);
    }

    #[test]
    fn verdict_status_fail_when_errors_outrank_warns() {
        let counts = VerdictCounts {
            warn: 1,
            error: 1,
            ..Default::default()
        };
        assert_eq!(compute_verdict_status(&counts), VerdictStatus::Fail);
    }
}
