#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub(super) enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub(super) fn icon(&self) -> &'static str {
        match self {
            Severity::Info => "[36mℹ[0m ",     // ℹ cyan
            Severity::Low => "[34m●[0m ",      // ● blue
            Severity::Medium => "[33m⚠[0m ",   // ⚠ yellow
            Severity::High => "[91m⚠[0m ",     // ⚠ red
            Severity::Critical => "[31m✘[0m ", // ✘ red
        }
    }

    pub(super) fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub(super) fn score_penalty(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 5,
            Severity::High => 10,
            Severity::Critical => 20,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct Finding {
    pub(super) category: &'static str,
    pub(super) severity: Severity,
    pub(super) title: String,
    pub(super) fix: String,
}

pub(super) struct CheckResult {
    pub(super) category: &'static str,
    pub(super) passed: Vec<String>,
    pub(super) findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_labels() {
        assert_eq!(Severity::Info.label(), "info");
        assert_eq!(Severity::Low.label(), "low");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Critical.label(), "critical");
    }

    #[test]
    fn test_severity_score_penalty() {
        assert_eq!(Severity::Info.score_penalty(), 0);
        assert_eq!(Severity::Low.score_penalty(), 2);
        assert_eq!(Severity::Medium.score_penalty(), 5);
        assert_eq!(Severity::High.score_penalty(), 10);
        assert_eq!(Severity::Critical.score_penalty(), 20);
    }

    #[test]
    fn test_severity_icons_exist() {
        assert!(!Severity::Info.icon().is_empty());
        assert!(!Severity::High.icon().is_empty());
    }
}
