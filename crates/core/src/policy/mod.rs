use crate::incident::Incident;
use crate::signal::Signal;

pub mod enforcement;
pub use enforcement::EnforcementPosture;

#[derive(Debug, Default)]
pub struct PolicyDecision {
    pub ignore: bool,
    pub create_incident: bool,
    pub incident: Option<Incident>,
}

/// Policy takes weak signals and decides whether to emit incidents.
///
/// Responsibilities (intended):
/// - ignore/allowlist
/// - elevate severity
/// - dedupe
/// - group signals into incidents
pub fn apply_policy(_signals: &[Signal]) -> Vec<PolicyDecision> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_policy_returns_empty_for_empty_signals() {
        let result = apply_policy(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn policy_decision_defaults_to_no_action() {
        let pd = PolicyDecision::default();
        assert!(!pd.ignore);
        assert!(!pd.create_incident);
        assert!(pd.incident.is_none());
    }
}
