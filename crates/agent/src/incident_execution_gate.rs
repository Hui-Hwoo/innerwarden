use std::path::Path;

use tracing::info;

use crate::agent_context::incident_detector;
use crate::{ai, config, execute_decision, is_trusted, AgentState};

pub(crate) enum GateResult {
    Execute { trusted_override: bool },
    Skip(String),
}

pub(crate) fn evaluate_execution_gate(
    auto_execute: bool,
    confidence: f32,
    confidence_threshold: f32,
    responder_enabled: bool,
    trusted: bool,
) -> GateResult {
    if (auto_execute || trusted) && confidence >= confidence_threshold && responder_enabled {
        GateResult::Execute {
            trusted_override: trusted && !auto_execute,
        }
    } else if !responder_enabled {
        GateResult::Skip("skipped: responder disabled".to_string())
    } else if !auto_execute && !trusted {
        GateResult::Skip("skipped: AI did not recommend auto-execution (no trust rule)".to_string())
    } else {
        GateResult::Skip(format!(
            "skipped: confidence {:.2} below threshold {:.2}",
            confidence, confidence_threshold
        ))
    }
}

/// Execute a decision when it passes trust/confidence/responder gates,
/// otherwise return a deterministic skip reason.
pub(crate) async fn execute_or_skip_decision(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    let detector = incident_detector(&incident.incident_id);
    let action_name = decision.action.name();
    let trusted = is_trusted(&state.trust_rules, detector, action_name);

    match evaluate_execution_gate(
        decision.auto_execute,
        decision.confidence,
        cfg.ai.confidence_threshold,
        cfg.responder.enabled,
        trusted,
    ) {
        GateResult::Execute { trusted_override } => {
            if trusted_override {
                info!(
                    incident_id = %incident.incident_id,
                    detector,
                    action = action_name,
                    "trust rule override: executing without AI auto_execute flag"
                );
            }
            state
                .telemetry
                .observe_execution_path(cfg.responder.dry_run);
            execute_decision(decision, incident, data_dir, cfg, state).await
        }
        GateResult::Skip(reason) => (reason, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_allows_auto_execute_when_confidence_high() {
        let result = evaluate_execution_gate(true, 0.9, 0.8, true, false);
        assert!(matches!(
            result,
            GateResult::Execute {
                trusted_override: false
            }
        ));
    }

    #[test]
    fn gate_allows_trusted_override_even_if_no_auto_execute() {
        let result = evaluate_execution_gate(false, 0.9, 0.8, true, true);
        assert!(matches!(
            result,
            GateResult::Execute {
                trusted_override: true
            }
        ));
    }

    #[test]
    fn gate_blocks_if_responder_disabled() {
        let result = evaluate_execution_gate(true, 0.9, 0.8, false, false);
        if let GateResult::Skip(msg) = result {
            assert!(msg.contains("responder disabled"));
        } else {
            panic!("expected skip");
        }
    }

    #[test]
    fn gate_blocks_if_not_auto_execute_and_not_trusted() {
        let result = evaluate_execution_gate(false, 0.9, 0.8, true, false);
        if let GateResult::Skip(msg) = result {
            assert!(msg.contains("did not recommend auto-execution"));
        } else {
            panic!("expected skip");
        }
    }

    #[test]
    fn gate_blocks_if_confidence_below_threshold() {
        let result = evaluate_execution_gate(true, 0.7, 0.8, true, false);
        if let GateResult::Skip(msg) = result {
            assert!(msg.contains("below threshold"));
        } else {
            panic!("expected skip");
        }
    }
}
