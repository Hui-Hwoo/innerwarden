//! Spec 056 Phase 3b: the playbook command channel.
//!
//! Three virtual skills (`route_alert`, `capture_pcap`, `set_tag`) act on
//! agent subsystems that live behind `&mut AgentState` (notification
//! clients + cooldown store, `PcapCapture`, the attacker-profile map).
//! The executor is deliberately decoupled from `AgentState` so it stays
//! unit-testable and so `StepExecutor::dispatch` can stay `&self` (parallel
//! steps run concurrently via `join_all`).
//!
//! Rather than reach into those subsystems mid-run, these skills record a
//! typed [`PlaybookCommand`] intent. The executor collects the commands
//! and hands them back on the [`super::executor::PlaybookOutcome`]; the
//! incident loop drains them against `&mut AgentState` AFTER the playbook
//! finishes. Effects are fire-and-forget (no skill_gate floor, no output
//! feeding a later step), so post-run execution loses nothing the three
//! skills need.
//!
//! This typed vocabulary is also the substrate the future Active Defense
//! premium module emits into: the LLM, the YAML playbook path, and SOC
//! manual actions all converge on one command enum, one drain, and one
//! audit surface, so the same safety floor + audit applies regardless of
//! who decided the action.

use serde::Serialize;

/// A deferred side effect queued by a Phase-3b virtual skill.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub(crate) enum PlaybookCommand {
    /// `route_alert`: re-dispatch incident notifications. `destination`
    /// and `severity_override` are advisory hints until per-rule routing
    /// (spec 059) lands; today the drain routes through the operator's
    /// existing notification channels.
    RouteAlert {
        step_id: String,
        destination: Option<String>,
        severity_override: Option<String>,
    },
    /// `capture_pcap`: start a selective packet capture for an IP.
    CapturePcap { step_id: String, target_ip: String },
    /// `set_tag`: mark an IP in its attacker profile so downstream rules
    /// can pivot on it.
    SetTag {
        step_id: String,
        target_ip: String,
        tag: String,
    },
}

impl PlaybookCommand {
    /// The owning step's id, for audit / logging.
    pub(crate) fn step_id(&self) -> &str {
        match self {
            PlaybookCommand::RouteAlert { step_id, .. }
            | PlaybookCommand::CapturePcap { step_id, .. }
            | PlaybookCommand::SetTag { step_id, .. } => step_id,
        }
    }

    /// Short label for logs / metrics.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            PlaybookCommand::RouteAlert { .. } => "route_alert",
            PlaybookCommand::CapturePcap { .. } => "capture_pcap",
            PlaybookCommand::SetTag { .. } => "set_tag",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_id_and_kind_cover_all_variants() {
        let cmds = [
            PlaybookCommand::RouteAlert {
                step_id: "a".into(),
                destination: Some("pagerduty".into()),
                severity_override: None,
            },
            PlaybookCommand::CapturePcap {
                step_id: "b".into(),
                target_ip: "1.2.3.4".into(),
            },
            PlaybookCommand::SetTag {
                step_id: "c".into(),
                target_ip: "1.2.3.4".into(),
                tag: "c2".into(),
            },
        ];
        assert_eq!(cmds[0].step_id(), "a");
        assert_eq!(cmds[0].kind(), "route_alert");
        assert_eq!(cmds[1].step_id(), "b");
        assert_eq!(cmds[1].kind(), "capture_pcap");
        assert_eq!(cmds[2].step_id(), "c");
        assert_eq!(cmds[2].kind(), "set_tag");
    }

    #[test]
    fn serializes_with_command_tag() {
        let c = PlaybookCommand::SetTag {
            step_id: "c".into(),
            target_ip: "1.2.3.4".into(),
            tag: "c2".into(),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["command"], "set_tag");
        assert_eq!(v["target_ip"], "1.2.3.4");
        assert_eq!(v["tag"], "c2");
    }
}
