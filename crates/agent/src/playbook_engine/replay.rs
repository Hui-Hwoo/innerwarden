//! Offline playbook replay: run a batch of captured incidents through the
//! playbook engine in dry-run and report what the playbooks WOULD have
//! done — without firing skills or writing audit.
//!
//! This is the fast validation path: instead of waiting days for live
//! traffic, replay a host's real `incidents-<date>.jsonl` history (or a
//! captured sample) through the loaded playbooks and measure match rate,
//! per-step outcomes, and — critically — that no block would ever land on
//! a trusted / cloud-safelisted target (the skill_gate floor should make
//! that impossible; the replay proves it on real data).
//!
//! Reuses the exact `matches_incident` + `execute` the live loop uses, so
//! the replay can never drift from production behaviour. Driven by
//! `innerwarden-agent --playbook-replay <file>`.

use std::collections::BTreeMap;

use innerwarden_core::entities::EntityType as CoreEntityType;
use innerwarden_core::incident::Incident;

use super::executor::{
    self, PlaybookAudit, PlaybookStepRecord, RegistryStepExecutor, StepStatus, TriggerCtx,
};
use super::Playbook;
use crate::skills;

/// Discards audit records — a replay must never write `decisions.jsonl` or
/// `playbook_steps-*.jsonl`.
struct NoopAudit;
impl PlaybookAudit for NoopAudit {
    fn record(&self, _rec: PlaybookStepRecord<'_>) {}
}

/// Aggregate outcome of replaying a batch of incidents.
#[derive(Debug, Default, Clone)]
pub(crate) struct ReplayReport {
    /// Incidents processed.
    pub total_incidents: usize,
    /// Incidents that armed at least one playbook.
    pub matched_incidents: usize,
    /// Match count per playbook id.
    pub per_playbook: BTreeMap<String, u32>,
    /// `(skill, status)` -> count across every executed step.
    pub steps_by_skill_status: BTreeMap<(String, String), u32>,
    /// Block steps the skill_gate floor REFUSED (trusted / cloud / invalid).
    /// Should normally be 0 because `matches_incident` already filters
    /// trusted/cloud IPs via `ip_not_in`; a non-zero value here means the
    /// floor caught something the trigger conditions let through.
    pub block_refusals: u32,
    /// Block steps that would have fired (dry-run success), with the target.
    pub would_block: Vec<WouldBlock>,
}

#[derive(Debug, Clone)]
pub(crate) struct WouldBlock {
    pub incident_id: String,
    pub playbook_id: String,
    pub skill: String,
    pub target_ip: Option<String>,
}

impl ReplayReport {
    /// Human-readable summary for the CLI.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Playbook replay report ===\n");
        out.push_str(&format!("Incidents processed : {}\n", self.total_incidents));
        let pct = if self.total_incidents > 0 {
            100.0 * self.matched_incidents as f64 / self.total_incidents as f64
        } else {
            0.0
        };
        out.push_str(&format!(
            "Matched >=1 playbook: {} ({pct:.1}%)\n",
            self.matched_incidents
        ));

        out.push_str("\nMatches per playbook:\n");
        if self.per_playbook.is_empty() {
            out.push_str("  (none)\n");
        }
        for (id, n) in &self.per_playbook {
            out.push_str(&format!("  {id}: {n}\n"));
        }

        out.push_str("\nStep outcomes (skill / status -> count):\n");
        if self.steps_by_skill_status.is_empty() {
            out.push_str("  (none)\n");
        }
        for ((skill, status), n) in &self.steps_by_skill_status {
            out.push_str(&format!("  {skill} / {status}: {n}\n"));
        }

        out.push_str("\nSafety:\n");
        out.push_str(&format!(
            "  block steps refused by skill_gate floor: {}\n",
            self.block_refusals
        ));
        out.push_str(&format!(
            "  block steps that WOULD fire (dry-run): {}\n",
            self.would_block.len()
        ));
        // Show a small sample of would-block targets for eyeballing.
        for wb in self.would_block.iter().take(10) {
            out.push_str(&format!(
                "    - {} via {} -> {} (target {})\n",
                wb.incident_id,
                wb.playbook_id,
                wb.skill,
                wb.target_ip.as_deref().unwrap_or("?")
            ));
        }
        if self.would_block.len() > 10 {
            out.push_str(&format!(
                "    ... and {} more\n",
                self.would_block.len() - 10
            ));
        }
        out
    }
}

fn is_block_skill(skill: &str) -> bool {
    skill.starts_with("block_ip") || skill == "block_subnet"
}

/// Replay `incidents` through `playbooks` in dry-run, returning the
/// aggregate report. `trusted_ips` is the operator allowlist; `asset_tags`
/// is empty until spec 058 (mirrors the live path).
pub(crate) async fn replay_incidents(
    playbooks: &[Playbook],
    registry: &skills::SkillRegistry,
    trusted_ips: &[String],
    asset_tags: &[String],
    incidents: &[Incident],
) -> ReplayReport {
    let mut report = ReplayReport {
        total_incidents: incidents.len(),
        ..Default::default()
    };
    let audit = NoopAudit;

    for incident in incidents {
        let tctx = TriggerCtx::from_incident(incident);
        let primary_ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == CoreEntityType::Ip)
            .map(|e| e.value.clone());
        let mut armed = false;
        for pb in playbooks {
            if !executor::matches_incident(pb, incident, &tctx, trusted_ips, asset_tags) {
                continue;
            }
            armed = true;
            *report
                .per_playbook
                .entry(pb.metadata.id.as_str().to_string())
                .or_insert(0) += 1;

            let exec = RegistryStepExecutor {
                registry,
                trusted_ips,
                dry_run: true,
                host: incident.host.clone(),
                data_dir: std::env::temp_dir(),
                base_incident: incident.clone(),
                honeypot: skills::HoneypotRuntimeConfig::default(),
                ai_provider: None,
                command_sink: std::sync::Mutex::new(Vec::new()),
            };
            let outcome = executor::execute(pb, incident, &exec, &audit).await;
            for step in &outcome.steps {
                *report
                    .steps_by_skill_status
                    .entry((step.skill.clone(), step.status.as_str().to_string()))
                    .or_insert(0) += 1;
                if is_block_skill(&step.skill) {
                    match step.status {
                        StepStatus::Refused => report.block_refusals += 1,
                        StepStatus::Success => report.would_block.push(WouldBlock {
                            incident_id: incident.incident_id.clone(),
                            playbook_id: pb.metadata.id.as_str().to_string(),
                            skill: step.skill.clone(),
                            target_ip: primary_ip.clone(),
                        }),
                        _ => {}
                    }
                }
            }
        }
        if armed {
            report.matched_incidents += 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtins() -> Vec<Playbook> {
        super::super::load_builtins().expect("builtins load")
    }

    #[tokio::test]
    async fn replay_matches_credential_builtin_on_ssh_bruteforce() {
        let reg = skills::SkillRegistry::default_builtin();
        let pbs = builtins();
        // ssh_bruteforce incident from a clean IP arms the credential
        // builtin; a port_scan-kind incident arms nothing built-in.
        let inc_match = crate::tests::test_incident("198.51.100.42");
        let inc_nomatch =
            crate::tests::test_incident_with_kind("198.51.100.7", "nmap_scan_unrelated");
        let report = replay_incidents(&pbs, &reg, &[], &[], &[inc_match, inc_nomatch]).await;

        assert_eq!(report.total_incidents, 2);
        assert_eq!(report.matched_incidents, 1, "only the ssh_bruteforce armed");
        assert_eq!(
            report.per_playbook.get("pb-credential-stuffing-default"),
            Some(&1)
        );
        // The credential builtin's first step is a dry-run block on a clean
        // IP -> a "would block", not a refusal.
        assert_eq!(report.block_refusals, 0);
        assert_eq!(report.would_block.len(), 1);
        assert_eq!(
            report.would_block[0].target_ip.as_deref(),
            Some("198.51.100.42")
        );
        // Render must not panic and must mention the playbook.
        let txt = report.render();
        assert!(txt.contains("pb-credential-stuffing-default"));
        assert!(txt.contains("Incidents processed : 2"));
    }

    #[tokio::test]
    async fn replay_block_refused_for_trusted_source() {
        let reg = skills::SkillRegistry::default_builtin();
        let pbs = builtins();
        // Same ssh_bruteforce incident, but the source IP is operator-
        // trusted: `matches_incident`'s `ip_not_in: [$trusted_ips]` should
        // make the playbook NOT match at all -> 0 matches, 0 would-block.
        let inc = crate::tests::test_incident("203.0.113.7");
        let trusted = vec!["203.0.113.7".to_string()];
        let report = replay_incidents(&pbs, &reg, &trusted, &[], std::slice::from_ref(&inc)).await;
        assert_eq!(
            report.matched_incidents, 0,
            "trusted IP must not arm a block"
        );
        assert!(report.would_block.is_empty());
    }

    #[tokio::test]
    async fn replay_empty_is_zeroed() {
        let reg = skills::SkillRegistry::default_builtin();
        let report = replay_incidents(&builtins(), &reg, &[], &[], &[]).await;
        assert_eq!(report.total_incidents, 0);
        assert_eq!(report.matched_incidents, 0);
        assert!(report.render().contains("Incidents processed : 0"));
    }
}
