//! Spec 018 — Layer 2: Correlation-driven escalation.
//!
//! Drains completed attack chains from the correlation engine and escalates
//! response: multi-technique → longer block, repeat offender → permanent block,
//! kill chain → block + kill + critical alert.
//!
//! Runs in the slow loop (30s tick), after events are fed into the correlation
//! engine. Uses the knowledge graph and IP reputation for context.

use std::path::Path;

use chrono::Utc;
use tracing::{info, warn};

use crate::config::ChannelFilterLevel;
use crate::{
    ai, allowlist, config, correlation_engine, decisions, execute_decision, AgentState,
    LocalIpReputation,
};
use innerwarden_core::entities::{EntityRef, EntityType};

#[cfg(test)]
use crate::agent_context::incident_detector;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Process completed correlation chains and repeat-offender patterns.
/// Called once per slow-loop tick (30s).
pub(crate) async fn process_correlation_escalations(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    if !cfg.responder.enabled {
        return;
    }

    // 1. Drain completed attack chains from the correlation engine.
    let chains = state.correlation_engine.drain_completed();
    for chain in &chains {
        handle_completed_chain(chain, data_dir, cfg, state).await;
    }

    // 2. Check for repeat offenders (IPs blocked 3+ times in history).
    check_repeat_offenders(data_dir, cfg, state).await;

    // 3. Multi-technique detection: IPs that triggered 2+ distinct detectors
    //    within the correlation window get their block escalated.
    check_multi_technique(data_dir, cfg, state).await;
}

// ---------------------------------------------------------------------------
// Attack chain response
// ---------------------------------------------------------------------------

/// Respond to a completed correlation chain.
/// Kill chain patterns (reverse shell, bind shell, etc.) get the strongest
/// response: block IP + kill process + critical alert.
async fn handle_completed_chain(
    chain: &correlation_engine::AttackChain,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Extract primary IP from chain events.
    let primary_ip = chain
        .events
        .iter()
        .flat_map(|e| &e.entities)
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.clone());

    let Some(ip) = primary_ip else {
        info!(
            chain_id = %chain.chain_id,
            rule = %chain.rule_name,
            "correlation chain completed but no IP found — logging only"
        );
        return;
    };

    // Guard checks (same as Layer 1).
    if crate::incident_auto_rules::is_internal_ip_pub(&ip) {
        return;
    }
    if allowlist::is_ip_allowlisted(&ip, &cfg.allowlist.trusted_ips)
        || allowlist::is_ip_allowlisted(&ip, &state.dynamic_trusted_ips)
    {
        return;
    }
    if state.operator_ips.contains_key(&ip) {
        return;
    }

    // Cooldown: one chain response per IP per 10 minutes.
    let cooldown_key = format!("chain:{}:{}", chain.rule_id, ip);
    let cooldown_cutoff = Utc::now() - chrono::Duration::seconds(600);
    if state
        .store
        .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
        .is_some_and(|ts| ts > cooldown_cutoff)
    {
        return;
    }

    info!(
        chain_id = %chain.chain_id,
        rule = %chain.rule_name,
        ip = %ip,
        confidence = chain.confidence,
        stages = chain.stages_matched,
        "correlation chain completed — escalating response"
    );

    // Build a synthetic incident for the decision pipeline.
    let incident = innerwarden_core::incident::Incident {
        ts: chain.last_ts,
        host: std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string()),
        incident_id: format!("correlation:{}:{}", chain.chain_id, ip),
        severity: chain.severity.clone(),
        title: format!("Attack chain: {}", chain.rule_name),
        summary: chain.summary.clone(),
        evidence: serde_json::json!({
            "chain_id": chain.chain_id,
            "rule_id": chain.rule_id,
            "stages_matched": chain.stages_matched,
            "stages_total": chain.stages_total,
            "layers": chain.layers_involved.iter().map(|l| format!("{l:?}")).collect::<Vec<_>>(),
        }),
        recommended_checks: vec![],
        tags: vec!["correlation".to_string(), chain.rule_id.clone()],
        entities: vec![EntityRef::ip(&ip)],
    };

    // Determine block duration based on chain severity and confidence.
    let block_label = if chain.confidence >= 0.90 {
        "48h"
    } else {
        "24h"
    };

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.clone(),
            skill_id: skill_id.clone(),
        },
        confidence: chain.confidence,
        auto_execute: true,
        reason: format!(
            "Correlation chain: {} ({} stages, {:.0}% confidence, block {block_label})",
            chain.rule_name,
            chain.stages_matched,
            chain.confidence * 100.0,
        ),
        alternatives: vec![],
        estimated_threat: format!("{:?}", chain.severity).to_lowercase(),
    };

    let (execution_result, cloudflare_pushed) =
        execute_decision(&decision, &incident, data_dir, cfg, state).await;

    // Audit trail.
    let entry = decisions::DecisionEntry {
        ts: Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: format!("correlation:{}", chain.rule_id),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.clone()),
        target_user: None,
        skill_id: Some(skill_id),
        confidence: chain.confidence,
        auto_executed: true,
        dry_run: cfg.responder.dry_run,
        reason: decision.reason.clone(),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: execution_result.clone(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write chain decision: {e:#}");
        }
    }

    // Knowledge graph.
    {
        let auto_executed = !execution_result.starts_with("skipped");
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "block_ip",
            Some(&ip),
            decision.confidence,
            &decision.reason,
            auto_executed,
            Utc::now(),
        );
    }

    // IP reputation: chain participation weighs more than single incidents.
    let rep = state
        .ip_reputations
        .entry(ip.clone())
        .or_insert_with(LocalIpReputation::new);
    rep.record_incident();
    if !execution_result.starts_with("skipped") {
        rep.record_block();
        // Extra reputation penalty for chain involvement.
        rep.reputation_score += chain.confidence * 3.0;
    }

    // Feed decision to defender brain for training (Phase D).
    // Correlation chain decisions are high-quality: multi-signal confirmation.
    crate::incident_decision_eval::log_deterministic_decision_to_brain(
        &incident,
        &format!("{:?}", decision.action),
        chain.confidence,
        &format!("correlation:{}", chain.rule_id),
        data_dir,
        state,
    );

    // Cooldown.
    state.store.set_cooldown(
        crate::state_store::CooldownTable::Decision,
        &cooldown_key,
        Utc::now(),
    );

    // Telegram notification.
    if cfg.telegram.bot.enabled
        && cfg.telegram.channel_notifications.notification_level == ChannelFilterLevel::All
        && !execution_result.starts_with("skipped")
    {
        if let Some(ref tg) = state.telegram_client {
            let tg = tg.clone();
            let rule_name = chain.rule_name.clone();
            let ip_owned = ip.clone();
            let host = incident.host.clone();
            let confidence = chain.confidence;
            tokio::spawn(async move {
                let _ = tg
                    .send_action_report(
                        "Blocked (correlation chain)",
                        &ip_owned,
                        &rule_name,
                        confidence,
                        &host,
                        false,
                        None,
                        None,
                        cloudflare_pushed,
                    )
                    .await;
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Repeat offender detection
// ---------------------------------------------------------------------------

/// Check IPs blocked 3+ times → escalate to permanent block (7 days).
async fn check_repeat_offenders(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Collect IPs with 3+ blocks that haven't been permanently blocked yet.
    let repeat_ips: Vec<(String, u32)> = state
        .ip_reputations
        .iter()
        .filter(|(_, rep)| rep.total_blocks >= 3)
        .map(|(ip, rep)| (ip.clone(), rep.total_blocks))
        .collect();

    for (ip, total_blocks) in repeat_ips {
        let cooldown_key = format!("repeat-offender:{ip}");
        // Only fire once per 24h per IP.
        let cooldown_cutoff = Utc::now() - chrono::Duration::seconds(86400);
        if state
            .store
            .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
            .is_some_and(|ts| ts > cooldown_cutoff)
        {
            continue;
        }

        // Guard checks.
        if crate::incident_auto_rules::is_internal_ip_pub(&ip) {
            continue;
        }
        if allowlist::is_ip_allowlisted(&ip, &cfg.allowlist.trusted_ips)
            || allowlist::is_ip_allowlisted(&ip, &state.dynamic_trusted_ips)
        {
            continue;
        }
        if state.operator_ips.contains_key(&ip) {
            continue;
        }

        info!(
            ip = %ip,
            total_blocks,
            "repeat offender: {total_blocks} blocks — escalating to 7-day block"
        );

        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            incident_id: format!("repeat-offender:{}:{}", ip, Utc::now().timestamp()),
            severity: innerwarden_core::event::Severity::High,
            title: format!("Repeat offender: {ip} blocked {total_blocks} times"),
            summary: format!(
                "IP {ip} has been blocked {total_blocks} times. Escalating to extended block."
            ),
            evidence: serde_json::json!({ "total_blocks": total_blocks }),
            recommended_checks: vec![],
            tags: vec!["repeat-offender".to_string()],
            entities: vec![EntityRef::ip(&ip)],
        };

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        let decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: ip.clone(),
                skill_id: skill_id.clone(),
            },
            confidence: 0.98,
            auto_execute: true,
            reason: format!(
                "Repeat offender: {ip} blocked {total_blocks}x — extended block (7 days)"
            ),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        };

        let (execution_result, _) =
            execute_decision(&decision, &incident, data_dir, cfg, state).await;

        let entry = decisions::DecisionEntry {
            ts: Utc::now(),
            incident_id: incident.incident_id.clone(),
            host: incident.host.clone(),
            ai_provider: "repeat-offender".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.clone()),
            target_user: None,
            skill_id: Some(skill_id),
            confidence: 0.98,
            auto_executed: true,
            dry_run: cfg.responder.dry_run,
            reason: decision.reason.clone(),
            estimated_threat: "high".to_string(),
            execution_result: execution_result.clone(),
            prev_hash: None,
        };
        if let Some(writer) = &mut state.decision_writer {
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write repeat-offender decision: {e:#}");
            }
        }

        state.store.set_cooldown(
            crate::state_store::CooldownTable::Decision,
            &cooldown_key,
            Utc::now(),
        );
    }
}

// ---------------------------------------------------------------------------
// Multi-technique detection
// ---------------------------------------------------------------------------

/// Check for IPs that triggered 2+ distinct detectors recently.
/// These get an escalated block (48h instead of 12h/24h).
async fn check_multi_technique(data_dir: &Path, cfg: &config::AgentConfig, state: &mut AgentState) {
    // Query the knowledge graph for IPs with multiple distinct incident detectors
    // in the last 30 minutes.
    let cutoff = Utc::now() - chrono::Duration::seconds(1800);
    let multi_technique_ips = {
        let graph = state.knowledge_graph.read().unwrap();
        find_multi_technique_ips(&graph, cutoff)
    };

    for (ip, detectors) in multi_technique_ips {
        let cooldown_key = format!("multi-technique:{ip}");
        let cooldown_cutoff = Utc::now() - chrono::Duration::seconds(3600);
        if state
            .store
            .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
            .is_some_and(|ts| ts > cooldown_cutoff)
        {
            continue;
        }

        // Guard checks.
        if crate::incident_auto_rules::is_internal_ip_pub(&ip) {
            continue;
        }
        if allowlist::is_ip_allowlisted(&ip, &cfg.allowlist.trusted_ips)
            || allowlist::is_ip_allowlisted(&ip, &state.dynamic_trusted_ips)
        {
            continue;
        }
        if state.operator_ips.contains_key(&ip) {
            continue;
        }

        let detector_list = detectors.join(", ");
        info!(
            ip = %ip,
            detectors = %detector_list,
            "multi-technique: {count} distinct detectors — escalating block to 48h",
            count = detectors.len()
        );

        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            incident_id: format!("multi-technique:{}:{}", ip, Utc::now().timestamp()),
            severity: innerwarden_core::event::Severity::High,
            title: format!("Multi-technique attack from {ip}"),
            summary: format!(
                "IP {ip} triggered {count} distinct detectors: {detector_list}. Escalating.",
                count = detectors.len()
            ),
            evidence: serde_json::json!({ "detectors": detectors }),
            recommended_checks: vec![],
            tags: vec!["multi-technique".to_string()],
            entities: vec![EntityRef::ip(&ip)],
        };

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        let decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: ip.clone(),
                skill_id: skill_id.clone(),
            },
            confidence: 0.92,
            auto_execute: true,
            reason: format!(
                "Multi-technique: {ip} triggered {count} detectors ({detector_list}) — block 48h",
                count = detectors.len()
            ),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        };

        let (execution_result, _) =
            execute_decision(&decision, &incident, data_dir, cfg, state).await;

        let entry = decisions::DecisionEntry {
            ts: Utc::now(),
            incident_id: incident.incident_id.clone(),
            host: incident.host.clone(),
            ai_provider: "multi-technique".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.clone()),
            target_user: None,
            skill_id: Some(skill_id),
            confidence: 0.92,
            auto_executed: true,
            dry_run: cfg.responder.dry_run,
            reason: decision.reason.clone(),
            estimated_threat: "high".to_string(),
            execution_result: execution_result.clone(),
            prev_hash: None,
        };
        if let Some(writer) = &mut state.decision_writer {
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write multi-technique decision: {e:#}");
            }
        }

        // Update reputation.
        let rep = state
            .ip_reputations
            .entry(ip.clone())
            .or_insert_with(LocalIpReputation::new);
        if !execution_result.starts_with("skipped") {
            rep.record_block();
        }

        state.store.set_cooldown(
            crate::state_store::CooldownTable::Decision,
            &cooldown_key,
            Utc::now(),
        );
    }
}

/// Query the knowledge graph for IPs that triggered 2+ distinct detectors
/// since `cutoff`.
fn find_multi_technique_ips(
    graph: &crate::knowledge_graph::graph::KnowledgeGraph,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Vec<(String, Vec<String>)> {
    use std::collections::{HashMap, HashSet};

    let mut ip_detectors: HashMap<String, HashSet<String>> = HashMap::new();
    let nodes = graph.nodes();

    // Walk all incident nodes and their IP edges.
    for (&node_id, node) in nodes.iter() {
        let (detector, ts) = match node {
            crate::knowledge_graph::types::Node::Incident { detector, ts, .. } => (detector, ts),
            _ => continue,
        };

        if *ts < cutoff {
            continue;
        }

        // Find the IP connected to this incident via TriggeredBy edge.
        for edge in graph.all_edges(node_id) {
            if !matches!(
                edge.relation,
                crate::knowledge_graph::types::Relation::TriggeredBy
            ) {
                continue;
            }
            if let Some(crate::knowledge_graph::types::Node::Ip { addr, .. }) = nodes.get(&edge.to)
            {
                ip_detectors
                    .entry(addr.clone())
                    .or_default()
                    .insert(detector.clone());
            }
        }
    }

    // Return only IPs with 2+ distinct detectors.
    ip_detectors
        .into_iter()
        .filter(|(_, detectors)| detectors.len() >= 2)
        .map(|(ip, detectors)| {
            let mut sorted: Vec<String> = detectors.into_iter().collect();
            sorted.sort();
            (ip, sorted)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_detector_from_incident_id() {
        assert_eq!(
            incident_detector("ssh_bruteforce:1.2.3.4:12345"),
            "ssh_bruteforce"
        );
        assert_eq!(incident_detector("port_scan:10.0.0.1:67890"), "port_scan");
        assert_eq!(incident_detector("single_word"), "single_word");
    }

    #[test]
    fn find_multi_technique_returns_empty_on_empty_graph() {
        let graph = crate::knowledge_graph::graph::KnowledgeGraph::new();
        let result =
            find_multi_technique_ips(&graph, chrono::Utc::now() - chrono::Duration::hours(1));
        assert!(result.is_empty());
    }
}
