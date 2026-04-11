use std::path::Path;

use anyhow::Result;
use tracing::info;

use crate::{correlation_engine, reader, AgentState};

/// Ingest newly written incidents and update narrative/correlation state.
pub(crate) fn ingest_new_incidents(
    data_dir: &Path,
    today: &str,
    state: &mut AgentState,
) -> Result<()> {
    // Also ingest any new incidents incrementally
    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
    let new_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        state.narrative_incidents_offset,
    )
    .inspect_err(|_| {
        state.telemetry.observe_error("incident_reader");
    })?;
    if !new_incidents.entries.is_empty() {
        state.narrative_acc.ingest_incidents(&new_incidents.entries);
        state.narrative_incidents_offset = new_incidents.new_offset;

        // Feed incidents into cross-layer correlation engine
        for incident in &new_incidents.entries {
            let corr_event = correlation_engine::CorrelationEngine::classify_incident(incident);
            state.correlation_engine.observe(corr_event);
        }

        // Check for completed attack chains
        let chains = state.correlation_engine.drain_completed();
        for chain in &chains {
            info!(
                chain_id = %chain.chain_id,
                rule = %chain.rule_id,
                name = %chain.rule_name,
                stages = chain.stages_matched,
                layers = chain.layers_involved.len(),
                confidence = chain.confidence,
                "cross-layer attack chain detected: {}",
                chain.summary
            );

            // Phase 014-C: Add CorrelatedWith edges between all incidents in this chain.
            // Two paths:
            // 1. Events with incident_id (narrative_incident_ingest path, killchain) —
            //    link those incidents directly.
            // 2. Events without incident_id (raw event chains like CL-008 file.read →
            //    network.outbound) — find incidents that share the chain's entities
            //    and link them. Without this, CL-008 chains would never produce edges
            //    because classify_event always yields empty incident_id.
            let mut incident_ids: Vec<String> = chain
                .events
                .iter()
                .filter(|e| !e.incident_id.is_empty())
                .map(|e| e.incident_id.clone())
                .collect();

            if incident_ids.len() < 2 {
                // Collect entities from chain events and find incidents touching them.
                let chain_entities: std::collections::HashSet<(String, String)> = chain
                    .events
                    .iter()
                    .flat_map(|e| e.entities.iter())
                    .map(|e| (format!("{:?}", e.r#type), e.value.clone()))
                    .collect();
                if !chain_entities.is_empty() {
                    use crate::knowledge_graph::types::{Node, NodeType, Relation};
                    let graph = state.knowledge_graph.read().unwrap();
                    let chain_start = chain.start_ts;
                    let chain_end = chain.last_ts;
                    for id in graph.nodes_of_type(NodeType::Incident) {
                        if let Some(Node::Incident {
                            incident_id, ts, ..
                        }) = graph.get_node(id)
                        {
                            // Time window: only incidents within or near the chain window
                            if *ts < chain_start - chrono::Duration::seconds(60)
                                || *ts > chain_end + chrono::Duration::seconds(60)
                            {
                                continue;
                            }
                            // Check if this incident shares any entity with the chain
                            let shares = graph.outgoing_edges(id).iter().any(|e| {
                                if e.relation != Relation::TriggeredBy {
                                    return false;
                                }
                                match graph.get_node(e.to) {
                                    Some(Node::Ip { addr, .. }) => {
                                        chain_entities.contains(&("Ip".into(), addr.clone()))
                                    }
                                    Some(Node::User { name, .. }) => {
                                        chain_entities.contains(&("User".into(), name.clone()))
                                    }
                                    Some(Node::File { path, .. }) => {
                                        chain_entities.contains(&("Path".into(), path.clone()))
                                    }
                                    _ => false,
                                }
                            });
                            if shares {
                                incident_ids.push(incident_id.clone());
                            }
                        }
                    }
                    drop(graph);
                }
            }

            if incident_ids.len() >= 2 {
                let mut graph = state.knowledge_graph.write().unwrap();
                graph.link_correlated_incidents(&incident_ids, &chain.chain_id);
                info!(
                    chain_id = %chain.chain_id,
                    incidents = incident_ids.len(),
                    "CorrelatedWith edges created"
                );
            }

            // Evaluate chain-triggered playbooks
            for incident in &new_incidents.entries {
                if let Some(exec) = state
                    .playbook_engine
                    .evaluate_chain(&chain.rule_id, incident)
                {
                    info!(
                        playbook = %exec.playbook_id,
                        chain = %chain.rule_id,
                        steps = exec.steps.len(),
                        "chain-triggered playbook: {}",
                        exec.playbook_name
                    );
                }
            }
        }

        // Persist detected chains to JSON for dashboard
        if !chains.is_empty() {
            let chains_path = data_dir.join("attack-chains.json");
            let mut existing: Vec<serde_json::Value> = std::fs::read_to_string(&chains_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for chain in &chains {
                if let Ok(val) = serde_json::to_value(chain) {
                    existing.push(val);
                }
            }
            // Keep last 100 chains
            if existing.len() > 100 {
                existing = existing.split_off(existing.len() - 100);
            }
            let _ = std::fs::write(
                &chains_path,
                serde_json::to_string(&existing).unwrap_or_default(),
            );
        }

        // Check for multi-low elevation
        if let Some(chain) = state.correlation_engine.check_multi_low_elevation() {
            info!(
                chain_id = %chain.chain_id,
                "multi-low severity elevation: {}",
                chain.summary
            );
        }
    }

    Ok(())
}
