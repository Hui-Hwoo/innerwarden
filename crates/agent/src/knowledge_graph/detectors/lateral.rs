//! Lateral-movement graph detector.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `knowledge_graph/detectors.rs`. No logic change.

use super::*;

// ── 2. Lateral Movement via Graph ───────────────────────────────────────
// Replaces: lateral_movement detector (per-event outbound connect to internal)
// Graph query: Process→ConnectedTo→Ip(internal) where same Process connects to 3+ internal IPs on port 22

pub(super) fn detect_lateral_movement(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(300);

    // Group: Process → set of internal IPs connected on port 22
    let mut ssh_scans: HashMap<NodeId, HashSet<String>> = HashMap::new();
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        for edge in graph.outgoing_edges(proc_id) {
            if edge.relation != Relation::ConnectedTo || edge.ts < cutoff {
                continue;
            }
            let port = edge
                .properties
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            if port != 22 {
                continue;
            }
            if let Some(Node::Ip {
                addr,
                is_internal: true,
                ..
            }) = graph.get_node(edge.to)
            {
                ssh_scans.entry(proc_id).or_default().insert(addr.clone());
            }
        }
    }

    for (proc_id, ips) in ssh_scans {
        if ips.len() < 3 {
            continue;
        }
        let key = format!("graph_lateral:{}", proc_id);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let proc_label = graph
            .get_node(proc_id)
            .map(|n| n.label())
            .unwrap_or_default();
        let ip_list: Vec<String> = ips.into_iter().collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_lateral_movement:{}:{}", proc_id, now.timestamp()),
            severity: Severity::High,
            title: format!(
                "Lateral movement: {} SSH scanning {} internal IPs",
                proc_label,
                ip_list.len()
            ),
            summary: format!(
                "Process {} connected via SSH (port 22) to {} internal IPs in 5 minutes: {}",
                proc_label,
                ip_list.len(),
                ip_list.join(", ")
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_lateral_movement",
                "process": proc_label,
                "internal_ips": ip_list,
            }),
            recommended_checks: vec!["Check for compromised credentials".to_string()],
            tags: vec!["T1021.004".to_string()],
            entities: ip_list.iter().map(EntityRef::ip).collect(),
        });
    }

    incidents
}
