//! Correlation-rule graph detectors (multi-stage attack chains as graph paths).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `knowledge_graph/detectors.rs`. No logic change.

use super::*;

// ── Phase 3C: Correlation Rules as Graph Paths ─────────────────────────

struct CorrelationRule {
    id: &'static str,
    name: &'static str,
    /// Detector slug patterns for each stage. Supports glob-like prefix match.
    stages: &'static [&'static [&'static str]],
    window_secs: i64,
    /// If true, stages must share the same entity (IP or User).
    entity_must_match: bool,
    severity: Severity,
    mitre: &'static str,
}

const CORRELATION_RULES: &[CorrelationRule] = &[
    CorrelationRule {
        id: "CL-002",
        name: "Recon to Exfiltration",
        stages: &[
            &["port_scan", "web_scan", "user_agent_scanner"],
            &["ssh_bruteforce", "credential_stuffing"],
            &["data_exfiltration", "data_exfil", "outbound_anomaly"],
        ],
        window_secs: 1800,
        entity_must_match: true,
        severity: Severity::Critical,
        mitre: "TA0010",
    },
    CorrelationRule {
        id: "CL-003",
        name: "Honeypot to Real Attack",
        stages: &[
            &["honeypot"],
            &["ssh_bruteforce", "credential_stuffing", "proto_anomaly"],
        ],
        window_secs: 3600,
        entity_must_match: true,
        severity: Severity::High,
        mitre: "TA0001",
    },
    CorrelationRule {
        id: "CL-005",
        name: "Container Escape to Host",
        stages: &[
            &["container_escape", "container_drift"],
            &["shell", "execution_guard", "suspicious_execution"],
            &["privilege", "escalat"],
        ],
        window_secs: 600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "T1611",
    },
    CorrelationRule {
        id: "CL-010",
        name: "Multi-Low Severity Elevation",
        stages: &[&["__multi_low__"]], // Special handling below
        window_secs: 600,
        entity_must_match: true,
        severity: Severity::High,
        mitre: "TA0001",
    },
    CorrelationRule {
        id: "CL-011",
        name: "Credential Theft to Lateral Movement",
        stages: &[
            &["credential_harvest", "credential_stuffing"],
            &["lateral_movement", "ssh_key_injection"],
        ],
        window_secs: 1800,
        entity_must_match: true,
        severity: Severity::Critical,
        mitre: "TA0008",
    },
    CorrelationRule {
        id: "CL-012",
        name: "Multi-Persistence",
        stages: &[
            &["crontab_persistence", "systemd_persistence"],
            &["ssh_key_injection", "user_creation"],
        ],
        window_secs: 3600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "TA0003",
    },
    CorrelationRule {
        id: "CL-014",
        name: "Cryptominer Deployment",
        stages: &[
            &["shell", "outbound_connect", "execution"],
            &["crypto_miner", "cgroup"],
        ],
        window_secs: 600,
        entity_must_match: false,
        severity: Severity::High,
        mitre: "T1496",
    },
    CorrelationRule {
        id: "CL-015",
        name: "Post-Compromise Log Tampering",
        stages: &[
            &["privilege", "reverse_shell", "ssh_bruteforce"],
            &["log_tampering"],
        ],
        window_secs: 600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "T1070",
    },
    CorrelationRule {
        id: "CL-024",
        name: "Fast Web Exploit to Exfil",
        stages: &[
            &["port_scan", "web_scan", "user_agent_scanner"],
            &["web_shell", "reverse_shell"],
            &["data_exfil", "dns_tunnel", "outbound_anomaly"],
        ],
        window_secs: 300,
        entity_must_match: true,
        severity: Severity::Critical,
        mitre: "TA0010",
    },
    CorrelationRule {
        id: "CL-029",
        name: "Multi-Persistence Attempt",
        stages: &[
            &["crontab", "systemd_persistence"],
            &["ssh_key", "authorized_keys"],
        ],
        window_secs: 3600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "TA0003",
    },
];

/// Run all correlation rules against the graph.
/// For each entity (IP/User) that has Incident nodes, check if the incident
/// detectors match the rule's stage pattern within the time window.
pub(super) fn detect_correlation_chains(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();

    // Collect all Incident nodes with their entity connections
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    if incident_nodes.len() < 2 {
        return incidents; // Need at least 2 incidents for correlation
    }

    // Build entity→incidents map: for each IP/User, list connected incidents
    let mut entity_incidents: HashMap<NodeId, Vec<(String, DateTime<Utc>, NodeId)>> =
        HashMap::new();

    for &inc_id in &incident_nodes {
        let (detector, ts) = match graph.get_node(inc_id) {
            Some(Node::Incident { detector, ts, .. }) => (detector.clone(), *ts),
            _ => continue,
        };

        // Find connected entities via TriggeredBy edges
        for edge in graph.outgoing_edges(inc_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            let entity_type = graph.get_node(edge.to).map(|n| n.node_type());
            if matches!(entity_type, Some(NodeType::Ip) | Some(NodeType::User)) {
                entity_incidents
                    .entry(edge.to)
                    .or_default()
                    .push((detector.clone(), ts, inc_id));
            }
        }
    }

    // Check each rule against each entity's incidents
    for rule in CORRELATION_RULES {
        // Special handling: CL-010 Multi-Low Elevation
        if rule.id == "CL-010" {
            for (entity_id, inc_list) in &entity_incidents {
                let window = Duration::seconds(rule.window_secs);
                let recent: Vec<&str> = inc_list
                    .iter()
                    .filter(|(_, ts, _)| now - *ts < window)
                    .map(|(det, _, _)| det.as_str())
                    .collect();

                let unique_detectors: HashSet<&str> = recent.iter().copied().collect();
                if unique_detectors.len() < 3 {
                    continue;
                }

                let entity_label = graph
                    .get_node(*entity_id)
                    .map(|n| n.label().to_string())
                    .unwrap_or_default();
                let key = format!("graph_corr:CL-010:{}", entity_label);
                if !state.check_and_set(&key, now, 600) {
                    continue;
                }

                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_correlation:CL-010:{}:{}", entity_label, now.timestamp()),
                    severity: rule.severity.clone(),
                    title: format!(
                        "Multi-detector elevation: {} triggered {} detectors",
                        entity_label,
                        unique_detectors.len()
                    ),
                    summary: format!(
                        "Entity {} triggered {} distinct detectors in {}s: {}. Multiple low-severity indicators elevate to high.",
                        entity_label,
                        unique_detectors.len(),
                        rule.window_secs,
                        unique_detectors.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_correlation",
                        "rule": rule.id,
                        "rule_name": rule.name,
                        "entity": entity_label,
                        "detectors": recent,
                    }),
                    recommended_checks: vec![
                        format!("Investigate entity: {}", entity_label),
                    ],
                    tags: vec![rule.mitre.to_string()],
                    entities: vec![],
                });
            }
            continue;
        }

        // Standard multi-stage rules: the entity-matched path below walks
        // `entity_incidents` directly; non-entity-match rules walk the global
        // incident list built elsewhere in the same tick. We no longer stage a
        // combined "check_entities" vector since it was unused by the matcher.

        // For entity-matched rules: check each entity
        if rule.entity_must_match {
            for (entity_id, inc_list) in &entity_incidents {
                if let Some(incident) =
                    check_rule_stages(graph, state, rule, inc_list, *entity_id, host, now)
                {
                    incidents.push(incident);
                }
            }
        } else {
            // For non-entity rules: merge all incidents and check globally
            let all_incs: Vec<(String, DateTime<Utc>, NodeId)> = entity_incidents
                .values()
                .flat_map(|v| v.iter().cloned())
                .collect();
            if let Some(incident) = check_rule_stages(graph, state, rule, &all_incs, 0, host, now) {
                incidents.push(incident);
            }
        }
    }

    incidents
}

/// Check if a set of incidents matches all stages of a correlation rule.
fn check_rule_stages(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    rule: &CorrelationRule,
    inc_list: &[(String, DateTime<Utc>, NodeId)],
    entity_id: NodeId,
    host: &str,
    now: DateTime<Utc>,
) -> Option<Incident> {
    let window = Duration::seconds(rule.window_secs);

    // For each stage, find at least one matching incident within the window
    let mut stage_matches: Vec<Option<(&str, DateTime<Utc>)>> = Vec::new();

    for stage_patterns in rule.stages {
        let matched = inc_list.iter().find(|(det, ts, _)| {
            now - *ts < window
                && stage_patterns
                    .iter()
                    .any(|pattern| det.starts_with(pattern) || det.contains(pattern))
        });
        stage_matches.push(matched.map(|(det, ts, _)| (det.as_str(), *ts)));
    }

    // All stages must have a match
    if stage_matches.iter().any(|m| m.is_none()) {
        return None;
    }

    // Verify ordering: each stage's timestamp must be >= previous stage
    let timestamps: Vec<DateTime<Utc>> = stage_matches.iter().map(|m| m.unwrap().1).collect();
    for pair in timestamps.windows(2) {
        if pair[1] < pair[0] {
            return None; // Wrong order
        }
    }

    let entity_label = if entity_id > 0 {
        graph
            .get_node(entity_id)
            .map(|n| n.label().to_string())
            .unwrap_or_default()
    } else {
        "global".to_string()
    };

    let key = format!("graph_corr:{}:{}", rule.id, entity_label);
    if !state.check_and_set(&key, now, 600) {
        return None;
    }

    let matched_detectors: Vec<&str> = stage_matches.iter().map(|m| m.unwrap().0).collect();

    Some(Incident {
        ts: now,
        host: host.to_string(),
        incident_id: format!("graph_correlation:{}:{}:{}", rule.id, entity_label, now.timestamp()),
        severity: rule.severity.clone(),
        title: format!("{}: {} ({})", rule.id, rule.name, entity_label),
        summary: format!(
            "Multi-stage attack chain detected ({}): {} stages matched for entity '{}' within {}s. Stages: {}.",
            rule.name,
            rule.stages.len(),
            entity_label,
            rule.window_secs,
            matched_detectors.join(" → ")
        ),
        evidence: serde_json::json!({
            "source": "knowledge_graph",
            "detector": "graph_correlation",
            "rule": rule.id,
            "rule_name": rule.name,
            "entity": entity_label,
            "stages_matched": matched_detectors,
            "window_secs": rule.window_secs,
        }),
        recommended_checks: vec![
            format!("Investigate attack chain for {}", entity_label),
            format!("Check timeline: /api/graph/timeline?node_id={}", entity_id),
        ],
        tags: vec![rule.mitre.to_string()],
        entities: vec![],
    })
}
