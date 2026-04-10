//! Daily AI Intelligence Briefing — generates structured threat summary from knowledge graph.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::knowledge_graph::KnowledgeGraph;
use crate::knowledge_graph::types::{Node, NodeType, Relation};

/// The generated briefing result.
#[derive(Debug, Clone, Serialize)]
pub struct Briefing {
    pub generated_at: DateTime<Utc>,
    pub date: String,
    pub threat_level: String,
    pub summary: String,
    pub sections: BriefingSections,
}

#[derive(Debug, Clone, Serialize)]
pub struct BriefingSections {
    pub overview: String,
    pub campaigns: Vec<String>,
    pub top_risks: Vec<TopRisk>,
    pub unresolved: Vec<UnresolvedThreat>,
    pub honeypot_intel: String,
    pub gaps: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopRisk {
    pub ip: String,
    pub detectors: Vec<String>,
    pub incident_count: usize,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedThreat {
    pub incident_id: String,
    pub severity: String,
    pub title: String,
    pub entity: String,
}

/// Build the structured context from the knowledge graph for LLM consumption.
pub fn build_briefing_context(
    kg: &Arc<RwLock<KnowledgeGraph>>,
) -> String {
    let graph = kg.read().unwrap();

    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    let ip_nodes = graph.nodes_of_type(NodeType::Ip);

    // Counts
    let total_incidents = incident_nodes.len();
    let total_ips = ip_nodes.iter().filter(|&&id| {
        matches!(graph.get_node(id), Some(Node::Ip { is_internal: false, .. }))
    }).count();

    // Severity breakdown
    let mut by_severity: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut by_detector: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut decisions_count = 0usize;
    let mut blocks = 0usize;
    let mut unresolved_high: Vec<(String, String, String, String)> = Vec::new();

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            incident_id, detector, severity, title, decision, ..
        }) = graph.get_node(id) {
            *by_severity.entry(severity.to_lowercase()).or_default() += 1;
            *by_detector.entry(detector.clone()).or_default() += 1;

            if let Some(dec) = decision {
                decisions_count += 1;
                if dec == "block_ip" { blocks += 1; }
            } else {
                let sev = severity.to_lowercase();
                if sev == "high" || sev == "critical" {
                    // Find entity
                    let entity = graph.outgoing_edges(id).iter()
                        .find(|e| e.relation == Relation::TriggeredBy)
                        .and_then(|e| graph.get_node(e.to))
                        .map(|n| n.label())
                        .unwrap_or_default();
                    unresolved_high.push((
                        incident_id.clone(),
                        sev,
                        title.clone(),
                        entity,
                    ));
                }
            }
        }
    }

    // Top attackers by incident count
    let mut ip_incidents: std::collections::HashMap<String, (usize, Vec<String>)> =
        std::collections::HashMap::new();
    for &inc_id in &incident_nodes {
        if let Some(Node::Incident { detector, .. }) = graph.get_node(inc_id) {
            for edge in graph.outgoing_edges(inc_id) {
                if edge.relation == Relation::TriggeredBy {
                    if let Some(Node::Ip { addr, is_internal: false, .. }) = graph.get_node(edge.to) {
                        let entry = ip_incidents.entry(addr.clone()).or_insert((0, Vec::new()));
                        entry.0 += 1;
                        if !entry.1.contains(detector) {
                            entry.1.push(detector.clone());
                        }
                    }
                }
            }
        }
    }
    let mut top_attackers: Vec<_> = ip_incidents.into_iter().collect();
    top_attackers.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    top_attackers.truncate(10);

    // Top detectors
    let mut sorted_detectors: Vec<_> = by_detector.into_iter().collect();
    sorted_detectors.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_detectors.truncate(10);

    // Threat level
    let critical = by_severity.get("critical").copied().unwrap_or(0);
    let high = by_severity.get("high").copied().unwrap_or(0);
    let threat_level = if critical > 5 || unresolved_high.len() > 10 {
        "CRITICAL"
    } else if critical > 0 || high > 10 || unresolved_high.len() > 3 {
        "ELEVATED"
    } else if high > 0 || total_incidents > 50 {
        "MODERATE"
    } else {
        "LOW"
    };

    // Build context string for LLM
    let mut ctx = format!(
        "DAILY SECURITY INTELLIGENCE BRIEFING CONTEXT\n\
         Date: {}\n\
         Threat Level: {}\n\n\
         OVERVIEW:\n\
         - Total incidents: {}\n\
         - Unique external IPs: {}\n\
         - AI decisions made: {}\n\
         - IPs blocked: {}\n\
         - Unresolved high/critical: {}\n\
         - Severity breakdown: {:?}\n\n",
        Utc::now().format("%Y-%m-%d"),
        threat_level,
        total_incidents,
        total_ips,
        decisions_count,
        blocks,
        unresolved_high.len(),
        by_severity,
    );

    ctx.push_str("TOP DETECTORS (by incident count):\n");
    for (det, count) in &sorted_detectors {
        ctx.push_str(&format!("  - {}: {}\n", det, count));
    }

    ctx.push_str("\nTOP ATTACKERS:\n");
    for (ip, (count, dets)) in &top_attackers {
        ctx.push_str(&format!("  - {} — {} incidents, detectors: {}\n", ip, count, dets.join(", ")));
    }

    if !unresolved_high.is_empty() {
        ctx.push_str("\nUNRESOLVED HIGH/CRITICAL THREATS:\n");
        for (id, sev, title, entity) in &unresolved_high {
            ctx.push_str(&format!("  - [{}] {} — {} ({})\n", sev, title, entity, id));
        }
    }

    // Event sources
    ctx.push_str(&format!("\nEVENT SOURCES: {} total events ingested\n", graph.total_events_ingested));
    for (src, &count) in graph.source_counts.iter() {
        ctx.push_str(&format!("  - {}: {}\n", src, count));
    }

    // Graph structure
    let metrics = graph.metrics();
    ctx.push_str(&format!(
        "\nKNOWLEDGE GRAPH: {} nodes, {} edges, {} KB\n",
        metrics.node_count, metrics.edge_count, metrics.memory_bytes / 1024
    ));

    ctx
}

/// The LLM prompt for generating the briefing.
pub fn briefing_prompt(context: &str) -> String {
    format!(
        "You are a senior security analyst generating a daily intelligence briefing for a server operator.\n\
         \n\
         Based on the security data below, write a concise, actionable briefing with these sections:\n\
         \n\
         1. **THREAT LEVEL** — one word (CRITICAL/ELEVATED/MODERATE/LOW) with a one-sentence justification\n\
         2. **EXECUTIVE SUMMARY** — 2-3 sentences covering the day's security posture\n\
         3. **CAMPAIGNS** — group related attacks by behavior/IP/timing. Name each campaign descriptively.\n\
         4. **TOP RISKS** — the 3 most dangerous unresolved threats with recommended actions\n\
         5. **GAPS** — what's suspicious by its ABSENCE (e.g., no lateral movement = possible evasion)\n\
         6. **RECOMMENDATIONS** — 3 specific, actionable steps the operator should take TODAY\n\
         \n\
         Be direct. No filler. Use bullet points. If something is urgent, say so clearly.\n\
         \n\
         ---\n\
         \n\
         {context}"
    )
}

/// Parse the LLM response into a structured Briefing.
pub fn parse_briefing(llm_response: &str, context_threat_level: &str) -> Briefing {
    let today = Utc::now().format("%Y-%m-%d").to_string();

    Briefing {
        generated_at: Utc::now(),
        date: today,
        threat_level: context_threat_level.to_string(),
        summary: llm_response.to_string(),
        sections: BriefingSections {
            overview: String::new(),
            campaigns: Vec::new(),
            top_risks: Vec::new(),
            unresolved: Vec::new(),
            honeypot_intel: String::new(),
            gaps: Vec::new(),
            recommendations: Vec::new(),
        },
    }
}
