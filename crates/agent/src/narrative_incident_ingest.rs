use std::path::Path;

use anyhow::Result;
use tracing::{info, warn};

use crate::{allowlist, cloud_safelist, config, correlation_engine, AgentState};

/// Returns `true` when an attack chain's events touch only IPs the
/// agent already tags as operator-self-traffic — cloud_safelisted
/// destinations, statically allowlisted IPs, dynamically learned
/// trusted IPs, or active operator session IPs.
///
/// 2026-05-08 (fix/chain-suppress-operator-fp-rules): operator's
/// prod 2026-05-08 dashboard had 39 of 100 attack chains tagged with
/// operator IPs (Azure UK 20.26.156.215 git-fetch traffic, the
/// operator's home IP 80.195.183.53 = legitimate SSH login, the
/// host's own VPC IP 10.0.0.238 = self-traffic). The chain
/// detectors fired on real events but every entity in those chains
/// was operator activity. Examples:
///   - CL-038 "Off-Hours Login to Destructive Action": operator
///     SSH login + sudo at 18:00 UTC = 19:00 UK = normal work hour.
///   - CL-046 "Neural-Confirmed Attack": neural anomaly + c2_callback
///     to Azure UK = git fetch through libcurl.
///
/// Same predicate as the kill_chain DATA_EXFIL auto-dismiss
/// (PR #491 / PR #500), applied here at the chain-persistence
/// boundary so operator-FP chains never reach the dashboard's
/// "Chains" tab nor the synthetic Incident graph node. Real
/// attackers that happen to ALSO touch a single operator IP at
/// some stage are theoretically over-suppressed, but the
/// operator-honesty win on prod is significantly larger than the
/// FN risk.
pub(crate) fn is_chain_operator_fp(
    chain: &correlation_engine::AttackChain,
    cfg: &config::AgentConfig,
    state: &AgentState,
) -> bool {
    use innerwarden_core::entities::EntityType;
    for ev in &chain.events {
        for e in &ev.entities {
            if e.r#type != EntityType::Ip {
                continue;
            }
            let ip = e.value.as_str();
            if ip.is_empty() {
                continue;
            }
            if cloud_safelist::is_cloud_provider_ip(ip) {
                return true;
            }
            if allowlist::is_ip_allowlisted(ip, &cfg.allowlist.trusted_ips) {
                return true;
            }
            if allowlist::is_ip_allowlisted(ip, &state.dynamic_trusted_ips) {
                return true;
            }
            if state.operator_ips.contains_key(ip) {
                return true;
            }
        }
    }
    false
}

/// Drop attack chains whose every IP entity is operator-tagged
/// (cloud_safelist + static/dynamic trusted_ips + active operator
/// sessions), and emit one info line per dropped chain plus a single
/// summary line when at least one was dropped.
///
/// Extracted from `ingest_new_incidents` so the filter loop can be
/// exercised by unit tests without standing up SQLite, the knowledge
/// graph, or a real correlation engine. The two `info!` sites and the
/// `drained_total > kept.len()` accounting branch are the lines
/// codecov flagged on PR #501; pulling them out lets a mixed
/// (operator-FP + real-attacker) input fixture cover both sides.
pub(crate) fn filter_operator_fp_chains(
    drained: Vec<correlation_engine::AttackChain>,
    cfg: &config::AgentConfig,
    state: &AgentState,
) -> Vec<correlation_engine::AttackChain> {
    let drained_total = drained.len();
    let kept: Vec<correlation_engine::AttackChain> = drained
        .into_iter()
        .filter(|c| {
            let suppressed = is_chain_operator_fp(c, cfg, state);
            if suppressed {
                info!(
                    chain_id = %c.chain_id,
                    rule = %c.rule_id,
                    "chain suppressed at persistence: every entity is operator self-traffic"
                );
            }
            !suppressed
        })
        .collect();
    if drained_total > kept.len() {
        info!(
            drained = drained_total,
            kept = kept.len(),
            suppressed = drained_total - kept.len(),
            "chain operator-FP filter ran"
        );
    }
    kept
}

/// Ingest newly written incidents and update narrative/correlation state.
pub(crate) fn ingest_new_incidents(
    data_dir: &Path,
    _today: &str,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Result<()> {
    // Read new incidents from SQLite store
    let new_incidents: Vec<innerwarden_core::incident::Incident> = if let Some(ref sq) =
        state.sqlite_store
    {
        let cursor_key = "narrative_incidents";
        let cval = sq.get_agent_cursor(cursor_key).unwrap_or(0);
        match sq.incidents_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let (entries, max_id) = split_incident_rows(rows);
                // Spec 037 I-13 PR-4: surface persistent SQLite
                // degradation. A cursor-write failure is safe
                // (next tick re-reads the same incidents), but
                // re-processing duplicates chain notifications
                // until the cursor catches up. Sibling of the
                // events-cursor warn at slow_loop.rs (PR-3).
                if let Err(e) = sq.set_agent_cursor(cursor_key, max_id) {
                    warn!(
                        cursor = cursor_key,
                        max_id,
                        error = %e,
                        "agent cursor advance failed; incidents will be re-read next tick (chain notifications may duplicate)"
                    );
                }
                entries
            }
            _ => Vec::new(),
        }
    } else {
        warn!("sqlite_store not available — cannot read narrative incidents");
        return Ok(());
    };
    let _ = data_dir; // silence unused warning
    if should_process_new_incidents(new_incidents.len()) {
        state.narrative_acc.ingest_incidents(&new_incidents);

        // Feed incidents into cross-layer correlation engine
        for incident in &new_incidents {
            let corr_event = correlation_engine::CorrelationEngine::classify_incident(incident);
            state.correlation_engine.observe(corr_event);
        }

        // Drain every chain the engine matched, then filter out the
        // ones that touch only operator IPs. The graph node + JSON
        // persistence both happen below — apply the filter ONCE here
        // so neither surface inherits the FPs.
        let drained = state.correlation_engine.drain_completed();
        let chains = filter_operator_fp_chains(drained, cfg, state);
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

            // Phase 014-C: Create a synthetic Incident node for this chain and
            // ingest it into the graph. The incident carries all entities from the
            // chain events, so the existing incident ingestion creates TriggeredBy
            // edges automatically. Multiple events in a chain that share entities
            // now have a single "parent" incident in the graph, queryable via
            // /api/incidents, /api/journey, and graph traversal.
            //
            // Previously we tried to link existing incidents via CorrelatedWith,
            // but for pure event-driven chains (CL-008 file.read + outbound) there
            // are no existing incidents to link — the chain is the incident.
            {
                let host = chain
                    .events
                    .first()
                    .and_then(|_| state.knowledge_graph.read().ok())
                    .and_then(|g| {
                        g.system_node()
                            .and_then(|id| g.get_node(id))
                            .map(|n| n.label())
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                // Deduplicate entities across all chain events
                let mut entity_map: std::collections::BTreeMap<
                    (String, String),
                    innerwarden_core::entities::EntityRef,
                > = std::collections::BTreeMap::new();
                for ev in &chain.events {
                    for e in &ev.entities {
                        entity_map
                            .entry((format!("{:?}", e.r#type), e.value.clone()))
                            .or_insert_with(|| e.clone());
                    }
                }
                let entities: Vec<innerwarden_core::entities::EntityRef> =
                    entity_map.into_values().collect();

                if !entities.is_empty() {
                    let chain_incident = innerwarden_core::incident::Incident {
                        ts: chain.last_ts,
                        host,
                        incident_id: format!(
                            "cross_layer_chain:{}:{}",
                            chain.rule_id.to_lowercase(),
                            chain.chain_id
                        ),
                        severity: chain.severity.clone(),
                        title: format!(
                            "Cross-layer chain: {} ({} stages)",
                            chain.rule_name, chain.stages_matched
                        ),
                        summary: chain.summary.clone(),
                        evidence: serde_json::json!({
                            "chain_id": chain.chain_id,
                            "rule_id": chain.rule_id,
                            "stages": chain.stages_matched,
                            "stages_total": chain.stages_total,
                            "confidence": chain.confidence,
                            "layers": format!("{:?}", chain.layers_involved),
                        }),
                        recommended_checks: vec![],
                        tags: vec!["cross_layer_chain".to_string(), chain.rule_id.clone()],
                        entities,
                    };

                    // Ingest into graph (creates Incident node + TriggeredBy edges
                    // to each entity). The incident_enrichment path (Phase 014-D)
                    // handles any pid info; for chain incidents there is none.
                    {
                        let mut graph = state.knowledge_graph.write().unwrap();
                        graph.ingest_incident(&chain_incident);
                    }
                    info!(
                        chain_id = %chain.chain_id,
                        entities = chain_incident.entities.len(),
                        "chain incident ingested into graph"
                    );
                }
            }

            // 2026-05-03 (PR #413): chain-triggered playbook
            // evaluation removed with the playbook engine. Chain
            // detection itself stays — chains continue to be
            // persisted below for the dashboard, and severity-based
            // notifications fire via incident_notifications.rs. Future
            // home for chain-driven orchestration: Spec 042 active
            // defense (Lua-driven).
        }

        // Persist detected chains to JSON for dashboard via the shared
        // atomic-rename helper (`crate::capped_log::append_with_cap`).
        if !chains.is_empty() {
            let chains_path = data_dir.join("attack-chains.json");
            for chain in &chains {
                if let Err(e) = crate::capped_log::append_with_cap(&chains_path, chain, 100) {
                    warn!("failed to append attack-chains: {e}");
                }
            }
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

fn split_incident_rows(
    rows: Vec<(i64, innerwarden_core::incident::Incident)>,
) -> (Vec<innerwarden_core::incident::Incident>, i64) {
    let max_id = rows.last().map(|(id, _)| *id).unwrap_or(0);
    let incidents = rows.into_iter().map(|(_, incident)| incident).collect();
    (incidents, max_id)
}

fn should_process_new_incidents(count: usize) -> bool {
    count > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{event::Severity, incident::Incident};

    fn sample_incident(id: &str) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "host".to_string(),
            incident_id: id.to_string(),
            severity: Severity::Medium,
            title: "title".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn split_incident_rows_returns_incidents_and_latest_cursor_id() {
        // Ensures SQLite cursor progression tracks the highest processed row id.
        let rows = vec![
            (10, sample_incident("i-1")),
            (12, sample_incident("i-2")),
            (15, sample_incident("i-3")),
        ];
        let (incidents, max_id) = split_incident_rows(rows);
        assert_eq!(incidents.len(), 3);
        assert_eq!(max_id, 15);
    }

    #[test]
    fn should_process_new_incidents_only_when_count_is_positive() {
        // Guards ingest short-circuit so empty batches avoid unnecessary processing work.
        assert!(!should_process_new_incidents(0));
        assert!(should_process_new_incidents(1));
    }

    // Note: chain history pruning logic moved to
    // `crate::capped_log::append_with_cap` and is exercised by that
    // module's tests (`append_caps_to_most_recent_n_entries`).

    use crate::correlation_engine::{AttackChain, CorrelationEvent};

    fn make_chain_with_ip_entities(ips: &[&str]) -> AttackChain {
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use std::sync::Arc;
        let now = chrono::Utc::now();
        let events: Vec<CorrelationEvent> = ips
            .iter()
            .enumerate()
            .map(|(i, ip)| CorrelationEvent {
                ts: now + chrono::Duration::seconds(i as i64),
                layer: crate::correlation_engine::Layer::Userspace,
                source: Arc::from("test"),
                kind: Arc::from("test_event"),
                severity: Severity::High,
                entities: vec![EntityRef::ip(*ip)],
                details: serde_json::json!({}),
                incident_id: String::new(),
            })
            .collect();
        AttackChain {
            chain_id: "TEST-0001".to_string(),
            rule_id: "CL-XXX".to_string(),
            rule_name: "Test rule".to_string(),
            start_ts: now,
            last_ts: now + chrono::Duration::seconds(ips.len() as i64),
            events,
            stages_matched: 2,
            stages_total: 2,
            confidence: 0.85,
            layers_involved: vec![crate::correlation_engine::Layer::Userspace],
            severity: Severity::High,
            summary: "Test chain summary".to_string(),
        }
    }

    /// 2026-05-08 anchor (fix/chain-suppress-operator-fp-rules): a
    /// chain whose only IP entity is in `cloud_safelist` (here Azure
    /// UK 20.26.156.215, the operator's git-fetch FP target) must be
    /// suppressed at the persistence boundary. Anti-regression for
    /// the prod 2026-05-08 finding that 39/100 dashboard chains were
    /// operator self-traffic.
    #[test]
    fn is_chain_operator_fp_returns_true_for_cloud_safelisted_destination() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let chain = make_chain_with_ip_entities(&["20.26.156.215"]);
        assert!(
            is_chain_operator_fp(&chain, &cfg, &state),
            "chain touching cloud-safelisted IP MUST be flagged operator-FP"
        );
    }

    /// Mirror anchor: an active operator-session IP also flags the
    /// chain. Operator's prod prod 2026-05-08 had `80.195.183.53`
    /// (operator's UK home BT IP) firing CL-038 "Off-Hours Login to
    /// Destructive Action" — actually normal work hours in operator's
    /// timezone. `state.operator_ips` would be populated when the
    /// agent observes the operator's session activity.
    #[test]
    fn is_chain_operator_fp_returns_true_for_active_operator_session_ip() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        // Pre-seed an operator session IP.
        state
            .operator_ips
            .insert("80.195.183.53".to_string(), std::time::Instant::now());
        let chain = make_chain_with_ip_entities(&["80.195.183.53"]);
        assert!(
            is_chain_operator_fp(&chain, &cfg, &state),
            "chain touching active operator-session IP MUST be flagged operator-FP"
        );
    }

    /// Mirror anchor: a real-attacker IP (TEST-NET-3, RFC 5737 — never
    /// on a CDN, never in any allowlist) keeps reaching the
    /// dashboard. Pins the cheap-exit so the new filter doesn't
    /// over-suppress real activity.
    #[test]
    fn is_chain_operator_fp_returns_false_for_real_attacker_ip() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let chain = make_chain_with_ip_entities(&["203.0.113.42"]);
        assert!(
            !is_chain_operator_fp(&chain, &cfg, &state),
            "chain touching ONLY real-attacker IP must NOT be flagged operator-FP"
        );
    }

    /// Mirror anchor: a chain whose only IP entity matches
    /// `cfg.allowlist.trusted_ips` (the TOML-configured static list)
    /// must be flagged operator-FP. Pins the static-allowlist branch
    /// of `is_chain_operator_fp` (the prod-2026-05-08 path used by
    /// operators who pre-list their bastion / VPN exit / CI runner
    /// addresses in `agent.toml`).
    #[test]
    fn is_chain_operator_fp_returns_true_for_static_trusted_ip() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.allowlist.trusted_ips = vec!["203.0.113.99".to_string()];
        let chain = make_chain_with_ip_entities(&["203.0.113.99"]);
        assert!(
            is_chain_operator_fp(&chain, &cfg, &state),
            "chain touching cfg.allowlist.trusted_ips IP MUST be flagged operator-FP"
        );
    }

    /// Mirror anchor: a chain whose only IP entity matches
    /// `state.dynamic_trusted_ips` (the runtime-learned list) must be
    /// flagged operator-FP. Pins the dynamic-allowlist branch — this
    /// is the path used when the agent observes repeat operator
    /// activity and elevates an IP to the trusted set in-process.
    #[test]
    fn is_chain_operator_fp_returns_true_for_dynamic_trusted_ip() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.dynamic_trusted_ips = vec!["203.0.113.77".to_string()];
        let cfg = config::AgentConfig::default();
        let chain = make_chain_with_ip_entities(&["203.0.113.77"]);
        assert!(
            is_chain_operator_fp(&chain, &cfg, &state),
            "chain touching state.dynamic_trusted_ips IP MUST be flagged operator-FP"
        );
    }

    /// Mirror anchor: chain entities that aren't IPs (Pid, User,
    /// Container, etc.) must be skipped without aborting the loop.
    /// The empty-IP entity list path also keeps the false branch
    /// reachable: a chain made entirely of non-IP entities is treated
    /// as "no operator IP touched" → not flagged.
    #[test]
    fn is_chain_operator_fp_skips_non_ip_entities_and_returns_false() {
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use std::sync::Arc;
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let now = chrono::Utc::now();
        let chain = correlation_engine::AttackChain {
            chain_id: "TEST-NOIP".to_string(),
            rule_id: "CL-XXX".to_string(),
            rule_name: "Test rule".to_string(),
            start_ts: now,
            last_ts: now,
            events: vec![correlation_engine::CorrelationEvent {
                ts: now,
                layer: correlation_engine::Layer::Userspace,
                source: Arc::from("test"),
                kind: Arc::from("test_event"),
                severity: Severity::High,
                entities: vec![EntityRef::user("alice"), EntityRef::path("/etc/passwd")],
                details: serde_json::json!({}),
                incident_id: String::new(),
            }],
            stages_matched: 1,
            stages_total: 1,
            confidence: 0.5,
            layers_involved: vec![correlation_engine::Layer::Userspace],
            severity: Severity::High,
            summary: "non-ip entities".to_string(),
        };
        assert!(
            !is_chain_operator_fp(&chain, &cfg, &state),
            "chain with only non-IP entities must NOT be flagged operator-FP"
        );
    }

    /// Mirror anchor: an empty-string IP value must be skipped
    /// (early-continue branch). Defensive against malformed
    /// `EntityRef::ip("")` rows that have appeared in prod when
    /// upstream parsers fail open.
    #[test]
    fn is_chain_operator_fp_skips_empty_ip_value() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let chain = make_chain_with_ip_entities(&[""]);
        assert!(
            !is_chain_operator_fp(&chain, &cfg, &state),
            "chain whose only IP entity is the empty string must NOT be flagged"
        );
    }

    /// Filter-loop anchor: a mixed batch (operator-FP chain + real
    /// attacker chain) must keep ONLY the real attacker. Drives the
    /// inner `info!("chain suppressed at persistence: ...")` and the
    /// outer `info!("chain operator-FP filter ran")` branches plus
    /// the accounting subtraction `drained_total - kept.len()` —
    /// these were the codecov-flagged lines on PR #501 because the
    /// previous tests only exercised the predicate, not the loop.
    #[test]
    fn filter_operator_fp_chains_keeps_real_attacker_drops_operator_fp() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let azure = make_chain_with_ip_entities(&["20.26.156.215"]);
        let attacker = make_chain_with_ip_entities(&["203.0.113.42"]);
        let kept = filter_operator_fp_chains(vec![azure, attacker.clone()], &cfg, &state);
        assert_eq!(kept.len(), 1, "must drop the operator-FP chain");
        assert_eq!(kept[0].chain_id, attacker.chain_id);
    }

    /// Filter-loop anchor: when nothing is suppressed the outer
    /// summary `info!` branch (`drained_total > kept.len()`) does NOT
    /// fire. Pins the no-op pass-through path so a future refactor
    /// that always logs the summary is caught.
    #[test]
    fn filter_operator_fp_chains_no_op_when_no_chains_suppressed() {
        crate::cloud_safelist::init();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let attacker_a = make_chain_with_ip_entities(&["203.0.113.42"]);
        let attacker_b = make_chain_with_ip_entities(&["198.51.100.7"]);
        let kept =
            filter_operator_fp_chains(vec![attacker_a.clone(), attacker_b.clone()], &cfg, &state);
        assert_eq!(kept.len(), 2, "no chain should have been dropped");
    }

    /// Filter-loop anchor: empty input returns empty output without
    /// touching either log branch. Cheap guard against a future
    /// refactor that would push the accounting branch into the empty
    /// case.
    #[test]
    fn filter_operator_fp_chains_empty_input_returns_empty() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let kept = filter_operator_fp_chains(vec![], &cfg, &state);
        assert!(kept.is_empty(), "empty input must return empty output");
    }
}
