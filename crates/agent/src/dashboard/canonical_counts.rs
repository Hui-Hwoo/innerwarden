//! Spec 049 PR22 — canonical dashboard counters.
//!
//! **The whack-a-mole ends here.** Before PR22 the dashboard had at
//! least six independent count-producing functions, each with subtly
//! different filters, scopes, and units. Operator-reported on
//! 2026-05-13 after 18 prior PRs: "nunca fica bom" — same field name
//! across surfaces, different math, no canonical.
//!
//! Concrete examples from the prod inspection that drove this PR:
//!
//! * `/api/overview.events_count` returned **129,853** (KG edge count).
//! * `/api/sensors.total_events` returned **3,774** (KG ingested
//!   counter). Same label, 34× gap, both internally consistent for
//!   their original purpose but nonsense to the operator.
//! * `/api/overview.incidents_count` returned **508** (SQLite count).
//! * `/api/sensors.total_incidents` returned **508** (KG nodes_of_type).
//!   These happen to agree TODAY but the SQL/KG sources can drift any
//!   time the cap evicts.
//! * `/api/status.graph.incident_nodes` returned **736** — the KG
//!   carries incidents from prior days, so it overcounts "today"
//!   when read by the Sensors HUD.
//!
//! ## Contract
//!
//! Every dashboard endpoint that needs a count for the current date
//! reads from [`CanonicalCounts`] via [`compute`]. No exceptions.
//! A cross-endpoint anchor (`every_dashboard_endpoint_reads_canonical_counts`)
//! source-greps the handlers to prove the rule.
//!
//! Endpoint migrations are tracked in `IMPACT.md` under "Dashboard
//! count surfaces"; each handler that calls anything other than
//! `canonical_counts::compute` for a today-count is a regression.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Snapshot of every numeric counter a dashboard page might want to
/// render, computed in one pass over the canonical SQLite source.
///
/// Field naming is honest about scope and unit:
/// * `_today` suffix = today's UTC calendar day (matches the date
///   picker default and the `incidents.ts LIKE 'YYYY-MM-DD%'` query).
/// * `attackers` = unique external IPs (dedup).
/// * `incidents` = SQLite row count.
/// * `events` = sensor-emitted event count, from `graph.total_events_ingested`
///   (the live counter the sensor increments; replaces both the legacy
///   `edge_count` proxy and the no-longer-written `events-*.jsonl`
///   line count).
// PR22: the foundation lands without a production caller of `compute`
// — the events_count fix in `data_api.rs` reads
// `graph.total_events_ingested` directly. Subsequent PRs migrate each
// endpoint to consume from this module; until then clippy correctly
// notes the struct/fn are test-only. The allow stays explicit so the
// next migration PR removes it deliberately.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct CanonicalCounts {
    pub(super) date: String,

    /// Sensor pipeline event volume for the date. Source:
    /// `graph.total_events_ingested` — the same counter the Sensors HUD
    /// reads. Pre-PR22 `/api/overview.events_count` used
    /// `metrics.edge_count` (a 30×–40× inflation) which is why Home
    /// said 130k while Sensors said 3.7k for the same day.
    pub(super) events_today: u64,

    /// SQLite `incidents` table row count for the date, post-filter
    /// (research_only + self-traffic excluded). Authoritative answer
    /// to "how many incidents did we surface to the operator today?".
    pub(super) incidents_today: usize,

    /// SQLite `decisions` table row count for the date. Includes every
    /// decision the agent wrote — block_ip, monitor, dismiss, etc.
    pub(super) decisions_today: usize,

    /// Distinct external IPs that appeared on any non-research_only
    /// incident today. Mirrors `/api/entities` total post-filter.
    pub(super) unique_attackers_today: usize,

    /// Spec 049 §5: "flagged by system" = the operator's audit slice.
    /// `contained + observing + filtered_out + needs_review`. Equals
    /// `unique_attackers_today` for a fully classified day.
    pub(super) flagged_by_system: usize,

    /// Spec 049 §5: "warden decisions" = contained + observing +
    /// filtered_out. Excludes `needs_review` (operator action pending).
    pub(super) warden_decisions: usize,

    /// Unique IPs with at least one block_ip / honeypot outcome today.
    pub(super) blocked_attackers: usize,

    /// Unique IPs with at least one monitor outcome today.
    pub(super) observing_attackers: usize,

    /// Unique IPs whose every outcome was dismiss / ignore today.
    pub(super) filtered_out_attackers: usize,

    /// Unique IPs with at least one open / awaiting-decision incident.
    pub(super) needs_review_attackers: usize,

    /// Unique IPs whose every incident landed in the allowlist bucket
    /// (operator trust rule silenced them pre-AI).
    pub(super) allowlisted_attackers: usize,

    /// Detector frequency on today's surfaced incidents.
    pub(super) by_detector: BTreeMap<String, usize>,

    /// Severity frequency on today's surfaced incidents
    /// (`low` / `medium` / `high` / `critical` / `info`).
    pub(super) by_severity: BTreeMap<String, usize>,
}

/// Side-channel inputs for the canonical computation. None of these
/// reach a SQL query — they're operator-facing filters applied to the
/// in-memory pass.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub(super) struct CountFilters {
    /// Minimum severity rank (0 = no filter, see
    /// `investigation::severity_rank`).
    pub(super) sev_min_rank: u8,

    /// Detector substring (case-insensitive); rows whose detector
    /// does NOT contain this drop out.
    pub(super) detector_substring: Option<String>,

    /// Hour-of-day window (inclusive, UTC). Both `Some` and
    /// `from <= to` to apply; otherwise no-op.
    pub(super) hour_filter: Option<(u32, u32)>,
}

/// Compute the canonical counter snapshot for `date`. Single SQL pass
/// over SQLite incidents+decisions; reads `events_today` from the live
/// KG ingestion counter so it agrees with the Sensors HUD source.
///
/// On store/IO errors returns an empty snapshot with the date set —
/// downstream handlers fall through to a "no data" UI rather than
/// crashing the response.
#[allow(dead_code)]
pub(super) fn compute(
    store: &innerwarden_store::Store,
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    date: &str,
    filters: &CountFilters,
    now: DateTime<Utc>,
) -> CanonicalCounts {
    let mut out = CanonicalCounts {
        date: date.to_string(),
        ..Default::default()
    };

    // ── events_today: read the sensor's live counter directly. The
    //    legacy `metrics.edge_count` proxy inflated this by ~30× because
    //    each event creates multiple graph edges (incident → ip,
    //    incident → process, etc.).
    {
        let graph = kg.read().unwrap();
        out.events_today = graph.total_events_ingested as u64;
    }

    // ── incidents + decisions today, with attacker dedup and bucket
    //    classification. Reuses `compute_overview_counts_from_sqlite`
    //    as the single source of bucket math; PR22 wraps its output
    //    into the canonical struct so every consumer reads the same
    //    shape. Future PRs may inline the body here once every caller
    //    is migrated; for now wrapping keeps the diff focused.
    let degraded = super::data_api::DegradedSignals::default();
    let data_dir = std::path::Path::new("");
    if let Some(snap) = super::data_api::compute_overview_counts_from_sqlite(
        store,
        date,
        filters.sev_min_rank,
        filters.detector_substring.as_deref(),
        filters.hour_filter,
        now,
        &degraded,
        data_dir,
    ) {
        out.incidents_today = snap.incidents_count;
        out.decisions_today = snap.decisions_count;
        out.unique_attackers_today = snap.handled_ips_today;
        out.flagged_by_system = snap.flagged_by_system_count;
        out.warden_decisions = snap.warden_decisions_count;
        out.blocked_attackers = snap.blocked_count;
        out.observing_attackers = snap.observing_count;
        out.filtered_out_attackers = snap.filtered_out_count;
        out.needs_review_attackers = snap.attention_count;
        out.allowlisted_attackers = snap.allowlisted_count;
        out.by_detector = snap.by_detector;
        // `severity_breakdown` is a HashMap; convert to BTreeMap for
        // stable ordering across surfaces (operator screenshots /
        // diffs are easier when severity buckets sort consistently).
        out.by_severity = snap.severity_breakdown.into_iter().collect();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::KnowledgeGraph;
    use innerwarden_core::entities::{EntityRef, EntityType};
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;
    use std::sync::{Arc, RwLock};

    fn mk_kg() -> Arc<RwLock<KnowledgeGraph>> {
        Arc::new(RwLock::new(KnowledgeGraph::new()))
    }

    fn day() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 5, 13).unwrap()
    }

    fn now() -> DateTime<Utc> {
        day().and_hms_opt(15, 0, 0).unwrap().and_utc()
    }

    fn insert_incident(
        store: &innerwarden_store::Store,
        id: &str,
        ts: DateTime<Utc>,
        sev: Severity,
        ip: &str,
    ) {
        let inc = Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity: sev,
            title: "fixture".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef {
                r#type: EntityType::Ip,
                value: ip.into(),
            }],
        };
        store.insert_incident(&inc).unwrap();
    }

    fn insert_decision(
        store: &innerwarden_store::Store,
        incident_id: &str,
        action: &str,
        ts: DateTime<Utc>,
        ip: &str,
    ) {
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts.to_rfc3339(),
            incident_id: incident_id.into(),
            action_type: action.into(),
            target_ip: Some(ip.into()),
            target_user: None,
            confidence: 0.95,
            auto_executed: true,
            reason: Some("test".into()),
            data: serde_json::json!({
                "ts": ts.to_rfc3339(),
                "incident_id": incident_id,
                "action_type": action,
                "target_ip": ip,
                "confidence": 0.95,
                "estimated_threat": "high",
                "reason": "test",
                "execution_result": "ok"
            })
            .to_string(),
        };
        store.insert_decision(&row).unwrap();
    }

    #[test]
    fn canonical_counts_returns_zero_for_clean_store() {
        // The boot path on a clean install must not crash and must
        // return well-formed zeros. The operator's first hour
        // should not be polluted with "Unknown" / "—" placeholders.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let counts = compute(
            &store,
            &mk_kg(),
            "2026-05-13",
            &CountFilters::default(),
            now(),
        );
        assert_eq!(counts.date, "2026-05-13");
        assert_eq!(counts.events_today, 0);
        assert_eq!(counts.incidents_today, 0);
        assert_eq!(counts.blocked_attackers, 0);
    }

    #[test]
    fn canonical_counts_aggregates_one_blocked_incident() {
        // Hot path: one incident with one block_ip decision must
        // land in incidents_today=1, blocked_attackers=1,
        // unique_attackers_today=1, flagged_by_system=1,
        // warden_decisions=1.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = now() - chrono::Duration::hours(2);
        insert_incident(&store, "ssh_bf:1", ts, Severity::High, "203.0.113.10");
        insert_decision(&store, "ssh_bf:1", "block_ip", ts, "203.0.113.10");

        let counts = compute(
            &store,
            &mk_kg(),
            "2026-05-13",
            &CountFilters::default(),
            now(),
        );
        assert_eq!(counts.incidents_today, 1);
        assert_eq!(counts.blocked_attackers, 1);
        assert_eq!(counts.unique_attackers_today, 1);
        assert_eq!(counts.flagged_by_system, 1);
        assert_eq!(counts.warden_decisions, 1);
        assert_eq!(counts.filtered_out_attackers, 0);
    }

    #[test]
    fn canonical_counts_excludes_self_traffic_ips() {
        // PR20+PR21 contract end-to-end: Cloudflare-edge IPs and
        // RFC1918 must not inflate any counter. An incident whose
        // only entity is 172.70.80.132 (Cloudflare) must surface as
        // zero across every bucket.
        //
        // `cloud_safelist::init()` populates the static CLOUD_RANGES
        // table; production calls it at agent boot, but tests have to
        // call it explicitly. Idempotent — multiple init()s are a
        // no-op after the first.
        crate::cloud_safelist::init();
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = now() - chrono::Duration::hours(2);
        // Cloudflare edge — should be filtered.
        insert_incident(&store, "self:cf", ts, Severity::High, "172.70.80.132");
        insert_decision(&store, "self:cf", "block_ip", ts, "172.70.80.132");
        // Real attacker — should count.
        insert_incident(&store, "ssh_bf:1", ts, Severity::High, "203.0.113.10");
        insert_decision(&store, "ssh_bf:1", "block_ip", ts, "203.0.113.10");

        let counts = compute(
            &store,
            &mk_kg(),
            "2026-05-13",
            &CountFilters::default(),
            now(),
        );
        assert_eq!(
            counts.unique_attackers_today, 1,
            "Cloudflare edge IP must not count as an attacker"
        );
        assert_eq!(counts.blocked_attackers, 1);
    }

    #[test]
    fn canonical_counts_reads_events_today_from_kg_ingest_counter() {
        // Anti-regression for Gap 1 (the 130k vs 3.7k mystery). The
        // canonical events_today must come from
        // `graph.total_events_ingested` — the same counter the
        // Sensors HUD reads — NOT `metrics.edge_count` which inflates
        // by ~30× because every event creates multiple edges.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let kg = mk_kg();
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 12_345;
        }
        let counts = compute(&store, &kg, "2026-05-13", &CountFilters::default(), now());
        assert_eq!(
            counts.events_today, 12_345,
            "events_today must read from graph.total_events_ingested, \
             not edge_count or any other proxy"
        );
    }
}
