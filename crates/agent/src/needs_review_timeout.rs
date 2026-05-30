//! Spec 062 Phase 2 — severity-gated honest timeout for `needs_review`.
//!
//! Phase 1 (`narrative_observation_verify::mark_needs_review`) guarantees that
//! every ambiguous incident the automated layers cannot resolve ends with an
//! explicit `needs_review` decision instead of a silent orphan. This module is
//! the back half: what happens when a human never acts on one.
//!
//! The rule, and why it is NOT "just auto-dismiss after a while" (that is the
//! exact bug spec 062 exists to kill):
//!
//! - **Low / Medium** severity: after a grace window with no human action,
//!   auto-resolve to `dismiss` with an honest reason (`auto_resolved_timeout`).
//!   Low-stakes noise that nobody triaged is safe to close, and the audit row
//!   says plainly it was closed by timeout, not by a real verdict.
//! - **High / Critical**: **never** auto-dismiss. A real threat that nobody
//!   looked at must stay visible. Phase 2b re-notifies on an escalating
//!   cadence; this module simply leaves the incident in `needs_review` and
//!   logs that it is overdue, so the count is honest.
//!
//! Safety: the underlying store query
//! (`find_timed_out_needs_review`) only returns incidents whose MOST RECENT
//! decision is still `needs_review`. The moment a human (or a later automated
//! layer) blocks/dismisses/ignores it, the incident drops out of this sweep —
//! so a resolved item is never re-touched.
//!
//! LLM-optional: nothing here needs an LLM. This is the deterministic floor
//! that makes the review lifecycle work on a free, no-LLM install.

use crate::decisions::DecisionEntry;
use crate::AgentState;
use chrono::Utc;
use std::path::Path;
use tracing::{info, warn};

/// Grace window: a `needs_review` decision older than this with no human
/// action is "timed out". 24h gives an operator a full day (and an off-hours
/// window) to act before a low/medium item auto-resolves. The clock is the
/// `needs_review` decision's own timestamp, which Phase 1 writes at the moment
/// the item is surfaced.
pub const NEEDS_REVIEW_TIMEOUT_SECS: i64 = 24 * 3600;

/// Cap per sweep, mirroring orphan-recovery's bounded scope.
const SWEEP_LIMIT: usize = 5000;

/// `ai_provider` label on the auto-resolve decision so the audit trail shows
/// the timeout closed it, distinct from a real human/AI/gate dismiss.
pub(crate) const TIMEOUT_AI_PROVIDER: &str = "needs-review-timeout";

/// Whether an incident of this severity may be auto-resolved on timeout.
/// Pure + exported for unit tests: the High/Critical-never-auto-dismiss
/// invariant lives here so it is trivially testable and cannot regress.
/// Severity strings are the lowercase serde form the store persists
/// (`low`, `medium`, `high`, `critical`); unknown values are treated as
/// NOT auto-resolvable (fail safe — surface to a human rather than silently
/// closing something we could not classify).
pub(crate) fn may_auto_resolve(severity: &str) -> bool {
    matches!(
        severity.trim().to_ascii_lowercase().as_str(),
        "low" | "medium"
    )
}

/// Run one needs_review-timeout sweep. Returns the number of incidents
/// auto-resolved. Best-effort: store errors are logged and swallowed.
pub(crate) fn run_sweep(state: &mut AgentState, data_dir: &Path) -> usize {
    let Some(store) = state.sqlite_store.as_ref() else {
        return 0;
    };
    let now = Utc::now();
    let cutoff_iso = (now - chrono::Duration::seconds(NEEDS_REVIEW_TIMEOUT_SECS)).to_rfc3339();

    let rows = match store.find_timed_out_needs_review(&cutoff_iso, SWEEP_LIMIT) {
        Ok(rs) => rs,
        Err(e) => {
            warn!(error = %e, "needs_review_timeout: query failed");
            return 0;
        }
    };
    if rows.is_empty() {
        return 0;
    }

    let mut resolved = 0usize;
    let mut overdue_high = 0usize;
    for (incident_id, severity, needs_review_ts, data_json) in rows {
        if !may_auto_resolve(&severity) {
            // High/Critical: never auto-dismiss. Leave in needs_review; just
            // count it so the operator-facing overdue number is honest.
            // (Phase 2b: re-notify on escalating cadence.)
            overdue_high += 1;
            continue;
        }
        let target_ip = crate::orphan_recovery::extract_target_ip(&data_json);
        let age_seconds = chrono::DateTime::parse_from_rfc3339(&needs_review_ts)
            .map(|t| (now - t.with_timezone(&Utc)).num_seconds())
            .unwrap_or(0);
        let age_human = format!("{}h{}m", age_seconds / 3600, (age_seconds % 3600) / 60);
        let entry = DecisionEntry {
            ts: now,
            incident_id: incident_id.clone(),
            host: String::new(),
            ai_provider: TIMEOUT_AI_PROVIDER.to_string(),
            action_type: "dismiss".to_string(),
            target_ip,
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason: format!(
                "Auto-resolved by needs_review timeout: {severity}-severity incident sat \
                 in needs_review for {age_human} with no human action. Low/medium items \
                 auto-close on timeout; high/critical never do."
            ),
            estimated_threat: "low".to_string(),
            execution_result: "dismissed".to_string(),
            prev_hash: None,
            decision_layer: Some("auto_rule".to_string()),
        };
        // Update the graph label in place too so dashboard graph-derived views
        // reflect the resolution.
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.ingest_decision(&incident_id, "dismiss", None, 1.0, &entry.reason, true, now);
        }
        match crate::decisions::append_chained(data_dir, &entry, Some(store)) {
            Ok(()) => resolved += 1,
            Err(e) => warn!(
                incident_id = %incident_id,
                error = %e,
                "needs_review_timeout: failed to write auto-resolve decision"
            ),
        }
    }

    if resolved > 0 || overdue_high > 0 {
        info!(
            resolved,
            overdue_high_critical = overdue_high,
            "needs_review_timeout: swept (low/med auto-resolved; high/crit left visible)"
        );
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn may_auto_resolve_only_low_and_medium() {
        assert!(may_auto_resolve("low"));
        assert!(may_auto_resolve("medium"));
        assert!(may_auto_resolve("LOW"));
        assert!(may_auto_resolve("  Medium "));
        // The safety-critical half of the invariant:
        assert!(!may_auto_resolve("high"));
        assert!(!may_auto_resolve("critical"));
        assert!(!may_auto_resolve("Critical"));
    }

    #[test]
    fn may_auto_resolve_unknown_severity_fails_safe() {
        // Anything we cannot classify must NOT auto-dismiss — surface it.
        assert!(!may_auto_resolve(""));
        assert!(!may_auto_resolve("weird"));
        assert!(!may_auto_resolve("info"));
    }

    #[test]
    fn run_sweep_returns_zero_without_store() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(tmp.path());
        assert!(state.sqlite_store.is_none());
        assert_eq!(run_sweep(&mut state, tmp.path()), 0);
    }
}
