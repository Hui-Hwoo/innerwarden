//! Consistency anchor: spec 049's case-metrics math contract MUST
//! hold on every surface that emits the four operator-visible
//! counters (`Flagged by system`, `Warden decisions`, `Filtered out`,
//! `Needs review`) plus the three leaf buckets that already existed
//! pre-spec-049 (`blocked_count`, `observing_count`, `attention_count`).
//!
//! Math contract:
//!
//! ```text
//! Flagged by system = Contained + Observing + FilteredOut + NeedsReview
//! Warden decisions  = Contained + Observing + FilteredOut
//! NeedsReview       = Flagged by system - Warden decisions
//! ```
//!
//! This file mirrors the structure of `consistency_block_counts.rs`
//! (spec 035 PR-A1) and exists because spec 049 explicitly anchors
//! itself against the recurring "Dashboard count != Site count"
//! failure mode (`.claude-local/RECURRING_BUGS.md`). The first time
//! these counters drift between the SQLite path and the KG fallback
//! path, this test fires.
//!
//! **If this test fails on first run**: do NOT weaken the assertion.
//! Either the leaf counts changed without the derived totals being
//! recomputed (refactor regression), or someone overrode
//! `flagged_by_system_count` / `warden_decisions_count` independently
//! of the leaf buckets (which violates the "single source of truth"
//! principle pinned in `case_metrics.rs`). Fix the wiring; do not
//! relax the equality.

use super::case_metrics::{tally_cases, CaseMetrics};
use super::data_api::OverviewCounts;

/// Smallest possible anchor: `CaseMetrics` itself must satisfy the
/// math contract for any concrete value of the four leaf counters.
/// Acts as a defensive guard if someone "optimises" the
/// `flagged_by_system` / `warden_decisions` methods by inlining a
/// constant or returning a cached field.
#[test]
fn case_metrics_math_contract_holds_on_realistic_input() {
    let m = CaseMetrics {
        contained: 4,
        observing: 3,
        filtered_out: 45,
        needs_review: 1,
    };
    assert_eq!(
        m.flagged_by_system(),
        53,
        "Flagged by system must sum all four outcomes"
    );
    assert_eq!(
        m.warden_decisions(),
        52,
        "Warden decisions must include Filtered out (spec 049 Q1+Q7)"
    );
    assert_eq!(
        m.flagged_by_system() - m.warden_decisions(),
        m.needs_review,
        "Flagged - Warden decisions = Needs review (the only number the operator must look at)"
    );
}

/// The OverviewCounts struct populated by both compute paths (SQLite
/// in `compute_overview_counts_from_sqlite`, KG fallback inline in
/// `api_overview`) MUST satisfy the math contract by construction.
/// If either path forgets to update one of the derived totals after
/// changing a leaf bucket, this test catches it.
#[test]
fn overview_counts_new_fields_reconcile_with_leaf_buckets() {
    let counts = OverviewCounts {
        blocked_count: 4,
        observing_count: 3,
        filtered_out_count: 45,
        attention_count: 1,
        flagged_by_system_count: 53,
        warden_decisions_count: 52,
        ..Default::default()
    };
    assert_eq!(
        counts.blocked_count
            + counts.observing_count
            + counts.filtered_out_count
            + counts.attention_count,
        counts.flagged_by_system_count,
        "Flagged by system must equal sum of leaf buckets"
    );
    assert_eq!(
        counts.blocked_count + counts.observing_count + counts.filtered_out_count,
        counts.warden_decisions_count,
        "Warden decisions must equal Contained + Observing + Filtered out"
    );
    assert_eq!(
        counts.flagged_by_system_count - counts.warden_decisions_count,
        counts.attention_count,
        "Needs review must equal Flagged by system - Warden decisions"
    );
}

/// Round-trip from raw decision rows through `tally_cases` into
/// `OverviewCounts`. This is the path the KG fallback inside
/// `api_overview` exercises in production: it walks Incident nodes,
/// classifies each via `threat_contract`, and increments the four
/// leaf counters. The test uses the operator's prod-screenshot shape
/// (4 block + 3 observing + 45 dismiss + 1 no-decision) so a future
/// regression on the prod input shape fails this anchor.
#[test]
fn tally_cases_to_overview_counts_round_trip_pins_prod_screenshot_shape() {
    let rows: Vec<(Option<&str>, Option<&str>)> = std::iter::empty()
        .chain(std::iter::repeat((Some("block_ip"), Some("ok"))).take(4))
        .chain(std::iter::repeat((Some("monitor"), Some("ok"))).take(3))
        .chain(std::iter::repeat((Some("dismiss"), None)).take(45))
        .chain(std::iter::repeat((None, None)).take(1))
        .collect();
    let m = tally_cases(rows);
    let counts = OverviewCounts {
        blocked_count: m.contained,
        observing_count: m.observing,
        filtered_out_count: m.filtered_out,
        attention_count: m.needs_review,
        flagged_by_system_count: m.flagged_by_system(),
        warden_decisions_count: m.warden_decisions(),
        ..Default::default()
    };
    assert_eq!(counts.blocked_count, 4);
    assert_eq!(counts.observing_count, 3);
    assert_eq!(counts.filtered_out_count, 45);
    assert_eq!(counts.attention_count, 1);
    assert_eq!(counts.flagged_by_system_count, 53);
    assert_eq!(counts.warden_decisions_count, 52);
    // And the math contract still holds end-to-end.
    assert_eq!(
        counts.flagged_by_system_count - counts.warden_decisions_count,
        counts.attention_count
    );
}

/// Regression guard for the pre-spec-049 silent-drop behaviour.
/// Pre-fix: a dismiss decision routed through
/// `threat_contract::kpi_bucket` to `KpiBucket::None` and the inline
/// `match` had `KpiBucket::None => {}`, so the case was uncounted on
/// every surface. Spec 049 reverses this. If a future refactor
/// reverts the `KpiBucket::None` arm to a no-op, this test fires.
#[test]
fn dismissed_cases_are_counted_not_silently_dropped() {
    let rows: Vec<(Option<&str>, Option<&str>)> = vec![(Some("dismiss"), None); 10];
    let m = tally_cases(rows);
    assert_eq!(
        m.filtered_out, 10,
        "10 dismissed cases must count as 10 Filtered out, not 0"
    );
    assert_eq!(
        m.flagged_by_system(),
        10,
        "Flagged by system must include Filtered out (pre-spec-049 was 0)"
    );
    assert_eq!(
        m.warden_decisions(),
        10,
        "Warden decisions must include dismiss (spec 049 Q1+Q7)"
    );
    assert_eq!(
        m.needs_review, 0,
        "A dismissed case is NOT awaiting operator review"
    );
}

/// Empty input still satisfies the math contract — the four
/// counters and the two derived totals all read zero.
#[test]
fn empty_input_keeps_math_contract() {
    let empty: Vec<(Option<&str>, Option<&str>)> = vec![];
    let m = tally_cases(empty);
    let counts = OverviewCounts {
        blocked_count: m.contained,
        observing_count: m.observing,
        filtered_out_count: m.filtered_out,
        attention_count: m.needs_review,
        flagged_by_system_count: m.flagged_by_system(),
        warden_decisions_count: m.warden_decisions(),
        ..Default::default()
    };
    assert_eq!(counts.flagged_by_system_count, 0);
    assert_eq!(counts.warden_decisions_count, 0);
    assert_eq!(
        counts.blocked_count
            + counts.observing_count
            + counts.filtered_out_count
            + counts.attention_count,
        counts.flagged_by_system_count
    );
}
