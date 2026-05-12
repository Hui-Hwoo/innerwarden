//! Spec 049 — "Auditable Cases Dashboard" math contract.
//!
//! Layered ON TOP of the existing [`super::threat_contract`] taxonomy.
//! Where `threat_contract` classifies one `(decision, exec_result)` pair
//! into one of five outcome strings plus a four-bucket [`KpiBucket`],
//! this module folds those into the four operator-visible **case
//! outcomes** the Home strip displays:
//!
//! | `CaseOutcome` | Comes from `KpiBucket` | Spec 049 meaning |
//! |---|---|---|
//! | `Contained`   | `Blocked`    | "houve ação defensiva efetiva (block ou honeypot)" |
//! | `Observing`   | `Observing`  | "segue em monitoramento" |
//! | `FilteredOut` | `None`       | "analisado e encerrado como baixo risco/ruído (decisão Warden, não lixeira)" |
//! | `NeedsReview` | `Attention`  | "o sistema não encerrou sozinho" |
//!
//! And asserts the math contract spec 049 commits to:
//!
//! ```text
//! Flagged by system = Contained + Observing + FilteredOut + NeedsReview
//! Warden decisions  = Contained + Observing + FilteredOut
//! NeedsReview       = Flagged by system - Warden decisions
//! ```
//!
//! Pre-spec-049 the dashboard summed `blocked + observing + attention`
//! but `dismiss` was dropped to `KpiBucket::None` and silently
//! uncounted, so the operator saw a "Warden decisions" tile that did
//! not include the most common decision (dismiss-as-noise). Spec 049
//! Q1+Q7 reversed that: dismiss IS a Warden decision and belongs in
//! the funnel. This module is the single place where that semantic
//! shift lives — every consumer goes through this function so a
//! future revert lights up the regression tests.

use super::threat_contract::{self, KpiBucket};

/// Spec 049 case outcomes — the operator-facing taxonomy.
///
/// The production path in `data_api.rs` populates [`CaseMetrics`]
/// directly from already-bucketed leaf counters; the enum + helpers
/// below exist for the test layer to assert the math contract and
/// for a future PR that may refactor the inline `match` into a
/// `tally_cases` call. `#[allow(dead_code)]` documents that intent.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CaseOutcome {
    Contained,
    Observing,
    FilteredOut,
    NeedsReview,
}

/// Aggregate counts for spec 049's four-outcome model.
///
/// Fields are `pub(super)` so the SQLite compute path and the KG
/// fallback can both build a `CaseMetrics` and the `OverviewResponse`
/// mapper can read the four counters directly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CaseMetrics {
    pub(super) contained: usize,
    pub(super) observing: usize,
    pub(super) filtered_out: usize,
    pub(super) needs_review: usize,
}

impl CaseMetrics {
    /// `Flagged by system = sum of all four outcomes`.
    ///
    /// The volume number the MSSP operator quotes to their client:
    /// "essa noite processamos 53 tentativas na sua infra".
    pub(super) fn flagged_by_system(&self) -> usize {
        self.contained + self.observing + self.filtered_out + self.needs_review
    }

    /// `Warden decisions = Contained + Observing + FilteredOut`.
    ///
    /// The "operator did not have to act" number. Dismiss is a
    /// decision, not a no-op (spec 049 Q1+Q7).
    pub(super) fn warden_decisions(&self) -> usize {
        self.contained + self.observing + self.filtered_out
    }
}

/// Map a [`KpiBucket`] to a spec-049 [`CaseOutcome`].
///
/// `KpiBucket::None` (dismissed/ignored) was silently excluded from
/// KPIs pre-spec-049. Spec 049 Q1+Q7 decided dismiss is a Warden
/// decision and belongs in the funnel — this mapping pins that
/// decision and is the only place it should live.
#[allow(dead_code)]
pub(super) fn case_outcome_from_kpi_bucket(b: KpiBucket) -> CaseOutcome {
    match b {
        KpiBucket::Blocked => CaseOutcome::Contained,
        KpiBucket::Observing => CaseOutcome::Observing,
        KpiBucket::None => CaseOutcome::FilteredOut, // spec 049 Q1+Q7
        KpiBucket::Attention => CaseOutcome::NeedsReview,
    }
}

/// Convenience: classify a `(decision, exec_result)` pair into a
/// [`CaseOutcome`] in one call, routing through `threat_contract`.
#[allow(dead_code)]
pub(super) fn case_outcome_from_decision(
    decision: Option<&str>,
    exec_result: Option<&str>,
) -> CaseOutcome {
    let outcome = threat_contract::classify_decision(decision, exec_result);
    let bucket = threat_contract::kpi_bucket(outcome);
    case_outcome_from_kpi_bucket(bucket)
}

/// Tally a stream of `(decision, exec_result)` pairs into a
/// [`CaseMetrics`]. Used by the KG fallback path which iterates
/// in-memory incidents; the SQLite path builds `CaseMetrics`
/// directly from the typed bucket aggregates.
#[allow(dead_code)]
pub(super) fn tally_cases<I, D, E>(iter: I) -> CaseMetrics
where
    I: IntoIterator<Item = (Option<D>, Option<E>)>,
    D: AsRef<str>,
    E: AsRef<str>,
{
    let mut m = CaseMetrics::default();
    for (d, e) in iter {
        let d_ref: Option<&str> = d.as_ref().map(AsRef::as_ref);
        let e_ref: Option<&str> = e.as_ref().map(AsRef::as_ref);
        match case_outcome_from_decision(d_ref, e_ref) {
            CaseOutcome::Contained => m.contained += 1,
            CaseOutcome::Observing => m.observing += 1,
            CaseOutcome::FilteredOut => m.filtered_out += 1,
            CaseOutcome::NeedsReview => m.needs_review += 1,
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flagged_by_system_eq_sum_of_four_outcomes() {
        let m = CaseMetrics {
            contained: 4,
            observing: 3,
            filtered_out: 45,
            needs_review: 1,
        };
        assert_eq!(m.flagged_by_system(), 53);
    }

    #[test]
    fn warden_decisions_excludes_needs_review() {
        let m = CaseMetrics {
            contained: 4,
            observing: 3,
            filtered_out: 45,
            needs_review: 1,
        };
        // The 1 needs_review case is the only one the operator must look at.
        assert_eq!(m.warden_decisions(), 52);
        // Math contract: flagged - warden_decisions = needs_review.
        assert_eq!(m.flagged_by_system() - m.warden_decisions(), m.needs_review);
    }

    #[test]
    fn empty_metrics_reconcile_to_zero() {
        let m = CaseMetrics::default();
        assert_eq!(m.flagged_by_system(), 0);
        assert_eq!(m.warden_decisions(), 0);
    }

    #[test]
    fn dismissed_kpi_bucket_maps_to_filtered_out_not_dropped() {
        // Pre-spec-049 behaviour: `KpiBucket::None` silently uncounted.
        // Spec 049 Q1+Q7: dismiss is a Warden decision, belongs in the
        // funnel. Pin the semantic shift here so a future revert lights
        // up.
        assert_eq!(
            case_outcome_from_kpi_bucket(KpiBucket::None),
            CaseOutcome::FilteredOut
        );
    }

    #[test]
    fn kpi_bucket_mapping_is_total_and_canonical() {
        // Every `KpiBucket` variant must map to exactly one
        // `CaseOutcome`. If a new `KpiBucket` variant lands without a
        // corresponding `CaseOutcome` mapping, this test forces the
        // author to decide instead of falling through to a silent
        // default.
        assert_eq!(
            case_outcome_from_kpi_bucket(KpiBucket::Blocked),
            CaseOutcome::Contained
        );
        assert_eq!(
            case_outcome_from_kpi_bucket(KpiBucket::Observing),
            CaseOutcome::Observing
        );
        assert_eq!(
            case_outcome_from_kpi_bucket(KpiBucket::None),
            CaseOutcome::FilteredOut
        );
        assert_eq!(
            case_outcome_from_kpi_bucket(KpiBucket::Attention),
            CaseOutcome::NeedsReview
        );
    }

    #[test]
    fn case_outcome_from_decision_routes_through_threat_contract() {
        // block_ip + ok-exec → Contained
        assert_eq!(
            case_outcome_from_decision(Some("block_ip"), Some("ok")),
            CaseOutcome::Contained
        );
        // honeypot + ok-exec → Contained (containment via deception)
        assert_eq!(
            case_outcome_from_decision(Some("honeypot"), Some("ok")),
            CaseOutcome::Contained
        );
        // monitor + ok-exec → Observing
        assert_eq!(
            case_outcome_from_decision(Some("monitor"), Some("ok")),
            CaseOutcome::Observing
        );
        // dismiss (any exec) → FilteredOut (the spec 049 signature shift)
        assert_eq!(
            case_outcome_from_decision(Some("dismiss"), None),
            CaseOutcome::FilteredOut
        );
        assert_eq!(
            case_outcome_from_decision(Some("ignore"), None),
            CaseOutcome::FilteredOut
        );
        // no decision yet → NeedsReview
        assert_eq!(
            case_outcome_from_decision(None, None),
            CaseOutcome::NeedsReview
        );
        // failed exec on block_ip → NeedsReview (block did not happen)
        assert_eq!(
            case_outcome_from_decision(Some("block_ip"), Some("error: rejected")),
            CaseOutcome::NeedsReview
        );
    }

    #[test]
    fn tally_cases_classifies_spec_049_prod_screenshot_input() {
        // Operator's prod input from the spec 049 screenshot (the
        // original number-confusion that motivated the whole spec):
        // 4 block + 3 observing + 45 dismissed + 1 needs review.
        let rows: Vec<(Option<&str>, Option<&str>)> = std::iter::empty()
            .chain(std::iter::repeat((Some("block_ip"), Some("ok"))).take(4))
            .chain(std::iter::repeat((Some("monitor"), Some("ok"))).take(3))
            .chain(std::iter::repeat((Some("dismiss"), None)).take(45))
            .chain(std::iter::repeat((None, None)).take(1))
            .collect();
        let m = tally_cases(rows);
        assert_eq!(m.contained, 4);
        assert_eq!(m.observing, 3);
        assert_eq!(m.filtered_out, 45);
        assert_eq!(m.needs_review, 1);
        // Math contract holds end-to-end on real-shape input.
        assert_eq!(m.flagged_by_system(), 53);
        assert_eq!(m.warden_decisions(), 52);
        assert_eq!(m.flagged_by_system() - m.warden_decisions(), m.needs_review);
    }

    #[test]
    fn tally_cases_handles_empty_iterator() {
        let empty: Vec<(Option<&str>, Option<&str>)> = vec![];
        let m = tally_cases(empty);
        assert_eq!(m, CaseMetrics::default());
        assert_eq!(m.flagged_by_system(), 0);
    }

    #[test]
    fn tally_cases_buckets_honeypot_into_contained() {
        // Honeypot is a containment action per spec 049 §5.2:
        // "houve ação defensiva efetiva, como block ou honeypot".
        let rows: Vec<(Option<&str>, Option<&str>)> = vec![
            (Some("honeypot"), Some("ok")),
            (Some("honeypot"), Some("ok")),
        ];
        let m = tally_cases(rows);
        assert_eq!(m.contained, 2);
        assert_eq!(m.observing, 0);
        assert_eq!(m.filtered_out, 0);
        assert_eq!(m.needs_review, 0);
    }

    #[test]
    fn tally_cases_buckets_escalate_and_unknown_into_needs_review() {
        // `escalate` + `request_confirmation` + unknown decisions all
        // route to `OUTCOME_OPEN` → NeedsReview per spec 049 principle
        // 8 (no silent drop).
        let rows: Vec<(Option<&str>, Option<&str>)> = vec![
            (Some("future_unknown_action_x"), None),
            (Some("escalate"), None),
            (Some("request_confirmation"), None),
        ];
        let m = tally_cases(rows);
        assert_eq!(m.needs_review, 3);
        assert_eq!(m.contained, 0);
        assert_eq!(m.observing, 0);
        assert_eq!(m.filtered_out, 0);
    }

    #[test]
    fn tally_cases_accepts_string_and_str_input() {
        // The SQLite path reads `Option<String>` rows; the KG path
        // passes `&str`. Both must work without copies on the caller
        // side.
        let owned: Vec<(Option<String>, Option<String>)> = vec![
            (Some("block_ip".to_string()), Some("ok".to_string())),
            (Some("dismiss".to_string()), None),
        ];
        let m_owned = tally_cases(owned);
        let borrowed: Vec<(Option<&str>, Option<&str>)> =
            vec![(Some("block_ip"), Some("ok")), (Some("dismiss"), None)];
        let m_borrowed = tally_cases(borrowed);
        assert_eq!(m_owned, m_borrowed);
    }
}
