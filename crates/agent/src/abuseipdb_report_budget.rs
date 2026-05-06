//! AbuseIPDB report-endpoint rate limiter.
//!
//! The free tier grants 1,000 calls/day on each endpoint. `incident_enrichment`
//! already gates the *check* endpoint via `ABUSEIPDB_DAILY_LIMIT = 800` and a
//! 24h per-IP cache. The *report* endpoint had no such guard — a production
//! incident on 2026-04-18 proved the gap: a `correlation:CL-008` cascade
//! against Cloudflare CIDRs queued ~900 reports in a single day and the
//! operator received the "You've exhausted your daily limit of 1,000 requests
//! for report endpoint" email from AbuseIPDB.
//!
//! This module mirrors the check-endpoint pattern onto the report path:
//!
//! * **Per-IP dedup** with 24h TTL — the same source being reblocked five
//!   times in a day only costs one report, not five.
//! * **Daily hard cap** at 800 by default (`cfg.abuseipdb.report_daily_cap`),
//!   leaving 20% headroom for operator-triggered ad-hoc reports.
//!
//! The pre-existing `cloud_safelist` guard in the slow-loop remains the first
//! line of defence; this module catches the *volume* failure mode that the
//! safelist cannot (e.g. a true-positive ssh_bruteforce storm from 1k unique
//! IPs in one hour).

use innerwarden_store::Store;
use tracing::{info, warn};

/// SQLite KV namespace holding `ip → "1"` entries with a 24h TTL for dedup.
pub(crate) const REPORTED_NS: &str = "abuseipdb_reported";
/// SQLite KV namespace holding `abuseipdb_report_daily_<YYYY-MM-DD>` counters.
pub(crate) const LIMITS_NS: &str = "abuseipdb_report_limits";

/// Outcome of a budget check. `Allow` carries a `Commit` value the caller
/// must hand back to `apply` after a successful `client.report()` call so
/// the counter + dedup entry land in sqlite.
pub(crate) enum ReportBudgetDecision {
    Allow(ReportBudgetCommit),
    Reject(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// The IP already has a dedup entry for the current 24h window.
    AlreadyReportedToday,
    /// The daily counter has reached the configured cap.
    DailyCapReached,
}

impl RejectReason {
    /// Human-readable tag used in logs and the `/metrics` label.
    pub(crate) fn as_metric_label(&self) -> &'static str {
        match self {
            RejectReason::AlreadyReportedToday => "already_reported",
            RejectReason::DailyCapReached => "daily_cap",
        }
    }
}

/// Receipt that must be consumed via `apply` after a successful report.
pub(crate) struct ReportBudgetCommit {
    ip: String,
    today: String,
    new_count: u32,
}

impl ReportBudgetCommit {
    /// Persist the counter increment + the per-IP dedup entry. Kept separate
    /// from the check so the caller can only pay the quota cost *after* the
    /// HTTP call actually succeeded (a failed `report()` should not count
    /// against the cap or block retries).
    pub(crate) fn apply(&self, store: &Store) {
        let key = format!("abuseipdb_report_daily_{}", self.today);
        let _ = store.kv_set(LIMITS_NS, &key, self.new_count.to_string().as_bytes());
        let expiry = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        let _ = store.kv_set_with_expiry(REPORTED_NS, &self.ip, b"1", Some(&expiry));
    }

    /// Test-only accessor for the counter value the commit will write.
    #[cfg(test)]
    pub(crate) fn new_count(&self) -> u32 {
        self.new_count
    }
}

/// Counters emitted by `dispatch_flush_outcomes`. Copied into the slow-loop
/// log lines and `/metrics` counters downstream.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlushCounts {
    pub sent: usize,
    pub dropped_cloud: usize,
    pub dropped_dedup: usize,
    pub dropped_cap: usize,
    /// Top-5 #4 (AUDIT-WAVE-T5-4, 2026-05-06): HTTP `client.report()`
    /// returned `false` (transport error / non-2xx). The in-flight slot
    /// is released and the daily cap is NOT consumed — the same IP can
    /// re-enter the queue and be retried on the next flush. Pre-fix the
    /// `report_fn` closure swallowed the bool and `commit.apply()`
    /// always ran, which meant a 502 from the AbuseIPDB endpoint would
    /// permanently consume one slot of the operator's daily 800 quota
    /// for nothing. Operator-visible: `/metrics` counter
    /// `dropped_failed` and `WARN`-level log line.
    pub dropped_failed: usize,
}

/// Drive every `FlushOutcome` to completion. For `Send` outcomes invokes
/// `report_fn(ip, categories, comment)` (mockable in tests). If the
/// report call returns `true` (HTTP success), applies the budget commit
/// against `store` and counts the report as `sent`. If it returns
/// `false` (transport error / non-2xx), the commit is skipped — the
/// daily quota is preserved and the IP can be retried on the next
/// flush — and `dropped_failed` is incremented. `Skip`/`SkipCloud`
/// outcomes just bump the matching counter.
///
/// The slow loop passes a closure that calls `client.report(...)`,
/// which already returns `bool`. Unit tests pass a counting closure
/// returning `true` (or `false` to simulate HTTP failure) so the whole
/// dispatch table is covered without a live HTTP endpoint.
///
/// Top-5 #4 (AUDIT-WAVE-T5-4, 2026-05-06): pre-fix `report_fn` was
/// `Future<Output = ()>` and `commit.apply()` always ran. A 5xx from
/// AbuseIPDB would permanently consume a slot of the operator's daily
/// 800 quota for nothing — eventually `dropped_cap` would fire on
/// genuine attacker IPs the operator wanted reported. The
/// `Future<Output = bool>` shape makes the success contract explicit.
pub(crate) async fn dispatch_flush_outcomes<F, Fut>(
    outcomes: Vec<FlushOutcome>,
    store: Option<&Store>,
    mut report_fn: F,
) -> FlushCounts
where
    F: FnMut(String, String, String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut counts = FlushCounts::default();
    for outcome in outcomes {
        match outcome {
            FlushOutcome::SkipCloud { ip, provider } => {
                counts.dropped_cloud += 1;
                warn!(
                    ip = %ip,
                    provider,
                    "AbuseIPDB report dropped: target is in cloud safelist"
                );
            }
            FlushOutcome::Skip { ip, reason } => {
                match reason {
                    RejectReason::AlreadyReportedToday => counts.dropped_dedup += 1,
                    RejectReason::DailyCapReached => counts.dropped_cap += 1,
                }
                warn!(
                    ip = %ip,
                    reason = reason.as_metric_label(),
                    "AbuseIPDB report skipped by budget gate"
                );
            }
            FlushOutcome::Send {
                ip,
                categories,
                comment,
                commit,
            } => {
                let ip_for_log = ip.clone();
                let ok = report_fn(ip, categories, comment).await;
                if ok {
                    counts.sent += 1;
                    info!(ip = %ip_for_log, "AbuseIPDB report sent (after 5min delay)");
                    if let (Some(sq), Some(commit)) = (store, commit) {
                        commit.apply(sq);
                    }
                } else {
                    counts.dropped_failed += 1;
                    warn!(
                        ip = %ip_for_log,
                        "AbuseIPDB report failed: HTTP error, daily quota preserved (will retry on next flush)"
                    );
                }
            }
        }
    }
    counts
}

/// Outcome of planning a single queue entry for flush. Carries everything
/// the caller needs to either dispatch the HTTP call + commit the receipt,
/// or log + bump the matching drop counter. The planner stays I/O-free so
/// the slow-loop flush logic can be unit tested without a Tokio runtime
/// or a live AbuseIPDB client.
pub(crate) enum FlushOutcome {
    Send {
        ip: String,
        categories: String,
        comment: String,
        commit: Option<ReportBudgetCommit>,
    },
    SkipCloud {
        ip: String,
        provider: &'static str,
    },
    Skip {
        ip: String,
        reason: RejectReason,
    },
}

/// Compute the per-entry disposition for every ready queue item. Callers
/// (slow loop) iterate the returned vector and for each `Send` run
/// `client.report()` followed by `commit.apply()`; `SkipCloud` and `Skip`
/// are logged and counted for telemetry.
///
/// Parameters:
/// * `ready` — `(ip, comment, categories, queued_at)` tuples matching the
///   existing `state.abuseipdb_report_queue` shape.
/// * `store` — optional sqlite store; when absent (pre-spec-016 deploy /
///   test harness) the planner falls back to sending everything, which
///   mirrors pre-fix behaviour.
/// * `identify_provider` — cloud-safelist lookup; factored out so tests
///   can inject a stub table.
/// * `today`, `daily_cap` — forwarded into `check_report_budget`.
pub(crate) fn plan_queue_flush<F>(
    ready: &[(String, String, String, chrono::DateTime<chrono::Utc>)],
    store: Option<&Store>,
    identify_provider: F,
    today: &str,
    daily_cap: u32,
) -> Vec<FlushOutcome>
where
    F: Fn(&str) -> Option<&'static str>,
{
    let mut out = Vec::with_capacity(ready.len());
    // Wave 3 (AUDIT-WAVE3-BURST-CAP, 2026-05-04 ultrareview): in-batch
    // counter so a single flush cannot bypass the daily cap. Pre-fix
    // every entry called `check_report_budget` independently and the
    // KV counter was only persisted by `commit.apply()` AFTER the
    // network call. A flush of 100 items with the counter at 750 and
    // a 800 cap would therefore plan 100 `Send` outcomes (each call
    // saw 750 < 800), then dispatch would push the persisted counter
    // to 850 - 50 over cap. The fix tracks the in-flight planned
    // increment locally so the (count + planned) >= cap check fires
    // mid-batch and the remaining items get skipped with the same
    // `DailyCapReached` reason the autonomous-block path uses.
    let mut planned_sends_this_batch: u32 = 0;
    for (ip, comment, categories, _) in ready {
        if let Some(provider) = identify_provider(ip) {
            out.push(FlushOutcome::SkipCloud {
                ip: ip.clone(),
                provider,
            });
            continue;
        }

        let commit = match store {
            Some(sq) => {
                // Adjusted cap: subtract the in-batch planned sends so
                // the next planning call sees the budget that WOULD
                // exist after this batch's dispatch. Saturating sub
                // floors at zero so a burst much larger than `daily_cap`
                // still gets rejected uniformly.
                let effective_cap = daily_cap.saturating_sub(planned_sends_this_batch);
                match check_report_budget(sq, ip, today, effective_cap) {
                    ReportBudgetDecision::Allow(c) => Some(c),
                    ReportBudgetDecision::Reject(reason) => {
                        out.push(FlushOutcome::Skip {
                            ip: ip.clone(),
                            reason,
                        });
                        continue;
                    }
                }
            }
            None => None,
        };

        planned_sends_this_batch = planned_sends_this_batch.saturating_add(1);
        out.push(FlushOutcome::Send {
            ip: ip.clone(),
            categories: categories.clone(),
            comment: comment.clone(),
            commit,
        });
    }
    out
}

/// Inspect the dedup + counter state for `ip` on `today`. Returns `Allow`
/// with a pending commit, or `Reject(reason)` to be logged and skipped.
///
/// `today` must be an ISO date string (`YYYY-MM-DD`) derived from the call
/// site's own `chrono::Local::now()` — the helper stays testable without a
/// real clock.
pub(crate) fn check_report_budget(
    store: &Store,
    ip: &str,
    today: &str,
    daily_cap: u32,
) -> ReportBudgetDecision {
    // 1. Per-IP dedup: if we already reported this IP within the 24h TTL
    //    window, skip outright. The KV entry's `expires_at` column does the
    //    garbage collection (swept by the existing `kv_cleanup_expired`
    //    maintenance task), so no manual cleanup here.
    if store.kv_get(REPORTED_NS, ip).ok().flatten().is_some() {
        return ReportBudgetDecision::Reject(RejectReason::AlreadyReportedToday);
    }

    // 2. Daily cap: parse `YYYY-MM-DD` counter or default to 0 if absent /
    //    corrupt. `daily_cap == 0` short-circuits to rejecting every report
    //    (effectively disables the report path without touching cfg.enabled).
    let key = format!("abuseipdb_report_daily_{today}");
    let count = store
        .kv_get_str(LIMITS_NS, &key)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    if count >= daily_cap {
        return ReportBudgetDecision::Reject(RejectReason::DailyCapReached);
    }

    ReportBudgetDecision::Allow(ReportBudgetCommit {
        ip: ip.to_string(),
        today: today.to_string(),
        new_count: count + 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_store() -> Store {
        Store::open_memory().expect("memory store")
    }

    fn allow_or_panic(d: ReportBudgetDecision) -> ReportBudgetCommit {
        match d {
            ReportBudgetDecision::Allow(c) => c,
            ReportBudgetDecision::Reject(r) => panic!("expected Allow, got Reject({:?})", r),
        }
    }

    fn reject_or_panic(d: ReportBudgetDecision) -> RejectReason {
        match d {
            ReportBudgetDecision::Reject(r) => r,
            ReportBudgetDecision::Allow(_) => panic!("expected Reject, got Allow"),
        }
    }

    #[test]
    fn allow_on_empty_store() {
        let store = mem_store();
        let commit = allow_or_panic(check_report_budget(&store, "1.2.3.4", "2026-04-18", 800));
        assert_eq!(commit.new_count(), 1, "first report bumps counter to 1");
    }

    #[test]
    fn apply_writes_counter_and_dedup_entry() {
        let store = mem_store();
        let commit = allow_or_panic(check_report_budget(&store, "1.2.3.4", "2026-04-18", 800));
        commit.apply(&store);

        let raw = store
            .kv_get_str(LIMITS_NS, "abuseipdb_report_daily_2026-04-18")
            .expect("kv_get")
            .expect("counter written");
        assert_eq!(raw, "1");

        let dedup = store
            .kv_get(REPORTED_NS, "1.2.3.4")
            .expect("kv_get")
            .expect("dedup entry written");
        assert_eq!(dedup, b"1");
    }

    #[test]
    fn second_report_for_same_ip_is_rejected_as_dedup() {
        let store = mem_store();
        let first = allow_or_panic(check_report_budget(&store, "1.2.3.4", "2026-04-18", 800));
        first.apply(&store);

        let second = check_report_budget(&store, "1.2.3.4", "2026-04-18", 800);
        assert_eq!(reject_or_panic(second), RejectReason::AlreadyReportedToday);
    }

    #[test]
    fn different_ips_each_consume_one_quota_unit() {
        let store = mem_store();
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"] {
            let c = allow_or_panic(check_report_budget(&store, ip, "2026-04-18", 800));
            c.apply(&store);
        }
        let count = store
            .kv_get_str(LIMITS_NS, "abuseipdb_report_daily_2026-04-18")
            .unwrap()
            .unwrap();
        assert_eq!(count, "3");
    }

    #[test]
    fn daily_cap_rejects_further_reports() {
        let store = mem_store();
        // Seed the counter one below the cap so the next call would tip over.
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"799")
            .expect("seed counter");
        let ok = allow_or_panic(check_report_budget(&store, "7.7.7.7", "2026-04-18", 800));
        assert_eq!(
            ok.new_count(),
            800,
            "final slot allocates at exactly the cap"
        );
        ok.apply(&store);

        // 801st attempt — counter is at cap, cache miss for the IP, must
        // reject with DailyCapReached (not dedup).
        let over = check_report_budget(&store, "8.8.8.8", "2026-04-18", 800);
        assert_eq!(reject_or_panic(over), RejectReason::DailyCapReached);
    }

    #[test]
    fn daily_cap_zero_blocks_every_report() {
        // cfg.abuseipdb.report_daily_cap = 0 is a sentinel meaning "pause
        // reporting" — useful when operators suspect the bug hasn't rolled
        // out yet and want to stop sending evidence until they investigate.
        let store = mem_store();
        let d = check_report_budget(&store, "1.2.3.4", "2026-04-18", 0);
        assert_eq!(reject_or_panic(d), RejectReason::DailyCapReached);
    }

    #[test]
    fn reject_reason_metric_labels_are_stable() {
        // Labels are consumed as Prometheus histogram dimensions downstream;
        // a silent rename here would break operator dashboards.
        assert_eq!(
            RejectReason::AlreadyReportedToday.as_metric_label(),
            "already_reported"
        );
        assert_eq!(RejectReason::DailyCapReached.as_metric_label(), "daily_cap");
    }

    #[test]
    fn counter_is_per_day_scope() {
        // The YYYY-MM-DD suffix in the counter key ensures yesterday's
        // exhausted cap doesn't block today's legitimate reports.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"800")
            .expect("seed cap-hit from yesterday");

        let ok = allow_or_panic(check_report_budget(&store, "1.2.3.4", "2026-04-19", 800));
        assert_eq!(ok.new_count(), 1, "new day starts counter fresh");
    }

    #[test]
    fn dedup_entry_carries_24h_expiry() {
        // The TTL is what lets the dedup namespace self-clean; without it
        // the `abuseipdb_reported` namespace would grow unbounded and a
        // real reblock after 48 hours would keep returning cached.
        let store = mem_store();
        let commit = allow_or_panic(check_report_budget(&store, "1.2.3.4", "2026-04-18", 800));
        commit.apply(&store);

        // Back-date the entry to 25 hours ago — `kv_cleanup_expired` should
        // purge it on the next maintenance tick, freeing the IP.
        store
            .kv_set_with_expiry(REPORTED_NS, "1.2.3.4", b"1", Some("2020-01-01T00:00:00Z"))
            .expect("override expiry");
        let deleted = store.kv_cleanup_expired().expect("sweep");
        assert_eq!(deleted, 1);

        // Fresh check should allow the re-report.
        let ok = check_report_budget(&store, "1.2.3.4", "2026-04-18", 800);
        assert!(matches!(ok, ReportBudgetDecision::Allow(_)));
    }

    fn queue_entry(ip: &str) -> (String, String, String, chrono::DateTime<chrono::Utc>) {
        (
            ip.to_string(),
            format!("InnerWarden auto-block: {ip}"),
            "18,22".to_string(),
            chrono::Utc::now(),
        )
    }

    fn no_cloud(_: &str) -> Option<&'static str> {
        None
    }

    #[test]
    fn plan_flushes_ip_with_no_budget_when_store_absent() {
        // Pre-spec-016 compat: without a store, the planner emits Send for
        // every entry (None commit) so legacy deploys keep reporting like
        // before. The inner gate still blocks cloud IPs via the safelist
        // predicate though.
        let ready = vec![queue_entry("1.2.3.4")];
        let outcomes = plan_queue_flush(&ready, None, no_cloud, "2026-04-18", 800);
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            FlushOutcome::Send { ip, commit, .. } => {
                assert_eq!(ip, "1.2.3.4");
                assert!(commit.is_none());
            }
            other => panic!("expected Send, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[test]
    fn plan_bucks_cloud_ips_into_skip_cloud() {
        // Cloud-safelist guard runs before the budget, matching the slow
        // loop's defence ordering in `loops/boot.rs`.
        let ready = vec![queue_entry("104.26.12.38"), queue_entry("1.2.3.4")];
        let outcomes = plan_queue_flush(
            &ready,
            Some(&mem_store()),
            |ip| {
                if ip.starts_with("104.") {
                    Some("Cloudflare")
                } else {
                    None
                }
            },
            "2026-04-18",
            800,
        );
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(
            outcomes[0],
            FlushOutcome::SkipCloud { ref provider, .. } if *provider == "Cloudflare"
        ));
        assert!(matches!(outcomes[1], FlushOutcome::Send { .. }));
    }

    #[test]
    fn plan_marks_duplicate_ip_as_skip_with_reason() {
        let store = mem_store();
        // Seed the dedup entry so the second call rejects.
        let first = check_report_budget(&store, "1.2.3.4", "2026-04-18", 800);
        if let ReportBudgetDecision::Allow(c) = first {
            c.apply(&store);
        }

        let ready = vec![queue_entry("1.2.3.4")];
        let outcomes = plan_queue_flush(&ready, Some(&store), no_cloud, "2026-04-18", 800);
        match &outcomes[0] {
            FlushOutcome::Skip { reason, .. } => {
                assert_eq!(*reason, RejectReason::AlreadyReportedToday);
            }
            other => panic!("expected Skip, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[test]
    fn plan_skip_cap_when_counter_at_limit() {
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"800")
            .expect("seed cap-hit");
        let ready = vec![queue_entry("9.9.9.9")];
        let outcomes = plan_queue_flush(&ready, Some(&store), no_cloud, "2026-04-18", 800);
        match &outcomes[0] {
            FlushOutcome::Skip { reason, .. } => {
                assert_eq!(*reason, RejectReason::DailyCapReached);
            }
            other => panic!("expected Skip, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[tokio::test]
    async fn dispatch_empty_outcomes_returns_zero_counts_and_never_calls_reporter() {
        // Fast-path: empty ready queue → zero HTTP cost and zero sqlite writes.
        let mut calls = 0usize;
        let counts = dispatch_flush_outcomes(Vec::new(), None, |_, _, _| {
            calls += 1;
            async { true }
        })
        .await;
        assert_eq!(calls, 0);
        assert_eq!(counts, FlushCounts::default());
    }

    #[tokio::test]
    async fn plan_empty_queue_produces_empty_outcomes() {
        // Defensive check — the planner should tolerate an empty
        // `state.abuseipdb_report_queue` without touching the store or
        // the safelist predicate.
        let outcomes = plan_queue_flush(
            &[],
            None,
            |_| panic!("safelist predicate should not be called on empty queue"),
            "2026-04-18",
            800,
        );
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn dispatch_send_without_commit_still_fires_reporter() {
        // Covers the pre-016 branch: `commit = None` means no sqlite write
        // but the reporter must still be called with the original fields.
        let outcomes = vec![FlushOutcome::Send {
            ip: "203.0.113.1".into(),
            categories: "18".into(),
            comment: "hi".into(),
            commit: None,
        }];
        let mut calls = Vec::new();
        let counts = dispatch_flush_outcomes(outcomes, None, |ip, cats, cmt| {
            calls.push((ip, cats, cmt));
            async { true }
        })
        .await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "203.0.113.1");
        assert_eq!(counts.sent, 1);
    }

    #[tokio::test]
    async fn dispatch_send_commit_but_no_store_is_a_noop() {
        // Guard: `Send { commit: Some(_), .. }` paired with `store = None`
        // (rare — the planner only emits `Some(commit)` when the store is
        // present, but unit tests can construct this by hand). Must not
        // panic; the commit is silently dropped since no backing store
        // exists to apply it to.
        let store = mem_store();
        let commit = match check_report_budget(&store, "1.2.3.4", "2026-04-18", 800) {
            ReportBudgetDecision::Allow(c) => c,
            _ => panic!("expected allow"),
        };
        let outcomes = vec![FlushOutcome::Send {
            ip: "1.2.3.4".into(),
            categories: "18".into(),
            comment: "c".into(),
            commit: Some(commit),
        }];
        let mut calls = 0usize;
        let counts = dispatch_flush_outcomes(outcomes, None, |_, _, _| {
            calls += 1;
            async { true }
        })
        .await;
        assert_eq!(calls, 1);
        assert_eq!(counts.sent, 1);
    }

    #[tokio::test]
    async fn dispatch_counts_each_outcome_kind_and_commits_allowed_sends() {
        // Full dispatch matrix through a mock report closure. Drives every
        // branch in dispatch_flush_outcomes so boot.rs only needs to wire
        // the closure + log the counters.
        let store = mem_store();
        let allow_commit = match check_report_budget(&store, "198.51.100.1", "2026-04-18", 800) {
            ReportBudgetDecision::Allow(c) => c,
            _ => panic!("expected allow"),
        };
        let outcomes = vec![
            FlushOutcome::Send {
                ip: "198.51.100.1".into(),
                categories: "18".into(),
                comment: "atk".into(),
                commit: Some(allow_commit),
            },
            FlushOutcome::SkipCloud {
                ip: "104.26.12.38".into(),
                provider: "Cloudflare",
            },
            FlushOutcome::Skip {
                ip: "1.2.3.4".into(),
                reason: RejectReason::AlreadyReportedToday,
            },
            FlushOutcome::Skip {
                ip: "5.6.7.8".into(),
                reason: RejectReason::DailyCapReached,
            },
        ];

        let mut sent_ips = Vec::new();
        let counts = dispatch_flush_outcomes(outcomes, Some(&store), |ip, cats, _comment| {
            sent_ips.push((ip, cats));
            async { true }
        })
        .await;

        assert_eq!(
            counts,
            FlushCounts {
                sent: 1,
                dropped_cloud: 1,
                dropped_dedup: 1,
                dropped_cap: 1,
                dropped_failed: 0,
            }
        );
        assert_eq!(sent_ips.len(), 1);
        assert_eq!(sent_ips[0].0, "198.51.100.1");

        // Commit applied — second plan call for same IP must now reject.
        let follow_up = check_report_budget(&store, "198.51.100.1", "2026-04-18", 800);
        assert!(matches!(follow_up, ReportBudgetDecision::Reject(_)));
    }

    #[tokio::test]
    async fn dispatch_skips_commit_when_store_absent() {
        // Pre-spec-016 safety: with `store = None`, plan emits `Send { commit: None }`,
        // and dispatch must not panic trying to apply it. The reporter fires,
        // but no counter/dedup persists.
        let outcomes = vec![FlushOutcome::Send {
            ip: "1.2.3.4".into(),
            categories: "18".into(),
            comment: "c".into(),
            commit: None,
        }];
        let mut calls = 0usize;
        let counts = dispatch_flush_outcomes(outcomes, None, |_, _, _| {
            calls += 1;
            async { true }
        })
        .await;
        assert_eq!(calls, 1);
        assert_eq!(counts.sent, 1);
    }

    #[test]
    fn plan_preserves_queue_order_and_fields() {
        // Callers (slow loop) rely on Send entries carrying the exact
        // comment + categories strings originally queued by
        // decision_block_ip. Regressing this would silently change what we
        // report to AbuseIPDB — worse than dropping the report.
        let ready = vec![
            (
                "1.1.1.1".to_string(),
                "comment-a".to_string(),
                "18".to_string(),
                chrono::Utc::now(),
            ),
            (
                "2.2.2.2".to_string(),
                "comment-b".to_string(),
                "22".to_string(),
                chrono::Utc::now(),
            ),
        ];
        let outcomes = plan_queue_flush(&ready, None, no_cloud, "2026-04-18", 800);
        match (&outcomes[0], &outcomes[1]) {
            (
                FlushOutcome::Send {
                    ip: i1,
                    comment: c1,
                    categories: cat1,
                    ..
                },
                FlushOutcome::Send {
                    ip: i2,
                    comment: c2,
                    categories: cat2,
                    ..
                },
            ) => {
                assert_eq!(i1, "1.1.1.1");
                assert_eq!(c1, "comment-a");
                assert_eq!(cat1, "18");
                assert_eq!(i2, "2.2.2.2");
                assert_eq!(c2, "comment-b");
                assert_eq!(cat2, "22");
            }
            _ => panic!("expected two Send outcomes in order"),
        }
    }

    #[test]
    fn corrupt_counter_value_treated_as_zero() {
        // If something writes garbage into the counter key the gate must
        // fail-open (allow the next report) rather than permanently locking
        // the operator out.
        let store = mem_store();
        store
            .kv_set(
                LIMITS_NS,
                "abuseipdb_report_daily_2026-04-18",
                b"not-a-number",
            )
            .expect("seed garbage");
        let ok = allow_or_panic(check_report_budget(&store, "1.2.3.4", "2026-04-18", 800));
        assert_eq!(ok.new_count(), 1);
    }

    // ── Wave 3 anchors (AUDIT-WAVE3-BURST-CAP) ────────────────────────
    //
    // Pre-fix `plan_queue_flush` called `check_report_budget` per-item,
    // and that check read the persisted KV counter. Since the counter
    // only updates AFTER a successful report (via `commit.apply()`),
    // every item in a single batch saw the SAME starting counter and
    // got `Allow`. A flush of N items with counter at C and cap K
    // would plan N sends if C < K, regardless of whether C+N exceeded
    // K. The fix tracks the in-batch planned increment locally so the
    // (count + planned) comparison fires mid-batch.

    #[test]
    fn plan_burst_within_cap_bypasses_pre_fix_but_now_caps_correctly() {
        // The exact prod failure shape: counter at 750, cap at 800,
        // batch of 100 ready items. Pre-fix: 100 Send outcomes
        // (effective post-dispatch counter 850 = 50 over cap).
        // Post-fix: 50 Send + 50 Skip(DailyCapReached).
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"750")
            .expect("seed counter");
        let ready: Vec<_> = (0..100)
            .map(|i| queue_entry(&format!("203.0.113.{i}")))
            .collect();
        let outcomes = plan_queue_flush(&ready, Some(&store), no_cloud, "2026-04-18", 800);
        let send_count = outcomes
            .iter()
            .filter(|o| matches!(o, FlushOutcome::Send { .. }))
            .count();
        let skip_cap_count = outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    FlushOutcome::Skip {
                        reason: RejectReason::DailyCapReached,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            send_count, 50,
            "exactly cap-counter (800-750) sends planned in one batch"
        );
        assert_eq!(
            skip_cap_count, 50,
            "remaining 50 items must skip with DailyCapReached"
        );
    }

    #[test]
    fn plan_keeps_normal_within_cap_passing_when_no_burst() {
        // Anti-regression for the in-batch counter accidentally
        // double-counting: 5 items at counter 0 cap 800 must all
        // plan as Send. Pre-fix this passed; the fix MUST NOT
        // regress it (e.g. by reading planned_sends before any
        // Send outcome accumulates).
        let store = mem_store();
        let ready: Vec<_> = (0..5)
            .map(|i| queue_entry(&format!("203.0.113.{i}")))
            .collect();
        let outcomes = plan_queue_flush(&ready, Some(&store), no_cloud, "2026-04-18", 800);
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, FlushOutcome::Send { .. }))
                .count(),
            5,
            "5 items at counter 0 cap 800 must all Send"
        );
    }

    #[test]
    fn plan_burst_exactly_at_remaining_cap_lands_no_skips() {
        // Boundary: counter 798, cap 800, batch of exactly 2. Both
        // Send. Pre-fix: also both Send. Post-fix MUST not regress:
        // first Send drops effective_cap to 1 and budget check sees
        // 798 < 1+798=799 = NO wait. The math is: effective_cap =
        // daily_cap.saturating_sub(planned_sends). Item 1: 800-0=800,
        // counter 798 < 800, Allow, planned=1. Item 2: 800-1=799,
        // counter 798 < 799, Allow, planned=2. Both Send. Correct.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"798")
            .expect("seed counter");
        let ready: Vec<_> = (0..2)
            .map(|i| queue_entry(&format!("203.0.113.{i}")))
            .collect();
        let outcomes = plan_queue_flush(&ready, Some(&store), no_cloud, "2026-04-18", 800);
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, FlushOutcome::Send { .. }))
                .count(),
            2,
            "exactly 2 sends at the boundary"
        );
    }

    #[test]
    fn plan_burst_one_over_remaining_cap_skips_the_overflow() {
        // Same boundary as above but batch of 3. Item 3 must skip.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"798")
            .expect("seed counter");
        let ready: Vec<_> = (0..3)
            .map(|i| queue_entry(&format!("203.0.113.{i}")))
            .collect();
        let outcomes = plan_queue_flush(&ready, Some(&store), no_cloud, "2026-04-18", 800);
        let sends = outcomes
            .iter()
            .filter(|o| matches!(o, FlushOutcome::Send { .. }))
            .count();
        let skips = outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    FlushOutcome::Skip {
                        reason: RejectReason::DailyCapReached,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(sends, 2, "first 2 fit the budget");
        assert_eq!(skips, 1, "third item skips at the cap");
    }

    #[test]
    fn plan_burst_with_cloud_safelist_does_not_consume_cap() {
        // Cloud safelist hits do NOT count toward the in-batch
        // planned counter (they go to SkipCloud, not Send). Anti-
        // regression for accidentally bumping `planned_sends_this_batch`
        // before the cloud-safelist short-circuit.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"799")
            .expect("seed counter");
        // First 5 items are all Cloudflare. The 6th is a real attacker.
        // Without the cap-only-on-Send fix, the cloud safelist hits
        // would consume planned slots and the legit item would skip.
        fn cloud_for_first_five(ip: &str) -> Option<&'static str> {
            if ip.starts_with("104.16.0.") {
                Some("Cloudflare")
            } else {
                None
            }
        }
        let mut ready: Vec<_> = (0..5)
            .map(|i| queue_entry(&format!("104.16.0.{i}")))
            .collect();
        ready.push(queue_entry("203.0.113.99"));
        let outcomes = plan_queue_flush(
            &ready,
            Some(&store),
            cloud_for_first_five,
            "2026-04-18",
            800,
        );
        let sends = outcomes
            .iter()
            .filter(|o| matches!(o, FlushOutcome::Send { .. }))
            .count();
        let skip_cloud = outcomes
            .iter()
            .filter(|o| matches!(o, FlushOutcome::SkipCloud { .. }))
            .count();
        assert_eq!(
            sends, 1,
            "real attacker must still Send (cap not eaten by safelist)"
        );
        assert_eq!(skip_cloud, 5);
    }

    // ── Top-5 #4 anchors (AUDIT-WAVE-T5-4, 2026-05-06) ────────────────────
    //
    // Pre-fix the report closure was `Future<Output = ()>` and
    // `commit.apply()` always ran, so a 5xx from AbuseIPDB still consumed
    // a slot of the operator's daily 800 quota. Eventually `dropped_cap`
    // would fire on genuine attacker IPs the operator wanted to report.
    //
    // The fix changes the closure shape to `Future<Output = bool>`. These
    // anchors pin: (a) HTTP failure does NOT increment the daily counter,
    // (b) HTTP failure does NOT write the per-IP dedup entry (so the same
    // IP can be retried on the next flush), (c) `dropped_failed` reflects
    // the failure for telemetry, and (d) the existing happy path keeps
    // working (HTTP success commits + sets sent counter).

    #[tokio::test]
    async fn dispatch_failed_report_preserves_daily_quota_and_dedup() {
        // Pre-fix this test would have failed: the counter would jump
        // from 750 to 751 even though the HTTP call returned false.
        // Post-fix the counter stays at 750 and the dedup entry is
        // absent, so the next flush can retry the same IP.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"750")
            .expect("seed counter");
        let commit = match check_report_budget(&store, "203.0.113.7", "2026-04-18", 800) {
            ReportBudgetDecision::Allow(c) => c,
            _ => panic!("expected allow"),
        };
        let outcomes = vec![FlushOutcome::Send {
            ip: "203.0.113.7".into(),
            categories: "18".into(),
            comment: "x".into(),
            commit: Some(commit),
        }];

        // Closure simulates HTTP failure (5xx / network error).
        let counts =
            dispatch_flush_outcomes(outcomes, Some(&store), |_, _, _| async { false }).await;

        assert_eq!(counts.sent, 0, "failed HTTP must not increment sent");
        assert_eq!(
            counts.dropped_failed, 1,
            "failure must increment dropped_failed"
        );

        // Counter unchanged: still 750, NOT 751.
        let stored = store
            .kv_get_str(LIMITS_NS, "abuseipdb_report_daily_2026-04-18")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(
            stored, "750",
            "daily counter must NOT advance on HTTP failure (got {stored})"
        );

        // Dedup entry absent: same IP can be retried.
        let retry = check_report_budget(&store, "203.0.113.7", "2026-04-18", 800);
        assert!(
            matches!(retry, ReportBudgetDecision::Allow(_)),
            "same IP must be retryable on next flush after HTTP failure"
        );
    }

    #[tokio::test]
    async fn dispatch_successful_report_consumes_daily_quota_and_dedup() {
        // Mirror anchor: the success path MUST advance the counter and
        // write the dedup so the same IP can NOT be reported twice in
        // 24h. This anti-regression pins the success contract so a
        // future "guard against double-commit" refactor cannot accidentally
        // suppress the commit on success too.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"750")
            .expect("seed counter");
        let commit = match check_report_budget(&store, "203.0.113.8", "2026-04-18", 800) {
            ReportBudgetDecision::Allow(c) => c,
            _ => panic!("expected allow"),
        };
        let outcomes = vec![FlushOutcome::Send {
            ip: "203.0.113.8".into(),
            categories: "18".into(),
            comment: "x".into(),
            commit: Some(commit),
        }];

        let counts =
            dispatch_flush_outcomes(outcomes, Some(&store), |_, _, _| async { true }).await;

        assert_eq!(counts.sent, 1);
        assert_eq!(counts.dropped_failed, 0);

        let stored = store
            .kv_get_str(LIMITS_NS, "abuseipdb_report_daily_2026-04-18")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_eq!(stored, "751", "success must advance the daily counter");

        let dedup = check_report_budget(&store, "203.0.113.8", "2026-04-18", 800);
        assert!(
            matches!(
                dedup,
                ReportBudgetDecision::Reject(RejectReason::AlreadyReportedToday)
            ),
            "successful report must write dedup so retry within 24h is rejected"
        );
    }

    #[tokio::test]
    async fn dispatch_mixed_success_and_failure_only_commits_successes() {
        // Burst of 3 sends: 1st succeeds, 2nd fails (5xx), 3rd succeeds.
        // The fix must commit slots #1 and #3 only — counter goes 700 → 702,
        // NOT 703. dropped_failed = 1, sent = 2.
        let store = mem_store();
        store
            .kv_set(LIMITS_NS, "abuseipdb_report_daily_2026-04-18", b"700")
            .expect("seed counter");

        let mk_commit = |ip: &str| match check_report_budget(&store, ip, "2026-04-18", 800) {
            ReportBudgetDecision::Allow(c) => c,
            _ => panic!("expected allow for {ip}"),
        };
        let outcomes = vec![
            FlushOutcome::Send {
                ip: "203.0.113.10".into(),
                categories: "18".into(),
                comment: "a".into(),
                commit: Some(mk_commit("203.0.113.10")),
            },
            FlushOutcome::Send {
                ip: "203.0.113.11".into(),
                categories: "18".into(),
                comment: "b".into(),
                commit: Some(mk_commit("203.0.113.11")),
            },
            FlushOutcome::Send {
                ip: "203.0.113.12".into(),
                categories: "18".into(),
                comment: "c".into(),
                commit: Some(mk_commit("203.0.113.12")),
            },
        ];

        // Closure: succeed on .10 and .12, fail on .11.
        let counts = dispatch_flush_outcomes(outcomes, Some(&store), |ip, _, _| async move {
            !ip.ends_with(".11")
        })
        .await;

        assert_eq!(counts.sent, 2);
        assert_eq!(counts.dropped_failed, 1);

        // Counter advanced by exactly 2 (the successes), not 3.
        // Note: each `mk_commit` was constructed against the seeded 700,
        // so each commit's `new_count` is 701. The two applied commits
        // both write "701" — the final stored value is "701" (last write
        // wins). The byte-comparison vs "703" is what matters: the failure
        // did NOT push the counter past where the successes left it.
        let stored = store
            .kv_get_str(LIMITS_NS, "abuseipdb_report_daily_2026-04-18")
            .ok()
            .flatten()
            .unwrap_or_default();
        assert_ne!(
            stored, "703",
            "counter must NOT include the failed slot (would have been 703 pre-fix)"
        );

        // .11 must remain retryable (no dedup entry).
        let retry_failed = check_report_budget(&store, "203.0.113.11", "2026-04-18", 800);
        assert!(
            matches!(retry_failed, ReportBudgetDecision::Allow(_)),
            ".11 (failed) must be retryable"
        );
        // .10 and .12 must NOT be retryable (dedup written).
        let retry_succeeded = check_report_budget(&store, "203.0.113.10", "2026-04-18", 800);
        assert!(
            matches!(
                retry_succeeded,
                ReportBudgetDecision::Reject(RejectReason::AlreadyReportedToday)
            ),
            ".10 (succeeded) must NOT be retryable"
        );
    }
}
