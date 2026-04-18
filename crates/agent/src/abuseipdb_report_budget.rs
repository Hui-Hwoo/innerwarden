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
}
