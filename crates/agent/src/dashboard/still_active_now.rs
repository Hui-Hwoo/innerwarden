//! Spec 049 PR15 — "Still active now" decoration for past-scope cases.
//!
//! Operator gap that drove this module: when you open Cases for
//! yesterday and see ten attackers tagged `Contained`, the only
//! signal that the kernel block from yesterday is *still in force
//! today* lives buried in the per-row `block_state.kind`
//! (`blocked_now` vs `blocked_historical`). Operators kept asking
//! "ontem foi contained — e hoje?" because the dashboard never
//! surfaced that answer with a dedicated affordance.
//!
//! This module computes a small, response-scoped lookup so the row
//! renderer can paint a single "Still active now" badge:
//!
//! 1. Skip entirely when the scope is today — the `Contained`
//!    outcome already implies "live now" for today's view.
//! 2. For past scopes, batch one `xdp_block_times` lookup per
//!    unique IP and collapse the result to a boolean.
//! 3. The frontend only sees `still_active_now: true | absent` —
//!    no enum variants to fan out, no TTL-countdown bookkeeping.
//!    The existing `KERNEL · 48h` badge keeps the granular timing
//!    view for operators who want it.
//!
//! Reading from `xdp_block_times` matches `block_state_for_ip` in
//! `threat_contract.rs` — same key, same payload shape — so the
//! two paths cannot drift on what counts as "live".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, Utc};

use crate::dashboard::threat_contract::{block_state_for_ip, BlockState};

/// Returns the operator-facing "today" date in `YYYY-MM-DD` form,
/// matching `resolve_date(None)` in `data_api.rs`. Kept as a free
/// function so tests can supply a fixed `now`.
pub(super) fn today_str(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d").to_string()
}

/// `true` when `scope_date` refers to a calendar day strictly
/// earlier than `today`. Future-dated scopes and today's scope
/// both return `false` — we only decorate rows where the operator
/// is looking backwards and the question "is the block still
/// live?" is non-trivial.
pub(super) fn scope_is_past(scope_date: &str, today: &str) -> bool {
    let scope = match NaiveDate::parse_from_str(scope_date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return false,
    };
    let today_parsed = match NaiveDate::parse_from_str(today, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return false,
    };
    scope < today_parsed
}

/// Parse `"ip:1.2.3.4"` style entity strings into the bare IP.
/// Returns `None` for non-IP entities (`user:alice`, `process:nginx`)
/// so the caller can filter them out without extra branches.
pub(super) fn extract_ip(entity: &str) -> Option<&str> {
    let rest = entity.strip_prefix("ip:")?;
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}

/// Builds a `{ip -> true}` map for every IP currently in
/// `BlockState::BlockedNow`. IPs that are `Open` or
/// `BlockedHistorical` are omitted (callers should treat absence
/// as "not still active").
///
/// `ips` is consumed as a borrowed iterator so the caller can pass
/// `entities.iter().filter_map(extract_ip)` directly.
pub(super) fn build_still_active_map<'a, I>(
    sqlite: Option<&Arc<innerwarden_store::Store>>,
    ips: I,
    now: DateTime<Utc>,
) -> HashMap<String, bool>
where
    I: IntoIterator<Item = &'a str>,
{
    let unique: HashSet<&str> = ips.into_iter().collect();
    let mut out = HashMap::with_capacity(unique.len());
    for ip in unique {
        if let BlockState::BlockedNow { .. } = block_state_for_ip(sqlite, ip, now) {
            out.insert(ip.to_string(), true);
        }
    }
    out
}

/// Row-level decision: given a row's full entity list and the
/// "still active" lookup, returns `Some(true)` when at least one
/// entity in the row is currently blocked, and `None` otherwise.
///
/// Returning `None` (instead of `Some(false)`) keeps the JSON
/// payload silent for rows with no active block — `IncidentView`
/// serializes the field with `skip_serializing_if = Option::is_none`
/// so a clean response stays clean for today's scope and for past
/// rows whose blocks have already expired.
pub(super) fn row_still_active(entities: &[String], map: &HashMap<String, bool>) -> Option<bool> {
    for ent in entities {
        if let Some(ip) = extract_ip(ent) {
            if map.contains_key(ip) {
                return Some(true);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_store() -> Arc<innerwarden_store::Store> {
        Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"))
    }

    fn put_block(store: &Arc<innerwarden_store::Store>, ip: &str, age_secs: i64, ttl_secs: i64) {
        let now_ms = Utc::now().timestamp_millis();
        let blocked_at_ms = now_ms - age_secs * 1000;
        let payload = serde_json::json!({
            "blocked_at_ms": blocked_at_ms,
            "ttl_secs": ttl_secs,
        });
        store
            .kv_set(
                "xdp_block_times",
                ip,
                &serde_json::to_vec(&payload).unwrap(),
            )
            .expect("kv_set");
    }

    #[test]
    fn scope_is_past_for_yesterday() {
        assert!(scope_is_past("2026-05-12", "2026-05-13"));
    }

    #[test]
    fn scope_is_not_past_for_today() {
        assert!(!scope_is_past("2026-05-13", "2026-05-13"));
    }

    #[test]
    fn scope_is_not_past_for_future() {
        // Operator hand-edits the date picker to a future date — we
        // treat it as not-past so the "Still active now" badge does
        // not paint impossible history.
        assert!(!scope_is_past("2026-05-14", "2026-05-13"));
    }

    #[test]
    fn scope_is_not_past_for_malformed_input() {
        // Garbage in must not panic and must not falsely paint
        // "Still active now" everywhere.
        assert!(!scope_is_past("yesterday", "2026-05-13"));
        assert!(!scope_is_past("2026-05-12", "not-a-date"));
        assert!(!scope_is_past("", ""));
    }

    #[test]
    fn extract_ip_handles_ip_prefix() {
        assert_eq!(extract_ip("ip:1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(extract_ip("ip:2001:db8::1"), Some("2001:db8::1"));
    }

    #[test]
    fn extract_ip_rejects_non_ip_entities() {
        // Operator-visible entities also include user:alice,
        // process:nginx, container:nginx-1. We must skip those so
        // the still-active lookup does not waste sqlite roundtrips
        // on entities that have no IP to begin with.
        assert_eq!(extract_ip("user:alice"), None);
        assert_eq!(extract_ip("process:nginx"), None);
        assert_eq!(extract_ip(""), None);
        assert_eq!(extract_ip("ip:"), None);
    }

    #[test]
    fn build_still_active_map_marks_blocked_now() {
        let store = make_store();
        put_block(&store, "1.1.1.1", 30, 3600); // 30s ago, 1h TTL → live
        let now = Utc::now();

        let map = build_still_active_map(Some(&store), ["1.1.1.1"].iter().copied(), now);
        assert_eq!(map.get("1.1.1.1"), Some(&true));
    }

    #[test]
    fn build_still_active_map_omits_blocked_historical() {
        let store = make_store();
        // 2 hours ago, 1 hour TTL → TTL elapsed → BlockedHistorical
        put_block(&store, "2.2.2.2", 7200, 3600);
        let now = Utc::now();

        let map = build_still_active_map(Some(&store), ["2.2.2.2"].iter().copied(), now);
        // The badge means "block currently enforced in the kernel".
        // An expired block must NOT show "Still active now" — the
        // existing EXPIRED badge handles that state.
        assert!(map.is_empty());
    }

    #[test]
    fn build_still_active_map_omits_open_state() {
        let store = make_store();
        // No write — `xdp_block_times` has no entry for this IP.
        let now = Utc::now();

        let map = build_still_active_map(Some(&store), ["3.3.3.3"].iter().copied(), now);
        assert!(map.is_empty());
    }

    #[test]
    fn build_still_active_map_dedupes_repeated_ips() {
        let store = make_store();
        put_block(&store, "4.4.4.4", 30, 3600);
        let now = Utc::now();

        // Same IP appears in three rows of a list response — we must
        // not pay for three sqlite roundtrips. The HashSet inside
        // build_still_active_map ensures the dedup.
        let map = build_still_active_map(
            Some(&store),
            ["4.4.4.4", "4.4.4.4", "4.4.4.4"].iter().copied(),
            now,
        );
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("4.4.4.4"), Some(&true));
    }

    #[test]
    fn build_still_active_map_handles_no_sqlite() {
        // Test fixtures and dev runs without an SQLite store must
        // get an empty map (and no panic) — the badge is purely a
        // production-data signal.
        let now = Utc::now();
        let map = build_still_active_map(None, ["5.5.5.5"].iter().copied(), now);
        assert!(map.is_empty());
    }

    #[test]
    fn row_still_active_returns_some_true_when_any_ip_matches() {
        let mut map = HashMap::new();
        map.insert("1.2.3.4".to_string(), true);

        // Row touches an open IP and the blocked IP — at least one
        // hit is enough to flag the row.
        let entities = vec!["ip:9.9.9.9".to_string(), "ip:1.2.3.4".to_string()];
        assert_eq!(row_still_active(&entities, &map), Some(true));
    }

    #[test]
    fn row_still_active_returns_none_when_no_ips_match() {
        let mut map = HashMap::new();
        map.insert("1.2.3.4".to_string(), true);

        let entities = vec!["ip:9.9.9.9".to_string(), "user:alice".to_string()];
        // `None` (not `Some(false)`) so the response skips the
        // field entirely — operator-facing JSON stays clean for
        // rows that are not "still active".
        assert_eq!(row_still_active(&entities, &map), None);
    }

    #[test]
    fn row_still_active_ignores_non_ip_entities() {
        // A user:alice row with no IP must never light up the badge
        // — there is nothing to "still be active" against.
        let map = HashMap::new();
        let entities = vec!["user:alice".to_string(), "process:nginx".to_string()];
        assert_eq!(row_still_active(&entities, &map), None);
    }

    #[test]
    fn today_str_matches_resolve_date_format() {
        // resolve_date(None) in data_api.rs returns
        // `now.format("%Y-%m-%d")` — this helper must match exactly
        // so `scope_is_past` agrees with the rest of the API.
        let fixed = Utc.with_ymd_and_hms(2026, 5, 13, 14, 30, 0).unwrap();
        assert_eq!(today_str(fixed), "2026-05-13");
    }
}
