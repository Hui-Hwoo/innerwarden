//! Small helpers extracted from `main.rs` on 2026-05-25 as PR2 of the
//! sensor decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. The 11 functions and 6 existing anchor tests
//! moved verbatim; the 5 additional anchors below pin behaviour that
//! was implicit before.
//!
//! ## Organisation
//!
//! The 11 helpers fall into three small groups that all live in this
//! one file so the cross-module surface from `main.rs` stays at a
//! single `use main_helpers::*` glob (or per-fn imports). When the
//! larger `process_event` / `main` decomposition lands (PRs 4-5 of
//! this series) the event-time helpers may move into the appropriate
//! sub-module then.
//!
//! - **Paths + state** — `state_path_for`, `blocked_ips_path_for`,
//!   `parse_blocked_ips`, `load_blocked_ips`. Pure path derivation
//!   plus the loader that reads `blocked-ips.txt`.
//! - **Boot config decisions** — `should_spawn_integrity_collector`,
//!   `should_enable_syslog_sink`, `parse_syslog_port`,
//!   `choose_syslog_protocol`. Called once at startup from `main()`
//!   to decide which subsystems wake up.
//! - **Event-time helpers** — `severity_rank`, `is_passthrough_source`,
//!   `should_use_blocked_ip_hint`. Called from the `process_event`
//!   hot loop. The last one anchors the 2026-05-23 "don't early-return
//!   for blocked IPs" rule — see the inline comment on the function
//!   for the prod incident that motivated it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::sinks;

// ---------------------------------------------------------------------------
// Paths + state
// ---------------------------------------------------------------------------

/// Load blocked IPs from the file written by the agent.
/// Returns an empty set if the file does not exist.
pub(crate) fn load_blocked_ips(data_dir: &Path) -> HashSet<String> {
    let path = blocked_ips_path_for(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(contents) => parse_blocked_ips(&contents),
        Err(_) => HashSet::new(),
    }
}

pub(crate) fn state_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join("state.json")
}

pub(crate) fn blocked_ips_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join("blocked-ips.txt")
}

pub(crate) fn parse_blocked_ips(contents: &str) -> HashSet<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Boot config decisions
// ---------------------------------------------------------------------------

pub(crate) fn should_spawn_integrity_collector(enabled: bool, paths: &[String]) -> bool {
    enabled && !paths.is_empty()
}

pub(crate) fn should_enable_syslog_sink(syslog_host: &str) -> bool {
    !syslog_host.is_empty()
}

pub(crate) fn parse_syslog_port(port: Option<&str>) -> u16 {
    port.and_then(|raw| raw.parse::<u16>().ok()).unwrap_or(514)
}

pub(crate) fn choose_syslog_protocol(tcp_enabled: bool) -> sinks::syslog_cef::SyslogProtocol {
    if tcp_enabled {
        sinks::syslog_cef::SyslogProtocol::Tcp
    } else {
        sinks::syslog_cef::SyslogProtocol::Udp
    }
}

// ---------------------------------------------------------------------------
// Event-time helpers (called from process_event)
// ---------------------------------------------------------------------------

/// Numeric rank for Severity so we can compare in the dedup cache.
pub(crate) fn severity_rank(s: &innerwarden_core::event::Severity) -> u8 {
    use innerwarden_core::event::Severity;
    match s {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

pub(crate) fn is_passthrough_source(source: &str) -> bool {
    let _ = source;
    false
}

/// Returns true if the event's src_ip is in the blocked set. Pure helper,
/// extracted so the "don't early-return for blocked IPs" rule can be
/// anchored in a unit test without spinning up the whole `process_event`
/// harness.
///
/// This used to gate a `return` inside `process_event` — see the inline
/// comment there for the 2026-05-23 incident that proved the early-return
/// was harmful. The helper now exists only so other code paths can use
/// the blocked-list as a hint (severity tagging, etc) without re-parsing
/// the event details.
pub(crate) fn should_use_blocked_ip_hint(
    ev: &innerwarden_core::event::Event,
    blocked: &std::collections::HashSet<String>,
) -> bool {
    let src_ip = ev
        .details
        .get("ip")
        .or_else(|| ev.details.get("src_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    !src_ip.is_empty() && blocked.contains(src_ip)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    // ── Existing anchors moved from main.rs ──────────────────────────────

    #[test]
    fn parse_blocked_ips_discards_blank_and_whitespace_lines() {
        // Covers parser normalization so blocked-ips feedback keeps only meaningful IP tokens.
        let parsed = parse_blocked_ips("\n 1.2.3.4 \n\n10.0.0.8\n   \n");
        assert!(parsed.contains("1.2.3.4"));
        assert!(parsed.contains("10.0.0.8"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn helper_paths_resolve_inside_data_dir() {
        // Verifies path derivation remains deterministic for state and blocked-IP files.
        let data_dir = Path::new("/var/lib/innerwarden");
        assert_eq!(
            state_path_for(data_dir),
            PathBuf::from("/var/lib/innerwarden/state.json")
        );
        assert_eq!(
            blocked_ips_path_for(data_dir),
            PathBuf::from("/var/lib/innerwarden/blocked-ips.txt")
        );
    }

    #[test]
    fn should_spawn_integrity_collector_requires_flag_and_paths() {
        // Ensures collector startup logic only runs when both config prerequisites are present.
        assert!(should_spawn_integrity_collector(
            true,
            &[String::from("/etc/passwd")]
        ));
        assert!(!should_spawn_integrity_collector(true, &[]));
        assert!(!should_spawn_integrity_collector(
            false,
            &[String::from("/etc/passwd")]
        ));
    }

    #[test]
    fn parse_syslog_port_uses_default_for_missing_or_invalid_values() {
        // Guards sink selection fallback so malformed env vars cannot break startup.
        assert_eq!(parse_syslog_port(None), 514);
        assert_eq!(parse_syslog_port(Some("not-a-port")), 514);
        assert_eq!(parse_syslog_port(Some("6514")), 6514);
    }

    #[test]
    fn choose_syslog_protocol_tracks_tcp_toggle() {
        // Validates protocol selection branch used by the optional syslog sink.
        assert!(matches!(
            choose_syslog_protocol(true),
            sinks::syslog_cef::SyslogProtocol::Tcp
        ));
        assert!(matches!(
            choose_syslog_protocol(false),
            sinks::syslog_cef::SyslogProtocol::Udp
        ));
    }

    #[test]
    fn severity_rank_orders_levels_from_debug_to_critical() {
        // Confirms dedup ranking keeps higher-severity incidents when multiple detectors fire.
        assert_eq!(severity_rank(&Severity::Debug), 0);
        assert_eq!(severity_rank(&Severity::Info), 1);
        assert_eq!(severity_rank(&Severity::Low), 2);
        assert_eq!(severity_rank(&Severity::Medium), 3);
        assert_eq!(severity_rank(&Severity::High), 4);
        assert_eq!(severity_rank(&Severity::Critical), 5);
    }

    // ── blocked-IP hint unit tests moved from main.rs ────────────────────
    //
    // The anti-regression `blocked_ip_hint_returns_true_but_does_not_imply_skip`
    // STAYS in main.rs::tests because it does `include_str!("main.rs")` to
    // source-grep the `process_event` body for the forbidden early-return
    // pattern — that part is fundamentally about `main.rs`, not about
    // this helper. The two pure unit tests move here.

    #[test]
    fn blocked_ip_hint_returns_false_for_unblocked_ip() {
        use innerwarden_core::event::{Event, Severity};
        use std::collections::HashSet;

        let mut blocked = HashSet::new();
        blocked.insert("1.1.1.1".to_string());

        let ev = Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "Failed login from 2.2.2.2".to_string(),
            details: serde_json::json!({ "ip": "2.2.2.2" }),
            tags: vec![],
            entities: vec![],
        };

        assert!(
            !should_use_blocked_ip_hint(&ev, &blocked),
            "helper must return false for an IP not in the blocked set"
        );
    }

    #[test]
    fn blocked_ip_hint_returns_false_when_event_has_no_ip() {
        use innerwarden_core::event::{Event, Severity};
        use std::collections::HashSet;

        let mut blocked = HashSet::new();
        blocked.insert("1.1.1.1".to_string());

        let ev = Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "exec_audit".to_string(),
            kind: "process.exec".to_string(),
            severity: Severity::Info,
            summary: "exec without IP".to_string(),
            details: serde_json::json!({ "comm": "ls" }),
            tags: vec![],
            entities: vec![],
        };

        assert!(
            !should_use_blocked_ip_hint(&ev, &blocked),
            "helper must return false when the event has no ip/src_ip field — \
             otherwise non-network events would spuriously trip the hint"
        );
    }

    // ── New anchors added with the extraction ────────────────────────────
    //
    // 2026-05-25: PR2 anchors. Pin behaviour that was implicit before —
    // each of these helpers had only one or two test cases, leaving real
    // edge cases (file missing, alternative `src_ip` key, etc.) uncovered.

    #[test]
    fn load_blocked_ips_returns_empty_for_missing_feedback_file() {
        // Anchor: a fresh deploy (no blocked-ips.txt yet) must not
        // crash the sensor. The function silently returns an empty
        // set when the file is absent — pin this so a future refactor
        // that switches to `?` propagation cannot turn a missing file
        // into a startup-time error.
        let dir = tempfile::tempdir().expect("tempdir");
        let blocked = load_blocked_ips(dir.path());
        assert!(blocked.is_empty());
    }

    #[test]
    fn load_blocked_ips_reads_agent_feedback_file() {
        // Round-trip anchor: write a real file, read it back, confirm
        // parse logic is wired correctly. Pre-extraction this was
        // implicit; pinning it means a future refactor that drops the
        // parse step (e.g. switching to a raw `lines().collect()`)
        // would be caught — empty / whitespace lines would no longer
        // be filtered.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            blocked_ips_path_for(dir.path()),
            "203.0.113.8\n198.51.100.9\n",
        )
        .expect("write blocked ips");

        let blocked = load_blocked_ips(dir.path());
        assert_eq!(blocked.len(), 2);
        assert!(blocked.contains("203.0.113.8"));
        assert!(blocked.contains("198.51.100.9"));
    }

    #[test]
    fn parse_blocked_ips_deduplicates_and_keeps_comment_lines_as_tokens() {
        // The feedback file is intentionally a raw one-IP-per-line token
        // list; comment-looking lines are kept rather than interpreted
        // as syntax. (HashSet dedupes the literal duplicates after trim.)
        let parsed = parse_blocked_ips("1.2.3.4\n 1.2.3.4 \n# operator note\n");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("1.2.3.4"));
        assert!(parsed.contains("# operator note"));
    }

    #[test]
    fn parse_syslog_port_rejects_out_of_range_values() {
        // u16 range is 0-65535 inclusive; the parse falls back to 514
        // when the value cannot be parsed as a u16. Pin boundary
        // behaviour: 0 and 65535 parse cleanly, 65536 falls back.
        assert_eq!(parse_syslog_port(Some("0")), 0);
        assert_eq!(parse_syslog_port(Some("65535")), 65535);
        assert_eq!(parse_syslog_port(Some("65536")), 514);
    }

    #[test]
    fn is_passthrough_source_returns_false_for_all_known_sources() {
        // Anchor: the function is a deliberate stub (`let _ = source; false`)
        // — it always returns false today because no source has been
        // promoted to passthrough yet. Pin the constant-false return so
        // a future refactor that adds a passthrough source without
        // updating the test suite is caught at test time. If passthrough
        // sources are added later, this anchor should be deleted with
        // a comment explaining the new contract.
        assert!(!is_passthrough_source(""));
        assert!(!is_passthrough_source("auth.log"));
        assert!(!is_passthrough_source("ebpf"));
        assert!(!is_passthrough_source("docker"));
        assert!(!is_passthrough_source("integrity"));
    }

    #[test]
    fn should_enable_syslog_sink_treats_empty_string_as_disabled() {
        // Anchor: `[sinks.syslog] host = ""` (operator left the key but
        // cleared the value) is a common operator mistake. Pin that
        // empty string disables the sink rather than attempting to send
        // to a malformed address — failure mode there would be silent
        // dropping of every CEF event.
        assert!(!should_enable_syslog_sink(""));
        assert!(should_enable_syslog_sink("siem.internal"));
        assert!(should_enable_syslog_sink("10.0.0.1"));
    }

    #[test]
    fn should_use_blocked_ip_hint_reads_both_ip_and_src_ip_event_keys() {
        // Anchor: events come from different collectors with different
        // detail-key conventions. `auth.log` uses "ip", `c2_callback`
        // and other eBPF-derived events use "src_ip". Pin that both
        // keys are honoured — a refactor that drops one would silently
        // turn off the blocked-IP hint for half the event surface.
        use innerwarden_core::event::{Event, Severity};
        let mut blocked = HashSet::new();
        blocked.insert("9.9.9.9".to_string());

        let make_ev = |key: &str| Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "test".into(),
            kind: "test".into(),
            severity: Severity::Info,
            summary: "test".into(),
            details: serde_json::json!({ key: "9.9.9.9" }),
            tags: vec![],
            entities: vec![],
        };

        assert!(
            should_use_blocked_ip_hint(&make_ev("ip"), &blocked),
            "auth.log-style `ip` key must be honoured"
        );
        assert!(
            should_use_blocked_ip_hint(&make_ev("src_ip"), &blocked),
            "ebpf-style `src_ip` key must be honoured"
        );
    }
}
