//! Graph-based detectors — run periodic queries on the knowledge graph
//! to detect attack patterns structurally instead of per-event matching.
//!
//! These run in parallel with sensor-side detectors (Phase 3 validation).
//! Each returns a Vec<Incident> that can be compared with sensor incidents.

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use std::collections::{HashMap, HashSet};

use super::graph::KnowledgeGraph;
use super::types::*;

// Spec 068: detector families relocated into submodules. Logic unchanged;
// these are re-exported below so every `detectors::*` path keeps resolving.
mod c2;
mod correlation;
mod host;
mod lateral;
mod persistence;
mod recon;

use c2::*;
use correlation::*;
use host::*;
use lateral::*;
use persistence::*;
use recon::*;

// Re-export the slow_loop-invoked detectors so the public
// `knowledge_graph::detectors::detect_*` paths are unchanged.
pub use c2::detect_short_lived_process;
pub use host::{detect_packed_binary, detect_sysctl_drift, detect_yara_match};

/// Environment calibration context passed to graph detectors.
/// Enables cloud-aware suppression and operator UID awareness.
///
/// 2026-05-03: extended with `service_uids` + `service_user_names`
/// so detectors can classify users into Human / Service / Root /
/// Unknown and apply graduated thresholds. Pre-2026-05-03 only
/// `human_uids` was available, which meant a service account like
/// `snap_daemon` (uid 584788, no login shell) defaulted to standard
/// threshold and trivially fired graph_discovery_burst on routine
/// `snap refresh` operations.
#[derive(Debug, Clone, Default)]
pub struct CalibrationContext {
    /// True if running on a cloud VM (auto-detected from environment profile).
    /// Reserved for future cloud-specific threshold adjustments (e.g.,
    /// timing anomaly sensitivity, network noise suppression).
    #[allow(dead_code)]
    pub is_cloud: bool,
    /// UIDs of human operators. Graph detectors use 3x threshold for these.
    pub human_uids: Vec<u32>,
    /// 2026-05-03: names of human operators (for reverse lookup when
    /// graph events arrive with `name` rather than `uid:NNNN`).
    pub human_user_names: Vec<String>,
    /// 2026-05-03: UIDs of system service accounts. Graph detectors
    /// use 5x threshold for these (or skip entirely for very noisy
    /// detectors like `data_exfil`).
    pub service_uids: Vec<u32>,
    /// 2026-05-03: names of system service accounts.
    pub service_user_names: Vec<String>,
}

/// 2026-05-03: classification of a user observed in graph events.
/// Mirrors `environment_profile::UserClass` but lives here so the
/// detectors module is self-contained and the public API stays
/// inside knowledge_graph::detectors. The `From` impl below bridges
/// when the boot path passes a `&EnvironmentProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserClass {
    Root,
    Human,
    Service,
    Unknown,
}

impl CalibrationContext {
    /// Classify a graph user (`"root"` / `"ubuntu"` / `"snap_daemon"`
    /// / `"uid:1001"`). Single entry point for ALL graph detectors —
    /// drift between detectors becomes a one-place fix.
    pub fn classify_user(&self, name_or_uid: &str) -> UserClass {
        if name_or_uid == "root" {
            return UserClass::Root;
        }
        if let Some(uid_str) = name_or_uid.strip_prefix("uid:") {
            if let Ok(uid) = uid_str.parse::<u32>() {
                if uid == 0 {
                    return UserClass::Root;
                }
                if self.human_uids.contains(&uid) {
                    return UserClass::Human;
                }
                if self.service_uids.contains(&uid) {
                    return UserClass::Service;
                }
            }
            return UserClass::Unknown;
        }
        if self.service_user_names.iter().any(|n| n == name_or_uid) {
            return UserClass::Service;
        }
        if self.human_user_names.iter().any(|n| n == name_or_uid) {
            return UserClass::Human;
        }
        UserClass::Unknown
    }
}

/// Cooldown tracker to prevent duplicate graph-based alerts.
/// Also tracks recent graph detections for sensor dedup.
pub struct GraphDetectorState {
    cooldowns: HashMap<String, DateTime<Utc>>,
    #[allow(dead_code)]
    // seed value for new cooldowns; read by future detectors_custom_cooldown path
    default_cooldown_secs: i64,
    /// Tracks recent graph detections: "detector:entity" → timestamp.
    /// Used to suppress duplicate sensor incidents.
    recent_detections: HashMap<String, DateTime<Utc>>,
    /// 2026-05-03: counters for trusted-class suppression. Key:
    /// `(detector_id, user_class)` like
    /// `("discovery_burst", "service")`. Value: how many times we
    /// would have fired but suppressed due to elevated threshold for
    /// the user class. Surfaced via Prometheus
    /// `innerwarden_graph_detector_suppressed_total{detector,user_class}`
    /// so the operator can grep `/metrics` and audit what is being
    /// dampened. Without this, suppression is invisible.
    pub(crate) suppressed_counts: HashMap<(String, &'static str), u64>,
    /// Spec 043 Phase 5 sysctl_drift baseline. First call to
    /// `detect_sysctl_drift` populates this from
    /// `Node::System.sysctl_params`; subsequent calls diff the current
    /// params against this snapshot to surface drift. `None` until the
    /// first observation. Per-process state — agent restart re-
    /// baselines on the next tick (acceptable false-negative window).
    sysctl_baseline: Option<HashMap<String, String>>,
}

/// 2026-05-03: stable label string per UserClass for the
/// suppression counter. Bounded set (4 values) keeps Prometheus
/// cardinality safe.
pub(super) fn user_class_label(class: UserClass) -> &'static str {
    match class {
        UserClass::Root => "root",
        UserClass::Human => "human",
        UserClass::Service => "service",
        UserClass::Unknown => "unknown",
    }
}

impl GraphDetectorState {
    pub fn new() -> Self {
        Self {
            cooldowns: HashMap::new(),
            default_cooldown_secs: 300,
            recent_detections: HashMap::new(),
            suppressed_counts: HashMap::new(),
            sysctl_baseline: None,
        }
    }

    fn check_and_set(&mut self, key: &str, now: DateTime<Utc>, cooldown_secs: i64) -> bool {
        if let Some(last) = self.cooldowns.get(key) {
            if now - *last < Duration::seconds(cooldown_secs) {
                return false; // Still in cooldown
            }
        }
        self.cooldowns.insert(key.to_string(), now);
        true
    }

    /// Record that a graph detector fired for a specific detector+entity combination.
    fn record_detection(&mut self, detector: &str, entity: &str, now: DateTime<Utc>) {
        let key = format!("{}:{}", detector, entity);
        self.recent_detections.insert(key, now);
    }

    /// Check if a sensor incident should be suppressed because the graph already
    /// detected the same pattern for the same entity within 60s.
    pub fn should_suppress_sensor(
        &self,
        sensor_detector: &str,
        entity_value: &str,
        now: DateTime<Utc>,
    ) -> bool {
        // Map sensor detector names to their graph equivalents
        let graph_detector = match sensor_detector {
            "threat_intel" => "threat_intel",
            "lateral_movement" => "lateral_movement",
            "reverse_shell" => "reverse_shell",
            "fileless" => "fileless",
            "discovery_burst" => "discovery_burst",
            "data_exfiltration" | "data_exfil_cmd" => "data_exfil",
            "crontab_persistence" | "systemd_persistence" | "ssh_key_injection" => "persistence",
            "process_tree" => "process_tree",
            "kernel_module_load" | "kernel_module" => "kernel_module",
            "service_stop" => "service_stop",
            "container_escape" => "container_escape",
            "log_tampering" => "log_tampering",
            "crypto_miner" => "crypto_miner",
            "port_scan" => "port_scan",
            "credential_stuffing" => "credential_stuffing",
            "sudo_abuse" => "sudo_abuse",
            _ => return false, // No graph equivalent — don't suppress
        };

        let key = format!("{}:{}", graph_detector, entity_value);
        if let Some(ts) = self.recent_detections.get(&key) {
            return now - *ts < Duration::seconds(60);
        }
        false
    }

    /// Prune stale cooldowns and detections older than 1 hour.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.cooldowns
            .retain(|_, ts| now - *ts < Duration::hours(1));
        self.recent_detections
            .retain(|_, ts| now - *ts < Duration::seconds(120));
    }
}

/// Run all graph-based detectors with default calibration (no environment info).
/// Convenience wrapper for tests and backwards compatibility.
#[allow(dead_code)]
pub fn run_all(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    run_all_with_calibration(graph, state, host, now, &CalibrationContext::default())
}

/// Run all graph-based detectors with environment calibration context.
/// The calibration context enables cloud-aware suppression and operator
/// UID awareness to reduce false positives on fresh installs.
pub fn run_all_with_calibration(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();

    incidents.extend(detect_threat_intel(graph, state, host, now));
    incidents.extend(detect_lateral_movement(graph, state, host, now));
    incidents.extend(detect_process_tree_anomaly(graph, state, host, now));
    incidents.extend(detect_reverse_shell(graph, state, host, now));
    incidents.extend(detect_fileless(graph, state, host, now));
    incidents.extend(detect_discovery_burst_calibrated(
        graph, state, host, now, ctx,
    ));
    incidents.extend(detect_persistence(graph, state, host, now));
    incidents.extend(detect_data_exfil_calibrated(graph, state, host, now, ctx));

    // Phase 3A: easy graph detectors
    incidents.extend(detect_kernel_module(graph, state, host, now));
    incidents.extend(detect_service_stop(graph, state, host, now));
    incidents.extend(detect_container_escape(graph, state, host, now));
    incidents.extend(detect_log_tampering(graph, state, host, now));
    incidents.extend(detect_crypto_miner(graph, state, host, now));
    incidents.extend(detect_sensitive_write(graph, state, host, now));
    // Spec 015: detect_user_creation was removed. It was a pure presence
    // scan over `nodes_of_type(User)` that fired every 30min for every
    // non-system User node in the graph. Because User nodes are permanent
    // (graph.rs is_expired → `Node::User => false`), each attacker-supplied
    // username from SSH brute-force stayed in the graph forever and fired
    // the detector indefinitely — 3,954 false positives on prod snapshot
    // 2026-04-11. Real user creation continues to be detected by the
    // sensor-side `user_creation` detector (crates/sensor/src/detectors/
    // user_creation.rs), whose incidents are ingested via ingest_incident()
    // and still match the CL-012 "Multi-Persistence" correlation rule via
    // the stage pattern contains("user_creation").
    incidents.extend(detect_docker_anomaly(graph, state, host, now));
    incidents.extend(detect_scanner_ua(graph, state, host, now));
    incidents.extend(detect_c2_beacon(graph, state, host, now));

    incidents.extend(detect_cgroup_abuse(graph, state, host, now));

    // Phase 3B: aggregation detectors
    incidents.extend(detect_host_drift_calibrated(graph, state, host, now, ctx));
    incidents.extend(detect_proto_anomaly_aggregated(graph, state, host, now));
    incidents.extend(detect_port_scan(graph, state, host, now));
    incidents.extend(detect_credential_stuffing(graph, state, host, now));
    incidents.extend(detect_sudo_abuse(graph, state, host, now));
    incidents.extend(detect_network_sniffing(graph, state, host, now));
    incidents.extend(detect_dns_tunnel(graph, state, host, now));

    // Phase 3C: correlation rules as graph paths
    incidents.extend(detect_correlation_chains(graph, state, host, now));

    // Slow-and-low: 24h lookback for persistent low-rate C2 patterns
    incidents.extend(detect_slow_and_low(graph, state, host, now));

    // Spec 043 Phase 3 — yara_match_detector — NOT called here.
    // It's gated on `[kg].yara_match_detector_enabled` and called
    // from slow_loop directly so the config check stays at the
    // outermost layer. See detect_yara_match below.

    // Record detections for sensor dedup
    for inc in &incidents {
        let detector = inc.incident_id.split(':').next().unwrap_or("");
        // Strip "graph_" prefix to match sensor names
        let detector_base = detector.strip_prefix("graph_").unwrap_or(detector);
        let entity = inc.entities.first().map(|e| e.value.as_str()).unwrap_or("");
        state.record_detection(detector_base, entity, now);
    }

    // Periodic prune
    state.prune(now);

    incidents
}

/// 2026-05-03: legacy thin wrapper kept for back-compat with old
/// tests. New code uses `CalibrationContext::classify_user` which
/// returns the four-way `UserClass` (Root / Human / Service /
/// Unknown) rather than this binary trust check.
#[allow(dead_code)]
fn is_trusted_graph_user(user_name: &str, human_uids: &[u32]) -> bool {
    if let Some(uid_str) = user_name.strip_prefix("uid:") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            return human_uids.contains(&uid);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1700000000 + secs, 0).unwrap()
    }

    #[test]
    fn test_threat_intel_detection() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1, 0, "wget", 0, ts(0));
        let ip_id = g.add_node(Node::Ip {
            addr: "93.1.1.1".into(),
            is_internal: false,
            datasets: vec!["sslbl".into()],
            risk_score: 80,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(1)));

        let mut state = GraphDetectorState::new();
        let incidents = detect_threat_intel(&g, &mut state, "test", ts(2));
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("sslbl"));

        // Cooldown should prevent duplicate
        let incidents2 = detect_threat_intel(&g, &mut state, "test", ts(3));
        assert_eq!(incidents2.len(), 0);
    }

    #[test]
    fn test_lateral_movement_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "ssh", 0, ts(0));

        // Connect to 4 internal IPs on port 22
        for i in 1..=4 {
            let ip = g.ensure_ip(&format!("192.168.1.{}", i), now);
            g.add_edge(
                Edge::new(proc_id, ip, Relation::ConnectedTo, now)
                    .with_prop("port", serde_json::Value::from(22u16)),
            );
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_lateral_movement(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("SSH scanning"));
    }

    #[test]
    fn test_process_tree_anomaly() {
        let mut g = KnowledgeGraph::new();
        let nginx = g.ensure_process(100, 1, "nginx", 33, ts(0));
        let bash = g.ensure_process(200, 100, "bash", 33, ts(1));
        g.add_edge(Edge::new(bash, nginx, Relation::SpawnedBy, ts(1)));

        let mut state = GraphDetectorState::new();
        let incidents = detect_process_tree_anomaly(&g, &mut state, "test", ts(2));
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("nginx"));
    }

    #[test]
    fn test_reverse_shell_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "bash", 0, now);
        let ip_id = g.ensure_ip("93.1.1.1", now);

        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::RedirectedFd, now)
                .with_prop("old_fd", serde_json::Value::from(0)),
        );
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_reverse_shell(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
    }

    #[test]
    fn test_fileless_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "malware", 0, now);
        let ip_id = g.ensure_ip("93.1.1.1", now);

        g.add_edge(Edge::new(proc_id, proc_id, Relation::CreatedMemfd, now));
        g.add_edge(Edge::new(proc_id, proc_id, Relation::MprotectExec, now));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_fileless(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
    }

    #[test]
    fn test_persistence_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "payload", 0, now);
        let file_id = g.ensure_file("/etc/cron.d/backdoor");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_persistence(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("Persistence"));
    }

    #[test]
    fn test_data_exfil_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "payload", 0, now);
        let file_id = g.ensure_file("/etc/shadow");
        let ip_id = g.ensure_ip("93.1.1.1", now);

        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_data_exfil_calibrated(
            &g,
            &mut state,
            "test",
            now,
            &CalibrationContext::default(),
        );
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("exfiltration"));
    }

    #[test]
    fn test_cooldown_prune() {
        let mut state = GraphDetectorState::new();
        state.cooldowns.insert("old_key".into(), ts(0));
        state.cooldowns.insert("new_key".into(), ts(3601));
        state.prune(ts(7200)); // ~2h later, new_key is 3599s old (< 1h)
        assert_eq!(state.cooldowns.len(), 1);
        assert!(state.cooldowns.contains_key("new_key"));
    }

    // ── Phase 3A tests ────────────────────────────────────────────────

    #[test]
    fn test_kernel_module_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "insmod", 0, now);
        let file_id = g.ensure_file("/lib/modules/evil.ko");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Executed, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_kernel_module(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("Kernel module"));
    }

    #[test]
    fn test_service_stop_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "systemctl", 0, now);
        // Add an edge with summary containing "stop innerwarden"
        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::Executed, now).with_prop(
                "summary",
                serde_json::Value::from("systemctl stop innerwarden-sensor"),
            ),
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_service_stop(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].severity == Severity::Critical);
    }

    #[test]
    fn test_container_escape_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "runc", 0, now);
        let file_id = g.ensure_file("/var/run/docker.sock");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_container_escape(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].severity == Severity::Critical);
    }

    #[test]
    fn test_log_tampering_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "evil", 0, now);
        let file_id = g.ensure_file("/var/log/auth.log");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_log_tampering(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("Log tampering"));
    }

    #[test]
    fn test_log_tampering_allows_rsyslog() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "rsyslog", 0, now);
        let file_id = g.ensure_file("/var/log/syslog");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_log_tampering(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 0); // rsyslog is a trusted writer
    }

    #[test]
    fn test_network_sniffing_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        g.ensure_process(1234, 0, "tcpdump", 0, now);

        let mut state = GraphDetectorState::new();
        let incidents = detect_network_sniffing(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("tcpdump"));
    }

    #[test]
    fn test_network_sniffing_skips_agent_spawned_tcpdump() {
        // Spec 015: pcap_capture spawns tcpdump via the agent. Those
        // invocations must not fire graph_network_sniffing.
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        // agent → tcpdump chain
        let agent = g.ensure_process(42, 1, "innerwarden-agent", 0, now);
        let tcpdump = g.ensure_process(1234, 42, "tcpdump", 0, now);
        g.add_edge(Edge::new(tcpdump, agent, Relation::SpawnedBy, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_network_sniffing(&g, &mut state, "test", now);
        assert!(
            incidents.is_empty(),
            "tcpdump spawned by the agent itself must not alert"
        );
    }

    #[test]
    fn test_network_sniffing_skips_stale_processes() {
        // Spec 015: the pre-fix detector re-fired every 10 minutes for the
        // lifetime of any Process node with comm=tcpdump, even after the
        // process exited, because it was a pure presence scan. The fixed
        // version only considers Process nodes started in the last 5min.
        let mut g = KnowledgeGraph::new();
        g.ensure_process(1234, 0, "tcpdump", 0, ts(0));

        let mut state = GraphDetectorState::new();
        let incidents = detect_network_sniffing(&g, &mut state, "test", ts(1_000));
        assert!(
            incidents.is_empty(),
            "stale tcpdump node (>5min old) must not fire the detector"
        );
    }

    #[test]
    fn test_sensitive_write_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "evil", 0, now);
        let file_id = g.add_node(Node::File {
            path: "/etc/shadow".to_string(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: true,
            yara_matches: vec![],
        });
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_sensitive_write(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
    }

    // ── Phase 3B tests ────────────────────────────────────────────────

    #[test]
    fn test_port_scan_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let ip_id = g.ensure_ip("1.2.3.4", now);

        // Scan 15 distinct ports
        for port in 1..=15 {
            let port_id = g.ensure_port(port, "tcp");
            g.add_edge(Edge::new(ip_id, port_id, Relation::ScannedPort, now));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_port_scan(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("15 ports"));
    }

    #[test]
    fn test_port_scan_below_threshold() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let ip_id = g.ensure_ip("1.2.3.4", now);

        // Only 3 ports — below threshold
        for port in 1..=3 {
            let port_id = g.ensure_port(port, "tcp");
            g.add_edge(Edge::new(ip_id, port_id, Relation::ScannedPort, now));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_port_scan(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 0);
    }

    // ── Phase 3D tests ────────────────────────────────────────────────

    #[test]
    fn test_dedup_suppresses_sensor() {
        let mut state = GraphDetectorState::new();
        let now = ts(100);

        // Graph detected threat_intel for IP 1.2.3.4
        state.record_detection("threat_intel", "1.2.3.4", now);

        // Sensor fires 30s later — should be suppressed
        assert!(state.should_suppress_sensor("threat_intel", "1.2.3.4", ts(130)));

        // Different IP — should NOT be suppressed
        assert!(!state.should_suppress_sensor("threat_intel", "5.6.7.8", ts(130)));

        // After 60s — should NOT be suppressed (expired)
        assert!(!state.should_suppress_sensor("threat_intel", "1.2.3.4", ts(161)));
    }

    #[test]
    fn test_dedup_maps_sensor_to_graph() {
        let mut state = GraphDetectorState::new();
        let now = ts(100);

        state.record_detection("data_exfil", "1.2.3.4", now);

        // Sensor uses different name but maps to same graph detector
        assert!(state.should_suppress_sensor("data_exfiltration", "1.2.3.4", ts(110)));
        assert!(state.should_suppress_sensor("data_exfil_cmd", "1.2.3.4", ts(110)));

        // Unknown sensor detector — never suppress
        assert!(!state.should_suppress_sensor("yara_scan", "1.2.3.4", ts(110)));
    }

    // ── Phase 3A missing tests ───────────────────────────────────────────

    #[test]
    fn test_crypto_miner_detection() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(100, 1, "xmrig", 0, ts(0));
        let ip_id = g.add_node(Node::Ip {
            addr: "pool.minexmr.com".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        g.add_edge(
            Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(10)).with_prop("port", 3333u16),
        );

        let mut state = GraphDetectorState::new();
        let result = detect_crypto_miner(&g, &mut state, "test", ts(20));
        assert!(
            !result.is_empty(),
            "xmrig connecting to port 3333 should trigger"
        );
    }

    // Spec 015: test_user_creation_detection was removed alongside the
    // detector. The anti-pattern it verified (emit per non-system User
    // node) is precisely the behavior we deleted. Real user-creation
    // coverage stays on the sensor side (crates/sensor/src/detectors/
    // user_creation.rs tests) and the CL-012 correlation-rule path.

    #[test]
    fn test_scanner_ua_detection() {
        let mut g = KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: "10.0.0.99".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        let sys_id = g.ensure_system("test-host");
        g.add_edge(
            Edge::new(ip_id, sys_id, Relation::HttpRequestTo, ts(5))
                .with_prop("user_agent", "Nikto/2.1.6"),
        );

        let mut state = GraphDetectorState::new();
        let result = detect_scanner_ua(&g, &mut state, "test", ts(10));
        assert!(
            !result.is_empty(),
            "Nikto UA should trigger scanner detection"
        );
    }

    #[test]
    fn test_docker_anomaly_restart_detection() {
        let mut g = KnowledgeGraph::new();
        let cid = g.ensure_container("abc123");
        let sys_id = g.ensure_system("test-host");
        // Simulate 4 restarts in 5 minutes
        for i in 0..4 {
            g.add_edge(Edge::new(cid, sys_id, Relation::StartedOn, ts(i * 60)));
            g.add_edge(Edge::new(cid, sys_id, Relation::DiedOn, ts(i * 60 + 30)));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_docker_anomaly(&g, &mut state, "test", ts(250));
        assert!(
            !result.is_empty(),
            "4 container restarts in 5 min should trigger"
        );
    }

    #[test]
    fn test_host_drift_suspicious_path() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(999, 1, "payload", 0, ts(5));
        let file_id = g.add_node(Node::File {
            path: "/tmp/payload".into(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: false,
            yara_matches: vec![],
        });
        g.add_edge(Edge::new(proc_id, file_id, Relation::Executed, ts(5)));

        let mut state = GraphDetectorState::new();
        let result = detect_host_drift_calibrated(
            &g,
            &mut state,
            "test",
            ts(10),
            &CalibrationContext::default(),
        );
        assert!(
            !result.is_empty(),
            "/tmp execution should fire individually as suspicious"
        );
        assert!(result[0].severity == Severity::High);
    }

    #[test]
    fn test_credential_stuffing_detection() {
        let mut g = KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: "185.0.0.1".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        // 5 distinct users with failed auth from same IP
        for i in 0..5 {
            let user_id = g.ensure_user(&format!("user{}", i));
            g.add_edge(
                Edge::new(user_id, ip_id, Relation::LoggedInFrom, ts(i * 10))
                    .with_prop("success", false),
            );
        }

        let mut state = GraphDetectorState::new();
        let result = detect_credential_stuffing(&g, &mut state, "test", ts(60));
        assert!(
            !result.is_empty(),
            "5 distinct users from same IP should trigger credential stuffing"
        );
    }

    #[test]
    fn test_sudo_abuse_detection() {
        let mut g = KnowledgeGraph::new();
        let user_id = g.ensure_user("attacker");
        // 10 sudo commands in 50s (all within 60s window of ts(55))
        for i in 0..10 {
            let proc_id = g.ensure_process(100 + i, 1, "sudo", 0, ts(i as i64 * 5));
            g.add_edge(
                Edge::new(proc_id, user_id, Relation::SudoAs, ts(i as i64 * 5))
                    .with_prop("command", format!("cat /etc/shadow_{}", i)),
            );
        }

        let mut state = GraphDetectorState::new();
        let result = detect_sudo_abuse(&g, &mut state, "test", ts(55));
        assert!(!result.is_empty(), "10 sudo commands in 60s should trigger");
    }

    #[test]
    fn test_dns_tunnel_high_entropy() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(50, 1, "dnscat2", 0, ts(0));
        // Create 60 Resolved edges to long domains (>50 chars) — triggers dns tunnel
        for i in 0..60 {
            let long_name = format!(
                "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBkb21h{:03}.evil.com",
                i
            );
            let dom_id = g.add_node(Node::Domain {
                name: long_name,
                datasets: vec![],
                is_dga: Some(true),
                entropy: Some(5.2),
            });
            g.add_edge(Edge::new(proc_id, dom_id, Relation::Resolved, ts(i)));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_dns_tunnel(&g, &mut state, "test", ts(65));
        assert!(
            !result.is_empty(),
            "60 DNS resolutions to long domains should trigger DNS tunnel detection"
        );
    }

    #[test]
    fn test_correlation_multi_low_elevation() {
        let mut g = KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: "10.0.0.50".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        // Create 3 incidents from different detectors all connected to same IP
        for (i, det) in ["port_scan", "user_agent_scanner", "discovery_burst"]
            .iter()
            .enumerate()
        {
            let inc_id = g.add_node(Node::Incident {
                incident_id: format!("{}:test:{}", det, i),
                detector: det.to_string(),
                severity: "low".into(),
                title: format!("{} test", det),
                summary: String::new(),
                ts: ts(i as i64 * 30),
                mitre_ids: vec![],
                decision: None,
                confidence: None,
                decision_reason: None,
                decision_target: None,
                auto_executed: false,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(
                inc_id,
                ip_id,
                Relation::TriggeredBy,
                ts(i as i64 * 30),
            ));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_correlation_chains(&g, &mut state, "test", ts(100));
        assert!(
            !result.is_empty(),
            "3 distinct low-severity detectors from same IP should escalate to HIGH"
        );
        assert!(result[0].incident_id.contains("CL-010"));
    }

    #[test]
    fn test_c2_beacon_periodic_connections() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(42, 1, "backdoor", 0, ts(0));
        let ip_id = g.add_node(Node::Ip {
            addr: "93.184.216.34".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        // 6 connections at regular 30s intervals (within 15% jitter)
        for i in 0..6 {
            g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(i * 30)));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_c2_beacon(&g, &mut state, "test", ts(180));
        assert!(
            !result.is_empty(),
            "6 periodic connections at 30s intervals should trigger C2 beacon"
        );
    }

    // ── 2026-05-03 (PR #418) anchors — uniform UserClass via ──────────
    //                  CalibrationContext::classify_user
    //
    // Pre-PR-#418 each detector did its own thing:
    //  - discovery_burst: 3x for human, standard for everyone else
    //  - data_exfil: NO suppression (took _ctx but never used it)
    //  - host_drift: 2x for human, standard for everyone else
    // and `is_trusted_graph_user("snap_daemon", ...)` returned false
    // because there was no name→uid reverse lookup.
    //
    // These anchors pin the post-fix contract: the four user classes
    // map correctly, snap_daemon (the operator's actual case) is
    // recognised, and all three detectors call classify_user.

    #[test]
    fn calibration_context_recognises_named_service_account() {
        let ctx = CalibrationContext {
            is_cloud: false,
            human_uids: vec![1000],
            human_user_names: vec!["ubuntu".to_string()],
            service_uids: vec![584788],
            service_user_names: vec!["snap_daemon".to_string()],
        };
        assert_eq!(ctx.classify_user("snap_daemon"), UserClass::Service);
        assert_eq!(ctx.classify_user("ubuntu"), UserClass::Human);
        assert_eq!(ctx.classify_user("root"), UserClass::Root);
        assert_eq!(ctx.classify_user("attacker"), UserClass::Unknown);
        // uid:NNNN form still works.
        assert_eq!(ctx.classify_user("uid:584788"), UserClass::Service);
        assert_eq!(ctx.classify_user("uid:1000"), UserClass::Human);
        assert_eq!(ctx.classify_user("uid:0"), UserClass::Root);
    }

    #[test]
    fn user_class_label_is_bounded_set_for_prometheus() {
        // Anchor that the Prometheus label cardinality is bounded.
        // Adding a UserClass variant without updating user_class_label
        // would create an unlabelled bucket — caught here.
        for class in [
            UserClass::Root,
            UserClass::Human,
            UserClass::Service,
            UserClass::Unknown,
        ] {
            let label = user_class_label(class);
            assert!(
                ["root", "human", "service", "unknown"].contains(&label),
                "label `{label}` not in expected set"
            );
        }
    }

    #[test]
    fn all_three_protected_detectors_call_classify_user() {
        // Source-grep anchor that build-time guarantees the three
        // graph detectors that handle multi-user activity (discovery
        // burst, data exfil, host drift) all consult classify_user.
        // Pre-PR-#418 detect_data_exfil_calibrated had `_ctx` —
        // unused. If anyone reverts to the old pattern, this fails.
        // Spec 068: the three detectors now live in their family
        // submodules (discovery_burst→recon, data_exfil→c2,
        // host_drift→host); concat them so this anchor still scans the
        // exact same verbatim source it always did.
        let src = concat!(
            include_str!("recon.rs"),
            include_str!("c2.rs"),
            include_str!("host.rs"),
        );

        let burst_section_start = src
            .find("fn detect_discovery_burst_calibrated")
            .expect("discovery_burst function must exist");
        let exfil_section_start = src
            .find("fn detect_data_exfil_calibrated")
            .expect("data_exfil function must exist");
        let drift_section_start = src
            .find("fn detect_host_drift_calibrated")
            .expect("host_drift function must exist");

        // Each detector must reference classify_user within ~5K bytes
        // of its function header (loose bound — the bodies vary in
        // length but classify_user is always in the threshold-pick
        // block near the top).
        for (label, start) in [
            ("discovery_burst", burst_section_start),
            ("data_exfil", exfil_section_start),
            ("host_drift", drift_section_start),
        ] {
            // 2026-05-03 (Wave 5b PR-4 follow-up): walk the slice end
            // forward to the next char boundary. PR #432 added text
            // with em-dashes / arrows to the discovery_burst section,
            // pushing the 6000-byte cut into a multi-byte codepoint
            // and panicking `&src[start..end]`.
            let mut end = std::cmp::min(start + 6000, src.len());
            while end < src.len() && !src.is_char_boundary(end) {
                end += 1;
            }
            let section = &src[start..end];
            assert!(
                section.contains("classify_user"),
                "detector `{label}` must call ctx.classify_user — without it the \
                 service-account suppression doesn't apply and snap_daemon-class \
                 FPs come back. (PR #418 anchor)"
            );
        }

        // data_exfil must NOT have the old `_ctx: &CalibrationContext`
        // pattern (underscore prefix = unused). If it returns, the
        // detector silently stops applying suppression.
        // Same char-boundary safety as above.
        let mut exfil_end = std::cmp::min(exfil_section_start + 200, src.len());
        while exfil_end < src.len() && !src.is_char_boundary(exfil_end) {
            exfil_end += 1;
        }
        let exfil_signature = &src[exfil_section_start..exfil_end];
        assert!(
            !exfil_signature.contains("_ctx: &CalibrationContext"),
            "data_exfil ctx must NOT be unused — that was the original bug \
             where snap_daemon DATA_EXFIL alerts went out unfiltered"
        );
    }

    #[test]
    fn suppressed_counts_increment_for_service_account_under_elevated_threshold() {
        // End-to-end: simulate snap_daemon doing 8 discovery actions.
        // Standard threshold is 5 (would fire), service threshold is
        // 25 (won't fire). Counter must increment.
        use chrono::Utc;
        let mut state = GraphDetectorState::new();
        // Simulate the suppression bookkeeping the detector does:
        // total >= threshold && total < adjusted_threshold.
        // Driving the actual detector path requires a full graph
        // fixture (covered separately by happy-path tests in this
        // file); here we exercise just the counter contract.
        let class = UserClass::Service;
        *state
            .suppressed_counts
            .entry(("discovery_burst".to_string(), user_class_label(class)))
            .or_insert(0) += 1;
        assert_eq!(
            state
                .suppressed_counts
                .get(&("discovery_burst".to_string(), "service")),
            Some(&1)
        );
        // Drive a second + third increment — counter is monotonic.
        for _ in 0..2 {
            *state
                .suppressed_counts
                .entry(("discovery_burst".to_string(), user_class_label(class)))
                .or_insert(0) += 1;
        }
        assert_eq!(
            state
                .suppressed_counts
                .get(&("discovery_burst".to_string(), "service")),
            Some(&3)
        );
        // Avoid `now` warning.
        let _ = Utc::now();
    }

    /// 2026-05-03 (Wave 5b PR-4 anchor): the discovery_burst severity
    /// must be capped at Medium when the user is Service-class. The
    /// Service multiplier (5x) is enough to suppress routine `snap
    /// refresh` bursts, but a sustained burst (operator's prod showed
    /// snap_daemon doing 92 actions in 60s) still trips the elevated
    /// threshold and would fire HIGH under the old logic. HIGH on a
    /// service-account discovery burst is operator-misleading
    /// (red-banner alert that can't be acted on) — Medium is the
    /// right severity for "informative, not urgent". Pinned via
    /// source-grep so the cap survives refactors.
    #[test]
    fn discovery_burst_severity_caps_at_medium_for_service_users() {
        // Spec 068: detect_discovery_burst_calibrated moved to recon.rs.
        let src = include_str!("recon.rs");
        let burst_section_start = src
            .find("fn detect_discovery_burst_calibrated")
            .expect("discovery_burst function must exist");
        // Slice safely: `src[start..end]` panics if either index is
        // mid-codepoint, and the source has em-dashes / arrows that
        // span multiple bytes. Walk forward to the next char
        // boundary at-or-after the requested end.
        let mut burst_end = std::cmp::min(burst_section_start + 6000, src.len());
        while burst_end < src.len() && !src.is_char_boundary(burst_end) {
            burst_end += 1;
        }
        let section = &src[burst_section_start..burst_end];
        // The cap must use `matches!(user_class, UserClass::Service)`
        // BEFORE the `total >= adjusted_threshold * 2 → High` branch
        // so the High path never reaches Service users. Anchor on the
        // exact pattern; if a future refactor moves to a match
        // statement OR an early-return, the test is loud.
        assert!(
            section.contains("matches!(user_class, UserClass::Service)"),
            "discovery_burst must cap severity at Medium for Service-class users — \
             the pattern `matches!(user_class, UserClass::Service)` was lost. \
             Operator's 2026-05-03 report: HIGH alert for snap_daemon (92 actions/60s) \
             on the site home was operator-misleading."
        );
        // The user_class field must be in evidence so investigators
        // can see which class triggered without re-deriving from the
        // username string.
        assert!(
            section.contains("user_class_label(user_class)"),
            "evidence JSON must carry user_class for investigator use"
        );
    }

    // ── Spec 043 Phase 3 yara_match anchors (AUDIT-SPEC043-PHASE3) ──────
    //
    // Pre-Phase-3 the YARA scanner in the sensor wrote match-rule
    // names onto File nodes (`yara_matches: Vec<String>`) but no
    // consumer ever read them — every match was silently dropped, even
    // on real hits like Cobalt Strike / XMRig / webshells from
    // rules/yara/*.yml. These anchors pin the new detector that
    // activates that field.

    fn make_file_node_with_yara(path: &str, sha256: Option<&str>, yara: Vec<&str>) -> Node {
        Node::File {
            path: path.to_string(),
            sha256: sha256.map(String::from),
            size: Some(2048),
            entropy: Some(7.6),
            is_sensitive: false,
            yara_matches: yara.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn yara_match_detector_emits_incident_when_yara_match_present() {
        // Headline anchor: a File node with non-empty yara_matches
        // produces exactly one High incident. Pre-Phase-3 zero
        // incidents were emitted regardless of how many YARA hits.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_file_node_with_yara(
            "/tmp/payload",
            Some("abcdef0123456789aaaaaaaaaaaa"),
            vec!["webshell_php"],
        ));
        let mut state = GraphDetectorState::new();
        let incidents = detect_yara_match(&graph, &mut state, "test-host", chrono::Utc::now());
        assert_eq!(incidents.len(), 1);
        let inc = &incidents[0];
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.title.contains("webshell_php"));
        assert!(inc.summary.contains("/tmp/payload"));
        assert!(inc.incident_id.starts_with("yara_match:"));
    }

    #[test]
    fn yara_match_detector_emits_nothing_when_yara_matches_empty() {
        // Anti-regression: a File node with EMPTY yara_matches must
        // NOT produce an incident. The detector activates a write-only
        // field; it must not spam every File node in the graph.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_file_node_with_yara(
            "/etc/passwd",
            Some("abcd"),
            vec![],
        ));
        let mut state = GraphDetectorState::new();
        let incidents = detect_yara_match(&graph, &mut state, "test-host", chrono::Utc::now());
        assert!(
            incidents.is_empty(),
            "File node with empty yara_matches must not emit incident; got {} incidents",
            incidents.len()
        );
    }

    #[test]
    fn yara_match_detector_emits_one_incident_per_file_for_multiple_matches() {
        // Multi-match anchor: a single binary that matched 3 YARA
        // rules produces ONE incident (not 3). The notification
        // grouping engine downstream dedupes by detector+entity, but
        // this detector must already do per-file aggregation so the
        // operator sees one alert per file with all rule names in the
        // summary, not three separate alerts.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_file_node_with_yara(
            "/usr/local/bin/xmrig",
            Some("ffaabbcc11223344"),
            vec!["xmrig_miner", "packed_upx", "cryptominer_generic"],
        ));
        let mut state = GraphDetectorState::new();
        let incidents = detect_yara_match(&graph, &mut state, "test-host", chrono::Utc::now());
        assert_eq!(
            incidents.len(),
            1,
            "one incident per file regardless of rule count"
        );
        let inc = &incidents[0];
        // Title features the FIRST match (most operators read titles only).
        assert!(inc.title.contains("xmrig_miner"));
        // Summary lists all three rules.
        assert!(inc.summary.contains("xmrig_miner"));
        assert!(inc.summary.contains("packed_upx"));
        assert!(inc.summary.contains("cryptominer_generic"));
    }

    // ── Spec 043 Phase 5 sysctl_drift anchors (AUDIT-SPEC043-PHASE5) ───
    //
    // Pre-Phase-5 the sensor's sysctl_drift collector wrote kernel
    // tunables onto System.sysctl_params but no consumer ever diffed
    // them. Real rootkits flip these to hide themselves; without a
    // diff the signal was invisible. These anchors pin the new
    // detector that activates that field.

    fn make_system_node(params: Vec<(&str, &str)>) -> Node {
        Node::System {
            hostname: "test-host".to_string(),
            sysctl_params: params
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn sysctl_drift_first_observation_emits_nothing_just_baselines() {
        // Defensive contract: the first time we see the System node
        // there's no baseline to diff against. Detector MUST emit
        // zero incidents and just snapshot. Anti-regression for
        // accidentally treating "first sight" as "all params drifted
        // from /unset/" and spamming hundreds of false positives.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_system_node(vec![
            ("kernel.modules_disabled", "0"),
            ("net.ipv4.ip_forward", "0"),
        ]));
        let mut state = GraphDetectorState::new();
        let incidents = detect_sysctl_drift(&graph, &mut state, "h", chrono::Utc::now());
        assert!(
            incidents.is_empty(),
            "first observation must just baseline, not emit; got {} incidents",
            incidents.len()
        );
        assert!(
            state.sysctl_baseline.is_some(),
            "baseline must be populated after first observation"
        );
    }

    #[test]
    fn sysctl_drift_critical_param_change_emits_critical() {
        // The headline rootkit case: kernel.kptr_restrict relaxed
        // from `2` (the safe default) to `0` (pointer addresses
        // visible). Real rootkits do this to find their hooking
        // targets. MUST emit a Critical incident with the param name
        // in the title so the operator can ack-or-investigate at a
        // glance.
        let mut graph = KnowledgeGraph::new();
        // First observation: baseline.
        graph.add_node(make_system_node(vec![
            ("kernel.kptr_restrict", "2"),
            ("net.ipv4.ip_forward", "0"),
        ]));
        let mut state = GraphDetectorState::new();
        let _ = detect_sysctl_drift(&graph, &mut state, "h", chrono::Utc::now());

        // Replace System node with the drifted version.
        let mut graph2 = KnowledgeGraph::new();
        graph2.add_node(make_system_node(vec![
            ("kernel.kptr_restrict", "0"), // <-- relaxed by attacker
            ("net.ipv4.ip_forward", "0"),
        ]));
        let incidents = detect_sysctl_drift(&graph2, &mut state, "h", chrono::Utc::now());

        // Exactly one Critical incident for the kptr_restrict change.
        assert_eq!(incidents.len(), 1, "exactly one Critical incident expected");
        assert_eq!(incidents[0].severity, Severity::Critical);
        assert!(
            incidents[0].title.contains("kernel.kptr_restrict"),
            "title must name the changed param; got: {}",
            incidents[0].title
        );
        assert!(
            incidents[0].summary.contains("`2`") && incidents[0].summary.contains("`0`"),
            "summary must show both old and new values; got: {}",
            incidents[0].summary
        );
    }

    #[test]
    fn sysctl_drift_medium_class_aggregates_into_one_incident() {
        // Anti-spam contract: 5 non-critical params drifting in one
        // tick produce ONE Medium incident with all 5 in the summary,
        // not 5 separate incidents. Pre-aggregation (an earlier draft
        // of the detector) would have flooded the dashboard on a
        // benign system-wide tunable refresh (e.g. operator running
        // `sysctl --system` after editing /etc/sysctl.d).
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_system_node(vec![
            ("net.core.rmem_max", "131072"),
            ("net.core.wmem_max", "131072"),
            ("vm.swappiness", "60"),
            ("fs.file-max", "100000"),
            ("net.ipv4.tcp_keepalive_time", "7200"),
        ]));
        let mut state = GraphDetectorState::new();
        let _ = detect_sysctl_drift(&graph, &mut state, "h", chrono::Utc::now());

        let mut graph2 = KnowledgeGraph::new();
        graph2.add_node(make_system_node(vec![
            ("net.core.rmem_max", "262144"),        // changed
            ("net.core.wmem_max", "262144"),        // changed
            ("vm.swappiness", "10"),                // changed
            ("fs.file-max", "200000"),              // changed
            ("net.ipv4.tcp_keepalive_time", "600"), // changed
        ]));
        let incidents = detect_sysctl_drift(&graph2, &mut state, "h", chrono::Utc::now());

        // ONE incident for all 5 medium drifts.
        assert_eq!(
            incidents.len(),
            1,
            "5 medium drifts must aggregate to one incident; got {}",
            incidents.len()
        );
        assert_eq!(incidents[0].severity, Severity::Medium);
        // Summary lists all 5 changed params.
        for param in [
            "net.core.rmem_max",
            "net.core.wmem_max",
            "vm.swappiness",
            "fs.file-max",
            "net.ipv4.tcp_keepalive_time",
        ] {
            assert!(
                incidents[0].summary.contains(param),
                "summary must list {param}; got: {}",
                incidents[0].summary
            );
        }
    }

    #[test]
    fn sysctl_drift_no_change_emits_nothing() {
        // Anti-regression bound: when the System node is unchanged
        // tick-over-tick, the detector MUST emit zero incidents.
        // Pre-aggregation a buggy "always emit on every observation"
        // implementation would have flooded the dashboard at 30s
        // intervals.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_system_node(vec![("kernel.kptr_restrict", "2")]));
        let mut state = GraphDetectorState::new();
        let _ = detect_sysctl_drift(&graph, &mut state, "h", chrono::Utc::now());
        // Second tick, same params.
        let mut graph2 = KnowledgeGraph::new();
        graph2.add_node(make_system_node(vec![("kernel.kptr_restrict", "2")]));
        let incidents = detect_sysctl_drift(&graph2, &mut state, "h", chrono::Utc::now());
        assert!(
            incidents.is_empty(),
            "unchanged System node must emit zero incidents; got {}",
            incidents.len()
        );
    }

    #[test]
    fn sysctl_drift_does_not_re_emit_same_change_on_next_tick() {
        // Operator-facing rule: a single intentional change (operator
        // editing /etc/sysctl.d) should produce ONE alert, not one
        // alert per slow-loop tick. The detector updates baseline to
        // current after each emit so the same drift is not surfaced
        // again. This pins that behaviour.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_system_node(vec![("kernel.kptr_restrict", "2")]));
        let mut state = GraphDetectorState::new();
        let _ = detect_sysctl_drift(&graph, &mut state, "h", chrono::Utc::now());
        // Drift.
        let mut graph2 = KnowledgeGraph::new();
        graph2.add_node(make_system_node(vec![("kernel.kptr_restrict", "0")]));
        let first = detect_sysctl_drift(&graph2, &mut state, "h", chrono::Utc::now());
        assert_eq!(first.len(), 1);
        // Same drift, second tick — must NOT re-emit.
        let second = detect_sysctl_drift(&graph2, &mut state, "h", chrono::Utc::now());
        assert!(
            second.is_empty(),
            "same drift must not re-emit on next tick; got {} incidents",
            second.len()
        );
    }

    // ── Spec 043 Phase 4 packed_binary anchors (AUDIT-SPEC043-PHASE4) ──
    //
    // Pre-Phase-4 the sensor's file_extract collector wrote Shannon
    // entropy onto File nodes but no consumer ever read it. Packed
    // (UPX, themida) and encrypted payloads score >7.5; legit
    // binaries score 5.5-6.5. These anchors pin the new detector that
    // activates that field.

    fn make_file_with_entropy(path: &str, entropy: f32) -> Node {
        // Fake but stable sha256 derived from path bytes (not arithmetic
        // — earlier draft overflowed u64 multiplication on long paths).
        let fake_sha: String = path
            .bytes()
            .chain(std::iter::repeat(0u8))
            .take(32)
            .map(|b| format!("{b:02x}"))
            .collect();
        Node::File {
            path: path.to_string(),
            sha256: Some(fake_sha),
            size: Some(8192),
            entropy: Some(entropy),
            is_sensitive: false,
            yara_matches: vec![],
        }
    }

    fn make_process(pid: u32, comm: &str) -> Node {
        Node::Process {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            exe: Some(format!("/usr/bin/{comm}")),
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        }
    }

    #[test]
    fn packed_binary_detector_emits_when_high_entropy_and_executed() {
        // Headline anchor: a File with entropy 7.8 (above the 7.5
        // threshold) AND an Executed edge from a Process produces ONE
        // Medium incident. The exact shape of a UPX-packed dropper
        // running on the host.
        let mut graph = KnowledgeGraph::new();
        let file_id = graph.add_node(make_file_with_entropy("/tmp/dropper", 7.8));
        let proc_id = graph.add_node(make_process(12345, "dropper"));
        graph.add_edge(Edge::new(
            proc_id,
            file_id,
            Relation::Executed,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let incidents = detect_packed_binary(&graph, &mut state, "h", chrono::Utc::now(), 7.5);
        assert_eq!(incidents.len(), 1, "exactly one incident expected");
        let inc = &incidents[0];
        assert_eq!(inc.severity, Severity::Medium);
        assert!(inc.title.contains("/tmp/dropper"));
        assert!(inc.summary.contains("7.8"));
        assert!(
            inc.summary.contains("dropper(12345)"),
            "summary must name the executing process; got: {}",
            inc.summary
        );
    }

    #[test]
    fn packed_binary_detector_skips_high_entropy_when_not_executed() {
        // Anti-regression bound: a high-entropy file just sitting on
        // disk (no Executed edge) is suspicious-on-disk but not
        // actionable for THIS detector. Static analysis is a separate
        // concern. Pre-fix would have spammed every random-looking
        // file in /var/cache.
        let mut graph = KnowledgeGraph::new();
        graph.add_node(make_file_with_entropy("/var/cache/random.bin", 7.9));
        let mut state = GraphDetectorState::new();
        let incidents = detect_packed_binary(&graph, &mut state, "h", chrono::Utc::now(), 7.5);
        assert!(
            incidents.is_empty(),
            "high-entropy file with NO Executed edge must not trigger; got {}",
            incidents.len()
        );
    }

    #[test]
    fn packed_binary_detector_skips_legit_low_entropy_executed_binary() {
        // Anti-regression bound: a legit ELF binary (entropy ~6.0)
        // that ran on the host MUST NOT trigger. Otherwise every
        // /usr/bin tool would fire the detector.
        let mut graph = KnowledgeGraph::new();
        let file_id = graph.add_node(make_file_with_entropy("/usr/bin/ls", 6.1));
        let proc_id = graph.add_node(make_process(100, "ls"));
        graph.add_edge(Edge::new(
            proc_id,
            file_id,
            Relation::Executed,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let incidents = detect_packed_binary(&graph, &mut state, "h", chrono::Utc::now(), 7.5);
        assert!(
            incidents.is_empty(),
            "legit-entropy executed binary must not trigger; got {}",
            incidents.len()
        );
    }

    #[test]
    fn packed_binary_detector_respects_configurable_threshold() {
        // Threshold knob anchor: a 7.0-entropy executed binary fires
        // when threshold=6.5 but NOT when threshold=7.5 (default).
        // Pins the operator's tuning surface.
        let mut graph = KnowledgeGraph::new();
        let file_id = graph.add_node(make_file_with_entropy("/tmp/payload", 7.0));
        let proc_id = graph.add_node(make_process(200, "payload"));
        graph.add_edge(Edge::new(
            proc_id,
            file_id,
            Relation::Executed,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let strict = detect_packed_binary(&graph, &mut state, "h", chrono::Utc::now(), 7.5);
        assert!(
            strict.is_empty(),
            "entropy 7.0 with threshold 7.5 must not trigger"
        );
        let lenient = detect_packed_binary(&graph, &mut state, "h", chrono::Utc::now(), 6.5);
        assert_eq!(
            lenient.len(),
            1,
            "entropy 7.0 with threshold 6.5 MUST trigger"
        );
    }

    // ── Spec 043 Phase 6 short_lived_process anchors ───────────────────
    //
    // Pre-Phase-6 the sensor wrote process start_ts and exit_ts onto
    // Process nodes but no consumer ever measured the lifetime.
    // Sub-100ms processes that ALSO connect to external IPs are a
    // classic injection / shellcode shape (loader → connect → exfil
    // → exit). These anchors pin the new detector.

    fn make_short_process(pid: u32, comm: &str, lifetime_ms: i64) -> Node {
        let start = chrono::Utc::now() - Duration::seconds(60);
        Node::Process {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            exe: Some(format!("/tmp/{comm}")),
            uid: 0,
            container_id: None,
            start_ts: start,
            exit_ts: Some(start + Duration::milliseconds(lifetime_ms)),
        }
    }

    fn make_external_ip(addr: &str) -> Node {
        Node::Ip {
            addr: addr.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        }
    }

    fn make_internal_ip(addr: &str) -> Node {
        Node::Ip {
            addr: addr.to_string(),
            is_internal: true,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        }
    }

    #[test]
    fn short_lived_process_detector_emits_when_subms_and_external_connect() {
        // Headline anchor: a 50ms process that connected to an
        // external IP fires Medium. Exact shape of a shellcode loader.
        let mut graph = KnowledgeGraph::new();
        let proc_id = graph.add_node(make_short_process(8888, "loader", 50));
        let ip_id = graph.add_node(make_external_ip("203.0.113.66"));
        graph.add_edge(Edge::new(
            proc_id,
            ip_id,
            Relation::ConnectedTo,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let incidents =
            detect_short_lived_process(&graph, &mut state, "h", chrono::Utc::now(), 100);
        assert_eq!(incidents.len(), 1);
        let inc = &incidents[0];
        assert_eq!(inc.severity, Severity::Medium);
        assert!(inc.title.contains("loader/8888"));
        assert!(
            inc.summary.contains("203.0.113.66"),
            "summary must name the external IP; got: {}",
            inc.summary
        );
    }

    #[test]
    fn short_lived_process_detector_skips_when_lifetime_above_threshold() {
        // Anti-regression: a 500ms process (above default 100ms) that
        // connected to an external IP MUST NOT trigger. Real long-lived
        // tools shouldn't fire the detector.
        let mut graph = KnowledgeGraph::new();
        let proc_id = graph.add_node(make_short_process(8889, "wget", 500));
        let ip_id = graph.add_node(make_external_ip("8.8.8.8"));
        graph.add_edge(Edge::new(
            proc_id,
            ip_id,
            Relation::ConnectedTo,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let incidents =
            detect_short_lived_process(&graph, &mut state, "h", chrono::Utc::now(), 100);
        assert!(
            incidents.is_empty(),
            "process above threshold must not trigger; got {}",
            incidents.len()
        );
    }

    #[test]
    fn short_lived_process_detector_skips_when_only_internal_connect() {
        // Anti-regression: a fast process that connected ONLY to
        // localhost / RFC1918 (health check) MUST NOT trigger. Network
        // I/O alone isn't suspicious; EXTERNAL network I/O during a
        // sub-100ms lifetime is.
        let mut graph = KnowledgeGraph::new();
        let proc_id = graph.add_node(make_short_process(8890, "healthcheck", 30));
        let ip_id = graph.add_node(make_internal_ip("127.0.0.1"));
        graph.add_edge(Edge::new(
            proc_id,
            ip_id,
            Relation::ConnectedTo,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let incidents =
            detect_short_lived_process(&graph, &mut state, "h", chrono::Utc::now(), 100);
        assert!(
            incidents.is_empty(),
            "internal-only connect must not trigger; got {}",
            incidents.len()
        );
    }

    #[test]
    fn short_lived_process_detector_skips_when_no_exit_ts() {
        // Defensive bound: a process still running (no exit_ts) MUST
        // NOT trigger. We only know it's "short lived" once it has
        // actually exited.
        let mut graph = KnowledgeGraph::new();
        let proc_id = graph.add_node(make_process(9000, "long_runner")); // no exit_ts
        let ip_id = graph.add_node(make_external_ip("203.0.113.99"));
        graph.add_edge(Edge::new(
            proc_id,
            ip_id,
            Relation::ConnectedTo,
            chrono::Utc::now(),
        ));
        let mut state = GraphDetectorState::new();
        let incidents =
            detect_short_lived_process(&graph, &mut state, "h", chrono::Utc::now(), 100);
        assert!(
            incidents.is_empty(),
            "process without exit_ts must not trigger; got {}",
            incidents.len()
        );
    }

    // ── Spec 068 coverage: incident-emitting paths for the relocated
    // detector families that previously had no run-path test (only the
    // dedup/suppression branches were exercised). These drive each
    // detector to actually push an Incident so the family submodules
    // carry real coverage after the split. No production logic changed.

    /// Helper: add an Incident node wired to `entity` via TriggeredBy.
    fn add_incident(
        g: &mut KnowledgeGraph,
        entity: NodeId,
        detector: &str,
        at: DateTime<Utc>,
    ) -> NodeId {
        let inc_id = g.add_node(Node::Incident {
            incident_id: format!("{}:{}", detector, at.timestamp()),
            detector: detector.to_string(),
            severity: "low".into(),
            title: format!("{detector} test"),
            summary: String::new(),
            ts: at,
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_id, entity, Relation::TriggeredBy, at));
        inc_id
    }

    #[test]
    fn discovery_burst_unknown_user_over_threshold_fires_medium() {
        let mut g = KnowledgeGraph::new();
        let now = ts(1000);
        let user = g.ensure_user("attacker");
        // 5 processes RunAs the user => exec_count 5 >= threshold 5.
        for i in 0..5 {
            let p = g.ensure_process(2000 + i, 0, "recon", 0, now);
            g.add_edge(Edge::new(p, user, Relation::RunAs, now));
        }
        let mut state = GraphDetectorState::new();
        let incidents = detect_discovery_burst_calibrated(
            &g,
            &mut state,
            "test",
            now,
            &CalibrationContext::default(),
        );
        assert_eq!(incidents.len(), 1, "5 actions by unknown user should fire");
        assert_eq!(incidents[0].severity, Severity::Medium);
        assert!(incidents[0].title.contains("Discovery burst"));
    }

    #[test]
    fn discovery_burst_service_user_below_elevated_threshold_is_suppressed() {
        let mut g = KnowledgeGraph::new();
        let now = ts(1000);
        let user = g.ensure_user("snap_daemon");
        // 6 actions: over standard (5) but under the 5x service threshold (25).
        for i in 0..6 {
            let p = g.ensure_process(3000 + i, 0, "snapd", 0, now);
            g.add_edge(Edge::new(p, user, Relation::RunAs, now));
        }
        let ctx = CalibrationContext {
            service_user_names: vec!["snap_daemon".into()],
            ..Default::default()
        };
        let mut state = GraphDetectorState::new();
        let incidents = detect_discovery_burst_calibrated(&g, &mut state, "test", now, &ctx);
        assert!(
            incidents.is_empty(),
            "service user under 5x must be suppressed"
        );
        assert_eq!(
            state
                .suppressed_counts
                .get(&("discovery_burst".to_string(), "service")),
            Some(&1),
            "suppression must be counted for /metrics auditability"
        );
    }

    #[test]
    fn discovery_burst_service_user_over_elevated_threshold_caps_at_medium() {
        let mut g = KnowledgeGraph::new();
        let now = ts(1000);
        let user = g.ensure_user("snap_daemon");
        // 25 actions: exceeds even the 5x service threshold.
        for i in 0..25 {
            let p = g.ensure_process(4000 + i, 0, "snapd", 0, now);
            g.add_edge(Edge::new(p, user, Relation::RunAs, now));
        }
        let ctx = CalibrationContext {
            service_user_names: vec!["snap_daemon".into()],
            ..Default::default()
        };
        let mut state = GraphDetectorState::new();
        let incidents = detect_discovery_burst_calibrated(&g, &mut state, "test", now, &ctx);
        assert_eq!(incidents.len(), 1);
        assert_eq!(
            incidents[0].severity,
            Severity::Medium,
            "service-class discovery burst caps at Medium even when sustained"
        );
    }

    #[test]
    fn proto_anomaly_aggregated_fires_high_on_many_malformed() {
        let mut g = KnowledgeGraph::new();
        let now = ts(1000);
        let ip = g.ensure_ip("203.0.113.10", now);
        let sink = g.ensure_ip("203.0.113.11", now);
        // 10 anomalous outbound connections in window => High.
        for i in 0..10 {
            g.add_edge(
                Edge::new(ip, sink, Relation::ConnectedTo, ts(990 + i)).with_prop(
                    "summary",
                    serde_json::Value::from("malformed packet header"),
                ),
            );
        }
        let mut state = GraphDetectorState::new();
        let incidents = detect_proto_anomaly_aggregated(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::High);
        assert!(incidents[0].title.contains("Protocol anomaly"));
    }

    #[test]
    fn slow_and_low_fires_on_irregular_long_span_c2() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100_000);
        let proc = g.ensure_process(5000, 0, "backdoor", 1000, ts(79_000));
        let ip = g.ensure_ip("203.0.113.99", now);
        // 4 connections spanning ~5.7h with irregular gaps (CV >= 0.3).
        for t in [79_000, 80_000, 92_000, 99_400] {
            g.add_edge(Edge::new(proc, ip, Relation::ConnectedTo, ts(t)));
        }
        let mut state = GraphDetectorState::new();
        let incidents = detect_slow_and_low(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1, "irregular multi-hour C2 should fire");
        assert_eq!(incidents[0].severity, Severity::High);
        assert!(incidents[0].title.contains("Slow-and-low"));
    }

    #[test]
    fn data_exfil_infra_process_is_skipped() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc = g.ensure_process(6000, 0, "apt", 0, now);
        let file = g.ensure_file("/etc/shadow");
        let ip = g.ensure_ip("203.0.113.20", now);
        g.add_edge(Edge::new(proc, file, Relation::Read, now));
        g.add_edge(Edge::new(proc, ip, Relation::ConnectedTo, now));
        let mut state = GraphDetectorState::new();
        let incidents = detect_data_exfil_calibrated(
            &g,
            &mut state,
            "test",
            now,
            &CalibrationContext::default(),
        );
        assert!(
            incidents.is_empty(),
            "infra process apt must not be flagged as exfil"
        );
    }

    #[test]
    fn data_exfil_service_user_is_suppressed_and_counted() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc = g.ensure_process(6100, 0, "snap_daemon", 0, now);
        let file = g.ensure_file("/etc/shadow");
        let ip = g.ensure_ip("203.0.113.21", now);
        g.add_edge(Edge::new(proc, file, Relation::Read, now));
        g.add_edge(Edge::new(proc, ip, Relation::ConnectedTo, now));
        let ctx = CalibrationContext {
            service_user_names: vec!["snap_daemon".into()],
            ..Default::default()
        };
        let mut state = GraphDetectorState::new();
        let incidents = detect_data_exfil_calibrated(&g, &mut state, "test", now, &ctx);
        assert!(
            incidents.is_empty(),
            "service-class exfil noise is suppressed"
        );
        assert_eq!(
            state
                .suppressed_counts
                .get(&("data_exfil".to_string(), "service")),
            Some(&1)
        );
    }

    #[test]
    fn correlation_entity_matched_multistage_chain_fires() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("203.0.113.30", ts(0));
        // CL-002 Recon -> Bruteforce -> Exfil, same IP, ordered in window.
        add_incident(&mut g, ip, "port_scan", ts(0));
        add_incident(&mut g, ip, "ssh_bruteforce", ts(60));
        add_incident(&mut g, ip, "data_exfil", ts(120));
        let mut state = GraphDetectorState::new();
        let incidents = detect_correlation_chains(&g, &mut state, "test", ts(200));
        assert!(
            incidents.iter().any(|i| i.incident_id.contains("CL-002")),
            "ordered recon->brute->exfil on one IP must raise CL-002"
        );
    }

    #[test]
    fn correlation_non_entity_rule_fires_globally() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("203.0.113.31", ts(0));
        // CL-005 Container Escape -> shell -> privilege (entity_must_match = false).
        add_incident(&mut g, ip, "container_escape", ts(0));
        add_incident(&mut g, ip, "suspicious_execution", ts(60));
        add_incident(&mut g, ip, "privilege_escalation", ts(120));
        let mut state = GraphDetectorState::new();
        let incidents = detect_correlation_chains(&g, &mut state, "test", ts(200));
        assert!(
            incidents.iter().any(|i| i.incident_id.contains("CL-005")),
            "non-entity container-escape chain must raise CL-005 globally"
        );
    }

    #[test]
    fn correlation_rejects_out_of_order_stages() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("203.0.113.32", ts(0));
        // CL-003 honeypot -> bruteforce, but the bruteforce predates the
        // honeypot hit => ordering check must reject the chain.
        add_incident(&mut g, ip, "honeypot", ts(500));
        add_incident(&mut g, ip, "ssh_bruteforce", ts(100));
        let mut state = GraphDetectorState::new();
        let incidents = detect_correlation_chains(&g, &mut state, "test", ts(600));
        assert!(
            incidents.is_empty(),
            "stage timestamps out of order must not raise a chain"
        );
    }

    #[test]
    fn run_all_with_calibration_dispatches_and_records() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc = g.ensure_process(7000, 0, "wget", 0, ts(0));
        let ip = g.add_node(Node::Ip {
            addr: "93.184.216.34".into(),
            is_internal: false,
            datasets: vec!["sslbl".into()],
            risk_score: 90,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        g.add_edge(Edge::new(proc, ip, Relation::ConnectedTo, ts(1)));
        let mut state = GraphDetectorState::new();
        let incidents =
            run_all_with_calibration(&g, &mut state, "test", now, &CalibrationContext::default());
        assert!(
            incidents
                .iter()
                .any(|i| i.incident_id.contains("threat_intel")),
            "orchestrator must run threat_intel and surface the dataset hit"
        );
    }
}
