//! Command-and-control / exfiltration graph detectors (reverse shell, data exfil, DNS tunnel, C2 beacon, slow-and-low, short-lived process).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `knowledge_graph/detectors.rs`. No logic change.

use super::*;

// ── 4. Reverse Shell via Graph ──────────────────────────────────────────
// Replaces: reverse_shell detector (eBPF fd_redirect + connect sequence)
// Graph query: Process with RedirectedFd(fd=0|1) AND ConnectedTo(external Ip)

pub(super) fn detect_reverse_shell(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(30);
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        let edges = graph.outgoing_edges(proc_id);

        // Check for fd redirect (fd 0, 1, or 2)
        let has_fd_redirect = edges.iter().any(|e| {
            e.relation == Relation::RedirectedFd
                && e.ts >= cutoff
                && e.properties
                    .get("old_fd")
                    .and_then(|v| v.as_i64())
                    .is_some_and(|fd| fd <= 2)
        });

        if !has_fd_redirect {
            continue;
        }

        // Check for outbound connection to external IP
        let external_ip = edges.iter().find_map(|e| {
            if e.relation == Relation::ConnectedTo && e.ts >= cutoff {
                match graph.get_node(e.to) {
                    Some(Node::Ip {
                        addr,
                        is_internal: false,
                        ..
                    }) => Some(addr.clone()),
                    _ => None,
                }
            } else {
                None
            }
        });

        if let Some(ip) = external_ip {
            let pid = match graph.get_node(proc_id) {
                Some(Node::Process { pid, .. }) => *pid,
                _ => continue,
            };
            let key = format!("graph_revshell:{}", pid);
            if !state.check_and_set(&key, now, 300) {
                continue;
            }

            let label = graph
                .get_node(proc_id)
                .map(|n| n.label())
                .unwrap_or_default();

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_reverse_shell:{}:{}", pid, now.timestamp()),
                severity: Severity::Critical,
                title: format!("Reverse shell: {} → {}", label, ip),
                summary: format!(
                    "Process {} redirected stdin/stdout to socket connected to external IP {}",
                    label, ip
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_reverse_shell",
                    "process": label,
                    "pid": pid,
                    "dst_ip": ip,
                }),
                recommended_checks: vec![format!("Kill PID {}", pid), format!("Block IP {}", ip)],
                tags: vec!["T1059.004".to_string()],
                entities: vec![EntityRef::ip(&ip)],
            });
        }
    }

    incidents
}

// ── 8. Data Exfiltration via Graph ──────────────────────────────────────
// Replaces: data_exfiltration + data_exfil_ebpf
// Graph query: Process that Read(sensitive file) AND ConnectedTo(external Ip) in <60s

pub(super) fn detect_data_exfil_calibrated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        let edges = graph.outgoing_edges(proc_id);

        // Check if process read a sensitive file recently
        let sensitive_read = edges.iter().find(|e| {
            e.relation == Relation::Read
                && e.ts >= cutoff
                && graph.get_node(e.to).is_some_and(|n| n.is_sensitive_file())
        });

        let read_file = match sensitive_read {
            Some(e) => match graph.get_node(e.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            },
            None => continue,
        };

        // Check if same process connected to external IP
        let external_conn = edges.iter().find(|e| {
            e.relation == Relation::ConnectedTo
                && e.ts >= cutoff
                && graph.get_node(e.to).is_some_and(|n| {
                    matches!(
                        n,
                        Node::Ip {
                            is_internal: false,
                            ..
                        }
                    )
                })
        });

        if let Some(conn_edge) = external_conn {
            let dst_ip = match graph.get_node(conn_edge.to) {
                Some(Node::Ip { addr, .. }) => addr.clone(),
                _ => continue,
            };

            // Suppress data exfil to cloud provider IPs and self-traffic
            // destinations (Telegram, GeoIP endpoints, Ubuntu archives, etc.).
            // The agent routinely reads /etc/passwd (NSS resolution) and
            // connects to cloud APIs — that's self-traffic, not exfil.
            if crate::cloud_safelist::is_self_traffic_ip(&dst_ip) {
                continue;
            }

            let (pid, comm, uid) = match graph.get_node(proc_id) {
                Some(Node::Process { pid, comm, uid, .. }) => (*pid, comm.clone(), *uid),
                _ => continue,
            };

            // Infrastructure processes that legitimately read sensitive files
            // and connect to external IPs are NOT data exfiltration.
            // Filter by process name — not IP — so new IPs are covered.
            const INFRA_COMMS: &[&str] = &[
                "crowdsec",          // CrowdSec threat intel
                "innerwarden",       // InnerWarden agent
                "tokio-rt-worker",   // InnerWarden agent runtime threads
                "innerwarden-agent", // Agent binary name
                "innerwarden-senso", // Sensor binary name (truncated to 16 chars)
                "fail2ban",          // Fail2ban
                "telegraf",          // Telegraf monitoring
                "prometheus",        // Prometheus
                "node_exporter",     // Node exporter
                "apt",               // Package manager
                "dpkg",              // Package manager
                "unattended-upgr",   // Unattended upgrades
                "cscli",             // CrowdSec CLI
            ];
            let comm_lower = comm.to_lowercase();
            if INFRA_COMMS.iter().any(|&c| comm_lower.starts_with(c)) {
                continue;
            }
            // Also skip InnerWarden UID (typically 998)
            if uid == 998 {
                continue;
            }

            // 2026-05-03: classify the process owner. data_exfil is
            // the noisiest of the graph detectors — `socket +
            // sensitive_read` is exactly what apt/snap/cloud-init
            // do during routine package work. Service-class users
            // get skipped entirely (counted in suppressed_total so
            // the operator can audit). Real exfil scenarios end up
            // in Unknown class and pass through unchanged.
            let owner_user = format!("uid:{uid}");
            let user_class_by_uid = ctx.classify_user(&owner_user);
            let user_class_by_name = ctx.classify_user(&comm);
            // Take whichever classification gives a service answer —
            // the comm path catches `snap_daemon` even when the uid
            // bookkeeping is missing in environment_profile.json.
            let user_class = if matches!(user_class_by_uid, UserClass::Service)
                || matches!(user_class_by_name, UserClass::Service)
            {
                UserClass::Service
            } else if matches!(user_class_by_uid, UserClass::Human) {
                UserClass::Human
            } else if matches!(user_class_by_uid, UserClass::Root) {
                UserClass::Root
            } else {
                UserClass::Unknown
            };
            if matches!(user_class, UserClass::Service) {
                *state
                    .suppressed_counts
                    .entry(("data_exfil".to_string(), user_class_label(user_class)))
                    .or_insert(0) += 1;
                continue;
            }

            let key = format!("graph_exfil:{}:{}", pid, dst_ip);
            if !state.check_and_set(&key, now, 300) {
                continue;
            }

            let label = graph
                .get_node(proc_id)
                .map(|n| n.label())
                .unwrap_or_default();

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_data_exfil:{}:{}:{}", pid, dst_ip, now.timestamp()),
                severity: Severity::High,
                title: format!("Data exfiltration: {} read {} → connected to {}", label, read_file, dst_ip),
                summary: format!(
                    "Process {} read sensitive file {} and connected to external IP {} within 60 seconds (CL-008 pattern)",
                    label, read_file, dst_ip
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_data_exfil",
                    "process": label,
                    "pid": pid,
                    "file": read_file,
                    "dst_ip": dst_ip,
                }),
                recommended_checks: vec![
                    format!("Block IP {}", dst_ip),
                    format!("Kill PID {}", pid),
                    "Check for credential theft".to_string(),
                ],
                tags: vec!["T1041".to_string()],
                entities: vec![EntityRef::ip(&dst_ip), EntityRef::path(&read_file)],
            });
        }
    }

    incidents
}

// 25. DNS tunneling — high query volume or high-entropy domains
pub(super) fn detect_dns_tunnel(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(60);

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Count DNS resolutions in window
        let dns_edges = graph.edges_in_window(pid_id, Relation::Resolved, now, window);
        if dns_edges.len() < 50 {
            continue; // Normal DNS volume
        }

        // Check for high-entropy domains (long labels = likely tunneling)
        let long_domains = dns_edges
            .iter()
            .filter(|e| {
                graph
                    .get_node(e.to)
                    .map(|n| n.label().len() > 50)
                    .unwrap_or(false)
            })
            .count();

        let is_tunnel = long_domains > 10 || dns_edges.len() > 100;
        if !is_tunnel {
            continue;
        }

        let key = format!("graph_dnstunnel:{}", comm);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let sample_domains: Vec<String> = dns_edges
            .iter()
            .take(5)
            .filter_map(|e| graph.get_node(e.to).map(|n| n.label().to_string()))
            .collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_dns_tunnel:{}:{}", comm, now.timestamp()),
            severity: Severity::High,
            title: format!("DNS tunneling: {} ({} queries, {} long domains in 1m)", comm, dns_edges.len(), long_domains),
            summary: format!(
                "Process '{}' resolved {} domains in 1 minute ({} with labels >50 chars). Pattern consistent with DNS tunneling/exfiltration.",
                comm, dns_edges.len(), long_domains
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_dns_tunnel",
                "process": comm,
                "query_count": dns_edges.len(),
                "long_domain_count": long_domains,
                "sample_domains": sample_domains,
            }),
            recommended_checks: vec![
                format!("Check DNS: dig +short any suspicious domain"),
                format!("Block process: kill $(pgrep {})", comm),
            ],
            tags: vec!["T1071.004".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// 18. C2 beacon detection (periodic outbound connections at regular intervals)
pub(super) fn detect_c2_beacon(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let min_connections = 5;
    let max_jitter_pct = 0.15; // 15% jitter tolerance

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Group outbound connections by destination IP
        let mut ip_times: HashMap<NodeId, Vec<i64>> = HashMap::new();
        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::ConnectedTo {
                continue;
            }
            if now - edge.ts > window {
                continue;
            }
            // Only external IPs
            if let Some(Node::Ip { is_internal, .. }) = graph.get_node(edge.to) {
                if *is_internal {
                    continue;
                }
            }
            ip_times
                .entry(edge.to)
                .or_default()
                .push(edge.ts.timestamp());
        }

        for (ip_id, mut times) in ip_times {
            if times.len() < min_connections {
                continue;
            }
            times.sort();

            // Calculate intervals between consecutive connections
            let intervals: Vec<i64> = times.windows(2).map(|w| w[1] - w[0]).collect();
            if intervals.is_empty() {
                continue;
            }

            let avg_interval = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
            if avg_interval < 5.0 {
                continue; // Too fast, likely normal traffic not beaconing
            }

            // Check jitter: all intervals within ±15% of average
            let is_periodic = intervals.iter().all(|&i| {
                let deviation = (i as f64 - avg_interval).abs() / avg_interval;
                deviation <= max_jitter_pct
            });

            if !is_periodic {
                continue;
            }

            let ip_addr = match graph.get_node(ip_id) {
                Some(Node::Ip { addr, .. }) => addr.clone(),
                _ => continue,
            };

            let key = format!("graph_c2:{}:{}", comm, ip_addr);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_c2_beacon:{}:{}:{}", comm, ip_addr, now.timestamp()),
                severity: Severity::High,
                title: format!("C2 beacon pattern: {} → {} (every ~{}s)", comm, ip_addr, avg_interval as i64),
                summary: format!(
                    "Process '{}' shows periodic outbound connections to {} every ~{}s ({} connections in 5m, {:.0}% jitter). This pattern is consistent with command-and-control beaconing.",
                    comm, ip_addr, avg_interval as i64, times.len(), max_jitter_pct * 100.0
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_c2_beacon",
                    "process": comm,
                    "ip": ip_addr,
                    "connection_count": times.len(),
                    "avg_interval_secs": avg_interval as i64,
                    "intervals": intervals,
                }),
                recommended_checks: vec![
                    format!("Check process: ps aux | grep {}", comm),
                    format!("Check destination: whois {}", ip_addr),
                    format!("Block IP: innerwarden block-ip {}", ip_addr),
                ],
                tags: vec!["T1071".to_string(), "T1573".to_string()],
                entities: vec![EntityRef::ip(&ip_addr)],
            });
        }
    }
    incidents
}

// ── Slow-and-low detector ──────────────────────────────────────────────
// Detects persistent low-rate C2 communication over 24h+.
// Complements the sensor's beaconing detector (5min window) by catching
// attackers who spread connections over hours/days with irregular intervals.

pub(super) fn detect_slow_and_low(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::hours(6); // 6h lookback (graph retains ~6h of edges)
    let min_connections = 4;
    let min_span_hours = 2;

    // Group: (process_id, external IP) → edge timestamps
    let mut patterns: std::collections::HashMap<(NodeId, String), Vec<DateTime<Utc>>> =
        std::collections::HashMap::new();

    for &proc_id in &graph.active_nodes_since(cutoff) {
        let (comm, uid) = match graph.get_node(proc_id) {
            Some(Node::Process { comm, uid, .. }) => (comm.clone(), *uid),
            _ => continue,
        };

        // Skip infra processes (same list as data exfil)
        const INFRA: &[&str] = &[
            "crowdsec",
            "innerwarden",
            "tokio-rt-worker",
            "innerwarden-agent",
            "innerwarden-senso",
            "fail2ban",
            "telegraf",
            "prometheus",
            "node_exporter",
            "apt",
            "dpkg",
            "cscli",
        ];
        let comm_lower = comm.to_lowercase();
        if INFRA.iter().any(|&c| comm_lower.starts_with(c)) || uid == 998 {
            continue;
        }

        for edge in graph.outgoing_edges(proc_id) {
            if edge.relation != Relation::ConnectedTo || edge.ts < cutoff {
                continue;
            }
            if let Some(Node::Ip {
                addr,
                is_internal: false,
                ..
            }) = graph.get_node(edge.to)
            {
                if crate::cloud_safelist::is_self_traffic_ip(addr) {
                    continue;
                }
                patterns
                    .entry((proc_id, addr.clone()))
                    .or_default()
                    .push(edge.ts);
            }
        }
    }

    for ((proc_id, ip), mut timestamps) in patterns {
        if timestamps.len() < min_connections {
            continue;
        }
        timestamps.sort();

        let first = timestamps.first().copied().unwrap();
        let last = timestamps.last().copied().unwrap();
        let span = last - first;
        if span < Duration::hours(min_span_hours) {
            continue;
        }

        // Check irregularity: coefficient of variation of intervals
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]).num_seconds() as f64)
            .collect();
        if intervals.is_empty() {
            continue;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < 1.0 {
            continue;
        }
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = variance.sqrt() / mean;

        // CV < 0.3 = regular beaconing (caught by sensor c2_callback).
        // CV >= 0.3 = irregular slow-and-low.
        if cv < 0.3 {
            continue;
        }

        let key = format!("graph_slow_low:{}:{}", proc_id, ip);
        if !state.check_and_set(&key, now, 3600) {
            continue;
        }

        let label = graph
            .get_node(proc_id)
            .map(|n| n.label())
            .unwrap_or_default();
        let hours = span.num_hours().max(1);

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_slow_low:{}:{}:{}", proc_id, ip, now.timestamp()),
            severity: Severity::High,
            title: format!(
                "Slow-and-low C2: {} → {} ({} connections over {}h)",
                label,
                ip,
                timestamps.len(),
                hours
            ),
            summary: format!(
                "Process {} made {} connections to external IP {} over {} hours with irregular \
                 intervals (CV={:.2}). This pattern evades short-window detectors and suggests \
                 intentional C2 communication.",
                label,
                timestamps.len(),
                ip,
                hours,
                cv
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_slow_low",
                "process": label,
                "ip": ip,
                "connections": timestamps.len(),
                "span_hours": hours,
                "coefficient_of_variation": cv,
            }),
            recommended_checks: vec![
                format!("Investigate {} for C2 implant or backdoor", label),
                format!("Check {} on AbuseIPDB/VirusTotal", ip),
                "Review process ancestry for initial compromise".to_string(),
            ],
            tags: vec!["T1071".to_string(), "slow_and_low".to_string()],
            entities: vec![EntityRef::ip(&ip)],
        });
    }

    incidents
}

/// Spec 043 Phase 6 — short_lived_process_detector. Activates a KG field
/// that was write-only pre-Phase-6 (`Node::Process.exit_ts`). The
/// sensor's `ebpf_syscall` collector records `start_ts` on `execve`
/// and `exit_ts` on `process_exit`, both timestamps written onto the
/// Process node — but no consumer ever measured the lifetime.
/// Sub-100ms processes that ALSO connect to external IPs are a
/// classic injection / shellcode shape: the parent forks a tiny
/// loader that does ONE TCP connect to a C2, exfils a token, and
/// dies. Real long-running tools take seconds at minimum.
///
/// Threshold 100ms is configurable via
/// `[kg].short_lived_process_threshold_ms` for operators on slow
/// hardware where legit tools (e.g. `whoami`, `id`) might dip below
/// the default. Empirically on a 4-core Xeon E3, even `cat /etc/passwd`
/// runs in 2-5ms — so the question isn't "is the process fast" but
/// "did this fast process do network I/O", which the ConnectedTo
/// edge gates.
///
/// Disabled by default per Spec 043 promotion gate
/// (`[kg].short_lived_process_detector_enabled`).
pub fn detect_short_lived_process(
    graph: &KnowledgeGraph,
    _state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    threshold_ms: u64,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let threshold = Duration::milliseconds(threshold_ms as i64);
    for id in graph.nodes_of_type(NodeType::Process) {
        let Some(node) = graph.get_node(id) else {
            continue;
        };
        let (pid, comm, start_ts, exit_ts) = match node {
            Node::Process {
                pid,
                comm,
                start_ts,
                exit_ts: Some(exit),
                ..
            } => (*pid, comm, *start_ts, *exit),
            _ => continue,
        };
        let lifetime = exit_ts - start_ts;
        if lifetime >= threshold {
            continue;
        }
        // Negative lifetime (clock skew) — skip rather than emit
        // bogus incident.
        if lifetime < Duration::zero() {
            continue;
        }
        // Require at least one ConnectedTo edge to an EXTERNAL IP.
        // Internal-only connections (loopback, RFC1918) are normal
        // for short-lived health probes and shouldn't trigger.
        let external_connect = graph
            .outgoing_edges(id)
            .iter()
            .filter(|e| e.relation == Relation::ConnectedTo)
            .filter_map(|e| graph.get_node(e.to))
            .filter_map(|n| match n {
                Node::Ip {
                    addr, is_internal, ..
                } if !is_internal => Some(addr.clone()),
                _ => None,
            })
            .next();
        let Some(external_ip) = external_connect else {
            continue;
        };
        let lifetime_ms = lifetime.num_milliseconds();
        // Stable id by pid + start_ts so the same short-lived
        // process across slow-loop ticks deduplicates.
        let incident_id = format!(
            "short_lived_process:{pid}:{}",
            start_ts.format("%Y-%m-%dT%H:%M:%S")
        );
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id,
            severity: Severity::Medium,
            title: format!(
                "Short-lived process with external connect: {comm}/{pid} ({lifetime_ms}ms)"
            ),
            summary: format!(
                "Process {comm} (pid {pid}) lived {lifetime_ms}ms before exit AND \
                 connected to external IP {external_ip} during that window. Real \
                 long-running tools take seconds at minimum; sub-{threshold_ms}ms \
                 processes that do network I/O are a classic injection / shellcode \
                 shape (tiny loader → connect → exfil → exit). Investigate: was \
                 this a legit short-lived health check or a payload?"
            ),
            evidence: serde_json::json!([{
                "kind": "short_lived_process",
                "pid": pid,
                "comm": comm,
                "start_ts": start_ts.to_rfc3339(),
                "exit_ts": exit_ts.to_rfc3339(),
                "lifetime_ms": lifetime_ms,
                "external_ip": external_ip,
            }]),
            recommended_checks: vec![
                format!("Check parent process for pid {pid} via `auditd`"),
                format!("Search the process binary path in `audit.log` for execve"),
            ],
            tags: vec!["short_lived_process".to_string(), "T1059".to_string()],
            entities: vec![EntityRef::ip(&external_ip)],
        });
    }
    incidents
}
