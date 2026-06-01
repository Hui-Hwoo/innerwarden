//! Host-integrity graph detectors (process-tree anomaly, fileless, network sniffing, kernel module, container escape, crypto miner, sensitive write, host drift, docker anomaly, cgroup abuse, yara match, sysctl drift, packed binary).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `knowledge_graph/detectors.rs`. No logic change.

use super::*;

// ── 3. Process Tree Anomaly via Graph ───────────────────────────────────
// Replaces: process_tree detector (parent→child pattern matching)
// Graph query: ancestors() with suspicious parent comm

pub(super) fn detect_process_tree_anomaly(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let suspicious_parents = [
        "nginx", "apache", "apache2", "httpd", "mysqld", "postgres", "java", "node", "php-fpm",
        "uwsgi", "gunicorn", "mongod",
    ];
    let shell_comms = ["bash", "sh", "dash", "zsh", "ash", "fish", "csh"];

    for proc_id in graph.nodes_of_type(NodeType::Process) {
        let (pid, comm) = match graph.get_node(proc_id) {
            Some(Node::Process { pid, comm, .. }) => (*pid, comm.clone()),
            _ => continue,
        };

        // Only check shell processes
        if !shell_comms.iter().any(|s| comm == *s) {
            continue;
        }

        let ancestors = graph.ancestors(pid);
        if ancestors.is_empty() {
            continue;
        }

        // Check if any ancestor is a suspicious parent
        for anc_id in &ancestors {
            let anc_comm = match graph.get_node(*anc_id) {
                Some(Node::Process { comm, .. }) => comm.clone(),
                _ => continue,
            };

            if suspicious_parents.iter().any(|s| anc_comm.contains(s)) {
                let key = format!("graph_ptree:{}:{}", anc_comm, pid);
                if !state.check_and_set(&key, now, 600) {
                    continue;
                }

                let chain: Vec<String> = std::iter::once(proc_id)
                    .chain(ancestors.iter().copied())
                    .filter_map(|id| graph.get_node(id).map(|n| n.label()))
                    .collect();

                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!(
                        "graph_process_tree:{}:{}:{}",
                        anc_comm,
                        pid,
                        now.timestamp()
                    ),
                    severity: Severity::High,
                    title: format!("Suspicious process tree: {} spawned shell", anc_comm),
                    summary: format!("Process chain: {}", chain.join(" → ")),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_process_tree",
                        "chain": chain,
                        "suspicious_parent": anc_comm,
                    }),
                    recommended_checks: vec![
                        format!("Check if {} was exploited", anc_comm),
                        "Review process tree for web shell or RCE".to_string(),
                    ],
                    tags: vec!["T1059.004".to_string()],
                    entities: vec![],
                });
                break; // One alert per process
            }
        }
    }

    incidents
}

// ── 5. Fileless Malware via Graph ───────────────────────────────────────
// Replaces: fileless detector (memfd_create + mprotect + connect)
// Graph query: Process with CreatedMemfd AND MprotectExec AND ConnectedTo(external)

pub(super) fn detect_fileless(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        let edges = graph.outgoing_edges(proc_id);

        let has_memfd = edges
            .iter()
            .any(|e| e.relation == Relation::CreatedMemfd && e.ts >= cutoff);
        let has_mprotect = edges
            .iter()
            .any(|e| e.relation == Relation::MprotectExec && e.ts >= cutoff);
        let has_external = edges.iter().any(|e| {
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

        if has_memfd && has_mprotect && has_external {
            let pid = match graph.get_node(proc_id) {
                Some(Node::Process { pid, .. }) => *pid,
                _ => continue,
            };
            let key = format!("graph_fileless:{}", pid);
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
                incident_id: format!("graph_fileless:{}:{}", pid, now.timestamp()),
                severity: Severity::Critical,
                title: format!("Fileless malware: {}", label),
                summary: format!(
                    "Process {} created memfd + made memory executable + connected to external IP (CL-006 pattern)",
                    label
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_fileless",
                    "process": label,
                    "pid": pid,
                }),
                recommended_checks: vec![format!("Kill PID {} immediately", pid)],
                tags: vec!["T1055.009".to_string()],
                entities: vec![],
            });
        }
    }

    incidents
}

// 24. Network sniffing — processes running capture tools
pub(super) fn detect_network_sniffing(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let sniffer_tools = [
        "tcpdump",
        "tshark",
        "wireshark",
        "ngrep",
        "ettercap",
        "bettercap",
        "dsniff",
        "arpspoof",
        "mitmproxy",
    ];
    // Spec 015: processes spawned by the agent itself must not trigger this
    // detector. The dashboard pcap_capture module spawns tcpdump for ~60s
    // bursts whenever a High/Critical incident fires, and the old presence
    // scan was counting each of those bursts as a new sniffing event —
    // contributing 67 graph_network_sniffing false positives on the prod
    // snapshot from 2026-04-11.
    let agent_ancestors = ["innerwarden-agent", "innerwarden-sensor"];

    // Only consider processes that actually started recently. This matches
    // the signal we care about ("someone just launched tcpdump") and stops
    // the presence-scan behavior where a stale Process node kept firing the
    // detector once per cooldown window forever.
    let window = Duration::seconds(300);

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let (pid, comm, start_ts) = match graph.get_node(pid_id) {
            Some(Node::Process {
                pid,
                comm,
                start_ts,
                ..
            }) => (*pid, comm.clone(), *start_ts),
            _ => continue,
        };
        if !sniffer_tools.iter().any(|t| comm == *t) {
            continue;
        }
        if now - start_ts > window {
            continue; // stale node — not a fresh launch
        }

        // Walk ancestors; if any is the agent/sensor itself, this sniffer
        // was spawned by InnerWarden's own pcap_capture and is not an alert.
        let spawned_by_agent = graph.ancestors(pid).iter().any(|&anc| {
            matches!(
                graph.get_node(anc),
                Some(Node::Process { comm: ac, .. }) if agent_ancestors.iter().any(|a| ac == a)
            )
        });
        if spawned_by_agent {
            continue;
        }

        // Fallback: if the ancestor walk couldn't find the parent (eBPF
        // event arrived with pid=0 or ppid not ingested), check the Process
        // node's own uid. The agent runs as uid 998 (innerwarden); tcpdump
        // spawned by pcap_capture inherits this uid. Observed 2026-04-12:
        // the ancestor walk returns empty when the graph doesn't have the
        // parent Process node, so the uid check is the safety net.
        if let Some(Node::Process { uid, .. }) = graph.get_node(pid_id) {
            if *uid == 998 {
                // innerwarden UID — this sniffer is our own pcap_capture
                continue;
            }
        }

        let key = format!("graph_sniff:{}:{}", comm, pid_id);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_network_sniffing:{}:{}", comm, now.timestamp()),
            severity: Severity::High,
            title: format!("Network sniffing tool detected: {}", comm),
            summary: format!(
                "Process '{}' is a known network capture tool. May indicate credential harvesting or traffic interception.",
                comm
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_network_sniffing",
                "process": comm,
            }),
            recommended_checks: vec![
                format!("Check process: ps aux | grep {}", comm),
                "Review CAP_NET_RAW: getpcaps $(pgrep tcpdump)".to_string(),
            ],
            tags: vec!["T1040".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// ── Phase 3A: Easy Graph Detectors ─────────────────────────────────────

// 9. Kernel module loading (insmod/modprobe/rmmod)
pub(super) fn detect_kernel_module(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let module_cmds = ["insmod", "modprobe", "rmmod"];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if !module_cmds.iter().any(|c| comm == *c) {
            continue;
        }
        // Find what file was executed/loaded
        let target = graph
            .outgoing_edges(pid_id)
            .iter()
            .find(|e| e.relation == Relation::Executed || e.relation == Relation::LoadedModule)
            .and_then(|e| graph.get_node(e.to).map(|n| n.label().to_string()))
            .unwrap_or_else(|| comm.clone());

        let key = format!("graph_km:{}", target);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_kernel_module:{}:{}", target, now.timestamp()),
            severity: Severity::High,
            title: format!("Kernel module operation: {} {}", comm, target),
            summary: format!(
                "Process '{}' loaded/unloaded kernel module '{}'. Kernel module operations can indicate rootkit installation or system tampering.",
                comm, target
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_kernel_module",
                "process": comm,
                "module": target,
            }),
            recommended_checks: vec![
                format!("Verify module {} is expected", target),
                "Check lsmod for unknown modules".to_string(),
            ],
            tags: vec!["T1547.006".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// 11. Container escape attempts (docker.sock access, /proc/1 reads)
pub(super) fn detect_container_escape(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let escape_paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/proc/1/root",
        "/proc/1/ns/mnt",
        "/proc/1/ns/pid",
        "/proc/1/ns/net",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::Read && edge.relation != Relation::Wrote {
                continue;
            }
            let file_path = match graph.get_node(edge.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            };
            if !escape_paths.iter().any(|p| file_path.starts_with(p)) {
                continue;
            }

            let key = format!("graph_escape:{}:{}", pid_id, file_path);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_container_escape:{}:{}", comm, now.timestamp()),
                severity: Severity::Critical,
                title: format!("Container escape attempt: {} accessed {}", comm, file_path),
                summary: format!(
                    "Process '{}' accessed '{}' which may indicate a container escape attempt.",
                    comm, file_path
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_container_escape",
                    "process": comm,
                    "file": file_path,
                }),
                recommended_checks: vec![
                    "Check if process is running inside a container".to_string(),
                    format!("Investigate why {} needs access to {}", comm, file_path),
                ],
                tags: vec!["T1611".to_string()],
                entities: vec![],
            });
        }
    }
    incidents
}

// 13. Crypto miner detection (connections to mining pools)
pub(super) fn detect_crypto_miner(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let miner_comms = [
        "xmrig",
        "minerd",
        "cpuminer",
        "ethminer",
        "cgminer",
        "bfgminer",
        "ccminer",
        "nbminer",
        "t-rex",
        "phoenixminer",
        "lolminer",
    ];
    let mining_ports: HashSet<u16> = [3333, 4444, 5555, 8333, 14444, 14433, 45700]
        .iter()
        .copied()
        .collect();

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        // Fetch comm + pid + uid in a single match so the incident evidence
        // below can populate the Phase 014-D ingestion path (pid/uid) without
        // needing a second get_node call and a separate defensive fallback.
        let (comm, pid, uid) = match graph.get_node(pid_id) {
            Some(Node::Process { comm, pid, uid, .. }) => (comm.clone(), *pid, *uid),
            _ => continue,
        };

        // Check by process name
        let name_match = miner_comms.iter().any(|m| comm.to_lowercase().contains(m));

        // Check by connection to mining ports
        let port_match = graph.outgoing_edges(pid_id).iter().any(|e| {
            if e.relation != Relation::ConnectedTo {
                return false;
            }
            e.properties
                .get("port")
                .and_then(|p| p.as_u64())
                .map(|p| mining_ports.contains(&(p as u16)))
                .unwrap_or(false)
        });

        if !name_match && !port_match {
            continue;
        }

        let key = format!("graph_miner:{}", comm);
        if !state.check_and_set(&key, now, 1800) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_crypto_miner:{}:{}", comm, now.timestamp()),
            severity: Severity::High,
            title: format!("Crypto miner detected: {}", comm),
            summary: format!(
                "Process '{}' matches crypto mining patterns (process name or mining pool connection).",
                comm
            ),
            evidence: serde_json::json!([{
                "source": "knowledge_graph",
                "detector": "graph_crypto_miner",
                "process": comm,
                "pid": pid,
                "comm": comm,
                "uid": uid,
                "name_match": name_match,
                "port_match": port_match,
            }]),
            recommended_checks: vec![
                format!("Kill process: kill -9 $(pgrep {})", comm),
                "Check CPU usage: top -bn1 | head -20".to_string(),
            ],
            tags: vec!["T1496".to_string()],
            entities: vec![EntityRef::path(format!("service:{comm}"))],
        });
    }
    incidents
}

// 14. Sensitive file writes by unexpected processes
pub(super) fn detect_sensitive_write(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let trusted_writers = [
        "apt",
        "dpkg",
        "yum",
        "rpm",
        "pacman",
        "systemd",
        "systemctl",
        "useradd",
        "usermod",
        "groupadd",
        "passwd",
        "chpasswd",
        "innerwarden-sensor",
        "innerwarden-agent",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if trusted_writers.iter().any(|w| comm == *w) {
            continue;
        }

        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::Wrote {
                continue;
            }
            let (file_path, is_sensitive) = match graph.get_node(edge.to) {
                Some(Node::File {
                    path, is_sensitive, ..
                }) => (path.clone(), *is_sensitive),
                _ => continue,
            };
            if !is_sensitive {
                continue;
            }

            let key = format!("graph_senswrite:{}:{}", comm, file_path);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_sensitive_write:{}:{}", comm, now.timestamp()),
                severity: Severity::High,
                title: format!("Sensitive file modified: {} wrote {}", comm, file_path),
                summary: format!(
                    "Unexpected process '{}' wrote to sensitive file '{}'. This may indicate unauthorized system modification.",
                    comm, file_path
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_sensitive_write",
                    "process": comm,
                    "file": file_path,
                }),
                recommended_checks: vec![
                    format!("Check file integrity: stat {}", file_path),
                    format!("Review process: ps aux | grep {}", comm),
                ],
                tags: vec!["T1222".to_string()],
                entities: vec![EntityRef::path(&file_path)],
            });
        }
    }
    incidents
}

// ── Phase 3B: Aggregation Detectors ────────────────────────────────────

// 19. Host drift — aggregated: instead of 1 incident per unknown process,
// group by user and fire 1 incident with count. Unknown binaries in /tmp always fire individually.
pub(super) fn detect_host_drift_calibrated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let system_binaries = [
        "apt",
        "apt-get",
        "dpkg",
        "yum",
        "rpm",
        "pacman",
        "snap",
        "systemctl",
        "service",
        "journalctl",
        "logrotate",
        "cron",
        "sshd",
        "bash",
        "sh",
        "zsh",
        "dash",
        "login",
        "su",
        "sudo",
        "grep",
        "find",
        "ls",
        "cat",
        "head",
        "tail",
        "awk",
        "sed",
        "ps",
        "top",
        "htop",
        "free",
        "df",
        "du",
        "mount",
        "umount",
        "ip",
        "ss",
        "netstat",
        "ping",
        "curl",
        "wget",
        "ssh",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "chmod",
        "chown",
        "tar",
        "gzip",
        "make",
        "cargo",
        "rustc",
        "gcc",
        "python3",
        "pip",
        "node",
        "npm",
        "git",
        "rsync",
        "docker",
        "containerd",
        "runc",
        "innerwarden-sensor",
        "innerwarden-agent",
        "innerwarden-watchdog",
        "date",
        "who",
        "w",
        "id",
        "uname",
        "hostname",
        "env",
        "touch",
        "tee",
        "sort",
        "uniq",
        "wc",
        "cut",
        "tr",
        "xargs",
        "readlink",
        "dirname",
        "basename",
        "stat",
        "file",
        "which",
        "locale",
        "stty",
        "tput",
        "clear",
        "less",
        "more",
        "vi",
        "vim",
        "nano",
    ];

    // Group unusual executions by user
    let mut user_drifts: HashMap<String, Vec<String>> = HashMap::new();

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let (comm, uid, start_ts) = match graph.get_node(pid_id) {
            Some(Node::Process {
                comm,
                uid,
                start_ts,
                ..
            }) => (comm.clone(), *uid, *start_ts),
            _ => continue,
        };
        if now - start_ts > window {
            continue;
        }
        if system_binaries.iter().any(|b| comm == *b) {
            continue;
        }

        // Check if exe path is suspicious (/tmp, /dev/shm, /var/tmp)
        let exe_suspicious = graph.outgoing_edges(pid_id).iter().any(|e| {
            e.relation == Relation::Executed
                && graph
                    .get_node(e.to)
                    .map(|n| {
                        let label = n.label();
                        label.starts_with("/tmp/")
                            || label.starts_with("/dev/shm/")
                            || label.starts_with("/var/tmp/")
                    })
                    .unwrap_or(false)
        });

        if exe_suspicious {
            // Suspicious path — fire individually (never aggregate these)
            let key = format!("graph_drift_sus:{}:{}", comm, pid_id);
            if state.check_and_set(&key, now, 300) {
                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_host_drift:{}:{}", comm, now.timestamp()),
                    severity: Severity::High,
                    title: format!("Suspicious execution: {} from temp directory", comm),
                    summary: format!(
                        "Process '{}' executed from suspicious path (/tmp, /dev/shm, /var/tmp).",
                        comm
                    ),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_host_drift",
                        "process": comm,
                        "suspicious_path": true,
                    }),
                    recommended_checks: vec![format!(
                        "Check process: ls -la /proc/{}/exe 2>/dev/null || echo 'process exited'",
                        pid_id
                    )],
                    tags: vec!["T1059".to_string()],
                    entities: vec![],
                });
            }
            continue;
        }

        // Normal drift — aggregate by user
        let user_name = format!("uid:{}", uid);
        user_drifts.entry(user_name).or_default().push(comm);
    }

    // Fire aggregated incidents per user
    for (user, procs) in &user_drifts {
        // 2026-05-03: graduated thresholds via UserClass.
        //   Root + Human → 30 (operators legitimately build / deploy /
        //     debug, exec many non-standard binaries from /usr/local).
        //   Service → 75 (5x — service accounts spawning many helper
        //     binaries during package work).
        //   Unknown → 15 (strict).
        let user_class = ctx.classify_user(user);
        let threshold = match user_class {
            UserClass::Root | UserClass::Human => 30,
            UserClass::Service => 75,
            UserClass::Unknown => 15,
        };
        // Suppression telemetry: would have fired but didn't because
        // of class-elevated threshold. Operator can grep /metrics.
        if procs.len() >= 15 && procs.len() < threshold {
            *state
                .suppressed_counts
                .entry(("host_drift".to_string(), user_class_label(user_class)))
                .or_insert(0) += 1;
        }
        if procs.len() < threshold {
            continue;
        }
        let key = format!("graph_drift_agg:{}", user);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }
        let unique: HashSet<&String> = procs.iter().collect();
        let sample: Vec<&str> = unique.iter().take(10).map(|s| s.as_str()).collect();
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_host_drift:{}:{}", user, now.timestamp()),
            severity: Severity::Medium,
            title: format!("Host drift: {} unusual executions by {} in 5m", procs.len(), user),
            summary: format!(
                "User {} ran {} non-standard processes in 5 minutes. Sample: {}. May indicate admin activity or compromise.",
                user, procs.len(), sample.join(", ")
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_host_drift",
                "user": user,
                "count": procs.len(),
                "unique_count": unique.len(),
                "sample": sample,
            }),
            recommended_checks: vec![
                format!("Check recent activity for {}", user),
            ],
            tags: vec!["T1059".to_string()],
            entities: vec![EntityRef::user(user)],
        });
    }
    incidents
}

// 15. User creation — new user accounts appearing (privilege escalation vector)
// Spec 015: `detect_user_creation` was removed as a presence-scan
// anti-pattern. See the comment in `run_all` above for the rationale.
// Real user-creation signal is preserved via the sensor-side
// `user_creation` detector, whose incidents reach the graph via
// `ingest_incident` and continue to feed correlation rules.

// 16. Docker anomaly — container rapid restarts or OOM kills
pub(super) fn detect_docker_anomaly(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);

    for &cid in graph.nodes_of_type(NodeType::Container).iter() {
        let (container_id, name, oom_killed) = match graph.get_node(cid) {
            Some(Node::Container {
                container_id,
                name,
                oom_killed,
                ..
            }) => (
                container_id.clone(),
                name.clone().unwrap_or_default(),
                *oom_killed,
            ),
            _ => continue,
        };

        // Count restart events (DiedOn + StartedOn pairs) in window
        let restart_count = graph
            .all_edges(cid)
            .iter()
            .filter(|e| {
                matches!(e.relation, Relation::DiedOn | Relation::StartedOn) && now - e.ts < window
            })
            .count();

        if oom_killed {
            let key = format!("graph_docker_oom:{}", container_id);
            if state.check_and_set(&key, now, 600) {
                let label = if name.is_empty() {
                    &container_id
                } else {
                    &name
                };
                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_docker_oom:{}:{}", container_id, now.timestamp()),
                    severity: Severity::Medium,
                    title: format!("Container OOM killed: {}", label),
                    summary: format!("Container '{}' was killed by OOM. May indicate resource exhaustion attack or crypto mining.", label),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_docker_anomaly",
                        "container_id": container_id,
                        "name": name,
                        "event": "oom_killed",
                    }),
                    recommended_checks: vec![
                        format!("Check container: docker inspect {}", container_id),
                    ],
                    tags: vec!["T1496".to_string()],
                    entities: vec![],
                });
            }
        }

        if restart_count >= 6 {
            // 3+ restarts (each = died + started)
            let key = format!("graph_docker_restart:{}", container_id);
            if state.check_and_set(&key, now, 600) {
                let label = if name.is_empty() {
                    &container_id
                } else {
                    &name
                };
                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_docker_restart:{}:{}", container_id, now.timestamp()),
                    severity: Severity::Medium,
                    title: format!("Container rapid restarts: {} ({} events in 5m)", label, restart_count),
                    summary: format!("Container '{}' has {} start/stop events in 5 minutes. May indicate crash loop or instability.", label, restart_count),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_docker_anomaly",
                        "container_id": container_id,
                        "restart_events": restart_count,
                    }),
                    recommended_checks: vec![
                        format!("Check logs: docker logs {}", container_id),
                    ],
                    tags: vec!["T1610".to_string()],
                    entities: vec![],
                });
            }
        }
    }
    incidents
}

// ── Phase 3A (T009): Cgroup Abuse ──────────────────────────────────────
// Detects processes with excessive CPU/memory usage based on cgroup monitoring
// events. Fires when a process appears in multiple cgroup-related events
// within a window (sustained resource abuse, e.g. cryptominer).

pub(super) fn detect_cgroup_abuse(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(120); // 2+ ticks (60s each)

    // Count cgroup-related edges per process in recent window
    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Count edges with cgroup properties in window
        let cgroup_events: usize = graph
            .outgoing_edges(pid_id)
            .iter()
            .filter(|e| {
                now - e.ts < window
                    && e.properties
                        .get("cgroup_cpu_pct")
                        .and_then(|v| v.as_f64())
                        .map(|pct| pct > 90.0)
                        .unwrap_or(false)
            })
            .count();

        if cgroup_events < 2 {
            continue; // Need sustained abuse (2+ observations)
        }

        let key = format!("graph_cgroup:{}:{}", comm, pid_id);
        if !state.check_and_set(&key, now, 1800) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_cgroup_abuse:{}:{}", comm, now.timestamp()),
            severity: Severity::Medium,
            title: format!("Cgroup abuse: {} sustained high CPU", comm),
            summary: format!(
                "Process '{}' shows sustained CPU usage >90% across {} observations in {}s. May indicate cryptominer or resource abuse.",
                comm, cgroup_events, window.num_seconds()
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_cgroup_abuse",
                "process": comm,
                "observations": cgroup_events,
                "window_secs": window.num_seconds(),
            }),
            recommended_checks: vec![
                format!("Check CPU: top -p $(pgrep -f {})", comm),
                format!("Check cgroup: cat /sys/fs/cgroup/system.slice/*/cpu.stat"),
            ],
            tags: vec!["T1496".to_string()],
            entities: vec![],
        });
    }
    incidents
}

/// Spec 043 Phase 3 — yara_match_detector. Activates a KG field that
/// was write-only pre-Phase-3 (`File.yara_matches`). The YARA scanner
/// runs in the sensor (`crates/sensor/src/detectors/yara_scan.rs`)
/// and writes match-rule names onto File nodes during ingestion. But
/// no consumer ever read those names — every match was silently
/// dropped, even on real hits like Cobalt Strike / XMRig / webshells
/// from `rules/yara/*.yml`.
///
/// This detector scans File nodes whose `yara_matches` is non-empty
/// and emits one High-severity incident per file. The incident_id is
/// stable on `sha256` so the notification grouping engine deduplicates
/// re-scans of the same binary across slow-loop ticks.
///
/// Disabled by default per Spec 043 promotion gate
/// (`[kg].yara_match_detector_enabled`); operator opts in on test001
/// first and observes the rate before promoting to prod. Hooked at
/// the slow_loop level (not inside `run_all_with_calibration`) so the
/// config check stays at the outermost layer.
pub fn detect_yara_match(
    graph: &KnowledgeGraph,
    _state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    for id in graph.nodes_of_type(NodeType::File) {
        let Some(node) = graph.get_node(id) else {
            continue;
        };
        let (path, sha256, size, entropy, yara_matches) = match node {
            Node::File {
                path,
                sha256,
                size,
                entropy,
                yara_matches,
                ..
            } => (path, sha256, size, entropy, yara_matches),
            _ => continue,
        };
        if yara_matches.is_empty() {
            continue;
        }
        // Stable id by sha256 (when present) so the same binary
        // re-scanned across ticks dedupes; fall back to path otherwise.
        let stable_key = sha256.as_deref().unwrap_or(path);
        let first_match = yara_matches
            .first()
            .map(|s| s.as_str())
            .unwrap_or("unknown_rule");
        let incident_id = format!(
            "yara_match:{}:{}",
            // truncate sha256 for readable id
            stable_key.chars().take(16).collect::<String>(),
            first_match
        );
        let entropy_label = entropy
            .map(|e| format!("{:.2}", e))
            .unwrap_or_else(|| "?".to_string());
        let size_label = size
            .map(|s| format!("{} bytes", s))
            .unwrap_or_else(|| "? bytes".to_string());
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id,
            severity: Severity::High,
            title: format!("YARA match on binary: {}", first_match),
            summary: format!(
                "File {} matched {} YARA rule(s): {}. Path: {}, size: {}, entropy: {}.",
                stable_key,
                yara_matches.len(),
                yara_matches.join(", "),
                path,
                size_label,
                entropy_label,
            ),
            evidence: serde_json::json!([{
                "kind": "yara_match",
                "path": path,
                "sha256": sha256,
                "size": size,
                "entropy": entropy,
                "yara_matches": yara_matches,
            }]),
            recommended_checks: vec![format!("file {path}"), format!("sha256sum {path}")],
            tags: vec!["yara_match".to_string()],
            entities: vec![EntityRef::path(path)],
        });
    }
    incidents
}

/// Spec 043 Phase 5 — sysctl_drift_detector. Activates a KG field that
/// was write-only pre-Phase-5 (`Node::System.sysctl_params`). The
/// sensor's `sysctl_drift` collector (`crates/sensor/src/collectors/
/// sysctl_drift.rs`) reads kernel tunables at boot/refresh and writes
/// them onto the System node — but no consumer ever diffed them.
/// Real rootkits flip these to hide themselves; without a diff the
/// signal is invisible.
///
/// Critical-class params (rootkit / persistence indicators):
///   - kernel.modules_disabled        → rootkit blocks module unload
///   - kernel.kptr_restrict           → rootkit relaxes pointer hiding
///   - kernel.dmesg_restrict          → rootkit wants dmesg access
///   - kernel.unprivileged_bpf_disabled → eBPF rootkit deployment
///   - kernel.yama.ptrace_scope       → process-debug abuse
///   - kernel.randomize_va_space      → ASLR weakening
///   - net.ipv4.ip_forward            → traffic redirection / pivot
///
/// Other params drift → Medium (operator review, not Critical).
///
/// Baseline lives in `GraphDetectorState.sysctl_baseline` — first call
/// snapshots, subsequent calls diff. Agent restart re-baselines on
/// the next tick (acceptable false-negative window during restart;
/// the alternative — persisting baseline to disk — invites schema
/// migration headaches and was rejected for Phase 5 scope).
///
/// Disabled by default per Spec 043 promotion gate
/// (`[kg].sysctl_drift_detector_enabled`); operator opts in on
/// test001 first.
pub fn detect_sysctl_drift(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    // Critical kernel tunables — drift on any of these is a
    // rootkit / persistence indicator at high confidence. Order
    // matters only for deterministic test output.
    const CRITICAL_PARAMS: &[&str] = &[
        "kernel.modules_disabled",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.unprivileged_bpf_disabled",
        "kernel.yama.ptrace_scope",
        "kernel.randomize_va_space",
        "net.ipv4.ip_forward",
    ];

    // Find the System node for this host — there should be exactly one.
    let mut current_params: Option<HashMap<String, String>> = None;
    for id in graph.nodes_of_type(NodeType::System) {
        if let Some(Node::System { sysctl_params, .. }) = graph.get_node(id) {
            current_params = Some(sysctl_params.clone());
            break;
        }
    }
    let Some(current) = current_params else {
        return Vec::new();
    };

    // First observation: snapshot and emit nothing. Subsequent calls
    // get the diff.
    let Some(baseline) = state.sysctl_baseline.as_ref() else {
        state.sysctl_baseline = Some(current);
        return Vec::new();
    };

    let mut incidents = Vec::new();
    let mut critical_changed: Vec<(String, String, String)> = Vec::new();
    let mut other_changed: Vec<(String, String, String)> = Vec::new();

    for (key, current_value) in &current {
        let baseline_value = baseline.get(key);
        if Some(current_value) != baseline_value {
            let old = baseline_value
                .cloned()
                .unwrap_or_else(|| "(unset)".to_string());
            if CRITICAL_PARAMS.contains(&key.as_str()) {
                critical_changed.push((key.clone(), old, current_value.clone()));
            } else {
                other_changed.push((key.clone(), old, current_value.clone()));
            }
        }
    }
    // Detect deletions (baseline had it, current doesn't).
    for (key, baseline_value) in baseline {
        if !current.contains_key(key) {
            let entry = (key.clone(), baseline_value.clone(), "(removed)".to_string());
            if CRITICAL_PARAMS.contains(&key.as_str()) {
                critical_changed.push(entry);
            } else {
                other_changed.push(entry);
            }
        }
    }

    // Sort for deterministic output.
    critical_changed.sort();
    other_changed.sort();

    // Critical incidents — one per critical param drift. Each is
    // important enough to escalate independently; aggregating would
    // hide which param flipped.
    for (key, old, new) in &critical_changed {
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("sysctl_drift:critical:{key}"),
            severity: Severity::Critical,
            title: format!("Critical sysctl drift: {key}"),
            summary: format!(
                "Kernel tunable `{key}` changed from `{old}` to `{new}`. \
                 This parameter is a rootkit / persistence indicator — \
                 attackers flip it to hide kernel modules, expose pointer \
                 addresses, suppress dmesg, or weaken ASLR. Verify the \
                 change was intentional (system administrator action) \
                 and audit `auditd` for the writing process."
            ),
            evidence: serde_json::json!([{
                "kind": "sysctl_drift",
                "param": key,
                "baseline_value": old,
                "current_value": new,
                "class": "critical",
            }]),
            recommended_checks: vec![
                format!("sysctl {key}"),
                "ausearch -k sysctl_change | tail -20".to_string(),
            ],
            tags: vec!["sysctl_drift".to_string(), "rootkit".to_string()],
            entities: vec![],
        });
    }

    // Aggregated Medium incident for non-critical drift — operator
    // sees one alert with all changes, not N alerts.
    if !other_changed.is_empty() {
        let summary_lines: Vec<String> = other_changed
            .iter()
            .take(20)
            .map(|(k, o, n)| format!("- {k}: `{o}` → `{n}`"))
            .collect();
        let extra = if other_changed.len() > 20 {
            format!("\n... and {} more", other_changed.len() - 20)
        } else {
            String::new()
        };
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: "sysctl_drift:medium:aggregate".to_string(),
            severity: Severity::Medium,
            title: format!(
                "Sysctl drift: {} kernel tunable(s) changed",
                other_changed.len()
            ),
            summary: format!(
                "Non-critical kernel tunables drifted from baseline. \
                 Worth investigating but not necessarily compromise:\n{}{extra}",
                summary_lines.join("\n")
            ),
            evidence: serde_json::json!([{
                "kind": "sysctl_drift",
                "class": "medium",
                "changes": other_changed
                    .iter()
                    .map(|(k, o, n)| serde_json::json!({"param": k, "baseline": o, "current": n}))
                    .collect::<Vec<_>>(),
            }]),
            recommended_checks: vec!["ausearch -k sysctl_change | tail -50".to_string()],
            tags: vec!["sysctl_drift".to_string()],
            entities: vec![],
        });
    }

    // Update baseline to current so we don't re-emit the same drift on
    // the next tick. Operator who intentionally changed a param sees
    // ONE alert per change, not one per tick.
    state.sysctl_baseline = Some(current);

    incidents
}

/// Spec 043 Phase 4 — packed_binary_detector. Activates a KG field that
/// was write-only pre-Phase-4 (`Node::File.entropy`). The sensor's
/// `file_extract` collector computes Shannon entropy on every executed
/// binary and writes it to the File node — but no consumer ever read
/// it. High Shannon entropy (>~7.5 bits/byte) is a strong signal that
/// the binary is packed (UPX, custom packer) or encrypted: legit
/// binaries typically score 5.5-6.5; only random/encrypted/compressed
/// data approaches the 8.0 ceiling.
///
/// This detector emits one Medium incident per File node whose
/// `entropy > threshold` AND that has at least one incoming `Executed`
/// edge from a Process node — i.e., the binary actually ran on the
/// host. A high-entropy file sitting in /tmp untouched is suspicious
/// but not actionable; a high-entropy file that JUST EXECUTED is the
/// shape that warrants operator attention.
///
/// Stable incident_id by sha256 (when present) so re-execution of the
/// same packed binary across slow-loop ticks deduplicates.
///
/// Disabled by default per Spec 043 promotion gate
/// (`[kg].packed_binary_detector_enabled`). Default threshold 7.5 is
/// configurable via `[kg].packed_binary_entropy_threshold` for
/// operators with unusually high-entropy legit workloads (e.g.
/// pre-compressed asset bundles).
pub fn detect_packed_binary(
    graph: &KnowledgeGraph,
    _state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    threshold: f32,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    for id in graph.nodes_of_type(NodeType::File) {
        let Some(node) = graph.get_node(id) else {
            continue;
        };
        let (path, sha256, entropy) = match node {
            Node::File {
                path,
                sha256,
                entropy: Some(e),
                ..
            } if *e > threshold => (path, sha256, *e),
            _ => continue,
        };
        // Require at least one incoming Executed edge — the file
        // actually ran on the host. Otherwise this is just a
        // suspicious-on-disk artifact (separate concern, would
        // belong to a "static analysis" detector that doesn't exist).
        let was_executed = graph
            .incoming_edges(id)
            .iter()
            .any(|e| e.relation == Relation::Executed);
        if !was_executed {
            continue;
        }
        let stable_key = sha256.as_deref().unwrap_or(path);
        let incident_id = format!(
            "packed_binary:{}",
            stable_key.chars().take(16).collect::<String>()
        );
        // Find the executing process (first Executed edge — usually
        // there's only one) for the operator's at-a-glance context.
        let executing_proc = graph
            .incoming_edges(id)
            .iter()
            .find(|e| e.relation == Relation::Executed)
            .and_then(|e| graph.get_node(e.from))
            .map(|n| n.label())
            .unwrap_or_else(|| "unknown".to_string());
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id,
            severity: Severity::Medium,
            title: format!(
                "Packed/encrypted binary executed: {}",
                path.chars().take(60).collect::<String>()
            ),
            summary: format!(
                "File {} has Shannon entropy {:.2} bits/byte (legit binaries are 5.5-6.5; \
                 packers / encrypted payloads approach 8.0). Executed by {executing_proc}. \
                 Investigate: is this a known packer (UPX, themida, vmprotect) or a \
                 legit pre-compressed asset?",
                stable_key, entropy
            ),
            evidence: serde_json::json!([{
                "kind": "packed_binary",
                "path": path,
                "sha256": sha256,
                "entropy": entropy,
                "executing_process": executing_proc,
            }]),
            recommended_checks: vec![
                format!("file {path}"),
                format!("upx -t {path}"),
                format!("strings {path} | head -20"),
            ],
            tags: vec!["packed_binary".to_string(), "T1027".to_string()],
            entities: vec![EntityRef::path(path)],
        });
    }
    incidents
}
