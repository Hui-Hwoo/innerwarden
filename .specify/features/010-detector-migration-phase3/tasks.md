# Tasks: Knowledge Graph Phase 3 — Detector Migration

**Input**: `.specify/features/010-detector-migration-phase3/`
**Target file**: `crates/agent/src/knowledge_graph/detectors.rs` (currently 901 lines, 8 detectors)

## Phase 3A: Easy Migrations (10 detectors)

Each follows the existing pattern: query graph → check cooldown → return Vec<GraphIncident>.

- [ ] T001 [P] [US1] `detect_kernel_module()` — Process→Executed where comm in [insmod, modprobe, rmmod]. Cooldown 600s per module name. Severity HIGH.
- [ ] T002 [P] [US1] `detect_user_creation()` — New User node created (check user_index growth vs last tick). Cooldown 1800s per username. Severity HIGH if added to sudo/wheel group.
- [ ] T003 [P] [US1] `detect_service_stop()` — Process→Executed(systemctl/service) with args containing "stop" + security service names (innerwarden, fail2ban, auditd, rsyslog, iptables, ufw). Cooldown 300s. Severity CRITICAL.
- [ ] T004 [P] [US1] `detect_container_escape()` — Process→Read(/var/run/docker.sock) OR Process→Read(/proc/1/root) OR Process→Read(/proc/1/ns/*). Cooldown 600s per PID. Severity CRITICAL.
- [ ] T005 [P] [US1] `detect_docker_anomaly()` — Container node with >3 restart events in 300s window. Cooldown 600s per container. Severity MEDIUM.
- [ ] T006 [P] [US1] `detect_crypto_miner()` — Process→ConnectedTo(Ip) where Ip matches known mining pool patterns (stratum+tcp, port 3333/4444/8333/14444) OR Process comm matches miner patterns. Cooldown 1800s. Severity HIGH.
- [ ] T007 [P] [US1] `detect_scanner_ua()` — Ip→RequestedHttp where User-Agent matches scanner patterns (Nmap, Nikto, sqlmap, ZAP, Burp, Gobuster, dirbuster, wfuzz). Cooldown 600s per IP. Severity MEDIUM.
- [ ] T008 [P] [US1] `detect_log_tampering()` — Process→Wrote(/var/log/*) where Process comm NOT in [rsyslog, syslog-ng, logrotate, journald, systemd]. Cooldown 600s. Severity HIGH.
- [ ] T009 [P] [US1] `detect_cgroup_abuse()` — Process with cgroup CPU >90% sustained over 2+ ticks. Cooldown 1800s per PID. Severity MEDIUM.
- [ ] T010 [P] [US1] `detect_c2_beacon()` — Process→ConnectedTo(external Ip) with periodic pattern: ≥5 connections at regular intervals (±10% jitter) within 300s. Cooldown 600s per IP. Severity HIGH.

- [ ] T011 [US1] Wire all 10 into `run_all()` in detectors.rs
- [ ] T012 [US1] Add tests: at least 1 test per detector with mock graph data

**Checkpoint**: `cargo test` passes. 18 graph detectors running. Deploy to production, compare with sensor output for 24h.

---

## Phase 3B: Medium Migrations — Aggregation Detectors (8 detectors)

These need aggregation helpers. Add `count_edges_in_window()` and `aggregate_by_entity()` to graph.rs first.

- [ ] T013 [US2] Add `count_edges_in_window(node, relation, window_secs)` helper to `graph.rs`
- [ ] T014 [US2] Add `aggregate_by_source(relation, window_secs)` helper to `graph.rs` — returns HashMap<NodeId, usize>

- [ ] T015 [US2] `detect_host_drift_aggregated()` — Per user: count Process nodes with exe NOT in system binary allowlist (apt, dpkg, logrotate, systemctl, cron, etc). If count > threshold (20 for root, 10 for others) in 300s → 1 aggregated incident with count. Unknown binaries (/tmp/*, /dev/shm/*) always fire individually. Cooldown 600s per user.
- [ ] T016 [US3] `detect_proto_anomaly_aggregated()` — Per source Ip: count ConnectedTo edges with malformed properties in 300s. If count > 5 → 1 incident per IP with total count. Cooldown 600s per IP.
- [ ] T017 [P] [US4] `detect_port_scan()` — Per source Ip: count distinct destination Port nodes in 60s. If ≥10 distinct ports → incident. Cooldown 600s per IP. Severity MEDIUM.
- [ ] T018 [P] `detect_network_sniffing_graph()` — Process→Executed where comm in [tcpdump, tshark, wireshark, ngrep, ettercap, bettercap] OR Process acquired CAP_NET_RAW. Cooldown 600s. Severity HIGH.
- [ ] T019 [P] `detect_dns_tunnel_graph()` — Aggregate Domain nodes: if domain label length >50 OR entropy >4.5 OR >100 queries to same domain in 60s. Cooldown 600s per domain. Severity HIGH.
- [ ] T020 [P] `detect_credential_stuffing_graph()` — Per source Ip: count distinct User nodes with FailedAuth edges in 300s. If ≥5 distinct users → incident. Cooldown 600s per IP. Severity HIGH.
- [ ] T021 [P] `detect_sudo_abuse_graph()` — Per User: count Executed edges with sudo=true in 60s. If ≥10 sudo commands → incident. Cooldown 1800s per user. Severity HIGH.
- [ ] T022 [P] `detect_sensitive_write()` — Process→Wrote→File where file.is_sensitive AND Process not in trusted_processes. Cooldown 600s per file path. Severity HIGH.

- [ ] T023 Wire all 8 into `run_all()`
- [ ] T024 Add tests for aggregation helpers + each detector

**Checkpoint**: 26 graph detectors running. host_drift incidents reduced from ~823 to <50/day. proto_anomaly from ~205 to <50/day.

---

## Phase 3C: Top 10 Correlation Rules as Graph Paths

Convert CL-001 to CL-010 from sliding window state machines to graph path queries.

- [ ] T025 `detect_correlation_recon_to_exploit()` — CL-001: port_scan/web_scan from IP X → ssh_bruteforce from X within 1800s. Query: Ip node with both scan and brute force incident edges.
- [ ] T026 `detect_correlation_recon_to_exfil()` — CL-002: port_scan → ssh_bruteforce → data_exfil from same IP within 1800s. Query: 3-hop path through same Ip node.
- [ ] T027 `detect_correlation_priv_esc_chain()` — CL-003: credential_stuffing → sudo_abuse from same User within 600s.
- [ ] T028 `detect_correlation_persistence_chain()` — CL-004: suspicious_login → crontab/systemd/ssh_key from same IP within 3600s.
- [ ] T029 `detect_correlation_container_breakout()` — CL-005: container_escape → privilege_escalation → data_exfil within 600s.
- [ ] T030 `detect_correlation_fileless()` — CL-006: fileless/memfd → mprotect → outbound within 300s.
- [ ] T031 `detect_correlation_reverse_shell()` — CL-007: outbound_connect → fd_redirect within 10s.
- [ ] T032 `detect_correlation_data_exfil()` — CL-008: file_read_sensitive → outbound_connect within 60s.
- [ ] T033 `detect_correlation_multi_low()` — CL-010: 3+ different Low-severity detectors from same IP within 600s → escalate to HIGH.
- [ ] T034 `detect_correlation_silence()` — CL-009: Event rate drops >80% after compromise indicators. Query: check edge creation rate vs baseline.

- [ ] T035 Wire correlation detectors into `run_all()` with separate cooldown namespace
- [ ] T036 Add tests for each correlation pattern

**Checkpoint**: Graph handles multi-stage attack detection. Correlation engine can be simplified (but not removed yet).

---

## Phase 3D: Dedup + Sensor Disable

- [ ] T037 Add `is_graph_detected: bool` field to Incident struct (or use incident_id prefix `graph_*`)
- [ ] T038 In `process_incidents()` main loop: if incident_id starts with `graph_`, check if sensor already fired for same entity+detector in 60s window → suppress sensor duplicate
- [ ] T039 After 1 week parallel running: disable sensor versions for detectors with ≥95% graph recall. Add config flag `graph_only_detectors = ["threat_intel", "lateral_movement", ...]`
- [ ] T040 Add metrics: graph_detection_count, sensor_detection_count, dedup_count per detector

**Checkpoint**: No duplicate incidents. Validated detectors run graph-only.

---

## Verification Matrix

| Phase | Test | Success Criteria |
|-------|------|-----------------|
| 3A | 24h parallel run | Graph ≥95% recall, ≤50% FP rate vs sensor |
| 3B | host_drift count | <50/day (vs 823 today) |
| 3B | proto_anomaly count | <50/day (vs 205 today) |
| 3C | CL-002 test | Multi-stage attack detected from graph path |
| 3D | Incident count | No increase vs sensor-only baseline |
| All | Graph tick time | <500ms |
| All | Memory | <50MB |
| All | `cargo test` | All tests pass |
