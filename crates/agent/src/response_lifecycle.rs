//! Unified response lifecycle: tracks all active responses (block IP, container pause,
//! nginx deny, sudo suspension) with TTL and auto-revert.
//!
//! Replaces the scattered cleanup functions and xdp_block_times HashMap with a single
//! manager that handles registration, expiration, manual revert, and Prometheus metrics.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{info, warn};

/// Backend that applied the response (determines how to revert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBackend {
    Xdp,
    Ufw,
    Iptables,
    Nftables,
    Pf,
    Cloudflare,
    Nginx,
    Container,
    Sudo,
}

/// Type of response action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    BlockIp,
    BlockContainer,
    SuspendSudo,
    RateLimitNginx,
    KillProcess,
}

/// A tracked active response with TTL.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveResponse {
    pub id: String,
    pub response_type: ResponseType,
    pub backend: ResponseBackend,
    pub target: String,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub ttl_secs: i64,
    pub expires_at: DateTime<Utc>,
    /// Backend-specific handle needed for revert (e.g., nftables rule handle).
    pub revert_handle: Option<String>,
}

/// Action to revert a response.
#[derive(Debug)]
pub struct RevertAction {
    pub id: String,
    pub backend: ResponseBackend,
    pub target: String,
    pub revert_handle: Option<String>,
}

/// Unified lifecycle manager for all response actions.
pub struct ResponseLifecycle {
    active: Vec<ActiveResponse>,
    history: VecDeque<CompletedResponse>,
    next_id: u64,
    /// Counters for Prometheus.
    total_registered: u64,
    total_reverted: u64,
    total_expired: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompletedResponse {
    pub id: String,
    pub response_type: ResponseType,
    pub backend: ResponseBackend,
    pub target: String,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub reverted_at: DateTime<Utc>,
    pub reason: String, // "expired" or "manual"
}

impl ResponseLifecycle {
    pub fn new() -> Self {
        Self {
            active: Vec::new(),
            history: VecDeque::new(),
            next_id: 1,
            total_registered: 0,
            total_reverted: 0,
            total_expired: 0,
        }
    }

    /// Register a new response. Returns the response ID.
    pub fn register(
        &mut self,
        response_type: ResponseType,
        backend: ResponseBackend,
        target: &str,
        incident_id: &str,
        ttl_secs: i64,
        revert_handle: Option<String>,
    ) -> String {
        let id = format!("resp-{}", self.next_id);
        self.next_id += 1;

        let now = Utc::now();
        let response = ActiveResponse {
            id: id.clone(),
            response_type,
            backend,
            target: target.to_string(),
            incident_id: incident_id.to_string(),
            created_at: now,
            ttl_secs,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            revert_handle,
        };

        info!(
            id = %response.id,
            backend = ?response.backend,
            target = %response.target,
            ttl_secs,
            "response registered"
        );

        self.active.push(response);
        self.total_registered += 1;
        id
    }

    /// Check for expired responses and return revert actions.
    /// Called from the slow loop (every 30s).
    pub fn tick_cleanup(&mut self) -> Vec<RevertAction> {
        let now = Utc::now();
        let mut reverts = Vec::new();

        let mut i = 0;
        while i < self.active.len() {
            if now > self.active[i].expires_at {
                let resp = self.active.remove(i);
                reverts.push(RevertAction {
                    id: resp.id.clone(),
                    backend: resp.backend.clone(),
                    target: resp.target.clone(),
                    revert_handle: resp.revert_handle.clone(),
                });
                self.history.push_back(CompletedResponse {
                    id: resp.id,
                    response_type: resp.response_type,
                    backend: resp.backend,
                    target: resp.target,
                    incident_id: resp.incident_id,
                    created_at: resp.created_at,
                    reverted_at: now,
                    reason: "expired".to_string(),
                });
                self.total_expired += 1;
            } else {
                i += 1;
            }
        }

        // Cap history at 1000 entries.
        while self.history.len() > 1000 {
            self.history.pop_front();
        }

        reverts
    }

    /// Manually revert a specific response by ID.
    pub fn revert(&mut self, id: &str) -> Option<RevertAction> {
        if let Some(idx) = self.active.iter().position(|r| r.id == id) {
            let resp = self.active.remove(idx);
            let revert = RevertAction {
                id: resp.id.clone(),
                backend: resp.backend.clone(),
                target: resp.target.clone(),
                revert_handle: resp.revert_handle.clone(),
            };
            self.history.push_back(CompletedResponse {
                id: resp.id,
                response_type: resp.response_type,
                backend: resp.backend,
                target: resp.target,
                incident_id: resp.incident_id,
                created_at: resp.created_at,
                reverted_at: Utc::now(),
                reason: "manual".to_string(),
            });
            self.total_reverted += 1;
            Some(revert)
        } else {
            None
        }
    }

    /// Get all currently active responses.
    pub fn list_active(&self) -> &[ActiveResponse] {
        &self.active
    }

    /// Get recent history of completed (expired/reverted) responses.
    pub fn list_history(&self) -> &VecDeque<CompletedResponse> {
        &self.history
    }

    /// Check if an IP is already tracked (to avoid duplicates).
    pub fn is_tracked(&self, target: &str, backend: &ResponseBackend) -> bool {
        self.active
            .iter()
            .any(|r| r.target == target && &r.backend == backend)
    }

    /// Generate Prometheus metrics lines.
    pub fn to_prometheus_lines(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP innerwarden_responses_active Currently active response actions\n");
        out.push_str("# TYPE innerwarden_responses_active gauge\n");

        // Count by backend
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for r in &self.active {
            let key = match r.backend {
                ResponseBackend::Xdp => "xdp",
                ResponseBackend::Ufw => "ufw",
                ResponseBackend::Iptables => "iptables",
                ResponseBackend::Nftables => "nftables",
                ResponseBackend::Pf => "pf",
                ResponseBackend::Cloudflare => "cloudflare",
                ResponseBackend::Nginx => "nginx",
                ResponseBackend::Container => "container",
                ResponseBackend::Sudo => "sudo",
            };
            *counts.entry(key).or_default() += 1;
        }
        for (backend, count) in &counts {
            out.push_str(&format!(
                "innerwarden_responses_active{{backend=\"{backend}\"}} {count}\n"
            ));
        }

        out.push_str("# HELP innerwarden_responses_total Total response actions registered\n");
        out.push_str("# TYPE innerwarden_responses_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_total {}\n",
            self.total_registered
        ));

        out.push_str("# HELP innerwarden_responses_expired_total Responses expired by TTL\n");
        out.push_str("# TYPE innerwarden_responses_expired_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_expired_total {}\n",
            self.total_expired
        ));

        out.push_str("# HELP innerwarden_responses_reverted_total Responses manually reverted\n");
        out.push_str("# TYPE innerwarden_responses_reverted_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_reverted_total {}\n",
            self.total_reverted
        ));

        out
    }

    /// Serialize active responses as JSON (for /api/responses).
    pub fn to_json(&self) -> serde_json::Value {
        let now = Utc::now();
        let active: Vec<serde_json::Value> = self
            .active
            .iter()
            .map(|r| {
                let remaining = (r.expires_at - now).num_seconds().max(0);
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "expires_at": r.expires_at.to_rfc3339(),
                    "ttl_secs": r.ttl_secs,
                    "remaining_secs": remaining,
                })
            })
            .collect();

        let history: Vec<serde_json::Value> = self
            .history
            .iter()
            .rev()
            .take(50)
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "reverted_at": r.reverted_at.to_rfc3339(),
                    "reason": r.reason,
                })
            })
            .collect();

        serde_json::json!({
            "active": active,
            "active_count": self.active.len(),
            "history": history,
            "totals": {
                "registered": self.total_registered,
                "expired": self.total_expired,
                "reverted": self.total_reverted,
            }
        })
    }
}

/// Execute a revert action on the appropriate backend.
pub async fn execute_revert(revert: &RevertAction, dry_run: bool) {
    let desc = format!("{:?} {}", revert.backend, revert.target);

    if dry_run {
        info!(id = %revert.id, action = %desc, "DRY RUN: would revert response");
        return;
    }

    let result = match &revert.backend {
        ResponseBackend::Ufw => {
            run_cmd("sudo", &["ufw", "delete", "deny", "from", &revert.target]).await
        }
        ResponseBackend::Iptables => {
            run_cmd(
                "sudo",
                &[
                    "iptables",
                    "-D",
                    "INPUT",
                    "-s",
                    &revert.target,
                    "-j",
                    "DROP",
                ],
            )
            .await
        }
        ResponseBackend::Nftables => {
            if let Some(handle) = &revert.revert_handle {
                run_cmd(
                    "sudo",
                    &[
                        "nft", "delete", "rule", "inet", "filter", "input", "handle", handle,
                    ],
                )
                .await
            } else {
                Err("no nftables handle stored for revert".to_string())
            }
        }
        ResponseBackend::Xdp => {
            // XDP revert via bpftool — parse IP octets.
            if let Ok(addr) = revert.target.parse::<std::net::Ipv4Addr>() {
                let b = addr.octets();
                run_cmd(
                    "sudo",
                    &[
                        "bpftool",
                        "map",
                        "delete",
                        "pinned",
                        "/sys/fs/bpf/innerwarden/blocklist",
                        "key",
                        &b[0].to_string(),
                        &b[1].to_string(),
                        &b[2].to_string(),
                        &b[3].to_string(),
                    ],
                )
                .await
            } else {
                Err(format!("cannot parse IP for XDP revert: {}", revert.target))
            }
        }
        // Container, Nginx, Sudo reverts are still handled by their existing
        // cleanup functions (file-based metadata with expires_at). The lifecycle
        // tracks them for dashboard visibility but delegates revert to the
        // existing code paths.
        ResponseBackend::Container | ResponseBackend::Nginx | ResponseBackend::Sudo => {
            // These are managed by their own metadata files and cleanup functions.
            // The lifecycle tracks them for visibility only.
            Ok(())
        }
        ResponseBackend::Cloudflare | ResponseBackend::Pf => {
            // Cloudflare: would need rule_id to delete. PF: macOS only.
            // Not auto-reverted for now.
            warn!(backend = ?revert.backend, "auto-revert not implemented for this backend");
            Ok(())
        }
    };

    match result {
        Ok(()) => {
            info!(id = %revert.id, backend = ?revert.backend, target = %revert.target, "response reverted")
        }
        Err(e) => {
            warn!(id = %revert.id, backend = ?revert.backend, target = %revert.target, error = %e, "revert failed")
        }
    }
}

async fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("spawn {program}: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{program} {} exited {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_expire() {
        let mut lc = ResponseLifecycle::new();

        // Register with 0-second TTL (expires immediately).
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "1.2.3.4",
            "inc-001",
            0,
            None,
        );

        assert_eq!(lc.list_active().len(), 1);

        // Tick should find it expired.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let reverts = lc.tick_cleanup();
        assert_eq!(reverts.len(), 1);
        assert_eq!(reverts[0].target, "1.2.3.4");
        assert_eq!(reverts[0].backend, ResponseBackend::Ufw);
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
    }

    #[test]
    fn test_manual_revert() {
        let mut lc = ResponseLifecycle::new();

        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "5.6.7.8",
            "inc-002",
            3600,
            None,
        );

        assert_eq!(lc.list_active().len(), 1);

        let revert = lc.revert(&id).unwrap();
        assert_eq!(revert.target, "5.6.7.8");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "manual");
    }

    #[test]
    fn test_is_tracked() {
        let mut lc = ResponseLifecycle::new();

        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "10.0.0.1",
            "inc-003",
            3600,
            None,
        );

        assert!(lc.is_tracked("10.0.0.1", &ResponseBackend::Xdp));
        assert!(!lc.is_tracked("10.0.0.1", &ResponseBackend::Ufw));
        assert!(!lc.is_tracked("10.0.0.2", &ResponseBackend::Xdp));
    }

    #[test]
    fn test_prometheus_output() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "1.1.1.1",
            "inc-004",
            3600,
            None,
        );
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "2.2.2.2",
            "inc-005",
            3600,
            None,
        );

        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_active{backend=\"ufw\"} 1"));
        assert!(prom.contains("innerwarden_responses_active{backend=\"xdp\"} 1"));
        assert!(prom.contains("innerwarden_responses_total 2"));
    }

    #[test]
    fn test_json_output() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "3.3.3.3",
            "inc-006",
            3600,
            None,
        );

        let json = lc.to_json();
        assert_eq!(json["active_count"], 1);
        assert_eq!(json["active"][0]["target"], "3.3.3.3");
        assert!(json["active"][0]["remaining_secs"].as_i64().unwrap() > 3500);
    }

    #[test]
    fn test_history_cap() {
        let mut lc = ResponseLifecycle::new();
        for i in 0..1100 {
            lc.register(
                ResponseType::BlockIp,
                ResponseBackend::Ufw,
                &format!("10.0.{}.{}", i / 256, i % 256),
                "inc",
                0,
                None,
            );
        }
        lc.tick_cleanup();
        assert!(lc.history.len() <= 1000);
    }
}
