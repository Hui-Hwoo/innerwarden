//! Firewall posture probe.
//!
//! Three backends in production order: ufw → nftables → iptables.
//! The probe queries each in turn; the first one that returns a
//! configured ruleset wins. Hosts running multiple backends in
//! parallel are rare in our deployment but the probe records all
//! configured ones so the downgrade engine sees the complete picture.
//!
//! What the downgrade engine reads:
//! - `default_policy`: when DROP, alerts about probes against
//!   non-listening ports get demoted (the firewall already drops
//!   them before they reach the listener).
//! - `allowed_ports`: ports explicitly opened in the ruleset. Used
//!   together with `services::has_listener_on_port` to decide whether
//!   a probed port is actually reachable from the wire.

use serde::{Deserialize, Serialize};
use std::process::Command;

use super::sshd::ProbeState;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallPosture {
    pub probe_state: ProbeState,
    /// Active backends detected. Empty when none of ufw/iptables/nft
    /// returned a configured ruleset.
    #[serde(default)]
    pub active_backends: Vec<FirewallBackend>,
    /// Coarse default INPUT policy across all detected backends.
    /// When backends disagree we report Permissive (bias toward
    /// keeping alerts at original severity).
    #[serde(default)]
    pub default_policy: DefaultPolicy,
    /// Ports the operator has explicitly allowed inbound. Sorted
    /// ascending. Limited to TCP — UDP is handled the same way
    /// by all three backends but rarely audited at this layer.
    #[serde(default)]
    pub allowed_tcp_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    Ufw,
    Iptables,
    Nftables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPolicy {
    Drop,
    Accept,
    /// No backend reported a confident default policy, OR backends
    /// disagreed. The downgrade engine treats Permissive as "do not
    /// demote based on default policy".
    #[default]
    Permissive,
}

impl FirewallPosture {
    /// True when the firewall would have dropped traffic to `port`
    /// before it reached any listener. Two cases qualify:
    /// - default policy is Drop AND port is not in `allowed_tcp_ports`
    /// - any backend explicitly denies the port (not modelled here yet)
    #[allow(dead_code)]
    pub fn would_drop_port(&self, port: u16) -> bool {
        if self.probe_state != ProbeState::Ok {
            return false;
        }
        self.default_policy == DefaultPolicy::Drop && !self.allowed_tcp_ports.contains(&port)
    }
}

pub fn probe_firewall() -> FirewallPosture {
    let mut posture = FirewallPosture::default();
    let mut errors: Vec<String> = Vec::new();
    let mut policies: Vec<DefaultPolicy> = Vec::new();

    if let Some((policy, ports, err)) = probe_ufw() {
        posture.active_backends.push(FirewallBackend::Ufw);
        policies.push(policy);
        for p in ports {
            if !posture.allowed_tcp_ports.contains(&p) {
                posture.allowed_tcp_ports.push(p);
            }
        }
        if let Some(e) = err {
            errors.push(format!("ufw: {e}"));
        }
    }
    if let Some((policy, ports, err)) = probe_nft() {
        posture.active_backends.push(FirewallBackend::Nftables);
        policies.push(policy);
        for p in ports {
            if !posture.allowed_tcp_ports.contains(&p) {
                posture.allowed_tcp_ports.push(p);
            }
        }
        if let Some(e) = err {
            errors.push(format!("nft: {e}"));
        }
    }
    if let Some((policy, ports, err)) = probe_iptables() {
        posture.active_backends.push(FirewallBackend::Iptables);
        policies.push(policy);
        for p in ports {
            if !posture.allowed_tcp_ports.contains(&p) {
                posture.allowed_tcp_ports.push(p);
            }
        }
        if let Some(e) = err {
            errors.push(format!("iptables: {e}"));
        }
    }

    posture.allowed_tcp_ports.sort();

    posture.default_policy = match policies.as_slice() {
        [] => DefaultPolicy::Permissive,
        ps if ps.iter().all(|p| *p == DefaultPolicy::Drop) => DefaultPolicy::Drop,
        ps if ps.iter().all(|p| *p == DefaultPolicy::Accept) => DefaultPolicy::Accept,
        // Mixed → permissive, bias toward keeping alerts.
        _ => DefaultPolicy::Permissive,
    };

    posture.probe_state = if posture.active_backends.is_empty() {
        ProbeState::Unavailable
    } else {
        ProbeState::Ok
    };
    if !errors.is_empty() {
        posture.error = Some(errors.join("; "));
    }
    posture
}

// ---------------------------------------------------------------------------
// UFW
// ---------------------------------------------------------------------------

fn probe_ufw() -> Option<(DefaultPolicy, Vec<u16>, Option<String>)> {
    let out = Command::new("ufw")
        .args(["status", "verbose"])
        .output()
        .ok()?;
    if !out.status.success() {
        // ufw not installed → None; we'll fall through to nft.
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(parse_ufw_status(&stdout))
}

/// Parse `ufw status verbose`. Output shape:
/// ```text
/// Status: active
/// Logging: on (low)
/// Default: deny (incoming), allow (outgoing), disabled (routed)
///
/// To                         Action      From
/// --                         ------      ----
/// 22/tcp                     ALLOW IN    Anywhere
/// 8787/tcp                   ALLOW IN    Anywhere
/// ```
pub(crate) fn parse_ufw_status(s: &str) -> (DefaultPolicy, Vec<u16>, Option<String>) {
    let mut policy = DefaultPolicy::Permissive;
    let mut allowed: Vec<u16> = Vec::new();
    let mut active = false;

    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Status:") {
            // "inactive" contains the substring "active" — match
            // word boundaries via whitespace tokens to avoid the
            // false positive.
            active = trimmed
                .split_whitespace()
                .any(|t| t.eq_ignore_ascii_case("active"));
        }
        if trimmed.starts_with("Default:") && trimmed.contains("incoming") {
            // "Default: deny (incoming), allow (outgoing), disabled (routed)"
            // Split on ',' so each chunk pairs a verb with a direction;
            // the first-chunk leading "Default:" prefix is stripped before
            // tokenising so the verb is the first whitespace-separated word.
            for chunk in trimmed.split(',') {
                let chunk = chunk.trim().trim_start_matches("Default:").trim();
                if chunk.contains("(incoming)") {
                    let verb = chunk.split_whitespace().next().unwrap_or("");
                    policy = match verb.to_ascii_lowercase().as_str() {
                        "deny" | "reject" => DefaultPolicy::Drop,
                        "allow" => DefaultPolicy::Accept,
                        _ => DefaultPolicy::Permissive,
                    };
                }
            }
        }
        // Listener rule lines look like `22/tcp ALLOW IN Anywhere`.
        // Split on whitespace, look for a `<port>/tcp` token followed
        // by ALLOW.
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 2 && cols.iter().any(|c| c == &"ALLOW") {
            if let Some(token) = cols.first() {
                if let Some(port_str) = token.strip_suffix("/tcp") {
                    if let Ok(p) = port_str.parse::<u16>() {
                        if !allowed.contains(&p) {
                            allowed.push(p);
                        }
                    }
                }
            }
        }
    }
    if !active {
        // Ruleset can be loaded but disabled. Treat as permissive.
        policy = DefaultPolicy::Permissive;
    }
    (policy, allowed, None)
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

fn probe_nft() -> Option<(DefaultPolicy, Vec<u16>, Option<String>)> {
    // `nft list ruleset` is the canonical query. Requires CAP_NET_ADMIN.
    let out = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        // Empty ruleset → no firewall. Bail rather than register Nftables
        // as active.
        return None;
    }
    Some(parse_nft_ruleset(&stdout))
}

/// Very loose parser for `nft list ruleset`. We are not building a
/// real rule evaluator — only extracting two facts: the chain INPUT
/// policy and obvious `tcp dport <port> accept` lines. Anything we
/// cannot read confidently falls into the Permissive bucket.
pub(crate) fn parse_nft_ruleset(s: &str) -> (DefaultPolicy, Vec<u16>, Option<String>) {
    let mut policy = DefaultPolicy::Permissive;
    let mut allowed: Vec<u16> = Vec::new();
    let mut in_input_chain = false;

    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("chain input") || trimmed.starts_with("chain INPUT") {
            in_input_chain = true;
            continue;
        }
        if trimmed.starts_with('}') {
            in_input_chain = false;
            continue;
        }
        if in_input_chain && trimmed.starts_with("type filter hook input") {
            // "type filter hook input priority 0; policy drop;"
            if trimmed.contains("policy drop") {
                policy = DefaultPolicy::Drop;
            } else if trimmed.contains("policy accept") {
                policy = DefaultPolicy::Accept;
            }
        }
        // Look for `tcp dport NN accept` or `tcp dport NN ct state new accept`.
        if trimmed.contains("tcp dport") && trimmed.contains("accept") {
            for token in trimmed.split_whitespace() {
                if let Ok(p) = token.parse::<u16>() {
                    if !allowed.contains(&p) {
                        allowed.push(p);
                    }
                    break;
                }
            }
        }
    }
    (policy, allowed, None)
}

// ---------------------------------------------------------------------------
// iptables
// ---------------------------------------------------------------------------

fn probe_iptables() -> Option<(DefaultPolicy, Vec<u16>, Option<String>)> {
    let out = Command::new("iptables")
        .args(["-L", "INPUT", "-n", "--line-numbers"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(parse_iptables_input(&stdout))
}

/// Parse `iptables -L INPUT -n --line-numbers`. Format:
/// ```text
/// Chain INPUT (policy DROP)
/// num  target prot opt source       destination
/// 1    ACCEPT tcp  --  0.0.0.0/0    0.0.0.0/0  tcp dpt:22
/// 2    ACCEPT tcp  --  0.0.0.0/0    0.0.0.0/0  tcp dpt:8787
/// ```
pub(crate) fn parse_iptables_input(s: &str) -> (DefaultPolicy, Vec<u16>, Option<String>) {
    let mut policy = DefaultPolicy::Permissive;
    let mut allowed: Vec<u16> = Vec::new();

    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Chain INPUT") {
            if trimmed.contains("policy DROP") {
                policy = DefaultPolicy::Drop;
            } else if trimmed.contains("policy ACCEPT") {
                policy = DefaultPolicy::Accept;
            }
        }
        if trimmed.contains("ACCEPT") && trimmed.contains("tcp dpt:") {
            // Extract NNN out of "tcp dpt:NNN"
            for chunk in trimmed.split_whitespace() {
                if let Some(rest) = chunk.strip_prefix("dpt:") {
                    if let Ok(p) = rest.parse::<u16>() {
                        if !allowed.contains(&p) {
                            allowed.push(p);
                        }
                    }
                }
            }
        }
    }
    (policy, allowed, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture(
        probe_state: ProbeState,
        policy: DefaultPolicy,
        allowed_tcp_ports: Vec<u16>,
    ) -> FirewallPosture {
        FirewallPosture {
            probe_state,
            active_backends: vec![FirewallBackend::Ufw],
            default_policy: policy,
            allowed_tcp_ports,
            error: None,
        }
    }

    #[test]
    fn would_drop_port_requires_successful_probe_drop_policy_and_unopened_port() {
        let drop_firewall = posture(ProbeState::Ok, DefaultPolicy::Drop, vec![22, 443]);
        assert!(drop_firewall.would_drop_port(8080));
        assert!(!drop_firewall.would_drop_port(22));

        let accept_firewall = posture(ProbeState::Ok, DefaultPolicy::Accept, vec![]);
        assert!(!accept_firewall.would_drop_port(8080));

        let failed_probe = posture(ProbeState::Failed, DefaultPolicy::Drop, vec![]);
        assert!(!failed_probe.would_drop_port(8080));
    }

    #[test]
    fn parse_ufw_active_deny_extracts_unique_allowed_tcp_ports() {
        let status = r#"
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp                     ALLOW IN    Anywhere (v6)
443/tcp                    ALLOW IN    Anywhere
53/udp                     ALLOW IN    Anywhere
8080/tcp                   DENY IN     Anywhere
"#;

        let (policy, ports, err) = parse_ufw_status(status);

        assert_eq!(policy, DefaultPolicy::Drop);
        assert_eq!(ports, vec![22, 443]);
        assert!(err.is_none());
    }

    #[test]
    fn parse_ufw_inactive_is_permissive_even_when_default_mentions_deny() {
        let status = r#"
Status: inactive
Default: deny (incoming), allow (outgoing), disabled (routed)
22/tcp ALLOW IN Anywhere
"#;

        let (policy, ports, _) = parse_ufw_status(status);

        assert_eq!(policy, DefaultPolicy::Permissive);
        assert_eq!(ports, vec![22]);
    }

    #[test]
    fn parse_ufw_reject_incoming_maps_to_drop_and_allow_maps_to_accept() {
        let reject_status = "Status: active\nDefault: reject (incoming), allow (outgoing)\n";
        let allow_status = "Status: active\nDefault: allow (incoming), allow (outgoing)\n";

        assert_eq!(parse_ufw_status(reject_status).0, DefaultPolicy::Drop);
        assert_eq!(parse_ufw_status(allow_status).0, DefaultPolicy::Accept);
    }

    #[test]
    fn parse_nft_ruleset_extracts_input_policy_and_accept_ports() {
        let ruleset = r#"
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport 22 accept
        tcp dport 8443 ct state new accept
        udp dport 53 accept
        tcp dport 22 accept
    }
}
"#;

        let (policy, ports, err) = parse_nft_ruleset(ruleset);

        assert_eq!(policy, DefaultPolicy::Drop);
        assert_eq!(ports, vec![22, 8443]);
        assert!(err.is_none());
    }

    #[test]
    fn parse_nft_ruleset_accept_policy_and_unknown_policy_fallback() {
        let accept_ruleset = r#"
table inet filter {
    chain INPUT {
        type filter hook input priority 0; policy accept;
    }
}
"#;
        let missing_policy_ruleset = "table inet filter { chain forward { policy drop; } }";

        assert_eq!(parse_nft_ruleset(accept_ruleset).0, DefaultPolicy::Accept);
        assert_eq!(
            parse_nft_ruleset(missing_policy_ruleset).0,
            DefaultPolicy::Permissive
        );
    }

    #[test]
    fn parse_iptables_input_extracts_policy_and_unique_tcp_ports() {
        let rules = r#"
Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:65535
4    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080
5    ACCEPT     udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:53
"#;

        let (policy, ports, err) = parse_iptables_input(rules);

        assert_eq!(policy, DefaultPolicy::Drop);
        assert_eq!(ports, vec![22, 65535]);
        assert!(err.is_none());
    }

    #[test]
    fn parse_iptables_input_accept_and_unknown_policy_fallbacks() {
        let accept_rules = "Chain INPUT (policy ACCEPT)\n";
        let unknown_rules = "Chain INPUT (policy QUEUE)\n";

        assert_eq!(parse_iptables_input(accept_rules).0, DefaultPolicy::Accept);
        assert_eq!(
            parse_iptables_input(unknown_rules).0,
            DefaultPolicy::Permissive
        );
    }
}
