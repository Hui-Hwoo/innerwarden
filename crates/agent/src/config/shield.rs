//! Shield (DDoS) config sections.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

/// DDoS Shield — inline rate limiting, SYN tracking, auto-escalation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldConfig {
    /// Enable inline shield processing. Default: true.
    #[serde(default = "default_shield_enabled")]
    pub enabled: bool,
    /// BPF pin path for XDP maps. Default: /sys/fs/bpf/innerwarden.
    #[serde(default = "default_shield_bpf_path")]
    pub bpf_path: String,
    /// Dry-run mode: skip actual bpftool calls. Default: false.
    #[serde(default)]
    pub dry_run: bool,
    /// 2026-05-21: auto-toggle Cloudflare DNS proxy when shield escalates
    /// to UnderAttack / Critical. Defaults to `dry_run = true` so the
    /// failover only logs what it would have done. Operator must
    /// explicitly flip `dry_run = false` after monitoring the
    /// state-transition cadence for at least a week.
    #[serde(default)]
    pub cloudflare_failover: ShieldCloudflareFailoverConfig,
    /// 2026-05-21: insert iptables rules to drop direct-to-origin TCP/80
    /// and TCP/443 during UnderAttack / Critical, forcing all HTTP(S)
    /// traffic through Cloudflare's edge. Defaults to `dry_run = true`
    /// — same calibration window as `cloudflare_failover`.
    #[serde(default)]
    pub origin_lockdown: ShieldOriginLockdownConfig,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bpf_path: default_shield_bpf_path(),
            dry_run: false,
            cloudflare_failover: ShieldCloudflareFailoverConfig::default(),
            origin_lockdown: ShieldOriginLockdownConfig::default(),
        }
    }
}

/// `[shield.cloudflare_failover]` — controls the orange-cloud auto-toggle.
///
/// `dry_run = true` (the default) records the would-be toggles in the
/// agent log but never calls the Cloudflare API. Flip to `false` only
/// after auditing the state-transition log for false-positive
/// volumetric spikes; an over-eager toggle is operator-visible because
/// the site briefly drops to Cloudflare's challenge page.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ShieldCloudflareFailoverConfig {
    /// Master switch. When false the failover is not even instantiated
    /// — useful for hosts that do not sit behind Cloudflare at all.
    #[serde(default)]
    pub enabled: bool,
    /// Safety gate. When true the toggle logs but never calls the API.
    /// New deploys default to `true`; lift after a week of clean state
    /// transitions in production logs.
    #[serde(default = "default_true_val")]
    pub dry_run: bool,
    /// Cloudflare API token with `Zone.DNS:Edit` permission on the zone.
    /// Required when `dry_run = false`. Empty string is treated as
    /// "not configured" and silently disables the toggle.
    #[serde(default)]
    pub api_token: String,
    /// Cloudflare zone id (the 32-char hex from the dashboard URL).
    #[serde(default)]
    pub zone_id: String,
    /// DNS record id whose `proxied` flag flips on escalation. Find via
    /// `GET /zones/{zone_id}/dns_records?name=<host>`.
    #[serde(default)]
    pub record_id: String,
    /// Escalation states that should activate the proxy. Default:
    /// `["UnderAttack", "Critical"]`. Lowering to `["Elevated", ...]`
    /// is operator-visible (more false positives).
    #[serde(default = "default_cf_activate_on")]
    pub activate_on: Vec<String>,
    /// Minimum proxy-on duration in seconds before we are allowed to
    /// flip back to grey-cloud. Prevents flap during borderline-Critical
    /// traffic. Default: 300 (5 min).
    #[serde(default = "default_cf_min_proxy_duration")]
    pub min_proxy_duration_secs: u64,
}

/// `[shield.origin_lockdown]` — controls the iptables CF-only lockdown.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ShieldOriginLockdownConfig {
    /// Master switch. When false the lockdown is not even instantiated.
    #[serde(default)]
    pub enabled: bool,
    /// Safety gate. When true the lockdown logs but never touches
    /// iptables. Default true — the iptables rules are operator-visible
    /// and a misconfigured Cloudflare CIDR set can lock the operator
    /// out of their own server.
    #[serde(default = "default_true_val")]
    pub dry_run: bool,
}
