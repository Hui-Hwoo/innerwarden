//! Responder config section.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResponderConfig {
    /// Enable skill execution on AI decisions
    #[serde(default)]
    pub enabled: bool,

    /// Dry-run mode: log decisions but don't execute any system commands.
    /// Start with true for safety; set false when ready to auto-respond.
    #[serde(default = "default_true")]
    pub dry_run: bool,

    /// Firewall backend for IP blocking: "ufw" | "iptables" | "nftables"
    #[serde(default = "default_block_backend")]
    pub block_backend: String,

    /// Whitelist of skill IDs the agent is allowed to execute automatically.
    /// Example: ["block-ip-ufw", "monitor-ip"]
    #[serde(default = "default_allowed_skills")]
    pub allowed_skills: Vec<String>,

    /// Enable deterministic auto-response rules (Layer 1).
    /// These block obvious threats (SSH brute-force, port scan, etc.) without AI.
    /// Respects dry_run and allowlist.
    #[serde(default = "default_true")]
    pub auto_rules_enabled: bool,

    /// Process names (comm) excluded from correlation-engine data exfil detection.
    /// Events from these processes are still logged but do not feed into attack
    /// chain correlation. Prevents false positives from agent's own API calls,
    /// monitoring tools, and package managers.
    ///
    /// Default includes InnerWarden's own processes. Add system daemons and
    /// monitoring tools that make legitimate outbound connections.
    #[serde(default = "default_trusted_processes")]
    pub trusted_processes: Vec<String>,

    /// Circuit breaker: hard ceiling on auto-blocks per UTC hour. Once the
    /// threshold is crossed the breaker trips (see `circuit_breaker_mode`).
    /// Default of 100/h catches the CL-008 class of cascade (1,021 blocks
    /// in 24h, ~43/h peaks) while staying out of the way during legitimate
    /// brute-force storms (≤ 30 unique IPs/h in prod baseline).
    #[serde(default = "default_max_blocks_per_hour")]
    pub max_blocks_per_hour: u64,

    /// Circuit breaker mode: "pause" (refuse blocks after trip, default),
    /// "dry_run" (audit-write the decision but skip the skill), or
    /// "log_only" (count but never refuse — calibration mode only).
    #[serde(default = "default_circuit_breaker_mode")]
    pub circuit_breaker_mode: String,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            block_backend: default_block_backend(),
            allowed_skills: default_allowed_skills(),
            auto_rules_enabled: true,
            trusted_processes: default_trusted_processes(),
            max_blocks_per_hour: default_max_blocks_per_hour(),
            circuit_breaker_mode: default_circuit_breaker_mode(),
        }
    }
}
