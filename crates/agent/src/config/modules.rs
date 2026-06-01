//! Ring/integrity module config sections (firmware, hypervisor, killchain, DNA).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

/// Firmware security monitoring via innerwarden-smm.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareConfig {
    /// Enable periodic firmware audits. Default: true.
    #[serde(default = "default_firmware_enabled")]
    pub enabled: bool,
    /// Audit interval in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_firmware_poll_secs")]
    pub poll_secs: u64,
    /// Trust score threshold for emitting incidents. Default: 0.85.
    #[serde(default = "default_firmware_trust_threshold")]
    pub trust_score_threshold: f64,
}

impl Default for FirmwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_secs: default_firmware_poll_secs(),
            trust_score_threshold: default_firmware_trust_threshold(),
        }
    }
}

/// Hypervisor security monitoring via innerwarden-hypervisor.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypervisorConfig {
    /// Enable periodic hypervisor audits. Default: true.
    #[serde(default = "default_hypervisor_enabled")]
    pub enabled: bool,
    /// Audit interval in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_hypervisor_poll_secs")]
    pub poll_secs: u64,
    /// Trust score threshold for emitting incidents. Default: 0.80.
    #[serde(default = "default_hypervisor_trust_threshold")]
    pub trust_score_threshold: f64,
}

impl Default for HypervisorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_secs: default_hypervisor_poll_secs(),
            trust_score_threshold: default_hypervisor_trust_threshold(),
        }
    }
}

/// Kill chain detection — inline PID tracking against 8 attack patterns.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillchainConfig {
    /// Enable kill chain detection on eBPF events. Default: true.
    #[serde(default = "default_killchain_enabled")]
    pub enabled: bool,
    /// Pre-chain warning threshold (0.0-1.0). Default: 0.6.
    #[serde(default = "default_killchain_pre_chain_threshold")]
    pub pre_chain_threshold: f32,
    /// PID session timeout in seconds. Default: 60.
    #[serde(default = "default_killchain_session_timeout")]
    pub session_timeout_secs: i64,
    /// 2026-05-03: extra `comm` values that count as self-traffic
    /// (operator/system tooling whose `socket + sensitive_read` is
    /// legitimate package-management or remote-admin activity, not
    /// data exfiltration). Builtins are defined in
    /// `killchain_inline::self_traffic::BUILTIN_SELF_TRAFFIC_COMMS`
    /// (apt, snap, ssh, scp, curl, wget, cloud-init, etc.). The
    /// operator can extend that list here without forking the
    /// binary — useful for shop-specific deployments that have
    /// custom package agents (puppet, chef, salt) or admin tools.
    ///
    /// Example: `[killchain] self_traffic_comms_extra = ["puppet", "chef-client"]`
    ///
    /// The merged list is consumed in two places:
    ///
    ///   1. `dismiss_self_traffic_incidents` — auto-dismisses the
    ///      kill_chain incident with `ai_provider="self-traffic-fp"`.
    ///   2. `notify_telegram` — suppresses the Telegram alert so the
    ///      operator does not get paged for an apt update they
    ///      kicked off five seconds ago.
    ///
    /// Both consumers MUST read from the same merged list — anchored
    /// in `telegram_notify_and_dismiss_consume_same_self_traffic_list`
    /// (killchain_inline.rs).
    #[serde(default)]
    pub self_traffic_comms_extra: Vec<String>,
}

impl Default for KillchainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pre_chain_threshold: default_killchain_pre_chain_threshold(),
            session_timeout_secs: default_killchain_session_timeout(),
            self_traffic_comms_extra: Vec::new(),
        }
    }
}

/// Threat DNA behavioral fingerprinting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnaConfig {
    /// Enable inline DNA fingerprinting. Default: true.
    #[serde(default = "default_dna_enabled")]
    pub enabled: bool,
    /// Minimum behavior sequence length to fingerprint. Default: 3.
    #[serde(default = "default_dna_min_sequence")]
    pub min_sequence: usize,
    /// Anomaly detection threshold (z-score). Default: 3.0.
    #[serde(default = "default_dna_anomaly_threshold")]
    pub anomaly_threshold: f64,
    /// Session inactivity timeout in seconds. Default: 300.
    #[serde(default = "default_dna_session_timeout")]
    pub session_timeout_secs: i64,
}

impl Default for DnaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_sequence: default_dna_min_sequence(),
            anomaly_threshold: default_dna_anomaly_threshold(),
            session_timeout_secs: default_dna_session_timeout(),
        }
    }
}
