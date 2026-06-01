//! Environment + security posture config sections.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Security (2FA)
// ---------------------------------------------------------------------------

/// Security settings for operator authentication.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Two-factor authentication method: "none", "totp", "dashboard".
    /// Default: "none" (2FA disabled, v1 behavior).
    #[serde(default = "default_two_factor_method")]
    pub two_factor_method: String,
    /// TOTP secret (base32 encoded). Stored in agent.env as INNERWARDEN_TOTP_SECRET.
    /// Leave empty in TOML; set via `innerwarden configure 2fa`.
    #[serde(default)]
    pub totp_secret: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            two_factor_method: default_two_factor_method(),
            totp_secret: String::new(),
        }
    }
}

/// Environment auto-profiling and census configuration.
///
/// ```toml
/// [environment]
/// auto_profile = true
/// census_interval_hours = 6
/// cloud_timing_multiplier = 10
/// ```
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfig {
    /// Run bootstrap profiling on first boot (or when profile missing).
    #[serde(default = "default_true_val")]
    pub auto_profile: bool,

    /// How often to run the periodic census (hours).
    #[serde(default = "default_census_interval_hours")]
    pub census_interval_hours: u64,

    /// Timing anomaly threshold multiplier for cloud/VM environments.
    /// Applied automatically when `platform` is detected as cloud VPS.
    #[serde(default = "default_cloud_timing_multiplier")]
    pub cloud_timing_multiplier: u32,

    /// 2026-05-03: extra service account names that should be
    /// classified as `Service` for graph-detector threshold
    /// purposes. Auto-detection (uid >= 1000 + nologin shell)
    /// covers the OS-shipped accounts (snap_daemon, _apt,
    /// systemd-resolve, messagebus, etc.). This list is for
    /// shop-specific accounts that the auto-detect can't reach —
    /// e.g. config-management agents (`puppet`, `chef-client`,
    /// `salt-minion`) installed in `/usr/local/bin` with a real
    /// login shell.
    ///
    /// Example:
    /// ```toml
    /// [environment]
    /// service_users_extra = ["puppet", "chef-client", "ansible-runner"]
    /// service_uids_extra = [991, 992]
    /// ```
    #[serde(default)]
    pub service_users_extra: Vec<String>,

    /// 2026-05-03: same as `service_users_extra` but by uid.
    /// Useful when the operator knows the uid but not a stable
    /// name (containerized service accounts, etc.).
    #[serde(default)]
    pub service_uids_extra: Vec<u32>,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            auto_profile: true,
            census_interval_hours: default_census_interval_hours(),
            cloud_timing_multiplier: default_cloud_timing_multiplier(),
            service_users_extra: Vec::new(),
            service_uids_extra: Vec::new(),
        }
    }
}
