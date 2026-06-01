//! Fleet management config sections.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

/// Fleet (MSSP multi-host) configuration. Spec 038 Phase 1.
///
/// Default `enabled = false` keeps every existing deploy unchanged.
/// When enabled, a background tokio task polls each configured spoke's
/// `/api/status` endpoint at `poll_interval_seconds` cadence and the
/// `GET /api/fleet/hosts` endpoint returns the cached status.
///
/// No new write paths on the spoke side: the manager talks to the
/// existing single-host dashboard endpoints over HTTPS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetConfig {
    /// Master switch. When false the poller is not spawned and
    /// `/api/fleet/hosts` returns 404. Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// List of spoke hosts the manager will poll.
    #[serde(default)]
    pub hosts: Vec<FleetHostConfig>,
    /// How often to refresh each host's status. Default: 30 s.
    #[serde(default = "default_fleet_poll_interval_seconds")]
    pub poll_interval_seconds: u64,
    /// HTTP request timeout for each spoke poll. Default: 5 s.
    /// Tight enough that a hung spoke does not stall the poll loop.
    #[serde(default = "default_fleet_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHostConfig {
    /// Stable identifier the manager uses in URLs and status keys.
    /// Must be unique across the fleet. Operator-chosen (e.g. `"prod-eu"`).
    pub id: String,
    /// Full URL of the spoke's dashboard, e.g.
    /// `https://prod-eu.example.com:8787`. The poller appends
    /// `/api/overview` to this base.
    pub url: String,
    /// Name of the env var holding the **initial** bearer token for
    /// this spoke. The poller uses this on first contact and falls
    /// back to login (`username_env` / `password_env`) on 401.
    /// Empty string means "no initial bearer" — typical when only
    /// the username/password are set and the manager logs in at
    /// boot.
    #[serde(default)]
    pub token_env: String,
    /// Phase 4: env var holding the Basic Auth username for
    /// session-token refresh. Set together with `password_env` to
    /// enable the manager to call `POST /api/auth/login` on the
    /// spoke and re-issue a bearer when the cached one rejects.
    #[serde(default)]
    pub username_env: String,
    /// Phase 4: env var holding the Basic Auth password.
    /// Plaintext password lives in the env; never on disk.
    #[serde(default)]
    pub password_env: String,
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: Vec::new(),
            poll_interval_seconds: default_fleet_poll_interval_seconds(),
            request_timeout_seconds: default_fleet_request_timeout_seconds(),
        }
    }
}
