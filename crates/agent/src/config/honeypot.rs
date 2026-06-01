//! Honeypot config sections.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Honeypot
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotConfig {
    /// Honeypot mode:
    /// - `demo`: synthetic marker only (safe default)
    /// - `listener`: starts bounded real decoys (ssh/http) with optional redirect
    /// - `always_on`: permanent SSH listener from agent startup with smart per-connection
    ///   filter (blocklist check → AbuseIPDB gate → accept into LLM shell). Runs
    ///   indefinitely until SIGTERM; each session triggers post-session AI verdict,
    ///   IOC extraction, auto-block (when responder.enabled), and Telegram T.5 report.
    #[serde(default = "default_honeypot_mode")]
    pub mode: String,

    /// Bind address used in listener mode
    #[serde(default = "default_honeypot_bind_addr")]
    pub bind_addr: String,

    /// Listener port used in listener mode
    #[serde(default = "default_honeypot_port")]
    pub port: u16,

    /// Listener lifetime in seconds used in listener mode
    #[serde(default = "default_honeypot_duration_secs")]
    pub duration_secs: u64,

    /// Enabled decoy services in listener mode.
    /// Supported: `ssh`, `http`.
    #[serde(default = "default_honeypot_services")]
    pub services: Vec<String>,

    /// HTTP decoy port used when `http` service is enabled.
    #[serde(default = "default_honeypot_http_port")]
    pub http_port: u16,

    /// Accept only connections from the action target IP.
    #[serde(default = "default_true")]
    pub strict_target_only: bool,

    /// Allow binding listener on non-loopback addresses.
    /// Default false for safer isolation.
    #[serde(default)]
    pub allow_public_listener: bool,

    /// Hard cap of accepted honeypot connections per session.
    #[serde(default = "default_honeypot_max_connections")]
    pub max_connections: usize,

    /// Max inbound payload bytes captured per connection.
    #[serde(default = "default_honeypot_max_payload_bytes")]
    pub max_payload_bytes: usize,

    /// Isolation profile for listener mode:
    /// - `strict_local` (default): hard guardrails for safer operation
    /// - `standard`: keeps only baseline guards
    #[serde(default = "default_honeypot_isolation_profile")]
    pub isolation_profile: String,

    /// Require non-privileged listener ports (>= 1024).
    #[serde(default = "default_true")]
    pub require_high_ports: bool,

    /// Retain honeypot forensics artifacts for this many days.
    #[serde(default = "default_honeypot_forensics_keep_days")]
    pub forensics_keep_days: usize,

    /// Hard cap for total honeypot forensics storage in MB.
    #[serde(default = "default_honeypot_forensics_max_total_mb")]
    pub forensics_max_total_mb: usize,

    /// Max bytes to render as readable transcript preview in evidence lines.
    #[serde(default = "default_honeypot_transcript_preview_bytes")]
    pub transcript_preview_bytes: usize,

    /// Consider active session lock stale after this many seconds.
    #[serde(default = "default_honeypot_lock_stale_secs")]
    pub lock_stale_secs: u64,

    /// Interaction level for decoy listeners:
    /// - `banner` (default): send static banner, read one payload, close
    /// - `medium`: full protocol emulation (SSH auth capture, HTTP form capture)
    #[serde(default = "default_honeypot_interaction")]
    pub interaction: String,

    /// Max SSH auth attempts before disconnecting client (medium interaction only).
    #[serde(default = "default_honeypot_ssh_max_auth_attempts")]
    pub ssh_max_auth_attempts: usize,

    /// Max HTTP requests handled per connection (medium interaction only).
    #[serde(default = "default_honeypot_http_max_requests")]
    pub http_max_requests: usize,

    #[serde(default)]
    pub sandbox: HoneypotSandboxConfig,

    #[serde(default)]
    pub pcap_handoff: HoneypotPcapHandoffConfig,

    #[serde(default)]
    pub containment: HoneypotContainmentConfig,

    #[serde(default)]
    pub external_handoff: HoneypotExternalHandoffConfig,

    #[serde(default)]
    pub redirect: HoneypotRedirectConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotSandboxConfig {
    /// Run decoy listeners in dedicated subprocess workers.
    #[serde(default)]
    pub enabled: bool,

    /// Optional absolute path to runner binary.
    /// Empty means current innerwarden-agent executable.
    #[serde(default)]
    pub runner_path: String,

    /// Clear environment for sandbox workers.
    #[serde(default = "default_true")]
    pub clear_env: bool,
}

impl Default for HoneypotSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            runner_path: String::new(),
            clear_env: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotPcapHandoffConfig {
    /// Run bounded pcap capture at session end.
    #[serde(default)]
    pub enabled: bool,

    /// Capture timeout in seconds.
    #[serde(default = "default_honeypot_pcap_timeout_secs")]
    pub timeout_secs: u64,

    /// Max captured packets.
    #[serde(default = "default_honeypot_pcap_max_packets")]
    pub max_packets: u64,
}

impl Default for HoneypotPcapHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_honeypot_pcap_timeout_secs(),
            max_packets: default_honeypot_pcap_max_packets(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotContainmentConfig {
    /// Containment mode:
    /// - `process`: standard subprocess runner (default)
    /// - `namespace`: try OS namespace wrapper (e.g., `unshare`)
    /// - `jail`: try dedicated jail wrapper (e.g., `bwrap`)
    #[serde(default = "default_honeypot_containment_mode")]
    pub mode: String,

    /// Fail execution if requested containment mode cannot be used.
    #[serde(default)]
    pub require_success: bool,

    /// Wrapper binary used in `namespace` mode.
    #[serde(default = "default_honeypot_namespace_runner")]
    pub namespace_runner: String,

    /// Arguments passed to namespace wrapper before the runner binary.
    #[serde(default = "default_honeypot_namespace_args")]
    pub namespace_args: Vec<String>,

    /// Wrapper binary used in `jail` mode.
    #[serde(default = "default_honeypot_jail_runner")]
    pub jail_runner: String,

    /// Arguments passed to jail wrapper before the runner binary.
    #[serde(default)]
    pub jail_args: Vec<String>,

    /// Jail policy preset:
    /// - `standard`: keep configured `jail_args` as-is
    /// - `strict`: append a hardened baseline profile for bwrap-style runners
    #[serde(default = "default_honeypot_jail_profile")]
    pub jail_profile: String,

    /// If true, `jail` mode can gracefully fall back to `namespace` mode.
    #[serde(default = "default_true")]
    pub allow_namespace_fallback: bool,
}

impl Default for HoneypotContainmentConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_containment_mode(),
            require_success: false,
            namespace_runner: default_honeypot_namespace_runner(),
            namespace_args: default_honeypot_namespace_args(),
            jail_runner: default_honeypot_jail_runner(),
            jail_args: Vec::new(),
            jail_profile: default_honeypot_jail_profile(),
            allow_namespace_fallback: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotExternalHandoffConfig {
    /// Execute optional external handoff command after session completion.
    #[serde(default)]
    pub enabled: bool,

    /// External command path/binary to execute.
    #[serde(default)]
    pub command: String,

    /// Command arguments. Supports placeholders:
    /// `{session_id}`, `{target_ip}`, `{metadata_path}`, `{evidence_path}`, `{pcap_path}`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Timeout for external handoff command.
    #[serde(default = "default_honeypot_external_handoff_timeout_secs")]
    pub timeout_secs: u64,

    /// Mark session as error if handoff command fails.
    #[serde(default)]
    pub require_success: bool,

    /// Clear environment variables before launching handoff command.
    #[serde(default = "default_true")]
    pub clear_env: bool,

    /// Optional command allowlist for trusted handoff integrations.
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Require external command to be present in `allowed_commands`.
    #[serde(default)]
    pub enforce_allowlist: bool,

    /// Enable signed handoff result sidecar (HMAC-SHA256).
    #[serde(default)]
    pub signature_enabled: bool,

    /// Environment variable name containing handoff signing key.
    #[serde(default = "default_honeypot_external_handoff_signature_key_env")]
    pub signature_key_env: String,

    /// Enable receiver attestation checks on external handoff output.
    #[serde(default)]
    pub attestation_enabled: bool,

    /// Environment variable name containing the shared attestation key.
    #[serde(default = "default_honeypot_external_handoff_attestation_key_env")]
    pub attestation_key_env: String,

    /// Prefix used by receiver attestation lines on stdout/stderr.
    #[serde(default = "default_honeypot_external_handoff_attestation_prefix")]
    pub attestation_prefix: String,

    /// Optional pinned receiver identifier required by attestation.
    #[serde(default)]
    pub attestation_expected_receiver: String,
}

impl Default for HoneypotExternalHandoffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: String::new(),
            args: Vec::new(),
            timeout_secs: default_honeypot_external_handoff_timeout_secs(),
            require_success: false,
            clear_env: true,
            allowed_commands: Vec::new(),
            enforce_allowlist: false,
            signature_enabled: false,
            signature_key_env: default_honeypot_external_handoff_signature_key_env(),
            attestation_enabled: false,
            attestation_key_env: default_honeypot_external_handoff_attestation_key_env(),
            attestation_prefix: default_honeypot_external_handoff_attestation_prefix(),
            attestation_expected_receiver: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotRedirectConfig {
    /// Enable selective redirection rules for target IP.
    #[serde(default)]
    pub enabled: bool,

    /// Redirect backend (`iptables` for now).
    #[serde(default = "default_honeypot_redirect_backend")]
    pub backend: String,
}

impl Default for HoneypotRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_honeypot_redirect_backend(),
        }
    }
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            mode: default_honeypot_mode(),
            bind_addr: default_honeypot_bind_addr(),
            port: default_honeypot_port(),
            duration_secs: default_honeypot_duration_secs(),
            services: default_honeypot_services(),
            http_port: default_honeypot_http_port(),
            strict_target_only: default_true(),
            allow_public_listener: false,
            max_connections: default_honeypot_max_connections(),
            max_payload_bytes: default_honeypot_max_payload_bytes(),
            isolation_profile: default_honeypot_isolation_profile(),
            require_high_ports: default_true(),
            forensics_keep_days: default_honeypot_forensics_keep_days(),
            forensics_max_total_mb: default_honeypot_forensics_max_total_mb(),
            transcript_preview_bytes: default_honeypot_transcript_preview_bytes(),
            lock_stale_secs: default_honeypot_lock_stale_secs(),
            interaction: default_honeypot_interaction(),
            ssh_max_auth_attempts: default_honeypot_ssh_max_auth_attempts(),
            http_max_requests: default_honeypot_http_max_requests(),
            sandbox: HoneypotSandboxConfig::default(),
            pcap_handoff: HoneypotPcapHandoffConfig::default(),
            containment: HoneypotContainmentConfig::default(),
            external_handoff: HoneypotExternalHandoffConfig::default(),
            redirect: HoneypotRedirectConfig::default(),
        }
    }
}
