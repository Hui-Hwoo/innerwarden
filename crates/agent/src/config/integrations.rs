//! External intel/integration config sections (cloudflare, crowdsec, abuseipdb, dshield, fail2ban, geoip, threat-feeds).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Cloudflare
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    /// Enable Cloudflare IP block push (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Cloudflare Zone ID (from dashboard)
    #[serde(default)]
    pub zone_id: String,

    /// Cloudflare API token (or CLOUDFLARE_API_TOKEN env var)
    #[serde(default)]
    pub api_token: String,

    /// Push block decisions to Cloudflare edge (default: true when enabled)
    #[serde(default = "default_true")]
    pub auto_push_blocks: bool,

    /// Prefix for Cloudflare rule notes (default: "innerwarden")
    #[serde(default = "default_cloudflare_notes_prefix")]
    pub block_notes_prefix: String,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            zone_id: String::new(),
            api_token: String::new(),
            auto_push_blocks: default_true(),
            block_notes_prefix: default_cloudflare_notes_prefix(),
        }
    }
}

// ---------------------------------------------------------------------------
// CrowdSec
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecConfig {
    /// Enable CrowdSec LAPI polling (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// CrowdSec Local API URL (default: http://localhost:8080)
    #[serde(default = "default_crowdsec_url")]
    pub url: String,

    /// CrowdSec LAPI API key. Can also be set via CROWDSEC_API_KEY env var.
    /// Find it in: /etc/crowdsec/local_api_credentials.yaml (password field)
    #[serde(default)]
    pub api_key: String,

    /// How often to poll the LAPI for new ban decisions (seconds, default: 60)
    #[serde(default = "default_crowdsec_poll_secs")]
    pub poll_secs: u64,

    /// Max new IPs to block per sync cycle (default: 50).
    /// CrowdSec CAPI can return thousands of IPs at once; blocking them all
    /// in a single tick stalls the agent and exhausts memory.
    /// Remaining IPs are processed in subsequent ticks.
    #[serde(default = "default_crowdsec_max_per_sync")]
    #[allow(dead_code)]
    pub max_per_sync: usize,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_crowdsec_url(),
            api_key: String::new(),
            poll_secs: default_crowdsec_poll_secs(),
            max_per_sync: default_crowdsec_max_per_sync(),
        }
    }
}

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseIpDbConfig {
    /// Enable AbuseIPDB IP reputation enrichment (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// AbuseIPDB API key. Can also be set via ABUSEIPDB_API_KEY env var.
    /// Free tier: 1,000 checks/day - sufficient for most self-hosted servers.
    #[serde(default)]
    pub api_key: String,

    /// Maximum age of abuse reports to consider (default: 30 days).
    #[serde(default = "default_abuseipdb_max_age_days")]
    pub max_age_days: u32,

    /// Auto-block threshold: if AbuseIPDB confidence score >= this value,
    /// block the IP immediately without calling the AI provider.
    /// 0 = disabled (default). Recommended: 75 for aggressive auto-blocking,
    /// 90 for conservative auto-blocking. Reduces AI API costs during attacks
    /// from known malicious IPs.
    #[serde(default)]
    pub auto_block_threshold: u8,

    /// Report blocked IPs back to AbuseIPDB (default: false).
    /// When enabled, every successful block_ip action is reported to the
    /// AbuseIPDB database with the appropriate attack categories.
    /// This contributes to the global threat intelligence network.
    #[serde(default)]
    pub report_blocks: bool,

    /// Maximum AbuseIPDB *report-endpoint* calls per 24h UTC. Free tier
    /// grants 1,000 per day; the default of 800 reserves 20% headroom for
    /// operator-triggered ad-hoc reports. A production incident on
    /// 2026-04-18 (`correlation:CL-008` cascade) burned ~900 reports in
    /// one day and tripped AbuseIPDB's quota email — the cap here is the
    /// second line of defence behind `cloud_safelist`. Set to `0` to
    /// pause outbound reporting entirely without disabling the rest of
    /// the AbuseIPDB integration.
    #[serde(default = "default_abuseipdb_report_daily_cap")]
    pub report_daily_cap: u32,
}

impl Default for AbuseIpDbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: String::new(),
            max_age_days: default_abuseipdb_max_age_days(),
            auto_block_threshold: 0,
            report_blocks: false,
            report_daily_cap: default_abuseipdb_report_daily_cap(),
        }
    }
}

// ---------------------------------------------------------------------------
// DShield (SANS Internet Storm Center) — read-only community enrichment
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DshieldConfig {
    /// Enable DShield (ISC) IP reputation enrichment (default: false).
    /// Keyless, read-only — attacker IPs get the community's global attack
    /// history + threat-feed membership alongside AbuseIPDB / CrowdSec.
    /// Opt-in like every other external-call enrichment.
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Fail2ban
// ---------------------------------------------------------------------------

/// Deprecated - InnerWarden's native detectors + XDP firewall supersede fail2ban.
/// Kept for config compatibility (existing agent.toml files won't break).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Fail2BanConfig {
    /// Enable fail2ban polling (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// How often to poll fail2ban for new ban decisions (seconds, default: 60)
    #[serde(default = "default_fail2ban_poll_secs")]
    pub poll_secs: u64,

    /// Jails to poll. Empty = all active jails (from `fail2ban-client status`).
    #[serde(default)]
    pub jails: Vec<String>,

    /// Prefix fail2ban-client calls with sudo (needed when agent runs as non-root,
    /// requires: `innerwarden ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client *` in sudoers).
    #[serde(default)]
    pub use_sudo: bool,
}

impl Default for Fail2BanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_secs: default_fail2ban_poll_secs(),
            jails: vec![],
            use_sudo: false,
        }
    }
}

// ---------------------------------------------------------------------------
// GeoIP enrichment
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GeoIpConfig {
    /// Enable IP geolocation enrichment via ip-api.com (default: false).
    /// No API key required. Free tier: 45 requests/minute.
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Threat Feeds
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ThreatFeedsConfig {
    /// External IOC feed URLs (plaintext IP/domain lists). Polled periodically.
    /// Free public feeds:
    /// - https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    /// - https://urlhaus.abuse.ch/downloads/text/
    /// - https://threatfox.abuse.ch/downloads/iocs/text/
    #[serde(default)]
    pub ioc_feed_urls: Vec<String>,

    /// VirusTotal API key for binary hash checking (optional).
    /// Can also be set via VT_API_KEY or VIRUSTOTAL_API_KEY env var.
    #[serde(default)]
    pub virustotal_api_key: String,

    /// Poll interval in seconds (default: 3600 = 1 hour).
    /// Currently feeds are polled on every slow tick; this field is reserved
    /// for rate-limiting the poll frequency in a future version.
    #[serde(default = "default_threat_feeds_poll_secs")]
    #[allow(dead_code)]
    pub poll_secs: u64,
}

impl Default for ThreatFeedsConfig {
    fn default() -> Self {
        Self {
            ioc_feed_urls: Vec::new(),
            virustotal_api_key: String::new(),
            poll_secs: default_threat_feeds_poll_secs(),
        }
    }
}

impl ThreatFeedsConfig {
    /// Effective feed URLs: user-configured if any, otherwise the curated defaults.
    pub fn effective_urls(&self) -> Vec<String> {
        if self.ioc_feed_urls.is_empty() {
            DEFAULT_IOC_FEEDS.iter().map(|u| u.to_string()).collect()
        } else {
            self.ioc_feed_urls.clone()
        }
    }
}
