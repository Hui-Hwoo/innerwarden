//! AI provider + triage config sections (AI, role providers, shadow, correlation, telemetry).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// AI provider
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiConfig {
    /// Enable AI-powered real-time incident analysis
    #[serde(default)]
    pub enabled: bool,

    /// AI provider to use: "openai" | "anthropic" (coming soon) | "ollama" (coming soon)
    #[serde(default = "default_ai_provider")]
    pub provider: String,

    /// API key for the provider. Prefer env var OPENAI_API_KEY / ANTHROPIC_API_KEY.
    #[serde(default)]
    pub api_key: String,

    /// Model identifier (provider-specific, e.g. "gpt-4o-mini")
    #[serde(default = "default_ai_model")]
    pub model: String,

    /// Number of recent events sent as context to the AI
    #[serde(default = "default_context_events")]
    pub context_events: usize,

    /// Minimum AI confidence (0.0–1.0) required to auto-execute a decision
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Poll interval for the fast incident-check loop (seconds)
    #[serde(default = "default_incident_poll_secs")]
    pub incident_poll_secs: u64,

    /// Base URL for the AI provider endpoint.
    /// - openai: defaults to https://api.openai.com (leave empty)
    /// - anthropic: defaults to https://api.anthropic.com (leave empty)
    /// - ollama: defaults to http://localhost:11434 (override for remote Ollama)
    ///   Can also be set via OLLAMA_BASE_URL env var for Ollama.
    /// - azure_openai: required - https://<resource>.openai.azure.com
    #[serde(default)]
    pub base_url: String,

    /// Azure OpenAI API version (only used when provider = "azure_openai").
    /// Defaults to "2024-12-01-preview" when empty. See Azure docs for the
    /// current stable/preview versions.
    #[serde(default)]
    pub api_version: String,

    /// Maximum number of AI calls per incident tick (default: 5).
    /// When more incidents arrive in a single tick than this limit, the excess
    /// are deferred to the next tick. Prevents API bill spikes during botnet attacks.
    /// Set to 0 to disable the limit (not recommended).
    #[serde(default = "default_max_ai_calls_per_tick")]
    pub max_ai_calls_per_tick: usize,

    /// Circuit breaker: if the number of new incidents in a single tick exceeds
    /// this threshold, skip AI analysis entirely for that tick and rely on
    /// deterministic blocklist/gate decisions only. 0 = disabled (default).
    /// Recommended value for DDoS scenarios: 20.
    #[serde(default)]
    pub circuit_breaker_threshold: usize,

    /// How long (seconds) to keep the circuit breaker open after it trips (default: 60).
    #[serde(default = "default_circuit_breaker_cooldown_secs")]
    pub circuit_breaker_cooldown_secs: u64,

    /// IPs that should NEVER be blocked, regardless of AI decision.
    /// Protects internal infrastructure from false positives.
    #[serde(default = "default_protected_ips")]
    pub protected_ips: Vec<String>,

    /// Untouchable detector classes — AI is not allowed to silently
    /// dismiss/ignore at Critical severity for these classes
    /// (kill_chain, reverse_shell with eBPF evidence, ransomware,
    /// data_exfil_ebpf, multi-stage cross-layer chains). The
    /// override forces the decision to `RequestConfirmation` so the
    /// operator sees it instead of the AI's auto-dismiss winning.
    ///
    /// Surfaced 2026-05-01 dashboard QA audit finding 1.3 — AI
    /// auto-dismissed a `kill_chain DATA_EXFIL + reverse_shell` at
    /// 100% confidence with rationale "ssh is a known operator/system
    /// tool". The detector evidence was eBPF kernel-level
    /// fd-redirect-to-socket. Auto-dismissing kernel-level evidence
    /// is the failure mode a security tool must never have.
    ///
    /// Modes:
    /// - `"enforce"` (default) — override fires, decision becomes
    ///   `RequestConfirmation`, original AI reasoning preserved in
    ///   the annotation suffix.
    /// - `"shadow"` — override is logged as a WARN counter but the
    ///   decision is left as-is. Use this for the first 24h after a
    ///   classifier-rule change to compare false-positive rates
    ///   before flipping to enforce.
    /// - `"off"` — disable entirely (not recommended; only here so
    ///   an operator can roll back without redeploying).
    #[serde(default = "default_untouchable_override_mode")]
    pub untouchable_override_mode: String,

    /// Minimum incident severity sent to AI analysis.
    /// "medium" (default) = Medium/High/Critical go to AI.
    /// "high" = only High/Critical go to AI (more conservative, fewer API calls).
    /// "low" = all incidents go to AI (expensive, not recommended).
    ///
    /// The default was "high" prior to v0.12.4. Production audit on
    /// 2026-04-15 found 1812 incidents → 0 AI-executed blocks; the "high"
    /// floor combined with the confidence_threshold bug in spec 018
    /// meant most real threats never reached AI triage. Lowering to
    /// "medium" lets AI see the Medium-severity layer (where most bot
    /// campaigns live) while keeping Low in the noise-gate. Operators
    /// with OpenAI/Anthropic cost sensitivity can set this back to
    /// "high" explicitly; Ollama local is free.
    #[serde(default = "default_ai_min_severity")]
    pub min_severity: String,

    /// Spec 005 Phase 8 — batch all closed groups into one AI prompt per window
    /// instead of one AI call per incident. Reduces API spend on noisy hosts.
    /// Disabled by default.
    #[serde(default)]
    pub batch_triage: bool,

    /// Window size for batch triage, in seconds. Default 3600 (1h) aligns with
    /// the notification_pipeline group window. Reserved for future harness
    /// revisions that pace batch triage independently from the tick loop;
    /// today the slow loop runs triage on every grouping tick.
    #[serde(default = "default_batch_window_secs")]
    #[allow(dead_code)]
    pub batch_window_secs: u64,

    /// Spec 025 — send the knowledge graph as a structured JSON subgraph
    /// to the LLM instead of a prose narrative. Measured on qwen2.5:3b
    /// (bench in innerwarden-test/ai-grounding): action accuracy 53% →
    /// 73%, target hallucination 47% → 7%.
    ///
    /// Default true. Operators on existing installs can temporarily set
    /// this to false for 48h to A/B compare against the old prose
    /// format. Flag scheduled for removal in the next minor release once
    /// prod drift is verified flat.
    #[serde(default = "default_use_structured_subgraph")]
    pub use_structured_subgraph: bool,

    /// Optional shadow provider: runs in parallel with the primary provider
    /// and logs each decision for operator audit. Primary drives production;
    /// shadow is purely observational. Use to validate a new provider (e.g.
    /// a local classifier) against a known-good one (e.g. Azure OpenAI)
    /// before promoting the shadow to primary.
    #[serde(default)]
    pub shadow: ShadowConfig,

    /// Spec 029 PR-C: dedicated provider for the classifier role
    /// (triage decisions + structured classification). When
    /// `enabled = false` (default), the primary `[ai]` block fills
    /// the classifier slot of the router — identical to the pre-029
    /// behaviour. When `enabled = true`, the router uses this block
    /// for `Capability::Decide` and `Capability::Classify`. Typical
    /// production config points this at the Local Warden Model
    /// (ONNX classifier) so triage runs without LLM cost.
    ///
    /// 2026-05-03: TOML key was `[ai.classifier]` — operator-facing
    /// rename to `[ai.warden]` keeps the canonical brand consistent
    /// with the model name itself (`warden` / `securebert`). The
    /// `classifier` alias preserves back-compat with existing prod
    /// configs; new operators write `[ai.warden]`.
    #[serde(default, alias = "classifier", rename = "warden")]
    pub classifier: RoleProviderConfig,

    /// Spec 029 PR-C: dedicated provider for the LLM role
    /// (free-form generation, explanation, honeypot shell
    /// simulation). When `enabled = false` (default), the primary
    /// `[ai]` block fills the llm slot. When enabled, the router
    /// uses this block for `Capability::Generate`,
    /// `Capability::Explain`, and `Capability::SimulateShell`.
    /// Typical production config points this at a full LLM (Azure
    /// OpenAI GPT-5.4-mini, Claude, etc.) so operator-facing chat
    /// and briefings keep working when the classifier role is
    /// served by a narrow local model.
    #[serde(default)]
    pub llm: RoleProviderConfig,
}

/// Slim per-role provider configuration introduced in spec 029 PR-C.
/// Shared by `[ai.warden]` (Local Warden Model — formerly
/// `[ai.classifier]`) and `[ai.llm]`. Fields are a subset of
/// `AiConfig` (only what a single provider needs to be constructed);
/// shared knobs like `confidence_threshold`, `min_severity`, and the
/// shadow wrapper continue to live on the top-level `[ai]` block.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RoleProviderConfig {
    /// Whether this role provides its own provider, as a tri-state:
    ///
    /// - `Some(true)`  - explicitly on; build the per-role provider.
    /// - `Some(false)` - explicitly off; fall back to the primary
    ///   `[ai]` block even if a `provider` is configured here.
    /// - `None` (the default, i.e. the key is omitted) - INFER from
    ///   `provider`: active when `provider` is non-empty, inactive
    ///   otherwise.
    ///
    /// The inference closes a release-blocking footgun: `install.sh`
    /// / `innerwarden setup` write `[ai.warden] provider = "local_warden"`
    /// to wire the on-device model, but pre-2026-05-29 the writer did
    /// NOT emit `enabled = true`, so the section parsed with
    /// `enabled = false` and the model - already downloaded and
    /// SHA-verified on disk - was silently never loaded. A section
    /// that names a provider should USE that provider unless the
    /// operator explicitly disables it. Read via [`Self::is_active`];
    /// never branch on this field directly.
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Provider name. Same set of valid values as `[ai].provider`
    /// (openai, anthropic, ollama, azure_openai, local_warden /
    /// local_classifier, stub, or any OpenAI-compatible registered
    /// name). `local_warden` is the canonical name for the on-device
    /// ONNX model; `local_classifier` is accepted as a legacy alias.
    #[serde(default)]
    pub provider: String,

    /// Same semantics as `[ai].api_key`. Empty string means the
    /// agent reads the provider-specific env var at startup
    /// (OPENAI_API_KEY, AZURE_OPENAI_API_KEY, etc.).
    #[serde(default)]
    pub api_key: String,

    /// Same semantics as `[ai].model`.
    #[serde(default)]
    pub model: String,

    /// Same semantics as `[ai].base_url`.
    #[serde(default)]
    pub base_url: String,

    /// Same semantics as `[ai].api_version` (used by `azure_openai`).
    #[serde(default)]
    pub api_version: String,
}

impl RoleProviderConfig {
    /// Whether this role should build its own provider. Resolves the
    /// tri-state `enabled` against `provider` (see the field docs):
    /// an omitted `enabled` with a configured `provider` is active,
    /// matching operator intent and the install/wizard write path.
    pub fn is_active(&self) -> bool {
        self.enabled
            .unwrap_or_else(|| !self.provider.trim().is_empty())
    }

    /// True when a `provider` is configured but the role is inactive
    /// because `enabled = false` was set explicitly. The boot path
    /// surfaces this as a loud warning so a deliberately-disabled (or
    /// accidentally-disabled) on-device model is never silent.
    pub fn is_provider_set_but_disabled(&self) -> bool {
        !self.provider.trim().is_empty() && !self.is_active()
    }

    /// Project this role config into a full `AiConfig` shell suitable
    /// for handing to `ai::build_provider`. Reuses the defaults from
    /// `AiConfig::default()` for all knobs that are not per-role
    /// (confidence threshold, max calls per tick, etc.). Leaves
    /// `api_key` as-is on the returned config so the downstream
    /// `AiConfig::resolved_api_key` env-var fallback fires exactly
    /// like it does for the primary `[ai]` block — operators set
    /// `AZURE_OPENAI_API_KEY` once and both the primary and the LLM
    /// slot pick it up.
    pub fn to_ai_config(&self) -> AiConfig {
        AiConfig {
            enabled: self.is_active(),
            provider: self.provider.clone(),
            api_key: self.api_key.clone(),
            model: self.model.clone(),
            base_url: self.base_url.clone(),
            api_version: self.api_version.clone(),
            ..AiConfig::default()
        }
    }
}

/// Shadow provider configuration (subset of AiConfig applied to a second
/// provider that runs in parallel with the primary for auditing).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowConfig {
    /// If false (default), no shadow provider is created.
    #[serde(default)]
    pub enabled: bool,

    /// Provider name. Same set of valid values as `[ai].provider`.
    #[serde(default)]
    pub provider: String,

    /// Same semantics as `[ai].api_key`. Can be empty if the env var
    /// (e.g. OPENAI_API_KEY) provides the key.
    #[serde(default)]
    pub api_key: String,

    /// Same semantics as `[ai].model`.
    #[serde(default)]
    pub model: String,

    /// Same semantics as `[ai].base_url`.
    #[serde(default)]
    pub base_url: String,

    /// Same semantics as `[ai].api_version` (used by `azure_openai`).
    #[serde(default)]
    pub api_version: String,

    /// Where to append per-incident comparison lines. Default:
    /// `/var/lib/innerwarden/shadow-decisions.jsonl`.
    #[serde(default = "default_shadow_log_path")]
    pub log_path: String,

    /// Fraction of `Decide` calls that run the shadow comparison.
    /// Default `1.0` (every call) preserves the original behaviour from
    /// the initial 028-b validation window.
    ///
    /// After RESULTS_V3 (2026-05-11) the spec 028-b validation window
    /// is satisfied with 22 days of data — operators can drop this to
    /// `0.1` to keep a 10% drift-detection sample at one-tenth the
    /// Azure latency + API spend per incident, then return to `1.0`
    /// temporarily when investigating a suspected model regression.
    ///
    /// Range `[0.0, 1.0]`. Values outside the range fail config
    /// validation rather than silently clamping.
    #[serde(default = "default_shadow_sample_rate")]
    pub sample_rate: f32,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: String::new(),
            api_key: String::new(),
            model: String::new(),
            base_url: String::new(),
            api_version: String::new(),
            log_path: default_shadow_log_path(),
            sample_rate: default_shadow_sample_rate(),
        }
    }
}

impl ShadowConfig {
    /// Validate the shadow config. Called from the agent boot path so
    /// a malformed `[ai.shadow]` block fails fast at startup rather
    /// than silently clamping a bad `sample_rate` to a confusing
    /// runtime behaviour.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !(0.0..=1.0).contains(&self.sample_rate) || self.sample_rate.is_nan() {
            anyhow::bail!(
                "[ai.shadow].sample_rate must be in [0.0, 1.0], got {}",
                self.sample_rate
            );
        }
        Ok(())
    }

    /// Resolve API key: config field first, then provider-specific env var.
    pub fn resolved_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        let env_var = match self.provider.as_str() {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            "ollama" => "OLLAMA_API_KEY",
            "azure_openai" => "AZURE_OPENAI_API_KEY",
            _ => "AI_API_KEY",
        };
        std::env::var(env_var).unwrap_or_default()
    }
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_ai_provider(),
            api_key: String::new(),
            model: default_ai_model(),
            context_events: default_context_events(),
            confidence_threshold: default_confidence_threshold(),
            incident_poll_secs: default_incident_poll_secs(),
            base_url: String::new(),
            api_version: String::new(),
            max_ai_calls_per_tick: default_max_ai_calls_per_tick(),
            circuit_breaker_threshold: 0,
            circuit_breaker_cooldown_secs: default_circuit_breaker_cooldown_secs(),
            protected_ips: default_protected_ips(),
            untouchable_override_mode: default_untouchable_override_mode(),
            min_severity: default_ai_min_severity(),
            batch_triage: false,
            batch_window_secs: default_batch_window_secs(),
            use_structured_subgraph: default_use_structured_subgraph(),
            shadow: ShadowConfig::default(),
            classifier: RoleProviderConfig::default(),
            llm: RoleProviderConfig::default(),
        }
    }
}

impl AiConfig {
    /// Parse `min_severity` config into a Severity enum.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "critical" => Severity::Critical,
            _ => Severity::High, // default
        }
    }

    /// Clamp an out-of-range `confidence_threshold` to a usable value and
    /// warn the operator. A threshold above 1.0 is unreachable (AiDecision
    /// confidence is in [0.0, 1.0]), which silently disables all AI-driven
    /// auto-execution — exactly the autonomy gap observed in production on
    /// 2026-04-15 (1812 incidents, 0 AI-executed blocks because the prod
    /// config set the threshold to 1.01).
    ///
    /// A negative threshold would technically let everything through but
    /// is almost certainly a typo; clamp and warn.
    pub fn clamp_confidence_threshold(&mut self) {
        if self.confidence_threshold > 1.0 {
            tracing::warn!(
                configured = self.confidence_threshold,
                clamped_to = default_confidence_threshold(),
                "ai.confidence_threshold > 1.0 is unreachable (AI decisions emit confidence in [0.0, 1.0]); clamping to default so autonomous execution can happen"
            );
            self.confidence_threshold = default_confidence_threshold();
        } else if self.confidence_threshold < 0.0 {
            tracing::warn!(
                configured = self.confidence_threshold,
                clamped_to = default_confidence_threshold(),
                "ai.confidence_threshold is negative; clamping to default"
            );
            self.confidence_threshold = default_confidence_threshold();
        }
    }

    /// Resolve the API key: config field takes precedence, then env var.
    pub fn resolved_api_key(&self) -> String {
        if !self.api_key.is_empty() {
            return self.api_key.clone();
        }
        // Try provider-specific env vars
        let env_var = match self.provider.as_str() {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            "ollama" => "OLLAMA_API_KEY",
            "azure_openai" => "AZURE_OPENAI_API_KEY",
            _ => "AI_API_KEY",
        };
        std::env::var(env_var).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Temporal correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationConfig {
    /// Enable lightweight temporal incident correlation (window + entity pivots)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Correlation window in seconds
    #[serde(default = "default_correlation_window_secs")]
    pub window_seconds: u64,

    /// Max number of related incidents attached to AI context
    #[serde(default = "default_max_related_incidents")]
    pub max_related_incidents: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: default_correlation_window_secs(),
            max_related_incidents: default_max_related_incidents(),
        }
    }
}

// ---------------------------------------------------------------------------
// Operational telemetry
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Enable local operational telemetry JSONL output
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}
