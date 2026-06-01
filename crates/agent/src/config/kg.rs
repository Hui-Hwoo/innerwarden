//! Knowledge-graph + incident-flow config sections.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

/// Incident lifecycle routing knobs (spec 028).
///
/// The only knob currently live is the `escalate_to_decide` feature flag. When
/// true, observation-verify's Escalate branch is expected to forward incidents
/// into the Fase 4 `ai_provider.decide()` pipeline so attackers that score
/// above the escalate threshold actually get actioned instead of sitting under
/// the OBSERVING bucket forever.
///
/// Default is `false` because the full wiring (threading the provider + skill
/// executor + state into narrative_observation_verify) is intentionally
/// staged: this PR lands the flag + config, the follow-up PR lands the decide
/// call. See spec 028 section 028-b.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct IncidentFlowConfig {
    /// When true, Escalate from observation-verify should trigger a Fase 4
    /// decide() call. The wiring itself is a follow-up PR; today the flag
    /// is read but the code path only logs an intent line. Flip to true in
    /// /etc/innerwarden/agent.toml after the wiring PR lands.
    #[serde(default)]
    pub escalate_to_decide: bool,
    /// Detector prefixes whose incidents should skip the Fase 3 observation
    /// verifier entirely and go direct to Fase 4. The spec lists
    /// `threat_intel:*`, `sudo_abuse:*`, and `suspicious_execution:*` as
    /// candidates because they are inherently high-signal. Matched via
    /// prefix (case-sensitive). Empty by default; the skip path is also
    /// Consumed by `incident_flow::evaluate_pre_ai_flow` (spec 028-b
    /// full wiring): when the incident id starts with any entry in
    /// this list (optionally followed by `:`), the pre-AI gate
    /// bypasses the below-severity and decision-cooldown guards so
    /// the incident reaches `ai_provider.decide()`. Allowlist and
    /// per-tick budget still apply.
    #[serde(default)]
    pub detectors_skip_fase3: Vec<String>,
}

/// KG-derived decision modifiers and detectors (spec 043). Each
/// behavior-changing knob ships in `shadow` mode by default so an
/// operator can observe a JSONL log of "what would have happened" for
/// at least 7 days before promoting to `enforce`. `off` is the rollback
/// path without redeploy. Same tri-state pattern as
/// `[ai].untouchable_override_mode`.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct KgConfig {
    /// Phase 1: pre-decide modifier that nudges AI confidence based on
    /// the entity's KG-derived history (prior incidents, benign vs
    /// malicious ratio, related campaigns, AbuseIPDB risk score, age).
    /// Modes: "off" | "shadow" | "enforce". Default: "shadow".
    #[serde(default = "default_kg_decide_modifier_mode")]
    pub decide_modifier_mode: String,
    /// Phase 3: yara_match_detector. When true, the slow loop scans
    /// File nodes with non-empty `yara_matches` and emits High
    /// incidents per matched binary. Activates a KG field that was
    /// write-only pre-Phase-3. Default: false (operator opts in on
    /// test001 first to observe rate before prod promotion).
    #[serde(default)]
    pub yara_match_detector_enabled: bool,
    /// Phase 5: sysctl_drift_detector. When true, the slow loop
    /// snapshots the System node's `sysctl_params` on first tick and
    /// emits incidents on subsequent ticks for any drift. Critical-
    /// class params (kernel.modules_disabled, kptr_restrict,
    /// dmesg_restrict, unprivileged_bpf_disabled, yama.ptrace_scope,
    /// randomize_va_space, net.ipv4.ip_forward) → Critical;
    /// other drifts → aggregated Medium. Activates a KG field that
    /// was write-only pre-Phase-5. Default: false.
    #[serde(default)]
    pub sysctl_drift_detector_enabled: bool,
    /// Phase 4: packed_binary_detector. When true, the slow loop
    /// emits Medium incidents for File nodes whose `entropy` exceeds
    /// `packed_binary_entropy_threshold` AND that have at least one
    /// incoming Executed edge. Activates `File.entropy` which was
    /// write-only pre-Phase-4. Default: false.
    #[serde(default)]
    pub packed_binary_detector_enabled: bool,
    /// Phase 4 threshold. Legit binaries score 5.5-6.5 on Shannon
    /// entropy; packers / encrypted payloads approach 8.0. Default
    /// 7.5 catches UPX / themida / vmprotect / generic obfuscators
    /// without firing on lightly-compressed assets. Operators with
    /// unusually high-entropy legit workloads can raise this.
    #[serde(default = "default_packed_binary_entropy_threshold")]
    pub packed_binary_entropy_threshold: f32,
    /// Phase 6: short_lived_process_detector. When true, the slow
    /// loop emits Medium incidents for Process nodes whose lifetime
    /// is below `short_lived_process_threshold_ms` AND that connected
    /// to at least one external IP during their lifetime. Activates
    /// `Process.exit_ts` which was write-only pre-Phase-6. Default:
    /// false.
    #[serde(default)]
    pub short_lived_process_detector_enabled: bool,
    /// Phase 6 threshold in milliseconds. Sub-100ms processes that do
    /// network I/O are a classic injection / shellcode shape (loader
    /// → connect → exfil → exit). Default 100 catches the common
    /// patterns; raise on slow hardware where legit tools dip below.
    #[serde(default = "default_short_lived_process_threshold_ms")]
    pub short_lived_process_threshold_ms: u64,
    /// Phase 7: KG-based FP suppression. Same tri-state pattern as
    /// `decide_modifier_mode`. Default `"shadow"` — the helper writes
    /// `kg_shadow_fp_suppression_<DATE>.jsonl` records but does NOT
    /// suppress until operator promotes to `"enforce"`. Critical
    /// floor is hardcoded (Critical incidents NEVER suppressed).
    #[serde(default = "default_fp_suppression_mode")]
    pub fp_suppression_mode: String,
    /// Phase 7 threshold: incidents with FP likelihood >= this value
    /// get suppressed (write dismiss decision, skip routing) when
    /// `fp_suppression_mode = "enforce"`. Default 0.80 per spec.
    /// Operator-tunable for tighter / looser suppression.
    #[serde(default = "default_fp_suppress_threshold")]
    pub fp_suppress_threshold: f32,
}

impl Default for KgConfig {
    fn default() -> Self {
        Self {
            decide_modifier_mode: default_kg_decide_modifier_mode(),
            yara_match_detector_enabled: false,
            sysctl_drift_detector_enabled: false,
            packed_binary_detector_enabled: false,
            packed_binary_entropy_threshold: default_packed_binary_entropy_threshold(),
            short_lived_process_detector_enabled: false,
            short_lived_process_threshold_ms: default_short_lived_process_threshold_ms(),
            fp_suppression_mode: default_fp_suppression_mode(),
            fp_suppress_threshold: default_fp_suppress_threshold(),
        }
    }
}
