//! Learning config section.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Learning (spec 062 — decision review + learned suppression)
// ---------------------------------------------------------------------------

/// Spec 062 Phase 4 — learned-suppression knobs. An absent `[learning]`
/// section deserializes to these defaults (shadow mode, N = 5) so existing
/// agent.toml files upgrade cleanly with no edits — the spec's hard
/// "no breakage" migration rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningConfig {
    /// Learned-suppression mode: `"off"` | `"shadow"` | `"enforce"`.
    /// Default `"shadow"`: the gate logs what it WOULD suppress to
    /// `learned_suppression_shadow_<DATE>.jsonl` and changes nothing,
    /// until the operator validates the numbers and promotes to
    /// `"enforce"`. Unknown values collapse to `"shadow"` (see
    /// `learned_suppression::parse_mode`), never silently to `"off"`.
    #[serde(default = "default_learned_suppression_mode")]
    pub suppression_mode: String,

    /// Minimum GENUINE repeated dismissals of a `(detector | ip)` shape
    /// before it becomes eligible for auto-suppression. Default 5 — above
    /// the autofp *suggestion* threshold of 3 because this acts SILENTLY;
    /// prod's top repeated shapes dwarf it (1105 / 456 / 82 dismissals),
    /// so 5 catches all real noise with margin. orphan-recovery and prior
    /// learned-suppression dismissals are excluded from the count.
    #[serde(default = "default_learned_min_dismissals")]
    pub min_dismissals: u64,

    /// Spec 062 Phase 5 — route escalated (warden-unresolved) incidents to
    /// the LLM for a second-opinion Decide. Default `true`: when an
    /// `[ai.llm]` provider is configured it now decides the ambiguous
    /// escalations the local warden parked, instead of the warden being
    /// asked twice (the production bug where the configured Azure LLM
    /// recorded zero decisions). With no LLM configured this is a no-op —
    /// the escalation falls back to whatever Decide provider exists, exactly
    /// as before. Set `false` as a kill switch without a redeploy.
    #[serde(default = "default_true")]
    pub llm_escalation_enabled: bool,

    /// Spec 062 Phase 5 — confidence floor below which a HIGH-IMPACT LLM
    /// escalation action (block_ip / suspend_user_sudo / kill_process /
    /// block_container / kill_chain_response) is NOT auto-executed but
    /// deferred to a human via `needs_review`. "Com peso, confirma" applied
    /// to the LLM: a confident high-impact call executes; an unsure one
    /// waits for the operator. Soft actions (monitor / dismiss / ignore /
    /// honeypot / request_confirmation) are never gated. Default 0.75.
    #[serde(default = "default_llm_escalation_min_confidence")]
    pub llm_escalation_min_confidence: f32,

    /// Spec 062 Phase 3 — when an ambiguous incident is parked as
    /// `needs_review`, send the operator a Telegram notification with inline
    /// Block / Ignore / Dismiss buttons so they can resolve it from chat.
    /// Default `false`: spec 062 ships disabled-by-default (nothing
    /// auto-enabled in prod). The operator flips this on after validating on
    /// a lab host. With no Telegram client configured this is a no-op.
    #[serde(default)]
    pub needs_review_notify: bool,

    /// Spec 062 Phase 6a — emit human-grade decisions (Telegram resolutions,
    /// operator honeypot/block/ignore choices, learned-suppression dismisses)
    /// to `labels-<date>.jsonl` as a warden re-distillation corpus. Default
    /// `true`: the channel is purely additive (a low-volume append-only log
    /// pruned alongside `decisions-*.jsonl`), introduces no behaviour change,
    /// and is worthless if off. Set `false` to opt out of the corpus entirely.
    #[serde(default = "default_true")]
    pub emit_labels: bool,

    /// Spec 062 Phase 6b — let high-trust mesh peers' suppression advisories
    /// CORROBORATE (never originate) a learned suppression. When `true`, a
    /// shape this host has already dismissed locally at least once can reach
    /// the suppression threshold with bounded peer help (capped at N/2). When
    /// `false` (default — disabled-by-default per spec 062), advisories are
    /// still received, gated, and audited, but never change a suppression
    /// decision. The honeypot/imds shapes prove out on the lab first.
    #[serde(default)]
    pub mesh_suppression_corroboration: bool,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            suppression_mode: default_learned_suppression_mode(),
            min_dismissals: default_learned_min_dismissals(),
            llm_escalation_enabled: default_true(),
            llm_escalation_min_confidence: default_llm_escalation_min_confidence(),
            needs_review_notify: false,
            emit_labels: true,
            mesh_suppression_corroboration: false,
        }
    }
}
