//! Enforcement posture: the single authoritative answer to "is the agent
//! actually acting on threats, or only watching?"
//!
//! The agent ships safe-by-default: `[responder] enabled = false` and
//! `dry_run = true`, so a fresh install detects and alerts but never
//! blocks. That is the correct default, but the readiness audit found it
//! was effectively invisible: the operator installs "a self-defending
//! agent", watches incidents pile up, and never learns that two config
//! flags gate every response path. The posture also lived implicitly in
//! two scattered booleans read at three different call sites, so every
//! surface that wanted to explain it grew its own wording.
//!
//! This type centralises both the logic and the operator-facing copy so
//! the CLI (`innerwarden get status`), the agent boot log, and the
//! installer all say the same thing. `innerwarden_core` is the shared
//! dependency of both the `agent` and `ctl` crates, which is why it
//! lives here rather than in either binary.

/// Whether the agent will execute response actions (block IPs, suspend
/// users, kill processes, redirect to honeypot, ...) on its findings.
///
/// Derived from the two `[responder]` flags; see [`Self::from_responder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementPosture {
    /// `enabled = true`, `dry_run = false`: response skills execute. The
    /// host is actively defended.
    Enforcing,
    /// `enabled = true`, `dry_run = true`: the agent decides and records
    /// what it WOULD do, but executes nothing.
    DryRun,
    /// `enabled = false`: no response path runs at all (the auto-rules,
    /// obvious-threat, and AI-decision gates all close on this flag).
    /// Pure monitoring and alerting.
    Disabled,
}

impl EnforcementPosture {
    /// Resolve the posture from the two `[responder]` flags. `dry_run` is
    /// irrelevant when the responder is disabled, so it collapses to a
    /// single `Disabled` state.
    pub fn from_responder(enabled: bool, dry_run: bool) -> Self {
        match (enabled, dry_run) {
            (false, _) => Self::Disabled,
            (true, true) => Self::DryRun,
            (true, false) => Self::Enforcing,
        }
    }

    /// True only when the agent will actually execute response actions.
    /// Both `DryRun` and `Disabled` return false: neither blocks anything.
    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Enforcing)
    }

    /// Stable machine-ish tag for logs and structured fields.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Enforcing => "enforcing",
            Self::DryRun => "monitor_only_dry_run",
            Self::Disabled => "monitor_only",
        }
    }

    /// One-line operator-facing summary of what the agent will actually do
    /// with what it detects. No em dashes (operator-copy house style).
    pub fn headline(&self) -> &'static str {
        match self {
            Self::Enforcing => "ENFORCING: the agent blocks threats automatically.",
            Self::DryRun => {
                "MONITOR-ONLY (dry-run): the agent decides and logs what it WOULD block, but executes nothing."
            }
            Self::Disabled => {
                "MONITOR-ONLY: the agent watches and alerts, but takes no action on threats."
            }
        }
    }

    /// The single next step to start enforcing, or `None` when the agent
    /// is already enforcing. Kept identical across every surface so the
    /// instruction never drifts.
    pub fn cta(&self) -> Option<&'static str> {
        match self {
            Self::Enforcing => None,
            Self::DryRun => Some(
                "To enforce for real, set `[responder] dry_run = false` in \
                 /etc/innerwarden/agent.toml and restart innerwarden-agent.",
            ),
            Self::Disabled => Some(
                "To enable autonomous response, set `[responder] enabled = true` \
                 (and `dry_run = false`) in /etc/innerwarden/agent.toml and restart \
                 innerwarden-agent.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_responder_maps_every_flag_combination() {
        assert_eq!(
            EnforcementPosture::from_responder(true, false),
            EnforcementPosture::Enforcing
        );
        assert_eq!(
            EnforcementPosture::from_responder(true, true),
            EnforcementPosture::DryRun
        );
        // dry_run is irrelevant when disabled: both collapse to Disabled.
        assert_eq!(
            EnforcementPosture::from_responder(false, false),
            EnforcementPosture::Disabled
        );
        assert_eq!(
            EnforcementPosture::from_responder(false, true),
            EnforcementPosture::Disabled
        );
    }

    #[test]
    fn only_enforcing_is_enforcing() {
        assert!(EnforcementPosture::Enforcing.is_enforcing());
        assert!(!EnforcementPosture::DryRun.is_enforcing());
        assert!(!EnforcementPosture::Disabled.is_enforcing());
    }

    #[test]
    fn enforcing_has_no_cta_others_do() {
        assert!(EnforcementPosture::Enforcing.cta().is_none());
        assert!(EnforcementPosture::DryRun.cta().is_some());
        assert!(EnforcementPosture::Disabled.cta().is_some());
    }

    #[test]
    fn copy_is_nonempty_and_has_no_em_dashes() {
        for p in [
            EnforcementPosture::Enforcing,
            EnforcementPosture::DryRun,
            EnforcementPosture::Disabled,
        ] {
            assert!(!p.headline().is_empty());
            assert!(!p.tag().is_empty());
            assert!(!p.headline().contains('\u{2014}'));
            if let Some(cta) = p.cta() {
                assert!(!cta.contains('\u{2014}'));
            }
        }
    }
}
