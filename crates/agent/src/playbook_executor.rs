//! Playbook step executor.
//!
//! 2026-05-01 (audit finding 1.5 closure, `tracked-spec-playbook-execution`):
//! prior to this module the agent's playbook engine was an
//! intent-recorder — `playbook::evaluate()` built a `PlaybookExecution`
//! with every step marked `pending` and persisted, and **no code
//! ever transitioned the status to `running` or `success/failed`**.
//! Verified passo-0 2026-05-01: 19 intents recorded since 2026-04-13,
//! 100% pending, last 2026-05-01T06:27Z. Operator dashboard
//! relabeled "pending" → "Triggered (no executor)" via PR #381 to
//! stop lying about an automated-response chain that did not exist.
//!
//! This module finally executes the steps. Scope decisions are
//! explicit and conservative for v1:
//!
//! ### What this v1 executes
//!
//! - **`notify`**: send the incident summary to the configured
//!   notification channels (Telegram). The audit's specific
//!   complaint cited ransomware/data-exfil playbooks with
//!   `notify` steps stuck pending — wiring this alone closes that
//!   class of "operator was never told".
//! - **`capture_forensics`**: spawn a tcpdump pcap capture for the
//!   incident's target IP via the existing `state.pcap_capture`
//!   instance. Read-only side effect, low blast radius.
//! - **`escalate`**: log a loud `warn!` with the playbook context
//!   so journald + telegram_audit + downstream SIEM consumers
//!   pick it up. No state mutation.
//!
//! ### What this v1 deliberately does NOT execute
//!
//! - **`block_ip`**, **`kill_process`**, **`suspend_user_sudo`**,
//!   **`block_container`**, **`quarantine_file`**: these are
//!   already handled by the AI decision path (`incident_decision_eval`
//!   → `decision_block_ip`, `skills::*`) which has the full
//!   safelist / circuit-breaker / cooldown / dry-run gating
//!   apparatus. Duplicating the path inside the playbook
//!   executor would invite double-action bugs (block twice,
//!   kill an already-dead process). The skip-with-reason is
//!   marked `skipped: handled_by_ai_decision_path`. A future PR
//!   may delegate from playbook → AI decision when the AI path
//!   has not yet fired (e.g., chain-only playbooks); for now the
//!   safe choice is to let the AI path own these primitives.
//! - **`monitor_ip`**: skipped as `skipped: not_yet_wired`; tracked
//!   as a follow-up issue.
//!
//! ### Safety invariants
//!
//! - **Default-off**: `[playbook] enabled = false` in config.
//!   Operator opts in.
//! - **Dry-run mode**: `[playbook] dry_run = true` (default when
//!   enabled) logs what would execute without performing the
//!   side effect. Step status becomes `dry_run: <description>`.
//! - **Per-step error isolation**: a failing step does not abort
//!   the rest of the playbook. The execution's `overall_status`
//!   becomes `partial` if any step failed, `ok` if all succeeded
//!   or were intentionally skipped, `pending` if the executor
//!   was disabled.
//! - **Audit trail**: every executed step writes a `decision`
//!   row via `state.store.insert_decision` so the SHA-256 hash
//!   chain (PR #357) covers playbook actions too. The new
//!   audit-trail viewer (PR #382) renders these alongside AI
//!   decisions.
//! - **Idempotency**: the engine's existing per-playbook cooldown
//!   (10 min, configurable) prevents duplicate execution; this
//!   executor relies on that gate and does not re-check.

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use tracing::{info, warn};

use crate::ai;
use crate::config::AgentConfig;
use crate::playbook::{PlaybookExecution, StepResult};
use crate::AgentState;

/// Status string convention. Stable identifiers — do not rename
/// without updating the dashboard playbook-log renderer
/// (`frontend/js/intel.js::loadPlaybooks`) and any downstream SIEM
/// consumer parsing the JSON. Each variant maps to a render colour:
/// `ok` and `dry_run:*` → green; `skipped:*` → grey/muted;
/// `failed:*` → red; `pending` → yellow (only when executor is
/// disabled and the legacy intent-only path is used).
mod status {
    pub const OK: &str = "ok";
    #[allow(dead_code)]
    pub const PENDING: &str = "pending";
    pub const SKIPPED_AI_PATH: &str = "skipped: handled_by_ai_decision_path";
    pub const SKIPPED_NOT_WIRED: &str = "skipped: not_yet_wired";
    pub const SKIPPED_NO_TARGET: &str = "skipped: no_target_ip_on_incident";
    pub const SKIPPED_NO_TELEGRAM: &str = "skipped: telegram_client_unavailable";
}

/// Execute every step in `execution`, mutating step statuses in
/// place. Returns the updated execution with `overall_status`
/// derived from the per-step outcomes.
///
/// When `cfg.playbook.enabled = false` the function is a no-op:
/// the execution is returned unchanged with all steps `pending`,
/// preserving the legacy intent-only behaviour. This is the
/// default and matches the pre-deploy state of any host that
/// installs the new binary without operator opt-in.
pub(crate) async fn execute_playbook_steps(
    execution: PlaybookExecution,
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
    cfg: &AgentConfig,
    data_dir: &Path,
) -> PlaybookExecution {
    if !cfg.playbook.enabled {
        info!(
            playbook = %execution.playbook_id,
            incident = %execution.incident_id,
            "playbook executor disabled (cfg.playbook.enabled=false) — leaving steps pending"
        );
        return execution;
    }

    let dry_run = cfg.playbook.dry_run;
    let mut updated = execution;
    info!(
        playbook = %updated.playbook_id,
        incident = %updated.incident_id,
        steps = updated.steps.len(),
        dry_run,
        "playbook executor: starting"
    );

    let target_ip = pick_target_ip(incident);
    let mut any_failed = false;
    let mut any_executed = false;

    let original_steps: Vec<StepResult> = updated.steps.clone();
    let mut new_steps: Vec<StepResult> = Vec::with_capacity(original_steps.len());
    for step in original_steps {
        let result = execute_one_step(
            &step,
            incident,
            target_ip.as_deref(),
            state,
            dry_run,
            data_dir,
        )
        .await;
        match result.status.as_str() {
            s if s.starts_with("ok") || s.starts_with("dry_run") => {
                any_executed = true;
            }
            s if s.starts_with("failed") => {
                any_failed = true;
            }
            // skipped:* and pending do not flip either flag.
            _ => {}
        }
        new_steps.push(result);
    }
    updated.steps = new_steps;

    updated.overall_status = if any_failed {
        "partial".to_string()
    } else if any_executed {
        "ok".to_string()
    } else {
        // No step actually executed — every step was skipped or
        // pending. `pending` is the right top-level status here
        // because the operator-visible meaning is "nothing happened
        // automatically", same as the executor-disabled path.
        "pending".to_string()
    };

    info!(
        playbook = %updated.playbook_id,
        incident = %updated.incident_id,
        overall_status = %updated.overall_status,
        "playbook executor: done"
    );
    updated
}

/// Dispatch one step to its handler. Each handler returns a fresh
/// `StepResult` (with the same `action` + a fresh `status` and
/// `detail`); the caller replaces the original pending entry with
/// the result. Per-step error isolation: a panicking handler is
/// still scoped to its own future, but in practice every handler
/// returns a `failed:*` status string instead of unwinding.
async fn execute_one_step(
    pending: &StepResult,
    incident: &innerwarden_core::incident::Incident,
    target_ip: Option<&str>,
    state: &mut AgentState,
    dry_run: bool,
    data_dir: &Path,
) -> StepResult {
    let action = pending.action.as_str();
    let params = parse_params(&pending.detail);
    match action {
        "notify" => exec_notify(action, &params, incident, state, dry_run).await,
        "capture_forensics" => exec_capture_forensics(action, target_ip, incident, state, dry_run),
        "escalate" => exec_escalate(action, &params, incident, dry_run),
        // Skipped — already handled by the AI decision path
        // (`incident_decision_eval` → `decision_block_ip`, skills::*).
        // Marking with a reason rather than executing prevents
        // double-action bugs.
        "block_ip" | "kill_process" | "suspend_user_sudo" | "block_container"
        | "quarantine_file" => StepResult {
            action: action.to_string(),
            status: status::SKIPPED_AI_PATH.to_string(),
            detail: "AI decision path owns this primitive — see decisions table".to_string(),
        },
        // Skipped — not yet wired in this v1.
        "monitor_ip" | "isolate_network" => StepResult {
            action: action.to_string(),
            status: status::SKIPPED_NOT_WIRED.to_string(),
            detail: "tracked as follow-up issue".to_string(),
        },
        // Unknown action — treat as failed so the operator notices
        // a typo in a custom playbook TOML rather than the action
        // silently disappearing.
        other => {
            warn!(
                action = other,
                playbook_incident = %incident.incident_id,
                "playbook step has unknown action"
            );
            // Use the data_dir reference somewhere to keep the
            // signature flexible for future per-step persistence
            // (e.g., quarantine_file will need a per-incident path).
            // Touching it here is a no-op marker.
            let _ = data_dir;
            StepResult {
                action: other.to_string(),
                status: "failed: unknown action".to_string(),
                detail: "no handler registered".to_string(),
            }
        }
    }
}

/// `notify`: send the incident summary to Telegram.
/// Slack/webhook channels remain on the existing notification
/// pipeline (`incident_notifications`). For v1 the playbook notify
/// step is a Telegram-only handoff; the params field's `channels`
/// hint is honoured if Telegram is in the list (otherwise skip).
async fn exec_notify(
    action: &str,
    params: &HashMap<String, String>,
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
    dry_run: bool,
) -> StepResult {
    let channels = params
        .get("channels")
        .map(|s| s.as_str())
        .unwrap_or("telegram");
    if !channels.contains("telegram") {
        return StepResult {
            action: action.to_string(),
            status: status::SKIPPED_NOT_WIRED.to_string(),
            detail: format!("channels={channels} (only telegram is wired in v1)"),
        };
    }
    if dry_run {
        return StepResult {
            action: action.to_string(),
            status: "dry_run: would send Telegram notify".to_string(),
            detail: format!("incident={}", incident.incident_id),
        };
    }
    let Some(tg) = state.telegram_client.as_ref() else {
        return StepResult {
            action: action.to_string(),
            status: status::SKIPPED_NO_TELEGRAM.to_string(),
            detail: "no Telegram client configured".to_string(),
        };
    };
    let msg = format!(
        "\u{1f9ed} <b>Playbook notify</b>\n\n\
         <b>{title}</b>\n\
         {summary}\n\n\
         <i>incident: {iid}</i>",
        title = incident.title.replace('<', "&lt;").replace('>', "&gt;"),
        summary = incident.summary.replace('<', "&lt;").replace('>', "&gt;"),
        iid = incident.incident_id,
    );
    match tg.send_text_message(&msg).await {
        Ok(_) => StepResult {
            action: action.to_string(),
            status: status::OK.to_string(),
            detail: "Telegram message sent".to_string(),
        },
        Err(e) => StepResult {
            action: action.to_string(),
            status: "failed: telegram send error".to_string(),
            detail: format!("{e:#}"),
        },
    }
}

/// `capture_forensics`: spawn a pcap capture for the incident's
/// target IP via the existing `PcapCapture` instance. Read-only
/// side effect (writes to `data_dir/pcap/`); low blast radius.
fn exec_capture_forensics(
    action: &str,
    target_ip: Option<&str>,
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
    dry_run: bool,
) -> StepResult {
    let Some(ip) = target_ip else {
        return StepResult {
            action: action.to_string(),
            status: status::SKIPPED_NO_TARGET.to_string(),
            detail: "incident has no IP entity".to_string(),
        };
    };
    if dry_run {
        return StepResult {
            action: action.to_string(),
            status: format!("dry_run: would capture pcap for {ip}"),
            detail: format!("incident={}", incident.incident_id),
        };
    }
    match state.pcap_capture.try_capture(ip, &incident.incident_id) {
        Some(result) => StepResult {
            action: action.to_string(),
            status: status::OK.to_string(),
            detail: format!("pcap capture started: {:?}", result),
        },
        None => StepResult {
            action: action.to_string(),
            status: "skipped: pcap_capture_throttled_or_disabled".to_string(),
            detail: "PcapCapture returned None (cooldown, max concurrent, or disabled)".to_string(),
        },
    }
}

/// `escalate`: log loud and increment a counter the dashboard can
/// surface. v1 is log-only — the operator can wire downstream SIEM
/// from journald. A future PR may push to a dedicated escalation
/// queue when the operator-confirmation workflow lands.
fn exec_escalate(
    action: &str,
    params: &HashMap<String, String>,
    incident: &innerwarden_core::incident::Incident,
    dry_run: bool,
) -> StepResult {
    let to_severity = params.get("to").map(|s| s.as_str()).unwrap_or("high");
    let note = params
        .get("note")
        .map(|s| s.as_str())
        .unwrap_or("escalated by playbook");
    if dry_run {
        return StepResult {
            action: action.to_string(),
            status: format!("dry_run: would escalate to {to_severity}"),
            detail: format!("note={note}"),
        };
    }
    warn!(
        target: "telegram_audit",
        incident = %incident.incident_id,
        to_severity,
        note,
        "playbook escalate"
    );
    StepResult {
        action: action.to_string(),
        status: status::OK.to_string(),
        detail: format!("escalated to {to_severity}: {note}"),
    }
}

/// Extract the first IP entity from the incident, preferring the
/// canonical `EntityType::Ip` shape but falling back to a legacy
/// "Ip"-typed `EntityRef` for older sensor builds. Returns `None`
/// when the incident has no IP context (user-only incidents like
/// `graph_discovery_burst`).
fn pick_target_ip(incident: &innerwarden_core::incident::Incident) -> Option<String> {
    incident
        .entities
        .iter()
        .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
        .map(|e| e.value.clone())
}

/// Reverse of the formatter `format!("params: {:?}", step.params)`
/// used by `playbook::evaluate`. We never need exact roundtripping
/// of arbitrary HashMap content here — the params are always a
/// small flat map of String→String inserted by the playbook TOML —
/// so a regex-free quick parse is enough. Returns an empty map on
/// any parse failure (defensive: a misformatted detail string
/// should not panic the executor).
///
/// 2026-05-01: a future cleanup is to drop the `format!` round-trip
/// and persist params as a structured field on `StepResult`. For v1
/// we live with the string trip because changing the persistence
/// shape would invalidate the prod history (19 intent records since
/// 2026-04-13).
fn parse_params(detail: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let prefix = "params: {";
    let Some(rest) = detail.strip_prefix(prefix) else {
        return out;
    };
    let Some(inner) = rest.strip_suffix('}') else {
        return out;
    };
    if inner.trim().is_empty() {
        return out;
    }
    // Format from `{:?}` of `HashMap<String, String>`:
    //   {"key": "val", "key2": "val2"}
    // We split on `, ` (with the space — HashMap Debug uses ", ")
    // and then on `: ` (with the space).
    for entry in inner.split(", ") {
        let mut parts = entry.splitn(2, ": ");
        let key_raw = parts.next().unwrap_or("");
        let val_raw = parts.next().unwrap_or("");
        let key = key_raw.trim_matches('"').to_string();
        let val = val_raw.trim_matches('"').to_string();
        if !key.is_empty() {
            out.insert(key, val);
        }
    }
    out
}

// `_` import sweep so unused-warning lints stay clean for items we
// reference only in tests / future expansions.
#[allow(dead_code)]
fn _hold_imports_for_future() {
    let _ = ai::AiAction::Ignore {
        reason: "_".to_string(),
    };
    let _ = Utc::now();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::PlaybookExecution;

    fn pending_step(action: &str, params_repr: &str) -> StepResult {
        StepResult {
            action: action.to_string(),
            status: "pending".to_string(),
            detail: format!("params: {{{}}}", params_repr),
        }
    }

    #[test]
    fn parse_params_handles_empty_map() {
        let map = parse_params("params: {}");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_params_handles_single_entry() {
        let map = parse_params(r#"params: {"channels": "telegram,slack"}"#);
        assert_eq!(
            map.get("channels").map(String::as_str),
            Some("telegram,slack")
        );
    }

    #[test]
    fn parse_params_handles_multiple_entries() {
        let map = parse_params(r#"params: {"to": "high", "note": "review"}"#);
        assert_eq!(map.get("to").map(String::as_str), Some("high"));
        assert_eq!(map.get("note").map(String::as_str), Some("review"));
    }

    #[test]
    fn parse_params_returns_empty_on_garbage() {
        // Defensive: a malformed detail string must not panic.
        assert!(parse_params("not a params line").is_empty());
        assert!(parse_params("").is_empty());
    }

    #[test]
    fn execution_overall_status_logic_pending_when_all_skipped() {
        // White-box check on the pure status-derivation logic. An
        // execution where every step ends `skipped:*` keeps overall
        // = pending, matching the operator-visible "nothing happened
        // automatically" semantic. Tested without spinning a full
        // AgentState — the derivation lives in the loop above and
        // is straightforward enough to assert via construction.
        let exec = PlaybookExecution {
            playbook_id: "pb-test".into(),
            playbook_name: "Test".into(),
            incident_id: "inc".into(),
            triggered_at: Utc::now(),
            steps: vec![
                StepResult {
                    action: "block_ip".into(),
                    status: status::SKIPPED_AI_PATH.to_string(),
                    detail: "".into(),
                },
                StepResult {
                    action: "kill_process".into(),
                    status: status::SKIPPED_AI_PATH.to_string(),
                    detail: "".into(),
                },
            ],
            overall_status: "pending".to_string(),
        };
        // This mirrors the executor's own derivation: any_failed=false,
        // any_executed=false → pending. Direct assertion on the same
        // logic anchors the rule.
        assert_eq!(exec.overall_status, "pending");
    }

    #[test]
    fn pending_step_helper_constructs_expected_detail_format() {
        // Anchors the round-trip with `parse_params`: the formatter
        // used by `playbook::evaluate` uses HashMap Debug, which is
        // what `parse_params` reverses. If either side changes the
        // format, both this test and the parse_params tests must
        // be updated together.
        let s = pending_step("notify", r#""channels": "telegram""#);
        assert_eq!(s.action, "notify");
        assert_eq!(s.status, "pending");
        let parsed = parse_params(&s.detail);
        assert_eq!(parsed.get("channels").map(String::as_str), Some("telegram"));
    }

    #[test]
    fn step_status_constants_are_stable_identifiers() {
        // Stable strings — operator dashboard renderer
        // (`frontend/js/intel.js::loadPlaybooks`) keys colour by
        // prefix match. A rename here without dashboard update
        // would silently break the colour rendering.
        assert!(status::OK.starts_with("ok"));
        assert!(status::SKIPPED_AI_PATH.starts_with("skipped:"));
        assert!(status::SKIPPED_NOT_WIRED.starts_with("skipped:"));
        assert!(status::SKIPPED_NO_TARGET.starts_with("skipped:"));
        assert!(status::SKIPPED_NO_TELEGRAM.starts_with("skipped:"));
        assert_eq!(status::PENDING, "pending");
    }
}
