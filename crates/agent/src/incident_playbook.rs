use std::path::Path;

use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::AgentState;

/// Evaluate playbooks for an incident, execute the steps when the
/// executor is enabled, and persist the (possibly updated) execution
/// record to JSON log + SQLite blob.
///
/// 2026-05-01 (`tracked-spec-playbook-execution`): the persistence
/// shape is unchanged from the legacy intent-only path, so the
/// on-disk format is backward compatible. The only difference is
/// that step `status` now transitions away from `"pending"` when
/// `cfg.playbook.enabled = true`. With the default
/// `enabled = false`, behaviour is identical to the pre-spec
/// version (operator opts in via agent.toml).
pub(crate) async fn maybe_evaluate_and_persist_playbook(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &AgentConfig,
    state: &mut AgentState,
) {
    // Playbook evaluation: check if this incident triggers a playbook.
    let Some(intent) = state.playbook_engine.evaluate(incident) else {
        return;
    };
    info!(
        playbook = %intent.playbook_id,
        incident = %intent.incident_id,
        steps = intent.steps.len(),
        "playbook triggered: {}",
        intent.playbook_name
    );

    // Execute the steps if the operator opted in. With the default
    // (cfg.playbook.enabled = false) the executor is a no-op and
    // the intent is persisted as-is — preserving the legacy
    // pre-2026-05-01 shape.
    let exec =
        crate::playbook_executor::execute_playbook_steps(intent, incident, state, cfg, data_dir)
            .await;

    // Persist the (possibly executed) playbook record to JSON log
    // via the shared atomic-rename helper. Pre-2026-04-23 each call
    // site had its own RMW loop; a crash mid-write left dashboard
    // readers with half-written JSON. `append_with_cap` uses
    // temp-file + rename so observers see either old or new
    // content, never a partial file. Dual-write to SQLite blob
    // preserved for back-compat.
    let log_path = data_dir.join("playbook-log.json");
    if let Err(e) = crate::capped_log::append_with_cap(&log_path, &exec, 100) {
        warn!("failed to append playbook-log: {e}");
    }
    if let Some(ref sq) = state.sqlite_store {
        // Re-read the file we just wrote so the SQLite blob always
        // mirrors the on-disk JSON exactly. Cheaper than re-doing
        // the read+merge in two places.
        if let Ok(content) = std::fs::read_to_string(&log_path) {
            if let Err(e) = sq.set_blob("playbook_log", &content) {
                warn!("failed to write playbook_log blob: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_playbook_rule(
        rules_dir: &std::path::Path,
        playbook_id: &str,
        detector: &str,
        min_severity: &str,
    ) {
        let playbooks_dir = rules_dir.join("playbooks");
        std::fs::create_dir_all(&playbooks_dir).expect("playbooks dir");
        let content = format!(
            r#"[playbook.{playbook_id}]
name = "Unit Test Playbook"
trigger = {{ detector = "{detector}", min_severity = "{min_severity}" }}
steps = [{{ action = "notify" }}]
"#
        );
        std::fs::write(playbooks_dir.join("unit.toml"), content).expect("write rule");
    }

    /// Default config used by the persistence-only tests. The
    /// executor is disabled (matching production default) so the
    /// behaviour is identical to the pre-spec intent-only path:
    /// step `status` stays `"pending"`, `overall_status` stays
    /// `"pending"`, persistence still happens.
    fn default_test_config() -> crate::config::AgentConfig {
        crate::config::AgentConfig::default()
    }

    #[tokio::test]
    async fn maybe_evaluate_and_persist_playbook_persists_log_and_sqlite_blob_on_match() {
        // Invariant: matching playbooks must be persisted to both JSON log and SQLite blob.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-enabled");
        write_playbook_rule(&rules_dir, "pb-unit", "ssh_bruteforce", "high");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());
        let incident = crate::tests::test_incident("203.0.113.51");
        let cfg = default_test_config();

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &cfg, &mut state).await;

        let log_path = dir.path().join("playbook-log.json");
        let raw = std::fs::read_to_string(&log_path).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["playbook_id"], "pb-unit");

        let blob = store
            .get_blob("playbook_log")
            .expect("blob read")
            .expect("blob value");
        assert!(blob.contains("\"playbook_id\":\"pb-unit\""));
    }

    #[tokio::test]
    async fn maybe_evaluate_and_persist_playbook_skips_when_no_playbook_matches() {
        // Invariant: when playbook evaluation returns `None`, no persistence side effects should occur.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-disabled");
        write_playbook_rule(&rules_dir, "pb-never", "never_match", "critical");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.52");
        let cfg = default_test_config();

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &cfg, &mut state).await;

        assert!(!dir.path().join("playbook-log.json").exists());
    }

    #[tokio::test]
    async fn maybe_evaluate_and_persist_playbook_recovers_from_corrupted_existing_log() {
        // Invariant: malformed on-disk playbook log must be treated as empty and replaced with valid JSON.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-recovery");
        write_playbook_rule(&rules_dir, "pb-recover", "ssh_bruteforce", "high");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.53");
        let log_path = dir.path().join("playbook-log.json");
        std::fs::write(&log_path, "{not-valid-json").expect("seed corrupted log");
        let cfg = default_test_config();

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &cfg, &mut state).await;

        let raw = std::fs::read_to_string(&log_path).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["playbook_id"], "pb-recover");
    }

    #[tokio::test]
    async fn executor_disabled_leaves_steps_pending_legacy_shape() {
        // Anchors the back-compat invariant: with cfg.playbook.enabled=false
        // (production default), behaviour is identical to the pre-spec
        // intent-only persistence — step.status stays "pending" and
        // overall_status stays "pending". An operator who installs the
        // new binary without opting in sees no observable change.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-disabled-exec");
        write_playbook_rule(&rules_dir, "pb-disabled", "ssh_bruteforce", "high");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.54");
        let mut cfg = default_test_config();
        cfg.playbook.enabled = false;

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &cfg, &mut state).await;

        let raw =
            std::fs::read_to_string(dir.path().join("playbook-log.json")).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        assert_eq!(entries[0]["overall_status"], "pending");
        let steps = entries[0]["steps"].as_array().unwrap();
        assert!(
            steps.iter().all(|s| s["status"] == "pending"),
            "every step must remain pending when executor disabled"
        );
    }

    #[tokio::test]
    async fn executor_dry_run_marks_steps_as_dry_run() {
        // Anchor: with enabled=true + dry_run=true (the default
        // when an operator first opts in), every executable step
        // type ends up with status = "dry_run: ..." and
        // overall_status = "ok". No real side effect runs.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-dry-run");
        // Custom playbook with notify+escalate+capture_forensics so
        // every executable step type is exercised in one run.
        std::fs::create_dir_all(rules_dir.join("playbooks")).expect("dir");
        std::fs::write(
            rules_dir.join("playbooks/v1.toml"),
            r#"[playbook.pb-dry]
name = "Dry-Run Coverage"
trigger = { detector = "ssh_bruteforce", min_severity = "high" }
steps = [
  { action = "notify", params = { channels = "telegram" } },
  { action = "capture_forensics" },
  { action = "escalate", params = { to = "high", note = "test" } },
]
"#,
        )
        .expect("write rule");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.55");
        let mut cfg = default_test_config();
        cfg.playbook.enabled = true;
        cfg.playbook.dry_run = true;

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &cfg, &mut state).await;

        let raw =
            std::fs::read_to_string(dir.path().join("playbook-log.json")).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        let steps = entries[0]["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 3);
        for s in steps {
            let st = s["status"].as_str().unwrap_or("");
            assert!(
                st.starts_with("dry_run") || st.starts_with("skipped"),
                "step {} must be dry_run or skipped in dry-run mode, got '{}'",
                s["action"],
                st
            );
        }
        assert_eq!(entries[0]["overall_status"], "ok");
    }

    #[tokio::test]
    async fn executor_skips_dangerous_actions_with_explicit_reason() {
        // Anchors the v1 scope rule: block_ip / kill_process / etc.
        // are NOT executed by the playbook executor — the AI decision
        // path owns those primitives. The skip reason is stable and
        // operator-readable, not a silent no-op.
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_dir = dir.path().join("rules-dangerous");
        std::fs::create_dir_all(rules_dir.join("playbooks")).expect("dir");
        std::fs::write(
            rules_dir.join("playbooks/v1.toml"),
            r#"[playbook.pb-dangerous]
name = "Dangerous Actions Coverage"
trigger = { detector = "ssh_bruteforce", min_severity = "high" }
steps = [
  { action = "block_ip" },
  { action = "kill_process" },
  { action = "suspend_user_sudo" },
  { action = "block_container" },
  { action = "quarantine_file" },
]
"#,
        )
        .expect("write rule");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.playbook_engine = crate::playbook::PlaybookEngine::new(&rules_dir);
        let incident = crate::tests::test_incident("203.0.113.56");
        let mut cfg = default_test_config();
        cfg.playbook.enabled = true;
        cfg.playbook.dry_run = false; // even when "live", these stay skipped

        maybe_evaluate_and_persist_playbook(&incident, dir.path(), &cfg, &mut state).await;

        let raw =
            std::fs::read_to_string(dir.path().join("playbook-log.json")).expect("playbook log");
        let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("valid json log");
        let steps = entries[0]["steps"].as_array().unwrap();
        for s in steps {
            let st = s["status"].as_str().unwrap_or("");
            assert!(
                st.starts_with("skipped: handled_by_ai_decision_path"),
                "dangerous action {} must be skipped with AI-path reason, got '{}'",
                s["action"],
                st
            );
        }
        // No step was actually executed → overall stays "pending".
        assert_eq!(entries[0]["overall_status"], "pending");
    }
}
