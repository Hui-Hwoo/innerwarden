//! Spec 056 Phase 5a: the `GET /api/playbooks` dashboard endpoint.
//!
//! Surfaces SOC-playbook activity by reading the per-step audit trail the
//! executor writes (`playbook_steps-<date>.jsonl`, spec 056 Phase 2): one
//! line per executed step with `ts / incident_id / playbook_id / step_id /
//! skill / status / attempts / dry_run`. We aggregate per playbook id
//! (firing counts, status breakdown, success rate, last-fired) and return
//! the most recent step records as an activity feed.
//!
//! Note: per-step latency is NOT recorded in the step log today, so this
//! endpoint does not report it. Adding it would be a Phase-2 schema change
//! (a `latency_ms` field on `PlaybookStepLine`); deferred.

use super::*;
use chrono::{DateTime, Utc};

/// One parsed line of `playbook_steps-<date>.jsonl`. Owned + `#[serde(default)]`
/// so a partially-written or older line never fails the whole read.
#[derive(serde::Deserialize)]
struct StepRecord {
    #[serde(default)]
    ts: Option<DateTime<Utc>>,
    #[serde(default)]
    incident_id: String,
    #[serde(default)]
    playbook_id: String,
    #[serde(default)]
    step_id: String,
    #[serde(default)]
    skill: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Default)]
struct Agg {
    total: u64,
    success: u64,
    failed: u64,
    refused: u64,
    skipped: u64,
    deferred: u64,
    queued: u64,
    last_fired: Option<DateTime<Utc>>,
}

/// Read every `playbook_steps-*.jsonl` under `data_dir` and parse each
/// line. Returns records oldest-to-newest by file name (date) then file
/// order. Best-effort: unreadable files / unparseable lines are skipped.
fn read_step_records(data_dir: &std::path::Path) -> Vec<StepRecord> {
    let mut files: Vec<std::path::PathBuf> = match std::fs::read_dir(data_dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("playbook_steps-") && n.ends_with(".jsonl"))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();

    let mut records = Vec::new();
    for path in files {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<StepRecord>(line) {
                records.push(rec);
            }
        }
    }
    records
}

/// Build the `/api/playbooks` JSON payload from parsed step records.
/// Pure (no I/O) so the shape is unit-testable without a data dir.
fn build_playbooks_payload(records: &[StepRecord]) -> serde_json::Value {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<&str, Agg> = BTreeMap::new();

    for r in records {
        let agg = by_id.entry(r.playbook_id.as_str()).or_default();
        agg.total += 1;
        match r.status.as_str() {
            "success" => agg.success += 1,
            "failed" => agg.failed += 1,
            "refused" => agg.refused += 1,
            "skipped" => agg.skipped += 1,
            "deferred" => agg.deferred += 1,
            "queued" => agg.queued += 1,
            _ => {}
        }
        if let Some(ts) = r.ts {
            agg.last_fired = Some(agg.last_fired.map_or(ts, |cur| cur.max(ts)));
        }
    }

    let playbooks: Vec<serde_json::Value> = by_id
        .iter()
        .map(|(id, a)| {
            // Success rate over steps that actually ran (success + failed);
            // queued / skipped / deferred / refused are not "attempts".
            let attempted = a.success + a.failed;
            let success_rate = if attempted > 0 {
                a.success as f64 / attempted as f64
            } else {
                0.0
            };
            serde_json::json!({
                "playbook_id": id,
                "total_steps": a.total,
                "success": a.success,
                "failed": a.failed,
                "refused": a.refused,
                "skipped": a.skipped,
                "deferred": a.deferred,
                "queued": a.queued,
                "success_rate": success_rate,
                "last_fired": a.last_fired,
            })
        })
        .collect();

    // Activity feed: last 100 step records, newest first.
    let mut recent: Vec<&StepRecord> = records.iter().collect();
    recent.sort_by(|a, b| b.ts.cmp(&a.ts));
    let recent_json: Vec<serde_json::Value> = recent
        .into_iter()
        .take(100)
        .map(|r| {
            serde_json::json!({
                "ts": r.ts,
                "incident_id": r.incident_id,
                "playbook_id": r.playbook_id,
                "step_id": r.step_id,
                "skill": r.skill,
                "status": r.status,
                "attempts": r.attempts,
                "dry_run": r.dry_run,
            })
        })
        .collect();

    serde_json::json!({
        "playbooks": playbooks,
        "recent": recent_json,
        "total_steps": records.len(),
        // Honesty: the step log does not record per-step latency yet.
        "latency_recorded": false,
    })
}

/// `GET /api/playbooks` - SOC playbook firing stats + recent step activity.
pub(super) async fn api_playbooks(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let records = read_step_records(&state.data_dir);
    Json(build_playbooks_payload(&records))
}

// ---------------------------------------------------------------------------
// POST /api/playbook/test - dry-run simulate (spec 056 Phase 5b)
// ---------------------------------------------------------------------------

use crate::playbook_engine::{self, executor};

#[derive(serde::Deserialize)]
pub(super) struct PlaybookTestRequest {
    playbook_id: String,
    incident: innerwarden_core::incident::Incident,
}

/// No-op audit: a simulate must NOT write to `decisions.jsonl` /
/// `playbook_steps-*.jsonl`, so the executor's audit calls go nowhere.
struct NoopAudit;
impl executor::PlaybookAudit for NoopAudit {
    fn record(&self, _rec: executor::PlaybookStepRecord<'_>) {}
}

/// `POST /api/playbook/test` - run one playbook against a captured
/// incident in dry-run, WITHOUT firing skills or writing audit. Reuses
/// the exact executor + matcher the live incident loop uses (zero drift),
/// so the CLI (`innerwarden playbook test`), the dashboard, and the future
/// Active Defense LLM all simulate through one path.
pub(super) async fn api_playbook_test(
    State(state): State<DashboardState>,
    Json(req): Json<PlaybookTestRequest>,
) -> Json<serde_json::Value> {
    let sim = &state.playbook_sim;

    // Same loading the live path uses: built-ins + operator dir, operator
    // overrides by id. Empty/absent rules_dir -> built-ins only.
    let playbooks = match playbook_engine::load_dir(&sim.rules_dir) {
        Ok(p) => p,
        Err(e) => {
            return Json(serde_json::json!({
                "error": "failed to load playbooks",
                "detail": e.to_string(),
            }));
        }
    };

    let Some(pb) = playbooks
        .iter()
        .find(|p| p.metadata.id.as_str() == req.playbook_id)
    else {
        return Json(serde_json::json!({
            "error": "unknown playbook",
            "playbook_id": req.playbook_id,
            "available": playbooks
                .iter()
                .map(|p| p.metadata.id.as_str())
                .collect::<Vec<_>>(),
        }));
    };

    let tctx = executor::TriggerCtx::from_incident(&req.incident);
    let matched =
        executor::matches_incident(pb, &req.incident, &tctx, &sim.trusted_ips, &sim.asset_tags);
    if !matched {
        return Json(serde_json::json!({
            "playbook_id": req.playbook_id,
            "matched": false,
        }));
    }

    // dry_run = true: block-ip skills report success without touching the
    // firewall; Phase-3b virtual skills enqueue commands we surface but
    // never drain. ai_provider None: a simulate needs no LLM.
    let registry = crate::skills::SkillRegistry::default_builtin();
    let exec = executor::RegistryStepExecutor {
        registry: &registry,
        trusted_ips: &sim.trusted_ips,
        dry_run: true,
        host: req.incident.host.clone(),
        data_dir: state.data_dir.clone(),
        base_incident: req.incident.clone(),
        honeypot: crate::skills::HoneypotRuntimeConfig::default(),
        ai_provider: None,
        command_sink: std::sync::Mutex::new(Vec::new()),
    };
    let audit = NoopAudit;
    let mut outcome = executor::execute(pb, &req.incident, &exec, &audit).await;
    outcome.commands = exec.drain_commands();

    Json(serde_json::json!({
        "playbook_id": req.playbook_id,
        "matched": true,
        "dry_run": true,
        "summary": outcome.summary(),
        "outcome": serde_json::to_value(&outcome).unwrap_or_default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pb: &str, status: &str) -> StepRecord {
        StepRecord {
            ts: Some(Utc::now()),
            incident_id: "inc".into(),
            playbook_id: pb.into(),
            step_id: "s".into(),
            skill: "block_ip_xdp".into(),
            status: status.into(),
            attempts: 1,
            dry_run: true,
        }
    }

    #[test]
    fn payload_empty_when_no_records() {
        let v = build_playbooks_payload(&[]);
        assert_eq!(v["total_steps"], 0);
        assert_eq!(v["playbooks"].as_array().unwrap().len(), 0);
        assert_eq!(v["recent"].as_array().unwrap().len(), 0);
        assert_eq!(v["latency_recorded"], false);
    }

    #[test]
    fn payload_aggregates_per_playbook_and_success_rate() {
        let records = vec![
            rec("pb-a", "success"),
            rec("pb-a", "success"),
            rec("pb-a", "failed"),
            rec("pb-a", "queued"),
            rec("pb-b", "refused"),
        ];
        let v = build_playbooks_payload(&records);
        assert_eq!(v["total_steps"], 5);
        let pbs = v["playbooks"].as_array().unwrap();
        assert_eq!(pbs.len(), 2);
        let a = pbs.iter().find(|p| p["playbook_id"] == "pb-a").unwrap();
        assert_eq!(a["total_steps"], 4);
        assert_eq!(a["success"], 2);
        assert_eq!(a["failed"], 1);
        assert_eq!(a["queued"], 1);
        // success_rate over attempted (success+failed) = 2/3.
        assert!((a["success_rate"].as_f64().unwrap() - 2.0 / 3.0).abs() < 1e-9);
        let b = pbs.iter().find(|p| p["playbook_id"] == "pb-b").unwrap();
        // No attempted steps -> success_rate 0.0, not NaN.
        assert_eq!(b["success_rate"], 0.0);
        assert_eq!(b["refused"], 1);
    }

    #[test]
    fn recent_feed_capped_at_100_newest_first() {
        let records: Vec<StepRecord> = (0..150).map(|_| rec("pb", "success")).collect();
        let v = build_playbooks_payload(&records);
        assert_eq!(v["recent"].as_array().unwrap().len(), 100);
        assert_eq!(v["total_steps"], 150);
    }

    // ---- POST /api/playbook/test (simulate) ----------------------------

    fn sim_state(dir: &std::path::Path) -> DashboardState {
        crate::dashboard::state::test_dashboard_state(dir)
    }

    #[tokio::test]
    async fn simulate_unknown_playbook_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let state = sim_state(dir.path());
        let req = PlaybookTestRequest {
            playbook_id: "pb-does-not-exist".to_string(),
            incident: crate::tests::test_incident("198.51.100.42"),
        };
        let Json(v) = api_playbook_test(State(state), Json(req)).await;
        assert_eq!(v["error"], "unknown playbook");
        assert!(v["available"].as_array().is_some());
    }

    #[tokio::test]
    async fn simulate_matched_credential_builtin_runs_dry() {
        let dir = tempfile::tempdir().unwrap();
        let state = sim_state(dir.path());
        // ssh_bruteforce rule_id + clean IP arms the credential built-in.
        let req = PlaybookTestRequest {
            playbook_id: "pb-credential-stuffing-default".to_string(),
            incident: crate::tests::test_incident("198.51.100.42"),
        };
        let Json(v) = api_playbook_test(State(state), Json(req)).await;
        assert_eq!(v["matched"], true, "got: {v}");
        assert_eq!(v["dry_run"], true);
        assert!(v["summary"].as_str().unwrap().contains("playbook"));
        assert!(v["outcome"]["steps"].as_array().is_some());
        // A simulate must NOT write audit logs.
        let wrote_logs = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("playbook_steps-") || n.starts_with("decisions-")
            });
        assert!(!wrote_logs, "simulate must not write audit logs");
    }

    #[tokio::test]
    async fn simulate_not_matched_reports_false() {
        let dir = tempfile::tempdir().unwrap();
        let state = sim_state(dir.path());
        // data-exfil built-in triggers on CL-002 + needs env=prod asset
        // tag; a plain ssh_bruteforce incident matches neither.
        let req = PlaybookTestRequest {
            playbook_id: "pb-data-exfil-default".to_string(),
            incident: crate::tests::test_incident("198.51.100.42"),
        };
        let Json(v) = api_playbook_test(State(state), Json(req)).await;
        assert_eq!(v["matched"], false, "got: {v}");
    }

    #[test]
    fn read_step_records_skips_bad_lines_and_missing_dir() {
        // Missing dir -> empty, no panic.
        assert!(read_step_records(std::path::Path::new("/no/such/dir/xyz")).is_empty());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbook_steps-2026-05-29.jsonl");
        std::fs::write(
            &path,
            "{\"playbook_id\":\"pb\",\"status\":\"success\",\"attempts\":1}\n\
             not-json\n\
             \n\
             {\"playbook_id\":\"pb\",\"status\":\"queued\"}\n",
        )
        .unwrap();
        // A non-playbook file in the same dir must be ignored.
        std::fs::write(dir.path().join("decisions-2026-05-29.jsonl"), "{}\n").unwrap();

        let records = read_step_records(dir.path());
        assert_eq!(records.len(), 2, "2 valid lines, bad/blank skipped");
        let v = build_playbooks_payload(&records);
        assert_eq!(v["total_steps"], 2);
    }
}
