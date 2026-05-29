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
