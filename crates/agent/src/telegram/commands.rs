//! Allowlist + false-positive bot-command helpers extracted from
//! `telegram/client.rs`.
//!
//! These functions do filesystem I/O (append to `allowlist.toml`, write to
//! `allowlist-history.jsonl`, write to `false-positive-history.jsonl`) and
//! are triggered by `/add`, `/rm`, and `/fp` bot commands on the
//! operator's Telegram chat. They don't touch the TelegramClient's HTTP
//! layer at all — keeping them here makes client.rs exclusively about
//! speaking to the Telegram API.

use tracing::warn;

pub fn append_to_allowlist(
    allowlist_path: &std::path::Path,
    section: &str,
    key: &str,
    reason: &str,
) -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use fs2::FileExt;
    use std::io::{Read, Seek, Write};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(allowlist_path)
        .with_context(|| format!("open allowlist {}", allowlist_path.display()))?;
    file.lock_exclusive()?;

    let update_result = (|| -> anyhow::Result<()> {
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("read allowlist {}", allowlist_path.display()))?;

        let mut root = if content.trim().is_empty() {
            toml::Table::new()
        } else {
            content
                .parse::<toml::Table>()
                .with_context(|| format!("parse allowlist {}", allowlist_path.display()))?
        };

        let section_value = root
            .entry(section.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let section_table = section_value
            .as_table_mut()
            .ok_or_else(|| anyhow!("allowlist section {section:?} is not a TOML table"))?;

        section_table.insert(
            key.replace('\n', " "),
            toml::Value::String(reason.replace('\n', " ")),
        );

        let output = toml::to_string_pretty(&root)
            .with_context(|| format!("serialize allowlist {}", allowlist_path.display()))?;
        file.seek(std::io::SeekFrom::Start(0))
            .with_context(|| format!("rewind allowlist {}", allowlist_path.display()))?;
        file.set_len(0)
            .with_context(|| format!("truncate allowlist {}", allowlist_path.display()))?;
        file.write_all(output.as_bytes())
            .with_context(|| format!("write allowlist {}", allowlist_path.display()))?;
        file.flush()
            .with_context(|| format!("flush allowlist {}", allowlist_path.display()))?;
        Ok(())
    })();

    let unlock_result = file.unlock();
    update_result?;
    unlock_result?;
    Ok(())
}

/// Append the allowlist-change entry to `allowlist-history.jsonl`,
/// surfacing both failure modes (file open + line write) via `warn!`
/// with structured context. Replaces the prior nested
/// `if let Ok(mut f) = OpenOptions::new()...open(..)` + silent
/// `let _ = writeln!(...)` cascade (Spec 037 I-13 follow-up #2).
///
/// Failure here means the operator's undo/rollback history loses one
/// entry. The dashboard's "revert allowlist change" affordance reads
/// this file, so a silent drop means the operator cannot recover from
/// an accidental allowlist mutation. Carrying key/section/operator/action
/// in the warn lets the operator reconstruct what was lost.
fn append_allowlist_history_or_warn(
    path: &std::path::Path,
    entry: &serde_json::Value,
    key: &str,
    section: &str,
    operator: &str,
    action: &str,
) {
    use std::io::Write;
    let mut f = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            warn!(
                path = %path.display(),
                key,
                section,
                operator,
                action,
                error = %e,
                "allowlist history file open failed (undo/rollback entry lost)"
            );
            return;
        }
    };
    if let Err(e) = writeln!(f, "{}", entry) {
        warn!(
            path = %path.display(),
            key,
            section,
            operator,
            action,
            error = %e,
            "allowlist history write failed (undo/rollback entry lost)"
        );
    }
}

/// Log an allowlist change (add or remove) to allowlist-history.jsonl.
pub fn log_allowlist_change(
    data_dir: &std::path::Path,
    key: &str,
    section: &str,
    operator: &str,
    action: &str,
) {
    let path = data_dir.join("allowlist-history.jsonl");
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "key": key,
        "section": section,
        "operator": operator,
        "action": action,
    });
    append_allowlist_history_or_warn(&path, &entry, key, section, operator, action);
}

/// Read allowlist history and return last N "add" entries without matching "remove".
pub fn read_undoable_allowlist_entries(
    data_dir: &std::path::Path,
    max_entries: usize,
) -> Vec<(String, String, String, String)> {
    // Returns Vec<(key, section, operator, ts)>
    let path = data_dir.join("allowlist-history.jsonl");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut adds: Vec<(String, String, String, String)> = Vec::new();
    let mut removed_keys: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    // Parse all entries
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let key = v
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let section = v
                .get("section")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let operator = v
                .get("operator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ts = v
                .get("ts")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let action = v
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if action == "add" {
                adds.push((key, section, operator, ts));
            } else if action == "remove" {
                removed_keys.insert((key, section));
            }
        }
    }

    // Filter out entries that have been removed, take last N
    adds.into_iter()
        .rev()
        .filter(|(key, section, _, _)| !removed_keys.contains(&(key.clone(), section.clone())))
        .take(max_entries)
        .collect()
}

/// Remove a key from allowlist.toml atomically.
/// Reads the file, removes lines containing the key in the appropriate section,
/// writes to a temp file, and renames over the original.
pub fn remove_from_allowlist(
    allowlist_path: &std::path::Path,
    section: &str,
    key: &str,
) -> anyhow::Result<()> {
    use fs2::FileExt;

    let content = std::fs::read_to_string(allowlist_path).unwrap_or_default();

    let mut result_lines: Vec<String> = Vec::new();
    let mut in_target_section = false;
    let normalized_key = key.replace('\n', " ");
    let escaped_key = normalized_key.replace('\\', "\\\\").replace('"', "\\\"");
    let quoted_key = format!("\"{escaped_key}\"");
    let legacy_quoted_key = format!("\"{normalized_key}\"");

    for line in content.lines() {
        let trimmed = line.trim();
        // Track section headers
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = &trimmed[1..trimmed.len() - 1];
            in_target_section = sec == section;
            result_lines.push(line.to_string());
            continue;
        }

        let key_matches = trimmed
            .split_once('=')
            .map(|(lhs, _)| {
                let lhs = lhs.trim();
                lhs == normalized_key || lhs == quoted_key || lhs == legacy_quoted_key
            })
            .unwrap_or(false);

        // If in the target section, skip the assignment for the requested key.
        if in_target_section && key_matches {
            continue;
        }

        result_lines.push(line.to_string());
    }

    // Remove trailing empty lines and consecutive empty section headers
    let output = result_lines.join("\n");

    // Write atomically: temp file + rename
    let temp_path = allowlist_path.with_extension("toml.tmp");
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;
        file.lock_exclusive()?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(&file);
        writer.write_all(output.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        file.unlock()?;
    }
    std::fs::rename(&temp_path, allowlist_path)?;

    Ok(())
}

/// Log an incident as a false positive to a daily JSONL file.
///
/// Used for training data collection and FP-rate tracking.  The file
/// is created if missing and each entry is one JSON line.
/// Append the false-positive report entry to `fp-reports-{date}.jsonl`,
/// surfacing both failure modes (file open + line write) via `warn!`
/// with structured context. Replaces the prior nested
/// `if let Ok(mut f) = OpenOptions::new()...open(..)` + silent
/// `let _ = writeln!(...)` cascade (Spec 037 I-13 follow-up #2,
/// sibling of `append_allowlist_history_or_warn` shipped in PR #319).
///
/// Failure here means an operator-marked false positive disappears.
/// Detection-tuning workflows read these JSONL files to retrain the
/// classifier and to diff which detectors are creating noise; a silent
/// drop means the feedback loop swallows the operator's annotation.
/// Carrying incident_id/detector/reporter in the warn lets the operator
/// reconstruct what was lost.
fn append_fp_report_or_warn(
    path: &std::path::Path,
    entry: &serde_json::Value,
    incident_id: &str,
    detector: &str,
    reporter: &str,
) {
    use std::io::Write;
    let mut f = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            warn!(
                path = %path.display(),
                incident_id,
                detector,
                reporter,
                error = %e,
                "false-positive report file open failed (FP entry lost)"
            );
            return;
        }
    };
    if let Err(e) = writeln!(f, "{}", entry) {
        warn!(
            path = %path.display(),
            incident_id,
            detector,
            reporter,
            error = %e,
            "false-positive report write failed (FP entry lost)"
        );
    }
}

pub fn log_false_positive(
    data_dir: &std::path::Path,
    incident_id: &str,
    detector: &str,
    reporter: &str,
) {
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let path = data_dir.join(format!("fp-reports-{today}.jsonl"));
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "incident_id": incident_id,
        "detector": detector,
        "reporter": reporter,
        "action": "reported_fp"
    });
    append_fp_report_or_warn(&path, &entry, incident_id, detector, reporter);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_allowlist(path: &std::path::Path) -> toml::Table {
        let content = std::fs::read_to_string(path).expect("allowlist content");
        content.parse::<toml::Table>().expect("valid TOML")
    }

    #[test]
    fn append_to_allowlist_creates_parseable_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.toml");

        append_to_allowlist(&path, "ips", "203.0.113.7", "known scanner").unwrap();

        let parsed = parse_allowlist(&path);
        assert_eq!(parsed["ips"]["203.0.113.7"].as_str(), Some("known scanner"));
    }

    #[test]
    fn append_to_allowlist_updates_existing_section_without_duplicate_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.toml");

        append_to_allowlist(&path, "ips", "203.0.113.7", "first reason").unwrap();
        append_to_allowlist(&path, "ips", "203.0.113.7", "updated reason").unwrap();
        append_to_allowlist(&path, "ips", "198.51.100.9", "neighbor").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("[ips]").count(), 1);
        let parsed = parse_allowlist(&path);
        assert_eq!(
            parsed["ips"]["203.0.113.7"].as_str(),
            Some("updated reason")
        );
        assert_eq!(parsed["ips"]["198.51.100.9"].as_str(), Some("neighbor"));
    }

    #[test]
    fn append_to_allowlist_handles_toml_sensitive_text_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.toml");

        append_to_allowlist(
            &path,
            "processes",
            "worker\"\\name\nblue",
            "quoted \"safe\" path C:\\tmp\napproved",
        )
        .unwrap();

        let parsed = parse_allowlist(&path);
        assert_eq!(
            parsed["processes"]["worker\"\\name blue"].as_str(),
            Some("quoted \"safe\" path C:\\tmp approved")
        );
    }

    #[test]
    fn append_to_allowlist_returns_clear_error_for_invalid_existing_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.toml");
        std::fs::write(&path, "[ips\nbroken").unwrap();

        let err = append_to_allowlist(&path, "ips", "203.0.113.7", "known scanner")
            .expect_err("invalid TOML should fail");

        assert!(err.to_string().contains("parse allowlist"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[ips\nbroken");
    }

    #[test]
    fn log_allowlist_change_writes_valid_jsonl() {
        let dir = tempfile::tempdir().expect("tempdir");

        log_allowlist_change(dir.path(), "203.0.113.7", "ips", "alice", "add");

        let path = dir.path().join("allowlist-history.jsonl");
        let content = std::fs::read_to_string(path).expect("history file");
        let line = content.lines().next().expect("history line");
        let entry: serde_json::Value = serde_json::from_str(line).expect("valid json");
        assert!(entry["ts"].as_str().unwrap_or_default().contains('T'));
        assert_eq!(entry["key"], "203.0.113.7");
        assert_eq!(entry["section"], "ips");
        assert_eq!(entry["operator"], "alice");
        assert_eq!(entry["action"], "add");
    }

    #[test]
    fn read_undoable_allowlist_entries_filters_removed_and_honors_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        log_allowlist_change(dir.path(), "203.0.113.1", "ips", "alice", "add");
        log_allowlist_change(dir.path(), "203.0.113.2", "ips", "alice", "add");
        log_allowlist_change(dir.path(), "203.0.113.1", "ips", "alice", "remove");
        log_allowlist_change(dir.path(), "worker", "processes", "bob", "add");

        let entries = read_undoable_allowlist_entries(dir.path(), 2);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "worker");
        assert_eq!(entries[0].1, "processes");
        assert_eq!(entries[1].0, "203.0.113.2");
        assert_eq!(entries[1].1, "ips");
    }

    #[test]
    fn remove_from_allowlist_removes_only_requested_section_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.toml");
        append_to_allowlist(&path, "ips", "203.0.113.7", "network").unwrap();
        append_to_allowlist(&path, "processes", "203.0.113.7", "process name").unwrap();

        remove_from_allowlist(&path, "ips", "203.0.113.7").unwrap();

        let parsed = parse_allowlist(&path);
        assert!(parsed["ips"]
            .as_table()
            .unwrap()
            .get("203.0.113.7")
            .is_none());
        assert_eq!(
            parsed["processes"]["203.0.113.7"].as_str(),
            Some("process name")
        );
    }

    #[test]
    fn remove_from_allowlist_handles_bare_toml_process_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.toml");
        append_to_allowlist(&path, "processes", "sshd", "trusted process").unwrap();
        append_to_allowlist(&path, "processes", "sshd-helper", "keep helper").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("\nsshd = "),
            "serializer should use a bare key for this regression guard: {content}"
        );

        remove_from_allowlist(&path, "processes", "sshd").unwrap();

        let parsed = parse_allowlist(&path);
        assert!(parsed["processes"]
            .as_table()
            .unwrap()
            .get("sshd")
            .is_none());
        assert_eq!(
            parsed["processes"]["sshd-helper"].as_str(),
            Some("keep helper")
        );
    }

    #[test]
    fn log_false_positive_appends_to_existing_daily_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        log_false_positive(dir.path(), "inc-1", "ssh_bruteforce", "alice");
        log_false_positive(dir.path(), "inc-2", "credential_stuffing", "bob");

        let today = chrono::Utc::now().format("%Y-%m-%d");
        let path = dir.path().join(format!("fp-reports-{today}.jsonl"));
        let content = std::fs::read_to_string(path).expect("fp report file");
        let entries = content
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid json"))
            .collect::<Vec<_>>();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["incident_id"], "inc-1");
        assert_eq!(entries[1]["incident_id"], "inc-2");
        assert_eq!(entries[1]["action"], "reported_fp");
    }

    // Spec 037 I-13 follow-up #2 (smallest slice): append_allowlist_history_or_warn
    //
    // Wraps the two-level silent cascade (open + write) of the
    // allowlist history append. The cascade was the same shape as
    // the honeypot evidence cascade fixed in PR-6 (#308) and
    // PR #318 -- this is the same helper-or-warn pattern applied
    // to the undo/rollback history that powers the dashboard's
    // "revert allowlist change" affordance.
    //
    // Two anchors:
    //   1. happy path: writable parent => entry appended, no warn
    //   2. failure path: parent is a regular file (not a dir) so
    //      `OpenOptions::open(create=true)` cannot create the file =>
    //      no entry written and a warn carrying path + key + section
    //      + operator + action + error.

    #[test]
    fn append_allowlist_history_or_warn_appends_silently_on_writable_path() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist-history.jsonl");
        let entry = serde_json::json!({
            "ts": "2026-04-28T07:00:00Z",
            "key": "203.0.113.42",
            "section": "ips",
            "operator": "alice",
            "action": "add",
        });

        append_allowlist_history_or_warn(&path, &entry, "203.0.113.42", "ips", "alice", "add");

        let written = std::fs::read_to_string(&path).expect("history file");
        assert!(
            written.contains("203.0.113.42"),
            "entry must be appended, got: {written}"
        );
        assert!(
            written.ends_with('\n'),
            "writeln! must terminate with newline, got: {written:?}"
        );

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("allowlist history"),
            "happy path must not emit any failure warn, got: {captured}"
        );
    }

    #[test]
    fn append_allowlist_history_or_warn_emits_warn_on_open_failure() {
        // Force `OpenOptions::open(create=true)` to fail by parking
        // the target path beneath a regular file.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("allowlist-history.jsonl");

        let entry = serde_json::json!({
            "ts": "2026-04-28T07:00:00Z",
            "key": "198.51.100.5",
            "section": "ips",
            "operator": "bob",
            "action": "remove",
        });

        append_allowlist_history_or_warn(&path, &entry, "198.51.100.5", "ips", "bob", "remove");

        // No file was created (parent is a regular file).
        assert!(
            !path.exists(),
            "open under a regular-file parent must not produce the file"
        );

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("allowlist history file open failed"),
            "open-failure warn missing, got: {captured}"
        );
        // Every structured field promised by the helper rustdoc must
        // be in the captured output -- these are what the operator
        // needs to reconstruct the lost undo/rollback entry.
        assert!(
            captured.contains("key=\"198.51.100.5\"") || captured.contains("key=198.51.100.5"),
            "key field missing, got: {captured}"
        );
        assert!(
            captured.contains("section=\"ips\"") || captured.contains("section=ips"),
            "section field missing, got: {captured}"
        );
        assert!(
            captured.contains("operator=\"bob\"") || captured.contains("operator=bob"),
            "operator field missing, got: {captured}"
        );
        assert!(
            captured.contains("action=\"remove\"") || captured.contains("action=remove"),
            "action field missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }

    // Spec 037 I-13 follow-up #2 (sibling slice): append_fp_report_or_warn
    //
    // Same two-level cascade shape as append_allowlist_history_or_warn
    // (open + write nested), wrapping the FP report append in
    // log_false_positive. Operator-marked false positives feed
    // detector-tuning workflows; silent drops broke the feedback loop.

    #[test]
    fn append_fp_report_or_warn_appends_silently_on_writable_path() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fp-reports-2026-04-28.jsonl");
        let entry = serde_json::json!({
            "ts": "2026-04-28T08:00:00Z",
            "incident_id": "inc-abc-1",
            "detector": "ssh_bruteforce",
            "reporter": "alice",
            "action": "reported_fp",
        });

        append_fp_report_or_warn(&path, &entry, "inc-abc-1", "ssh_bruteforce", "alice");

        let written = std::fs::read_to_string(&path).expect("fp report file");
        assert!(
            written.contains("inc-abc-1"),
            "entry must be appended, got: {written}"
        );
        assert!(
            written.ends_with('\n'),
            "writeln! must terminate with newline, got: {written:?}"
        );

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("false-positive report"),
            "happy path must not emit any failure warn, got: {captured}"
        );
    }

    #[test]
    fn append_fp_report_or_warn_emits_warn_on_open_failure() {
        // Force `OpenOptions::open(create=true)` to fail by parking
        // the target path beneath a regular file.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("fp-reports-2026-04-28.jsonl");

        let entry = serde_json::json!({
            "ts": "2026-04-28T08:00:00Z",
            "incident_id": "inc-xyz-9",
            "detector": "credential_stuffing",
            "reporter": "bob",
            "action": "reported_fp",
        });

        append_fp_report_or_warn(&path, &entry, "inc-xyz-9", "credential_stuffing", "bob");

        assert!(
            !path.exists(),
            "open under a regular-file parent must not produce the file"
        );

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("false-positive report file open failed"),
            "open-failure warn missing, got: {captured}"
        );
        // Every structured field promised by the helper rustdoc must
        // be in the captured output.
        assert!(
            captured.contains("incident_id=\"inc-xyz-9\"")
                || captured.contains("incident_id=inc-xyz-9"),
            "incident_id field missing, got: {captured}"
        );
        assert!(
            captured.contains("detector=\"credential_stuffing\"")
                || captured.contains("detector=credential_stuffing"),
            "detector field missing, got: {captured}"
        );
        assert!(
            captured.contains("reporter=\"bob\"") || captured.contains("reporter=bob"),
            "reporter field missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }
}
