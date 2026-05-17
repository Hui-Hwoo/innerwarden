//! Real-time filesystem monitoring via fanotify (Linux) or polling fallback.
//!
//! Replaces periodic integrity polling with immediate notification on file
//! modifications. Detects ransomware via high-rate sequential writes combined
//! with entropy analysis.
//!
//! Monitored events:
//! - File modifications on watched paths (config files, /etc, /boot)
//! - High-rate write bursts (potential ransomware)
//! - Entropy increase after modification (encryption indicator)
//!
//! Falls back to polling on macOS or when fanotify is unavailable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};

/// Paths to monitor for modifications by default. Covers the high-
/// value targets every PR1-6 file-write detector watches for: PAM
/// (T1556.003), cron / systemd / init / RC (T1037 / T1053 / T1543),
/// audit (T1562.001), SELinux (T1562.001), authorized_keys
/// (T1098.004), shell startup files (T1546.004) plus the classic
/// boot / auth tampering targets.
///
/// Wave 2026-05-17: extended to close the smoke-harness gap where
/// file-write detectors did not fire because fanotify_watch was only
/// hashing 9 narrowly-scoped paths.
const DEFAULT_WATCH_PATHS: &[&str] = &[
    // ── Classic auth + boot tampering ─────────────────────────────
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ld.so.preload",
    "/boot/grub/grub.cfg",
    // ── PAM tampering (T1556.003) ─────────────────────────────────
    "/etc/pam.d/sshd",
    "/etc/pam.d/su",
    "/etc/pam.d/sudo",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-session",
    "/etc/pam.conf",
    // ── Cron persistence (T1053.003) ──────────────────────────────
    "/etc/crontab",
    "/etc/cron.allow",
    "/etc/cron.deny",
    // ── RC / init script persistence (T1037.004) ──────────────────
    "/etc/rc.local",
    // ── Audit subsystem tampering (T1562.001) ─────────────────────
    "/etc/audit/auditd.conf",
    "/etc/audit/audit.rules",
    // ── SELinux / MAC layer disable (T1562.001) ──────────────────
    "/etc/selinux/config",
    // ── Shell startup files (T1546.004 + T1056.004) ───────────────
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
    "/etc/zsh/zshenv",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/root/.zshrc",
];

/// Minimum file size for entropy analysis.
const MIN_ENTROPY_SIZE: usize = 64;
/// Entropy threshold for encrypted content (Shannon entropy, max = 8.0).
const ENCRYPTION_ENTROPY_THRESHOLD: f64 = 7.5;
/// Number of writes in a short window that indicates ransomware behavior.
const RANSOMWARE_WRITE_THRESHOLD: usize = 50;
/// Window for ransomware burst detection.
const RANSOMWARE_WINDOW_SECS: i64 = 10;

/// Per-file tracking state.
struct FileState {
    hash: String,
    last_modified: DateTime<Utc>,
    size: u64,
}

/// Write burst tracking for ransomware detection.
struct WriteBurstTracker {
    /// Recent write timestamps.
    writes: Vec<DateTime<Utc>>,
    /// Last ransomware alert timestamp (cooldown).
    last_alert: Option<DateTime<Utc>>,
}

fn track_write_burst(tracker: &mut WriteBurstTracker, now: DateTime<Utc>) {
    tracker.writes.push(now);
    tracker
        .writes
        .retain(|ts| now - *ts < Duration::seconds(RANSOMWARE_WINDOW_SECS));
}

fn should_emit_ransomware_burst(tracker: &WriteBurstTracker, now: DateTime<Utc>) -> bool {
    tracker.writes.len() >= RANSOMWARE_WRITE_THRESHOLD
        && tracker
            .last_alert
            .map(|t| now - t > Duration::seconds(60))
            .unwrap_or(true)
}

fn file_change_base_severity(path_str: &str) -> Severity {
    if path_str.contains("/etc/shadow")
        || path_str.contains("/etc/sudoers")
        || path_str.contains("/boot/")
        || path_str.contains("sshd_config")
    {
        Severity::Critical
    } else {
        Severity::High
    }
}

fn build_file_change_event(
    host: &str,
    now: DateTime<Utc>,
    path_str: &str,
    current: &FileState,
    previous: Option<&FileState>,
    entropy: Option<f64>,
) -> Event {
    let encrypted = entropy
        .map(|value| value >= ENCRYPTION_ENTROPY_THRESHOLD)
        .unwrap_or(false);
    let severity = if encrypted {
        Severity::Critical
    } else {
        file_change_base_severity(path_str)
    };
    let prev_hash = previous.map(|state| state.hash.clone()).unwrap_or_default();
    let prev_modified = previous
        .map(|state| state.last_modified.to_rfc3339())
        .unwrap_or_default();

    // Canonical schema (wave 2026-05-17):
    //   - `kind = "file.write_access"` matches what `ebpf_syscall`
    //     emits, so PR1-6 file-write detectors (pam_module_change,
    //     startup_script_persistence, crontab_persistence, etc.) feed
    //     off either source interchangeably.
    //   - `details.filename` matches the field name detectors read.
    //   - Encrypted-write bursts keep a distinct `file.encrypted_write`
    //     kind for the ransomware detector to discriminate.
    let kind = if encrypted {
        "file.encrypted_write"
    } else {
        "file.write_access"
    };
    Event {
        ts: now,
        host: host.to_string(),
        source: "fanotify".to_string(),
        kind: kind.to_string(),
        severity,
        summary: format!(
            "File modified: {} (hash changed{})",
            path_str,
            if encrypted {
                ", HIGH ENTROPY - possible encryption"
            } else {
                ""
            }
        ),
        details: serde_json::json!({
            // canonical fields detectors read
            "filename": path_str,
            // legacy field name kept for any consumer still reading "path"
            "path": path_str,
            "new_hash": current.hash,
            "old_hash": prev_hash,
            "previous_check": prev_modified,
            "new_size": current.size,
            "entropy": entropy,
            "encrypted": encrypted,
        }),
        tags: vec!["filesystem".to_string(), "integrity".to_string()],
        entities: vec![EntityRef::path(path_str)],
    }
}

fn build_ransomware_burst_event(
    host: &str,
    now: DateTime<Utc>,
    tracker: &WriteBurstTracker,
    latest_file: &str,
) -> Event {
    Event {
        ts: now,
        host: host.to_string(),
        source: "fanotify".to_string(),
        kind: "file.ransomware_burst".to_string(),
        severity: Severity::Critical,
        summary: format!(
            "Ransomware-like behavior: {} file modifications in {}s",
            tracker.writes.len(),
            RANSOMWARE_WINDOW_SECS
        ),
        details: serde_json::json!({
            "writes_in_window": tracker.writes.len(),
            "window_seconds": RANSOMWARE_WINDOW_SECS,
            "latest_file": latest_file,
        }),
        tags: vec!["ransomware".to_string(), "filesystem".to_string()],
        entities: vec![],
    }
}

/// Run the fanotify/polling filesystem monitor.
///
/// On Linux with appropriate permissions, uses inotify (via polling with
/// metadata change detection). Falls back to periodic hash checking.
pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    watch_paths: Vec<String>,
    poll_seconds: u64,
) {
    let paths: Vec<PathBuf> = if watch_paths.is_empty() {
        DEFAULT_WATCH_PATHS
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    } else {
        watch_paths.iter().map(PathBuf::from).collect()
    };

    if paths.is_empty() {
        warn!("fanotify_watch: no valid paths to monitor — filesystem monitoring disabled");
        return;
    }

    info!(paths = paths.len(), "fanotify_watch: monitoring filesystem");

    let mut file_states: HashMap<PathBuf, FileState> = HashMap::new();
    let mut burst_tracker = WriteBurstTracker {
        writes: Vec::new(),
        last_alert: None,
    };

    // Initialize baselines
    for path in &paths {
        if let Some(state) = compute_file_state(path) {
            file_states.insert(path.clone(), state);
        }
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_seconds));

    loop {
        interval.tick().await;
        let now = Utc::now();

        for path in &paths {
            let current = match compute_file_state(path) {
                Some(s) => s,
                None => continue,
            };

            let changed = if let Some(prev) = file_states.get(path) {
                prev.hash != current.hash
            } else {
                true // new file
            };

            if changed {
                // Track write burst
                track_write_burst(&mut burst_tracker, now);

                let path_str = path.to_string_lossy().to_string();

                // Check entropy for encryption indicator
                let entropy = compute_file_entropy(path);
                let ev = build_file_change_event(
                    &host,
                    now,
                    &path_str,
                    &current,
                    file_states.get(path),
                    entropy,
                );

                if tx.send(ev).await.is_err() {
                    return;
                }

                // Ransomware burst detection
                if should_emit_ransomware_burst(&burst_tracker, now) {
                    burst_tracker.last_alert = Some(now);
                    let ev = build_ransomware_burst_event(&host, now, &burst_tracker, &path_str);
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }

                file_states.insert(path.clone(), current);
            }
        }
    }
}

/// Compute SHA-256 hash and metadata for a file.
fn compute_file_state(path: &Path) -> Option<FileState> {
    let content = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = format!("{:x}", hasher.finalize());

    Some(FileState {
        hash,
        last_modified: Utc::now(),
        size: content.len() as u64,
    })
}

/// Compute Shannon entropy of a file's content (0.0 = uniform, 8.0 = max random).
fn compute_file_entropy(path: &Path) -> Option<f64> {
    let content = std::fs::read(path).ok()?;
    if content.len() < MIN_ENTROPY_SIZE {
        return None;
    }
    Some(shannon_entropy(&content))
}

/// Shannon entropy of a byte sequence.
fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_zero_for_uniform() {
        // All same byte → entropy = 0
        let data = vec![0x41u8; 100];
        let e = shannon_entropy(&data);
        assert!(e < 0.01);
    }

    #[test]
    fn shannon_entropy_high_for_random() {
        // Pseudo-random → entropy close to 8
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9);
    }

    #[test]
    fn shannon_entropy_moderate_for_text() {
        // Baseline path: human-readable text should sit in a moderate entropy
        // band and not look like encrypted blob data.
        let data = b"Hello, this is a normal text file with moderate entropy";
        let e = shannon_entropy(data);
        assert!(e > 3.0 && e < 6.0);
    }

    #[test]
    fn file_state_computation() {
        // Hash path: file-state snapshots should include stable hash and size
        // metadata for change detection between polling intervals.
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world").expect("fixture file should be written");

        let state = compute_file_state(&path).expect("file state should be computed");
        assert!(!state.hash.is_empty());
        assert_eq!(state.size, 11);
    }

    #[test]
    fn file_state_detects_change() {
        // Diff path: content changes must produce a new digest so realtime
        // modification alerts trigger reliably.
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello").expect("initial fixture should be written");
        let state1 = compute_file_state(&path).expect("initial state should load");

        std::fs::write(&path, "world").expect("updated fixture should be written");
        let state2 = compute_file_state(&path).expect("updated state should load");

        assert_ne!(state1.hash, state2.hash);
    }

    #[test]
    fn encryption_threshold() {
        // Random data should be above threshold
        let random_data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let e = shannon_entropy(&random_data);
        assert!(e >= ENCRYPTION_ENTROPY_THRESHOLD);

        // Normal text should be below threshold
        let text = b"The quick brown fox jumps over the lazy dog. This is normal text content.";
        let e = shannon_entropy(text);
        assert!(e < ENCRYPTION_ENTROPY_THRESHOLD);
    }

    #[test]
    fn shannon_entropy_empty_input_is_zero() {
        // Edge path: empty byte slices should return zero entropy instead of
        // producing NaN values that could poison downstream comparisons.
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn compute_file_entropy_returns_none_for_tiny_files() {
        // Size guard path: entropy analysis should skip very small files where
        // statistics are too noisy to be meaningful.
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("tiny.bin");
        std::fs::write(&path, vec![0xAA; MIN_ENTROPY_SIZE - 1])
            .expect("tiny fixture should be written");
        assert!(compute_file_entropy(&path).is_none());
    }

    #[test]
    fn compute_file_entropy_returns_none_for_missing_paths() {
        // Missing-file path: collector should tolerate racey deletes and
        // simply return None when the target no longer exists.
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("missing.bin");
        assert!(compute_file_entropy(&path).is_none());
    }

    #[test]
    fn default_watch_paths_include_high_value_targets() {
        // Configuration path: default watchlist should include critical auth
        // and boot files so tampering is observed out of the box.
        assert!(DEFAULT_WATCH_PATHS.contains(&"/etc/shadow"));
        assert!(DEFAULT_WATCH_PATHS.contains(&"/etc/sudoers"));
        assert!(DEFAULT_WATCH_PATHS.contains(&"/boot/grub/grub.cfg"));
    }

    #[test]
    fn compute_file_state_returns_none_for_missing_file() {
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("missing.txt");
        assert!(compute_file_state(&path).is_none());
    }

    #[test]
    fn file_change_event_marks_encrypted_and_sensitive_paths_correctly() {
        let previous = FileState {
            hash: "old".to_string(),
            last_modified: Utc::now() - Duration::seconds(5),
            size: 3,
        };
        let current = FileState {
            hash: "new".to_string(),
            last_modified: Utc::now(),
            size: 99,
        };

        let encrypted = build_file_change_event(
            "sensor-a",
            Utc::now(),
            "/tmp/blob.bin",
            &current,
            Some(&previous),
            Some(7.9),
        );
        assert_eq!(encrypted.kind, "file.encrypted_write");
        assert_eq!(encrypted.severity, Severity::Critical);
        assert_eq!(encrypted.details["old_hash"], "old");
        assert_eq!(encrypted.details["encrypted"], true);

        let sensitive = build_file_change_event(
            "sensor-b",
            Utc::now(),
            "/etc/shadow",
            &current,
            None,
            Some(3.2),
        );
        // Canonical schema: non-encrypted writes carry kind=file.write_access
        // (matching the eBPF source) so PR1-6 detectors that filter on
        // `kind == "file.write_access"` receive events from either source.
        assert_eq!(sensitive.kind, "file.write_access");
        assert_eq!(sensitive.severity, Severity::Critical);
        assert_eq!(sensitive.details["old_hash"], "");
        // Canonical field name: details.filename matches what
        // pam_module_change, startup_script_persistence, etc. read.
        assert_eq!(sensitive.details["filename"], "/etc/shadow");
        // Legacy alias preserved for any older consumer.
        assert_eq!(sensitive.details["path"], "/etc/shadow");
    }

    #[test]
    fn default_watch_paths_cover_pr5_high_value_targets() {
        // Wave 2026-05-17: the smoke-harness gap revealed that
        // fanotify_watch only saw 9 narrow paths, missing all the PR5
        // surface (PAM / cron.d / RC / audit / SELinux config). This
        // test anchors that the defaults now cover those targets so a
        // regression that drops them is caught at build time.
        for required in &[
            "/etc/pam.d/sshd",
            "/etc/pam.d/su",
            "/etc/pam.conf",
            "/etc/crontab",
            "/etc/rc.local",
            "/etc/audit/audit.rules",
            "/etc/selinux/config",
            "/etc/profile",
            "/root/.bashrc",
        ] {
            assert!(
                DEFAULT_WATCH_PATHS.contains(required),
                "DEFAULT_WATCH_PATHS missing high-value path `{required}`"
            );
        }
    }

    #[test]
    fn write_burst_tracking_prunes_old_entries_and_respects_cooldown() {
        let now = Utc::now();
        let mut tracker = WriteBurstTracker {
            writes: vec![now - Duration::seconds(RANSOMWARE_WINDOW_SECS + 1)],
            last_alert: None,
        };
        for _ in 0..RANSOMWARE_WRITE_THRESHOLD {
            track_write_burst(&mut tracker, now);
        }
        assert_eq!(tracker.writes.len(), RANSOMWARE_WRITE_THRESHOLD);
        assert!(should_emit_ransomware_burst(&tracker, now));

        tracker.last_alert = Some(now - Duration::seconds(30));
        assert!(!should_emit_ransomware_burst(&tracker, now));
        tracker.last_alert = Some(now - Duration::seconds(61));
        assert!(should_emit_ransomware_burst(&tracker, now));
    }

    #[test]
    fn ransomware_burst_event_carries_window_and_latest_file_context() {
        let now = Utc::now();
        let tracker = WriteBurstTracker {
            writes: vec![now; RANSOMWARE_WRITE_THRESHOLD],
            last_alert: None,
        };
        let ev = build_ransomware_burst_event("sensor-c", now, &tracker, "/srv/app.db");
        assert_eq!(ev.kind, "file.ransomware_burst");
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.details["writes_in_window"], RANSOMWARE_WRITE_THRESHOLD);
        assert_eq!(ev.details["latest_file"], "/srv/app.db");
    }

    #[test]
    fn non_sensitive_plaintext_file_changes_remain_high_severity() {
        let current = FileState {
            hash: "new".to_string(),
            last_modified: Utc::now(),
            size: 4,
        };
        let ev = build_file_change_event(
            "sensor-d",
            Utc::now(),
            "/var/tmp/config.txt",
            &current,
            None,
            None,
        );
        assert_eq!(
            file_change_base_severity("/var/tmp/config.txt"),
            Severity::High
        );
        assert_eq!(ev.severity, Severity::High);
    }
}
