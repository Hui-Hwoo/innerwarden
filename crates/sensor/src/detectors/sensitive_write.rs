use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Sensitive paths that should never be written by unexpected processes.
/// Organized by category for clear incident reporting.
const CREDENTIAL_PATHS: &[&str] = &["/etc/shadow", "/etc/passwd", "/etc/gshadow", "/etc/group"];

const SSH_PATHS: &[&str] = &[
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/config",
];

const SUDO_PATHS: &[&str] = &["/etc/sudoers", "/etc/sudoers.d/"];

const CRON_PATHS: &[&str] = &[
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/var/spool/cron/",
];

const PERSISTENCE_PATHS: &[&str] = &[
    "/etc/systemd/system/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/rc.d/",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/",
    "/etc/profile",
    "/etc/profile.d/",
    "/etc/bashrc",
    "/etc/bash.bashrc",
    "/etc/environment",
    // Python startup hooks — attacker persistence via import hijacking
    "usercustomize.py",
    "sitecustomize.py",
];

const LOG_PATHS: &[&str] = &[
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/messages",
    ".bash_history",
];

/// User-level persistence paths (matched by suffix, not prefix).
/// These catch writes to .bashrc, .profile, .bash_profile in ANY user's home.
const USER_PERSISTENCE_SUFFIXES: &[&str] = &[
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/.zshrc",
    "/.bash_logout",
];

const PAM_PATHS: &[&str] = &["/etc/pam.d/"];

/// Processes that legitimately write to sensitive paths.
const ALLOWED_PROCESSES: &[&str] = &[
    "dpkg",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "rpm",
    "snap",
    "passwd",
    "chpasswd",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "visudo",
    "sudo",
    "sshd",
    "cron",
    "crond",
    "anacron",
    "systemd",
    "systemctl",
    "cloud-init",
    "puppet",
    "chef-client",
    "ansible",
    "salt-minion",
    "vipw",
    "vigr",
    "chsh",
    "chfn",
    "adduser",
    "deluser",
    "pam_tally2",
    "pam-auth-update",
    "faillock",
    "nscd",
    "sss_cache",
    "innerwarden",
];

/// Detects unauthorized writes to security-critical system files.
///
/// This detector consolidates protection for credentials, SSH keys,
/// sudo config, cron jobs, systemd units, PAM config, and LD preload.
/// It processes `file.write_access` events from the eBPF openat tracepoint
/// and `file.write_sensitive` events from the LSM file_open hook.
pub struct SensitiveWriteDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

impl SensitiveWriteDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "file.write_access" | "file.truncate" => self.check_write(event),
            // Some writes arrive as O_RDONLY open (program reads, modifies in memory,
            // writes to temp file, renames). For critical paths like PAM, detect
            // any non-system access as suspicious.
            "file.read_access" => self.check_critical_read(event),
            _ => None,
        }
    }

    fn check_write(&mut self, event: &Event) -> Option<Incident> {
        let filename = event.details.get("filename").and_then(|v| v.as_str())?;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip allowlisted processes
        if is_allowed(comm) {
            return None;
        }

        let (category, severity) = classify_path(filename)?;

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Interactive shells append their command history to ~/.bash_history on
        // exit — universal POSIX behaviour, not log tampering. Suppress ONLY
        // when a real shell, owned by the writing uid, opens its OWN history
        // append-only (O_APPEND set, O_TRUNC clear). Truncation (O_TRUNC), a
        // different user or a non-shell writer, or any other history path still
        // fire — those are the real anti-forensic moves. Missing flags ->
        // append_only is false -> the incident still fires (fail-safe).
        if category == "log_tampering" && filename.ends_with(".bash_history") {
            const O_APPEND: u64 = 0x400;
            const O_TRUNC: u64 = 0x200;
            let flags = event
                .details
                .get("flags")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let append_only = (flags & O_APPEND != 0) && (flags & O_TRUNC == 0);
            let is_shell = matches!(
                comm,
                "bash" | "zsh" | "ksh" | "sh" | "dash" | "tcsh" | "fish"
            );
            if append_only && is_shell && history_owned_by(uid, filename) {
                return None;
            }
        }

        let key = format!("sensitive_write:{category}:{comm}:{filename}");

        // Cooldown
        if let Some(&last) = self.alerted.get(&key) {
            if event.ts - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, event.ts);

        // Prune stale entries
        if self.alerted.len() > 500 {
            let cutoff = event.ts - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "sensitive_write:{category}:{comm}:{}",
                event.ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!(
                "Sensitive path write ({category}): {comm} → {}",
                truncate_path(filename, 60)
            ),
            summary: format!(
                "Process '{comm}' (pid={pid}, uid={uid}) opened '{filename}' for writing. \
                 This file is in the {category} category and should only be modified by \
                 authorized system tools."
            ),
            evidence: serde_json::json!([{
                "kind": "sensitive_write",
                "category": category,
                "filename": filename,
                "comm": comm,
                "pid": pid,
                "uid": uid,
            }]),
            recommended_checks: vec![
                format!("Verify if '{comm}' (pid {pid}) should be modifying {filename}"),
                "Check process tree: ps -ef --forest | grep <pid>".to_string(),
                format!("Review recent changes: stat {filename}"),
                "Check audit log: ausearch -f <filename>".to_string(),
            ],
            tags: vec![
                "sensitive_write".to_string(),
                category.to_string(),
                "persistence".to_string(),
            ],
            entities: vec![EntityRef::path(filename)],
        })
    }

    /// Detect reads to critical paths where ANY non-system access is suspicious.
    /// Catches attacks that open files O_RDONLY, modify in memory, then write via
    /// temp file + rename (which the openat hook misses as a write).
    fn check_critical_read(&mut self, event: &Event) -> Option<Incident> {
        let filename = event.details.get("filename").and_then(|v| v.as_str())?;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if is_allowed(comm) {
            return None;
        }

        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Skip InnerWarden's own processes (sensor reads PAM files during normal operation)
        if super::allowlists::is_innerwarden_process(uid, comm) {
            return None;
        }

        // Only trigger for paths where a READ by non-system process is itself suspicious
        let critical_read_paths: &[(&str, &str)] = &[
            ("/etc/pam.d/", "pam_tampering"),
            ("/etc/init.d/", "sysv_persistence"),
        ];

        let (path_match, category) = critical_read_paths
            .iter()
            .find(|(p, _)| filename.contains(p))?;
        let _ = path_match;

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Only alert for non-root, non-system reads (root PAM reads are normal for login)
        if uid == 0 {
            return None;
        }

        let key = format!("sensitive_read:{category}:{comm}:{filename}");
        if let Some(&last) = self.alerted.get(&key) {
            if event.ts - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, event.ts);

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "sensitive_write:{category}:{comm}:{}",
                event.ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: format!(
                "Suspicious access to {category} path: {comm} → {}",
                truncate_path(filename, 60)
            ),
            summary: format!(
                "Non-system process '{comm}' (pid={pid}, uid={uid}) accessed '{filename}'. \
                 This path is security-critical and should only be accessed by system tools."
            ),
            evidence: serde_json::json!([{
                "kind": "sensitive_access",
                "category": category,
                "filename": filename,
                "comm": comm,
                "pid": pid,
                "uid": uid,
            }]),
            recommended_checks: vec![
                format!("Verify if '{comm}' should access {filename}"),
                format!("Check for modifications: stat {filename}"),
            ],
            tags: vec!["sensitive_write".to_string(), category.to_string()],
            entities: vec![EntityRef::path(filename)],
        })
    }
}

fn is_allowed(comm: &str) -> bool {
    ALLOWED_PROCESSES
        .iter()
        .any(|p| comm == *p || comm.starts_with(p))
}

/// True iff `filename` is the writing `uid`'s OWN history file:
/// `/home/<user>/.bash_history` written by a non-root uid, or
/// `/root/.bash_history` written by root. Any path we cannot attribute returns
/// false, so the incident fires (fail-safe). Generic `/home`/`/root` layout +
/// uid ownership, not host-specific.
fn history_owned_by(uid: u64, filename: &str) -> bool {
    if let Some(rest) = filename.strip_prefix("/root/") {
        return uid == 0 && rest == ".bash_history";
    }
    if let Some(rest) = filename.strip_prefix("/home/") {
        // exactly /home/<user>/.bash_history, written by a non-root uid
        let segs: Vec<&str> = rest.split('/').collect();
        return segs.len() == 2 && segs[1] == ".bash_history" && uid != 0;
    }
    false
}

fn classify_path(filename: &str) -> Option<(&'static str, Severity)> {
    for p in CREDENTIAL_PATHS {
        if filename.contains(p) {
            return Some(("credentials", Severity::Critical));
        }
    }
    for p in SSH_PATHS {
        if filename.contains(p) {
            return Some(("ssh", Severity::Critical));
        }
    }
    for p in SUDO_PATHS {
        if filename.contains(p) {
            return Some(("sudo", Severity::Critical));
        }
    }
    for p in PAM_PATHS {
        if filename.contains(p) {
            return Some(("pam", Severity::Critical));
        }
    }
    for p in PERSISTENCE_PATHS {
        if filename.contains(p) {
            return Some(("persistence", Severity::High));
        }
    }
    for suffix in USER_PERSISTENCE_SUFFIXES {
        if filename.ends_with(suffix) {
            return Some(("persistence", Severity::High));
        }
    }
    for p in CRON_PATHS {
        if filename.contains(p) {
            return Some(("cron", Severity::High));
        }
    }
    for p in LOG_PATHS {
        if filename.contains(p) {
            return Some(("log_tampering", Severity::Critical));
        }
    }
    None
}

fn truncate_path(path: &str, max: usize) -> &str {
    if path.len() <= max {
        path
    } else {
        &path[path.len() - max..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Event;

    fn write_event(filename: &str, comm: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Medium,
            summary: format!("{comm} writing {filename}"),
            details: serde_json::json!({
                "filename": filename,
                "comm": comm,
                "pid": 1234,
                "uid": 1000,
                "flags": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_shadow_write() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/etc/shadow", "evil");
        let incident = det.process(&ev);
        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"credentials".to_string()));
    }

    fn write_event_full(filename: &str, comm: &str, uid: u64, flags: u64) -> Event {
        let mut e = write_event(filename, comm);
        e.details["uid"] = serde_json::json!(uid);
        e.details["flags"] = serde_json::json!(flags);
        e
    }

    #[test]
    fn bash_history_append_by_owner_is_benign_truncate_and_others_fire() {
        const O_WRONLY: u64 = 0x1;
        const O_APPEND: u64 = 0x400;
        const O_TRUNC: u64 = 0x200;
        let mut det = SensitiveWriteDetector::new("test", 300);
        // Owner's shell appending its OWN history on logout => benign.
        assert!(det
            .process(&write_event_full(
                "/home/alice/.bash_history",
                "bash",
                1000,
                O_WRONLY | O_APPEND,
            ))
            .is_none());
        // Truncation (O_TRUNC) = wiping history = real anti-forensics => fires.
        assert!(det
            .process(&write_event_full(
                "/home/bob/.bash_history",
                "bash",
                1000,
                O_WRONLY | O_TRUNC,
            ))
            .is_some());
        // Root writing a regular user's history => fires (anti-forensics).
        assert!(det
            .process(&write_event_full(
                "/home/carol/.bash_history",
                "bash",
                0,
                O_WRONLY | O_APPEND,
            ))
            .is_some());
        // Non-shell writer (python/curl) appending history => fires.
        assert!(det
            .process(&write_event_full(
                "/home/dave/.bash_history",
                "python3",
                1000,
                O_WRONLY | O_APPEND,
            ))
            .is_some());
    }

    #[test]
    fn detects_ssh_key_write() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/home/user/.ssh/authorized_keys", "python3");
        let incident = det.process(&ev);
        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"ssh".to_string()));
    }

    #[test]
    fn detects_systemd_persistence() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/etc/systemd/system/backdoor.service", "curl");
        let incident = det.process(&ev);
        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.tags.contains(&"persistence".to_string()));
    }

    #[test]
    fn detects_ld_preload() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/etc/ld.so.preload", "bash");
        let incident = det.process(&ev);
        assert!(incident.is_some());
    }

    #[test]
    fn allows_dpkg() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/etc/shadow", "dpkg");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_passwd_command() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/etc/shadow", "passwd");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/etc/shadow", "evil");
        assert!(det.process(&ev).is_some());
        assert!(det.process(&ev).is_none()); // suppressed by cooldown
    }

    #[test]
    fn ignores_normal_file() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let ev = write_event("/tmp/output.txt", "python3");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_read_events() {
        let mut det = SensitiveWriteDetector::new("test", 300);
        let mut ev = write_event("/etc/shadow", "evil");
        ev.kind = "file.read_access".to_string();
        assert!(det.process(&ev).is_none());
    }
}
