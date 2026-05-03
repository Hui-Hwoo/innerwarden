use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn suspicious_crontab_reason(line: &str) -> Option<&'static str> {
    let lower = line.to_lowercase();
    let trimmed = lower.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if (lower.contains("curl") || lower.contains("wget"))
        && (lower.contains("| sh")
            || lower.contains("|sh")
            || lower.contains("| bash")
            || lower.contains("|bash"))
    {
        return Some("download and execute (curl/wget piped to sh/bash)");
    }
    if lower.contains("/dev/tcp") || lower.contains("nc -e") || lower.contains("ncat -e") {
        return Some("possible reverse shell (nc / /dev/tcp)");
    }
    if lower.contains("base64 -d") || lower.contains("base64 --decode") {
        return Some("base64 decode (potential obfuscation)");
    }
    if lower.contains("> /tmp/") || lower.contains(">/tmp/") {
        return Some("writes to /tmp (common staging directory)");
    }
    None
}

pub(super) fn check_crontabs(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Crontabs";

    let mut scanned: usize = 0;

    // Helper: scan all files in a directory.
    let mut scan_dir = |dir: &str| {
        for entry in env.read_dir(dir) {
            if !entry.is_file {
                continue;
            }
            if let Some(contents) = env.read_to_string(&entry.path) {
                scanned += 1;
                for (lineno, line) in contents.lines().enumerate() {
                    if let Some(reason) = suspicious_crontab_reason(line) {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::Medium,
                            title: format!("{}:{} - {}", entry.path, lineno + 1, reason),
                            fix: format!(
                                "Review the entry in {} and remove it if unexpected",
                                entry.path
                            ),
                        });
                    }
                }
            }
        }
    };

    // User crontabs
    scan_dir("/var/spool/cron/crontabs");
    // System cron fragments
    scan_dir("/etc/cron.d");

    // /etc/crontab (single file)
    if let Some(contents) = env.read_to_string("/etc/crontab") {
        scanned += 1;
        for (lineno, line) in contents.lines().enumerate() {
            if let Some(reason) = suspicious_crontab_reason(line) {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Medium,
                    title: format!("/etc/crontab:{} - {}", lineno + 1, reason),
                    fix: "Review the entry in /etc/crontab and remove it if unexpected".into(),
                });
            }
        }
    }

    if findings.is_empty() {
        if scanned > 0 {
            passed.push(format!(
                "Scanned {scanned} crontab file(s) - no suspicious entries"
            ));
        } else {
            passed.push("No crontab files found to scan".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
