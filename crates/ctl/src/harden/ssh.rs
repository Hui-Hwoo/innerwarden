use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn ssh_config_value(full_config: &str, key: &str) -> Option<String> {
    for line in full_config.lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 && parts[0].eq_ignore_ascii_case(key) {
            return Some(parts[1].trim().to_string());
        }
    }
    None
}

pub(super) fn evaluate_ssh_config(
    full_config: &str,
    category: &'static str,
) -> (Vec<String>, Vec<Finding>) {
    let mut passed = Vec::new();
    let mut findings = Vec::new();

    // Password authentication
    match ssh_config_value(full_config, "PasswordAuthentication").as_deref() {
        Some("no") => passed.push("Password authentication disabled".into()),
        _ => findings.push(Finding {
            category,
            severity: Severity::High,
            title: "Password authentication is enabled".into(),
            fix: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config".into(),
        }),
    }

    // Root login
    match ssh_config_value(full_config, "PermitRootLogin").as_deref() {
        Some("no") | Some("prohibit-password") => {
            passed.push("Root login restricted".into());
        }
        _ => findings.push(Finding {
            category,
            severity: Severity::High,
            title: "Root login via SSH is permitted".into(),
            fix: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config".into(),
        }),
    }

    // Default port
    match ssh_config_value(full_config, "Port").as_deref() {
        Some("22") | None => findings.push(Finding {
            category,
            severity: Severity::Low,
            title: "SSH running on default port 22".into(),
            fix: "Consider changing to a non-standard port in /etc/ssh/sshd_config".into(),
        }),
        _ => passed.push("SSH on non-standard port".into()),
    }

    // MaxAuthTries
    match ssh_config_value(full_config, "MaxAuthTries") {
        Some(v) if v.parse::<u32>().unwrap_or(6) <= 3 => {
            passed.push(format!("MaxAuthTries set to {v}"));
        }
        _ => findings.push(Finding {
            category,
            severity: Severity::Medium,
            title: "MaxAuthTries not restricted (default: 6)".into(),
            fix: "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config".into(),
        }),
    }

    // Empty passwords
    match ssh_config_value(full_config, "PermitEmptyPasswords").as_deref() {
        Some("yes") => findings.push(Finding {
            category,
            severity: Severity::Critical,
            title: "Empty passwords are permitted".into(),
            fix: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config".into(),
        }),
        _ => passed.push("Empty passwords not permitted".into()),
    }

    (passed, findings)
}

pub(super) fn check_ssh(env: &impl HardenEnv) -> CheckResult {
    let cat = "SSH";

    let sshd_config = env
        .read_to_string("/etc/ssh/sshd_config")
        .unwrap_or_default();
    // Also read config fragments in sshd_config.d/
    let mut full_config = sshd_config.clone();
    for entry in env.read_dir("/etc/ssh/sshd_config.d") {
        if let Some(content) = env.read_to_string(&entry.path) {
            full_config.push('\n');
            full_config.push_str(&content);
        }
    }

    let (passed, findings) = evaluate_ssh_config(&full_config, cat);

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
