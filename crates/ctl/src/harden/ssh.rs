use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn ssh_config_value(full_config: &str, key: &str) -> Option<String> {
    for line in full_config.lines() {
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

    // OpenSSH's `sshd_config(5)`: "the first obtained value will be
    // used". Drop-in fragments in `/etc/ssh/sshd_config.d/` are
    // typically pulled in via an `Include` directive at the TOP of
    // `/etc/ssh/sshd_config`, so they are PARSED FIRST and therefore
    // OVERRIDE settings declared later in the base file. We mirror
    // that ordering here: concatenate fragments first, base file
    // second. Pre-fix the order was reversed and a hardened drop-in
    // (the Ubuntu Pro / unattended-upgrades pattern) appeared to
    // change nothing because the base file's insecure defaults won.
    let mut full_config = String::new();
    let mut entries: Vec<_> = env.read_dir("/etc/ssh/sshd_config.d");
    // Sort by path so the resolution order is deterministic across
    // filesystems that return readdir() in different orders. This
    // matches the lexicographic order OpenSSH itself uses for
    // `Include /etc/ssh/sshd_config.d/*.conf`.
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    for entry in entries {
        if let Some(content) = env.read_to_string(&entry.path) {
            full_config.push_str(&content);
            full_config.push('\n');
        }
    }
    if let Some(base) = env.read_to_string("/etc/ssh/sshd_config") {
        full_config.push_str(&base);
    }

    let (passed, findings) = evaluate_ssh_config(&full_config, cat);

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_config_value() {
        let config = "\
# comment
Port 2222
PasswordAuthentication yes
  PermitRootLogin no  
";
        assert_eq!(ssh_config_value(config, "Port").unwrap(), "2222");
        assert_eq!(
            ssh_config_value(config, "PasswordAuthentication").unwrap(),
            "yes"
        );
        assert_eq!(ssh_config_value(config, "PermitRootLogin").unwrap(), "no");
        assert_eq!(ssh_config_value(config, "NonExistent"), None);
    }

    #[test]
    fn test_ssh_config_value_takes_last() {
        let config = "\
Port 22
Port 2222
";
        // ssh_config takes the first value, so we must return the first occurrence found in the file.
        assert_eq!(ssh_config_value(config, "Port").unwrap(), "22");
    }

    #[test]
    fn test_evaluate_ssh_config_secure() {
        let config = "\
Port 2222
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
PermitEmptyPasswords no
";
        let (passed, findings) = evaluate_ssh_config(config, "SSH");
        assert_eq!(findings.len(), 0);
        assert_eq!(passed.len(), 5);
    }

    #[test]
    fn test_evaluate_ssh_config_insecure() {
        let config = "\
Port 22
PasswordAuthentication yes
PermitRootLogin yes
MaxAuthTries 6
PermitEmptyPasswords yes
";
        let (passed, findings) = evaluate_ssh_config(config, "SSH");
        assert_eq!(findings.len(), 5);
        assert_eq!(passed.len(), 0);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Password authentication is enabled")));
        assert!(findings.iter().any(|f| f.title.contains("Root login")));
        assert!(findings.iter().any(|f| f.title.contains("default port")));
        assert!(findings.iter().any(|f| f.title.contains("MaxAuthTries")));
        assert!(findings.iter().any(|f| f.title.contains("Empty passwords")));
    }
}
