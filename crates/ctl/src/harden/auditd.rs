use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_auditd(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Auditd";

    // Check if auditd is installed
    let auditd_installed = env.path_exists("/sbin/auditd") || env.path_exists("/usr/sbin/auditd");

    if !auditd_installed {
        findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "auditd not installed".into(),
            fix: "Install auditd: apt-get install auditd (Debian/Ubuntu) or yum install audit (RHEL/Rocky)".into(),
        });
        return CheckResult {
            category: cat,
            passed,
            findings,
        };
    }
    passed.push("auditd installed".into());

    // Check if auditd service is active
    let active = env
        .command_stdout("systemctl", &["is-active", "auditd"])
        .map(|stdout| stdout.trim().to_string())
        .unwrap_or_default();

    if active != "active" {
        findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "auditd service not running".into(),
            fix: "Enable and start auditd: systemctl enable --now auditd".into(),
        });
    } else {
        passed.push("auditd service active".into());
    }

    // Read all audit rules
    let mut rules = String::new();
    if let Some(content) = env.read_to_string("/etc/audit/audit.rules") {
        rules.push_str(&content);
    }
    // Also read rules.d/ directory
    for entry in env.read_dir("/etc/audit/rules.d") {
        if entry.path.ends_with(".rules") {
            if let Some(content) = env.read_to_string(&entry.path) {
                rules.push_str(&content);
            }
        }
    }

    // Critical ATT&CK rules that enable Sigma detection
    let critical_rules: &[(&str, &str, &str)] = &[
        (
            "-S execve",
            "Execution monitoring (T1059)",
            "Tracks all process execution — enables 120+ Sigma process_creation rules",
        ),
        (
            "-w /etc/passwd",
            "Identity file monitoring (T1003)",
            "Detects credential harvesting and user enumeration",
        ),
        (
            "-w /etc/shadow",
            "Credential file monitoring (T1003)",
            "Detects password hash access",
        ),
        (
            "-w /etc/sudoers",
            "Privilege config monitoring (T1548)",
            "Detects sudo policy tampering",
        ),
        (
            "-w /etc/cron",
            "Persistence monitoring (T1053)",
            "Detects crontab-based persistence",
        ),
        (
            "-w /etc/ssh",
            "SSH config monitoring (T1098.004)",
            "Detects SSH key injection and config tampering",
        ),
        (
            "-S connect",
            "Network connection monitoring (T1071)",
            "Tracks outbound connections for C2 detection",
        ),
        (
            "-S ptrace",
            "Process injection monitoring (T1055)",
            "Detects ptrace-based injection and debugging",
        ),
        (
            "-w /tmp -p x",
            "Temp execution monitoring (T1059)",
            "Detects execution from /tmp (common malware staging)",
        ),
        (
            "-S init_module",
            "Kernel module monitoring (T1547.006)",
            "Detects rootkit and kernel module loading",
        ),
    ];

    let mut missing = 0;
    for (rule_fragment, title, description) in critical_rules {
        if rules.contains(rule_fragment) {
            passed.push(format!("{title} enabled"));
        } else {
            missing += 1;
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{title} not configured"),
                fix: format!(
                    "{description}. Add to /etc/audit/rules.d/innerwarden.rules:\n\
                     auditctl -a always,exit -F arch=b64 {rule_fragment} -k innerwarden",
                ),
            });
        }
    }

    if missing == 0 {
        passed.push("All critical audit rules configured".into());
    } else if missing >= 5 {
        findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: format!("{missing}/10 critical audit rules missing"),
            fix: "Install InnerWarden audit rules: innerwarden harden --install-audit-rules \
                  (or copy from https://github.com/InnerWarden/innerwarden/wiki/Operations#auditd)"
                .into(),
        });
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Main command
// ---------------------------------------------------------------------------
