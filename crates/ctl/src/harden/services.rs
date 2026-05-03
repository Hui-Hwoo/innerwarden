use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn is_service_exposure_line_safe(line: &str) -> bool {
    line.contains(":22 ")
        || line.contains(":80 ")
        || line.contains(":443 ")
        || line.contains(":53 ")
        || line.contains(":8787 ")
        || line.contains(":8790 ")
        || line.contains(":2222 ")
        || line.contains("innerwarden")
        || line.contains("docker-proxy")
        || line.contains("containerd")
}

pub(super) fn exposed_service_lines(ss_output: &str) -> Vec<String> {
    ss_output
        .lines()
        .filter(|line| line.contains("0.0.0.0:") || line.contains(":::"))
        .filter(|line| !is_service_exposure_line_safe(line))
        .map(|line| line.to_string())
        .collect()
}

pub(super) fn check_services(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Services";

    // Check for commonly exploited services exposed on all interfaces
    if let Some(lines) = env.command_stdout("ss", &["-tlnp"]) {
        let listening_all = exposed_service_lines(&lines);

        if listening_all.len() > 5 {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{} services exposed on all interfaces", listening_all.len()),
                fix: "Review services binding to 0.0.0.0 - bind to 127.0.0.1 where possible".into(),
            });
        } else {
            passed.push("Service exposure looks reasonable".into());
        }
    }

    // Check fail2ban or equivalent
    let has_iw = env
        .command_stdout("systemctl", &["is-active", "innerwarden-agent"])
        .map(|stdout| stdout.trim() == "active")
        .unwrap_or(false);

    if has_iw {
        passed.push("Inner Warden agent is active".into());
    } else {
        findings.push(Finding {
            category: cat,
            severity: Severity::Medium,
            title: "Inner Warden agent is not running".into(),
            fix: "Run: sudo systemctl start innerwarden-agent".into(),
        });
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
