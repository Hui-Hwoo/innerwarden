use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_updates(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Updates";

    // Check for apt-based distros
    if env.path_exists("/usr/bin/apt") {
        if let Some(raw) = env.command_stdout("apt", &["list", "--upgradable"]) {
            let lines: Vec<&str> = raw
                .trim()
                .lines()
                .filter(|l| !l.starts_with("Listing"))
                .collect();
            let security_updates = lines.iter().filter(|l| l.contains("security")).count();

            if lines.is_empty() {
                passed.push("System is up to date".into());
            } else if security_updates > 0 {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::High,
                    title: format!(
                        "{} security update(s) pending ({} total)",
                        security_updates,
                        lines.len()
                    ),
                    fix: "Run: sudo apt update && sudo apt upgrade -y".into(),
                });
            } else {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Low,
                    title: format!("{} package update(s) available", lines.len()),
                    fix: "Run: sudo apt update && sudo apt upgrade -y".into(),
                });
            }
        }

        // Check unattended-upgrades
        if env.path_exists("/etc/apt/apt.conf.d/20auto-upgrades") {
            passed.push("Automatic security updates configured".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "Automatic security updates not configured".into(),
                fix: "Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades".into(),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
