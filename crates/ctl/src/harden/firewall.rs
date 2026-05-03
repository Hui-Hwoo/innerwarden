use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn firewalld_zone_is_recommended(zone: &str) -> bool {
    matches!(zone, "drop" | "block" | "public")
}

pub(super) fn ufw_is_active(status: &str) -> bool {
    status.contains("Status: active")
}

pub(super) fn ufw_default_is_deny_incoming(status: &str) -> bool {
    status.contains("Default: deny (incoming)")
}

pub(super) fn risky_open_services(ss_output: &str) -> Vec<&'static str> {
    let risky_ports: Vec<(&str, &str)> = vec![
        (":3306 ", "MySQL"),
        (":5432 ", "PostgreSQL"),
        (":6379 ", "Redis"),
        (":27017", "MongoDB"),
        (":11211", "Memcached"),
    ];
    risky_ports
        .into_iter()
        .filter_map(|(pattern, name)| {
            if ss_output.contains(pattern) && ss_output.contains("0.0.0.0:") {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn check_firewall(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Firewall";

    // Check firewalld first (RHEL/Rocky/CentOS/Fedora), then UFW (Debian/Ubuntu),
    // then iptables as fallback.
    let firewalld_active = env
        .command_stdout("firewall-cmd", &["--state"])
        .map(|stdout| stdout.trim() == "running")
        .unwrap_or(false);

    if firewalld_active {
        passed.push("firewalld is active".into());
        // Check default zone policy
        if let Some(out) = env.command_stdout("firewall-cmd", &["--get-default-zone"]) {
            let zone = out.trim().to_string();
            if firewalld_zone_is_recommended(&zone) {
                passed.push(format!("Default zone: {zone}"));
            } else {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Medium,
                    title: format!(
                        "Default firewalld zone is '{}' — consider 'public' or 'drop'",
                        zone
                    ),
                    fix: "Run: sudo firewall-cmd --set-default-zone=public".into(),
                });
            }
        }
    } else {
        // Check UFW (try sudo first, fall back to non-sudo; use verbose for default policy)
        let ufw = env
            .command_stdout("sudo", &["ufw", "status", "verbose"])
            .or_else(|| env.command_stdout("ufw", &["status", "verbose"]));
        match ufw {
            Some(status) => {
                if ufw_is_active(&status) {
                    passed.push("UFW firewall is active".into());

                    // Check default policy
                    if ufw_default_is_deny_incoming(&status) {
                        passed.push("Default incoming policy: deny".into());
                    } else {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: "Default incoming policy is not 'deny'".into(),
                            fix: "Run: sudo ufw default deny incoming".into(),
                        });
                    }
                } else {
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::Critical,
                        title: "Firewall (UFW) is not active".into(),
                        fix: "Run: sudo ufw enable".into(),
                    });
                }
            }
            None => {
                // Check iptables/nftables as fallback
                let ipt = env.command_stdout("iptables", &["-L", "-n"]);
                match ipt {
                    Some(rules) => {
                        if rules.lines().count() > 5 {
                            passed.push("iptables rules configured".into());
                        } else {
                            findings.push(Finding {
                                category: cat,
                                severity: Severity::High,
                                title: "No firewall rules detected".into(),
                                fix: "Install and configure a firewall: ufw (Debian/Ubuntu) or firewalld (RHEL/Rocky)".into(),
                            });
                        }
                    }
                    None => findings.push(Finding {
                        category: cat,
                        severity: Severity::High,
                        title: "No firewall detected".into(),
                        fix: "Install a firewall: ufw (Debian/Ubuntu) or firewalld (RHEL/Rocky)"
                            .into(),
                    }),
                }
            }
        }
    }

    // Check open ports
    if let Some(lines) = env.command_stdout("ss", &["-tlnp"]) {
        for service in risky_open_services(&lines) {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("{service} is listening on all interfaces"),
                fix: format!(
                    "Bind {service} to 127.0.0.1 only, or restrict access with firewall rules"
                ),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
