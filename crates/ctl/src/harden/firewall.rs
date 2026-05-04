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
    let mut results = Vec::new();
    for line in ss_output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let local_addr = fields[3];
        if !local_addr.starts_with("0.0.0.0:") {
            continue;
        }
        for (pattern, name) in &risky_ports {
            if line.contains(pattern) && !results.contains(name) {
                results.push(*name);
            }
        }
    }
    results
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewalld_zone_is_recommended() {
        assert!(firewalld_zone_is_recommended("drop"));
        assert!(firewalld_zone_is_recommended("block"));
        assert!(firewalld_zone_is_recommended("public"));
        assert!(!firewalld_zone_is_recommended("trusted"));
        assert!(!firewalld_zone_is_recommended("home"));
    }

    #[test]
    fn test_ufw_is_active() {
        assert!(ufw_is_active("Status: active\nLogging: on"));
        assert!(!ufw_is_active("Status: inactive"));
    }

    #[test]
    fn test_ufw_default_is_deny_incoming() {
        assert!(ufw_default_is_deny_incoming(
            "Status: active\nDefault: deny (incoming), allow (outgoing)"
        ));
        assert!(!ufw_default_is_deny_incoming(
            "Status: active\nDefault: allow (incoming), allow (outgoing)"
        ));
    }

    #[test]
    fn test_risky_open_services() {
        let ss_output = "\
State    Recv-Q   Send-Q   Local Address:Port   Peer Address:Port   Process
LISTEN   0        128      0.0.0.0:3306         0.0.0.0:*           users:((\"mysqld\",pid=1000,fd=10))
LISTEN   0        128      127.0.0.1:5432       0.0.0.0:*           users:((\"postgres\",pid=2000,fd=10))
LISTEN   0        128      0.0.0.0:6379         0.0.0.0:*           users:((\"redis-server\",pid=3000,fd=10))
";
        let risky = risky_open_services(ss_output);
        assert_eq!(risky.len(), 2);
        assert!(risky.contains(&"MySQL"));
        assert!(risky.contains(&"Redis"));
        assert!(!risky.contains(&"PostgreSQL")); // bound to localhost
    }
}
