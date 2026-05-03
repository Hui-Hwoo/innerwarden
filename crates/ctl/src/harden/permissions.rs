use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_permissions(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Permissions";

    // World-writable files in sensitive dirs
    if let Some(raw) = env.command_stdout(
        "find",
        &["/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"],
    ) {
        let files: Vec<&str> = raw.trim().lines().collect();
        if files.is_empty() || (files.len() == 1 && files[0].is_empty()) {
            passed.push("No world-writable files in /etc".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("{} world-writable file(s) in /etc", files.len()),
                fix: format!(
                    "Review and fix: {}",
                    files.into_iter().take(3).collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    // SUID binaries outside standard set
    let standard_suid = [
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/fusermount",
        "/usr/bin/fusermount3",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/snapd/snap-confine",
        "/usr/bin/pkexec",
        "/usr/bin/at",
        "/usr/bin/crontab",
    ];
    if let Some(out) = env.command_stdout("find", &["/usr", "-perm", "-4000", "-type", "f"]) {
        let suids: Vec<String> = out
            .trim()
            .lines()
            .filter(|l| !l.is_empty())
            .filter(|l| !standard_suid.contains(l))
            .map(String::from)
            .collect();
        if suids.is_empty() {
            passed.push("No unusual SUID binaries".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{} non-standard SUID binary(ies)", suids.len()),
                fix: format!(
                    "Review if needed: {}",
                    suids.into_iter().take(5).collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    // /etc/shadow permissions
    if let Some(mode) = env.metadata_mode("/etc/shadow").map(|mode| mode & 0o777) {
        if mode <= 0o640 {
            passed.push(format!("/etc/shadow permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Critical,
                title: format!("/etc/shadow too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 640 /etc/shadow".into(),
            });
        }
    }

    // /etc/gshadow permissions
    if let Some(mode) = env.metadata_mode("/etc/gshadow").map(|mode| mode & 0o777) {
        if mode <= 0o640 {
            passed.push(format!("/etc/gshadow permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("/etc/gshadow too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 640 /etc/gshadow".into(),
            });
        }
    }

    // /etc/sudoers permissions
    if let Some(mode) = env.metadata_mode("/etc/sudoers").map(|mode| mode & 0o777) {
        if mode <= 0o440 {
            passed.push(format!("/etc/sudoers permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("/etc/sudoers too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 440 /etc/sudoers".into(),
            });
        }
    }

    // SSH directory permissions
    for home in ["/root", "/home"] {
        for entry in env.read_dir(home) {
            let ssh_dir = format!("{}/.ssh", entry.path);
            if env.path_exists(&ssh_dir) {
                if let Some(mode) = env.metadata_mode(&ssh_dir).map(|mode| mode & 0o777) {
                    if mode > 0o700 {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: format!("{ssh_dir} too permissive: {mode:03o}"),
                            fix: format!("Run: sudo chmod 700 {ssh_dir}"),
                        });
                    }
                }
                let ak = format!("{ssh_dir}/authorized_keys");
                if let Some(mode) = env.metadata_mode(&ak).map(|mode| mode & 0o777) {
                    if mode > 0o600 {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: format!("{ak} too permissive: {mode:03o}"),
                            fix: format!("Run: sudo chmod 600 {ak}"),
                        });
                    }
                }
            }
        }
    }

    // /tmp sticky bit
    if let Some(mode) = env.metadata_mode("/tmp") {
        if mode & 0o1000 != 0 {
            passed.push("/tmp has sticky bit set".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "/tmp missing sticky bit".into(),
                fix: "Run: sudo chmod +t /tmp".into(),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
