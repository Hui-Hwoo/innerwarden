use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_docker(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Docker";

    // Check if Docker is installed
    if env.command_stdout("docker", &["--version"]).is_none() {
        passed.push("Docker not installed (no container risks)".into());
        return CheckResult {
            category: cat,
            passed,
            findings,
        };
    }

    // Check for privileged containers
    if let Some(containers) =
        env.command_stdout("docker", &["ps", "--format", "{{.Names}} {{.Status}}"])
    {
        let count = containers.trim().lines().filter(|l| !l.is_empty()).count();
        if count > 0 {
            passed.push(format!("{count} container(s) running"));
        }
    }

    if let Some(raw) = env.command_stdout("docker", &["ps", "-q"]) {
        let ids: Vec<&str> = raw.trim().lines().filter(|l| !l.is_empty()).collect();
        for id in &ids {
            if let Some(info) = env.command_stdout(
                "docker",
                &[
                    "inspect",
                    "--format",
                    "{{.Name}} {{.HostConfig.Privileged}}",
                    id,
                ],
            ) {
                if info.contains("true") {
                    let name = info.split_whitespace().next().unwrap_or(id);
                    findings.push(Finding {
                        category: cat,
                        severity: Severity::Critical,
                        title: format!("Container {name} running in privileged mode"),
                        fix: format!("Remove --privileged flag from container {name}"),
                    });
                }
            }
        }
        if findings.is_empty() && !ids.is_empty() {
            passed.push("No privileged containers".into());
        }
    }

    // Docker socket permissions
    if let Some(mode) = env
        .metadata_mode("/var/run/docker.sock")
        .map(|mode| mode & 0o777)
    {
        if mode > 0o660 {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("Docker socket too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 660 /var/run/docker.sock".into(),
            });
        } else {
            passed.push("Docker socket permissions OK".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
