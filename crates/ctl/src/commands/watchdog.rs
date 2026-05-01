use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{hostname, load_env_file, resolve_data_dir, send_telegram_message_md, Cli};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelemetryAgeStatus {
    Fresh,
    Recent,
    Stale,
}

fn local_today_yesterday() -> (String, String) {
    let now = chrono::Local::now();
    (
        now.format("%Y-%m-%d").to_string(),
        (now - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string(),
    )
}

fn telemetry_path_for_dates(dir: &Path, today: &str, yesterday: &str) -> Option<PathBuf> {
    let today_p = dir.join(format!("telemetry-{today}.jsonl"));
    let yest_p = dir.join(format!("telemetry-{yesterday}.jsonl"));

    if today_p.exists() {
        Some(today_p)
    } else if yest_p.exists() {
        Some(yest_p)
    } else {
        None
    }
}

fn file_mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

fn telemetry_age_status(age_secs: u64) -> TelemetryAgeStatus {
    if age_secs < 120 {
        TelemetryAgeStatus::Fresh
    } else if age_secs < 300 {
        TelemetryAgeStatus::Recent
    } else {
        TelemetryAgeStatus::Stale
    }
}

fn active_watchdog_cron_entry(crontab: &str) -> Option<&str> {
    crontab
        .lines()
        .find(|line| line.contains("innerwarden watchdog") && !line.trim_start().starts_with('#'))
}

fn cron_interval_minutes(line: &str) -> Option<u64> {
    line.split_whitespace()
        .next()
        .and_then(|s| s.strip_prefix("*/"))
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|minutes| (1..=59).contains(minutes))
}

pub(crate) fn cmd_watchdog(
    cli: &Cli,
    threshold_secs: u64,
    notify: bool,
    data_dir: &std::path::Path,
) -> Result<()> {
    // Try to read data_dir from agent.toml if using default
    let effective_dir = resolve_data_dir(cli, data_dir);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Format today and yesterday as YYYY-MM-DD using chrono
    let (today_str, yesterday_str) = local_today_yesterday();

    // Find the most recent telemetry file
    let telemetry_path = match telemetry_path_for_dates(&effective_dir, &today_str, &yesterday_str)
    {
        Some(path) => path,
        None => {
            println!("⚠️  No telemetry file found in {}", effective_dir.display());
            println!("   The agent may not be running: innerwarden status");
            if notify {
                maybe_send_watchdog_alert(
                    cli,
                    "InnerWarden agent appears offline - no telemetry files found.",
                );
            }
            return Ok(());
        }
    };

    // Use file mtime as the last-activity timestamp (most reliable)
    let last_ts_secs = file_mtime_secs(&telemetry_path);

    match last_ts_secs {
        Some(ts) => {
            let age = now_secs.saturating_sub(ts);
            if age > threshold_secs {
                println!("⚠️  Agent appears unhealthy - last activity {}s ago (threshold: {threshold_secs}s)", age);
                println!("   Check status: innerwarden status");
                println!("   Check logs:   journalctl -u innerwarden-agent -n 50");
                if notify {
                    let msg = format!(
                        "⚠️ InnerWarden agent appears unhealthy on {}.\nLast activity: {}s ago (threshold: {}s).",
                        hostname(),
                        age,
                        threshold_secs
                    );
                    maybe_send_watchdog_alert(cli, &msg);
                }
                std::process::exit(1);
            } else {
                println!("✅ Agent is healthy - last activity {}s ago", age);
            }

            // Memory check - restart agent if RSS exceeds 512MB
            let max_rss_kb: u64 = 512 * 1024;
            if let Some(rss_kb) = get_agent_rss_kb() {
                let rss_mb = rss_kb / 1024;
                if rss_kb > max_rss_kb {
                    println!(
                        "⚠️  Agent memory too high: {}MB (limit: {}MB) - restarting",
                        rss_mb,
                        max_rss_kb / 1024
                    );
                    let _ = std::process::Command::new("sudo")
                        .args(["systemctl", "restart", "innerwarden-agent"])
                        .status();
                    if notify {
                        let msg = format!(
                            "⚠️ InnerWarden agent on {} was using {}MB RAM (limit: {}MB). Auto-restarted.",
                            hostname(),
                            rss_mb,
                            max_rss_kb / 1024
                        );
                        maybe_send_watchdog_alert(cli, &msg);
                    }
                } else {
                    println!("✅ Agent memory OK - {}MB", rss_mb);
                }
            }
        }
        None => {
            println!(
                "⚠️  Could not determine agent liveness from {}",
                telemetry_path.display()
            );
            if notify {
                maybe_send_watchdog_alert(
                    cli,
                    "InnerWarden watchdog could not verify agent health.",
                );
            }
        }
    }

    Ok(())
}

/// Read the RSS (resident set size) of the innerwarden-agent process in KB.
/// Returns None if the process is not found or /proc is not available.
fn get_agent_rss_kb() -> Option<u64> {
    let output = std::process::Command::new("pgrep")
        .args(["-f", "innerwarden-agent"])
        .output()
        .ok()?;
    let pids = String::from_utf8_lossy(&output.stdout);
    // Get the main agent PID (the actual binary, not sudo wrapper)
    for pid_str in pids.lines() {
        let pid = pid_str.trim();
        if pid.is_empty() {
            continue;
        }
        let status_path = format!("/proc/{pid}/status");
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if kb > 0 {
                        return Some(kb);
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// innerwarden watchdog --status
// ---------------------------------------------------------------------------

pub(crate) fn cmd_watchdog_status(cli: &Cli, data_dir: &Path) -> Result<()> {
    println!("Watchdog Status");
    println!("{}", "─".repeat(56));

    // ── Cron entry ────────────────────────────────────────
    println!("\nCron schedule");
    let crontab = std::process::Command::new("crontab").arg("-l").output();

    match crontab {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            match active_watchdog_cron_entry(&text) {
                Some(line) => {
                    println!("  ✅ Installed: {line}");
                    // Parse interval from */N prefix
                    if let Some(interval) = cron_interval_minutes(line) {
                        println!("     Runs every {interval} minute(s)");
                    }
                }
                None => {
                    println!("  ○ Not installed");
                    println!(
                        "    Run 'innerwarden configure watchdog' to set up automatic monitoring."
                    );
                }
            }
        }
        Ok(_) => {
            println!("  ○ No crontab for current user");
            println!("    Run 'innerwarden configure watchdog' to set up automatic monitoring.");
        }
        Err(_) => {
            println!("  ○ crontab command not available");
            println!("    On macOS you may need to configure launchd manually.");
            println!("    See: innerwarden configure watchdog");
        }
    }

    // ── Last agent activity ───────────────────────────────
    println!("\nAgent health");
    let effective_dir = resolve_data_dir(cli, data_dir);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (today, yesterday) = local_today_yesterday();

    let telemetry_path = telemetry_path_for_dates(&effective_dir, &today, &yesterday);

    match telemetry_path {
        None => {
            println!("  ⚠️  No telemetry file found - agent may not be running");
            println!("     Run 'innerwarden status' to check.");
        }
        Some(ref path) => {
            let mtime_secs = file_mtime_secs(path);

            match mtime_secs {
                None => println!("  ⚠️  Could not read telemetry file mtime"),
                Some(ts) => {
                    let age = now_secs.saturating_sub(ts);
                    match telemetry_age_status(age) {
                        TelemetryAgeStatus::Fresh => {
                            println!("  ✅ Agent is healthy - last write {age}s ago");
                        }
                        TelemetryAgeStatus::Recent => {
                            println!("  ✅ Agent last wrote telemetry {age}s ago");
                        }
                        TelemetryAgeStatus::Stale => {
                            println!("  ⚠️  Agent last wrote telemetry {age}s ago - may be stuck");
                            println!("     Run 'innerwarden watchdog' to run a full health check.");
                        }
                    }
                }
            }
        }
    }

    // ── Quick tip ─────────────────────────────────────────
    println!("\nUseful commands");
    println!("  innerwarden watchdog            - run a health check now");
    println!("  innerwarden watchdog --notify   - check and alert via Telegram if unhealthy");
    println!("  innerwarden configure watchdog  - set up or change the cron schedule");

    Ok(())
}

fn watchdog_alert_credentials(cli: &Cli) -> Option<(String, String)> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);

    let token = env_vars
        .get("TELEGRAM_BOT_TOKEN")
        .cloned()
        .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok());
    let chat_id = env_vars
        .get("TELEGRAM_CHAT_ID")
        .cloned()
        .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok());

    match (token, chat_id) {
        (Some(tok), Some(cid)) if !tok.is_empty() && !cid.is_empty() => Some((tok, cid)),
        _ => None,
    }
}

fn maybe_send_watchdog_alert(cli: &Cli, message: &str) {
    if let Some((tok, cid)) = watchdog_alert_credentials(cli) {
        let _ = send_telegram_message_md(&tok, &cid, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::TempDir;

    fn test_cli(temp: &TempDir) -> Cli {
        let mut cli = Cli::parse_from(["innerwarden", "replay"]);
        cli.sensor_config = temp.path().join("sensor.toml");
        cli.agent_config = temp.path().join("agent.toml");
        cli.data_dir = temp.path().join("data");
        cli.dry_run = true;
        std::fs::create_dir_all(&cli.data_dir).expect("test should create data dir");
        std::fs::write(&cli.sensor_config, "").expect("test should create sensor config");
        std::fs::write(&cli.agent_config, "").expect("test should create agent config");
        cli
    }

    #[test]
    fn watchdog_status_data_dir_uses_explicit_data_dir() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let explicit = temp.path().join("explicit-data");

        assert_eq!(resolve_data_dir(&cli, &explicit), explicit);
    }

    #[test]
    fn watchdog_status_data_dir_reads_default_from_agent_config() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let configured = temp.path().join("configured-data");
        std::fs::write(
            &cli.agent_config,
            format!(
                "[output]\ndata_dir = \"{}\"\n",
                configured.to_string_lossy().replace('\\', "\\\\")
            ),
        )
        .expect("test should write agent config");

        assert_eq!(
            resolve_data_dir(&cli, Path::new("/var/lib/innerwarden")),
            configured
        );
    }

    #[test]
    fn watchdog_status_data_dir_keeps_default_when_config_missing_or_invalid() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(&cli.agent_config, "not toml").expect("test should write agent config");

        assert_eq!(
            resolve_data_dir(&cli, Path::new("/var/lib/innerwarden")),
            PathBuf::from("/var/lib/innerwarden")
        );
    }

    #[test]
    fn telemetry_path_for_dates_prefers_today_over_yesterday() {
        let temp = TempDir::new().expect("test should create temp dir");
        let today = temp.path().join("telemetry-2026-05-01.jsonl");
        let yesterday = temp.path().join("telemetry-2026-04-30.jsonl");
        std::fs::write(&yesterday, "").expect("test should write yesterday telemetry");
        std::fs::write(&today, "").expect("test should write today telemetry");

        assert_eq!(
            telemetry_path_for_dates(temp.path(), "2026-05-01", "2026-04-30"),
            Some(today)
        );
    }

    #[test]
    fn telemetry_path_for_dates_falls_back_to_yesterday() {
        let temp = TempDir::new().expect("test should create temp dir");
        let yesterday = temp.path().join("telemetry-2026-04-30.jsonl");
        std::fs::write(&yesterday, "").expect("test should write yesterday telemetry");

        assert_eq!(
            telemetry_path_for_dates(temp.path(), "2026-05-01", "2026-04-30"),
            Some(yesterday)
        );
    }

    #[test]
    fn telemetry_path_for_dates_returns_none_when_missing() {
        let temp = TempDir::new().expect("test should create temp dir");

        assert_eq!(
            telemetry_path_for_dates(temp.path(), "2026-05-01", "2026-04-30"),
            None
        );
    }

    #[test]
    fn file_mtime_secs_reads_existing_file() {
        let temp = TempDir::new().expect("test should create temp dir");
        let file = temp.path().join("telemetry-2026-05-01.jsonl");
        std::fs::write(&file, "{}\n").expect("test should write telemetry");

        assert!(file_mtime_secs(&file).is_some());
        assert_eq!(file_mtime_secs(&temp.path().join("missing.jsonl")), None);
    }

    #[test]
    fn telemetry_age_status_classifies_thresholds() {
        assert_eq!(telemetry_age_status(0), TelemetryAgeStatus::Fresh);
        assert_eq!(telemetry_age_status(119), TelemetryAgeStatus::Fresh);
        assert_eq!(telemetry_age_status(120), TelemetryAgeStatus::Recent);
        assert_eq!(telemetry_age_status(299), TelemetryAgeStatus::Recent);
        assert_eq!(telemetry_age_status(300), TelemetryAgeStatus::Stale);
    }

    #[test]
    fn active_watchdog_cron_entry_ignores_comments() {
        let crontab = "\
# */1 * * * * innerwarden watchdog
*/5 * * * * /usr/local/bin/innerwarden watchdog --notify
";

        assert_eq!(
            active_watchdog_cron_entry(crontab),
            Some("*/5 * * * * /usr/local/bin/innerwarden watchdog --notify")
        );
        assert_eq!(
            active_watchdog_cron_entry("# */5 * * * * innerwarden watchdog"),
            None
        );
    }

    #[test]
    fn cron_interval_minutes_parses_step_prefix() {
        assert_eq!(
            cron_interval_minutes("*/5 * * * * innerwarden watchdog"),
            Some(5)
        );
        assert_eq!(
            cron_interval_minutes("*/59 * * * * innerwarden watchdog"),
            Some(59)
        );
        assert_eq!(
            cron_interval_minutes("* * * * * innerwarden watchdog"),
            None
        );
        assert_eq!(
            cron_interval_minutes("*/0 * * * * innerwarden watchdog"),
            None
        );
        assert_eq!(
            cron_interval_minutes("*/60 * * * * innerwarden watchdog"),
            None
        );
        assert_eq!(
            cron_interval_minutes("*/bad * * * * innerwarden watchdog"),
            None
        );
    }

    #[test]
    fn watchdog_alert_credentials_reads_agent_env_file() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            temp.path().join("agent.env"),
            "TELEGRAM_BOT_TOKEN=\"tok\"\nTELEGRAM_CHAT_ID=chat\n",
        )
        .expect("test should write agent env");

        assert_eq!(
            watchdog_alert_credentials(&cli),
            Some(("tok".to_string(), "chat".to_string()))
        );
    }

    #[test]
    fn watchdog_alert_credentials_rejects_missing_or_empty_values() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        assert_eq!(watchdog_alert_credentials(&cli), None);

        std::fs::write(
            temp.path().join("agent.env"),
            "TELEGRAM_BOT_TOKEN=\nTELEGRAM_CHAT_ID=chat\n",
        )
        .expect("test should write agent env");
        assert_eq!(watchdog_alert_credentials(&cli), None);
    }

    #[test]
    fn cmd_watchdog_without_telemetry_returns_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        assert!(cmd_watchdog(&cli, 120, false, &cli.data_dir).is_ok());
    }

    #[test]
    fn cmd_watchdog_without_telemetry_notify_returns_ok_without_credentials() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        std::fs::write(
            temp.path().join("agent.env"),
            "TELEGRAM_BOT_TOKEN=\nTELEGRAM_CHAT_ID=\n",
        )
        .expect("test should write empty agent env");

        assert!(cmd_watchdog(&cli, 120, true, &cli.data_dir).is_ok());
    }

    #[test]
    fn cmd_watchdog_with_fresh_telemetry_returns_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let (today, _) = local_today_yesterday();
        std::fs::write(
            cli.data_dir.join(format!("telemetry-{today}.jsonl")),
            "{}\n",
        )
        .expect("test should write telemetry");

        assert!(cmd_watchdog(&cli, 3600, false, &cli.data_dir).is_ok());
    }

    #[test]
    fn cmd_watchdog_status_without_telemetry_returns_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        assert!(cmd_watchdog_status(&cli, &cli.data_dir).is_ok());
    }

    #[test]
    fn cmd_watchdog_status_with_today_telemetry_returns_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let (today, _) = local_today_yesterday();
        std::fs::write(
            cli.data_dir.join(format!("telemetry-{today}.jsonl")),
            "{}\n",
        )
        .expect("test should write telemetry");

        assert!(cmd_watchdog_status(&cli, &cli.data_dir).is_ok());
    }

    #[test]
    fn cmd_watchdog_status_with_yesterday_telemetry_returns_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let (_, yesterday) = local_today_yesterday();
        std::fs::write(
            cli.data_dir.join(format!("telemetry-{yesterday}.jsonl")),
            "{}\n",
        )
        .expect("test should write telemetry");

        assert!(cmd_watchdog_status(&cli, &cli.data_dir).is_ok());
    }
}
