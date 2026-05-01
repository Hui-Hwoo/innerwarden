use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{config_editor, prompt, require_sudo, restart_agent, write_env_key, Cli};

type RestartHook = fn(&Cli);

fn has_min_secret_length(value: &str, min: usize) -> bool {
    value.len() >= min
}

fn parse_abuseipdb_threshold_input(raw: &str) -> Option<u8> {
    raw.parse::<u8>().ok()
}

fn build_watchdog_cron_line(interval_mins: u64, bin: &str) -> String {
    format!("*/{interval_mins} * * * * {bin} watchdog --notify")
}

fn contains_watchdog_entry(current_crontab: &str) -> bool {
    current_crontab.contains("innerwarden watchdog")
}

fn append_cron_line(current_crontab: &str, cron_line: &str) -> String {
    if current_crontab.trim().is_empty() {
        format!("{cron_line}\n")
    } else {
        let trimmed = current_crontab.trim_end();
        format!("{trimmed}\n{cron_line}\n")
    }
}

fn print_geoip_probe_status(probe: impl FnOnce() -> bool) -> Result<()> {
    print!("  Checking ip-api.com connectivity... ");
    std::io::stdout().flush()?;
    if probe() {
        println!("ok");
    } else {
        println!("unreachable (will enable anyway - retried at runtime)");
    }
    Ok(())
}

#[cfg(test)]
fn geoip_probe_reaches_ip_api() -> bool {
    true
}

#[cfg(not(test))]
fn geoip_probe_reaches_ip_api() -> bool {
    ureq::get("http://ip-api.com/json/8.8.8.8?fields=status")
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .call()
        .is_ok()
}

pub(crate) fn cmd_configure_abuseipdb(
    cli: &Cli,
    api_key_arg: Option<&str>,
    auto_block_arg: Option<u8>,
) -> Result<()> {
    cmd_configure_abuseipdb_with_restart(cli, api_key_arg, auto_block_arg, Some(restart_agent))
}

fn cmd_configure_abuseipdb_with_restart(
    cli: &Cli,
    api_key_arg: Option<&str>,
    auto_block_arg: Option<u8>,
    restart: Option<RestartHook>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    let api_key = if let Some(k) = api_key_arg {
        k.to_string()
    } else {
        println!("InnerWarden - AbuseIPDB setup\n");
        println!("AbuseIPDB checks the reputation of every attacking IP before AI analysis.");
        println!("The reputation score (0–100) is injected into the AI prompt so decisions");
        println!("are more confident. IPs with known bad reputation can be blocked instantly");
        println!("without spending an AI token.\n");
        println!("Free tier: 1,000 lookups/day - enough for most servers.\n");
        println!("  1. Go to https://www.abuseipdb.com/register and create a free account");
        println!("  2. Once logged in, go to https://www.abuseipdb.com/account/api");
        println!("  3. Create a new API key and paste it below\n");
        let k = prompt("API key")?;
        if k.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }
        k
    };

    if !has_min_secret_length(&api_key, 10) {
        anyhow::bail!("API key looks too short - copy the full key from abuseipdb.com");
    }

    let threshold: u8 = if let Some(t) = auto_block_arg {
        t
    } else if api_key_arg.is_none() {
        println!("\nAuto-block threshold (0–100, 0 = disabled)");
        println!("  IPs with AbuseIPDB confidence score >= threshold are blocked immediately,");
        println!("  without calling AI. Useful during botnets and DDoS.\n");
        println!("  Recommended: 80  (blocks known botnet IPs, rarely a false positive)");
        println!("  Conservative: 0  (AbuseIPDB enriches AI context only, no auto-block)\n");
        let raw = prompt("Auto-block threshold [80]")?;
        if raw.is_empty() {
            80
        } else if let Some(parsed) = parse_abuseipdb_threshold_input(&raw) {
            parsed
        } else {
            println!("  Invalid value - using 80");
            80
        }
    } else {
        80
    };

    if cli.dry_run {
        println!(
            "\n  [dry-run] would write ABUSEIPDB_API_KEY=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [abuseipdb] enabled=true, auto_block_threshold={threshold} in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    write_env_key(&env_file, "ABUSEIPDB_API_KEY", &api_key)?;
    println!("\n  [ok] API key saved to {}", env_file.display());

    config_editor::write_bool(&cli.agent_config, "abuseipdb", "enabled", true)?;
    config_editor::write_int(
        &cli.agent_config,
        "abuseipdb",
        "auto_block_threshold",
        threshold as i64,
    )?;
    if threshold > 0 {
        println!("  [ok] agent.toml: abuseipdb.enabled = true, auto_block_threshold = {threshold}");
    } else {
        println!("  [ok] agent.toml: abuseipdb.enabled = true (auto-block disabled)");
    }

    if let Some(restart) = restart {
        restart(cli);
    }
    println!();
    if threshold > 0 {
        println!("AbuseIPDB enabled.");
        println!("  → IPs with score >= {threshold} are blocked instantly (no AI call needed).");
        println!("  → All other IPs get reputation context injected into AI analysis.");
    } else {
        println!("AbuseIPDB enabled. IP reputation will appear in AI analysis.");
        println!("  Tip: set auto_block_threshold = 80 to auto-block known botnet IPs.");
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "abuseipdb".to_string(),
        parameters: serde_json::json!({ "auto_block_threshold": threshold }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nRun 'innerwarden doctor' to validate.");
    Ok(())
}

pub(crate) fn cmd_configure_geoip(cli: &Cli) -> Result<()> {
    cmd_configure_geoip_with_options(cli, Some(restart_agent), true)
}

fn cmd_configure_geoip_with_options(
    cli: &Cli,
    restart: Option<RestartHook>,
    probe_connectivity: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    if cli.dry_run {
        println!(
            "[dry-run] would set [geoip] enabled=true in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    println!("InnerWarden - GeoIP setup\n");
    println!("GeoIP adds country and ISP context to AI analysis. No API key needed.");
    println!("Uses ip-api.com (free, 45 lookups/min).\n");

    if probe_connectivity {
        print_geoip_probe_status(geoip_probe_reaches_ip_api)?;
    }

    config_editor::write_bool(&cli.agent_config, "geoip", "enabled", true)?;
    println!("  [ok] agent.toml: geoip.enabled = true");

    if let Some(restart) = restart {
        restart(cli);
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "geoip".to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("GeoIP enabled. Country and ISP will appear in AI decisions.");
    Ok(())
}

pub(crate) fn cmd_configure_cloudflare(
    cli: &Cli,
    zone_id_arg: Option<&str>,
    api_token_arg: Option<&str>,
) -> Result<()> {
    cmd_configure_cloudflare_with_restart(cli, zone_id_arg, api_token_arg, Some(restart_agent))
}

fn cmd_configure_cloudflare_with_restart(
    cli: &Cli,
    zone_id_arg: Option<&str>,
    api_token_arg: Option<&str>,
    restart: Option<RestartHook>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    let (zone_id, api_token) = match (zone_id_arg, api_token_arg) {
        (Some(z), Some(t)) => (z.to_string(), t.to_string()),
        (zone_id_arg, api_token_arg) => {
            println!("InnerWarden - Cloudflare integration setup\n");
            println!("When InnerWarden blocks an IP, it will also push that block to Cloudflare's");
            println!(
                "edge via IP Access Rules - stopping the attacker before they reach your server.\n"
            );
            println!("You need:");
            println!("  1. Zone ID   - right panel of your domain at dash.cloudflare.com");
            println!("  2. API token - dash.cloudflare.com/profile/api-tokens");
            println!("     Use template 'Edit zone DNS' or custom with Zone > Firewall Services > Edit\n");

            let zid = if let Some(z) = zone_id_arg {
                z.to_string()
            } else {
                let z = prompt("Zone ID")?;
                if z.is_empty() {
                    anyhow::bail!("Zone ID cannot be empty");
                }
                z
            };

            let tok = if let Some(t) = api_token_arg {
                t.to_string()
            } else {
                let t = prompt("API token")?;
                if t.is_empty() {
                    anyhow::bail!("API token cannot be empty");
                }
                t
            };

            (zid, tok)
        }
    };

    if !has_min_secret_length(&zone_id, 10) {
        anyhow::bail!("Zone ID looks too short - copy it from the Cloudflare dashboard");
    }
    if !has_min_secret_length(&api_token, 10) {
        anyhow::bail!("API token looks too short - copy the full token from Cloudflare");
    }

    if cli.dry_run {
        println!(
            "\n  [dry-run] would write CLOUDFLARE_API_TOKEN=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [cloudflare] enabled=true, zone_id={zone_id} in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    write_env_key(&env_file, "CLOUDFLARE_API_TOKEN", &api_token)?;
    println!("\n  [ok] API token saved to {}", env_file.display());

    config_editor::write_bool(&cli.agent_config, "cloudflare", "enabled", true)?;
    config_editor::write_str(&cli.agent_config, "cloudflare", "zone_id", &zone_id)?;
    config_editor::write_bool(&cli.agent_config, "cloudflare", "auto_push_blocks", true)?;
    println!("  [ok] agent.toml: cloudflare.enabled = true, zone_id set, auto_push_blocks = true");

    if let Some(restart) = restart {
        restart(cli);
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "cloudflare".to_string(),
        parameters: serde_json::json!({ "zone_id": zone_id }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Cloudflare integration enabled.");
    println!("  → Every blocked IP will be pushed to Cloudflare edge IP Access Rules.");
    println!("  → Attackers are stopped at the CDN before reaching your server.");
    println!("\nRun 'innerwarden doctor' to validate.");
    Ok(())
}

pub(crate) fn cmd_configure_watchdog(cli: &Cli, interval_mins: u64) -> Result<()> {
    cmd_configure_watchdog_for_os(cli, interval_mins, std::env::consts::OS == "macos")
}

fn cmd_configure_watchdog_for_os(cli: &Cli, interval_mins: u64, is_macos: bool) -> Result<()> {
    cmd_configure_watchdog_with_bins(cli, interval_mins, is_macos, None, "crontab")
}

fn cmd_configure_watchdog_with_bins(
    cli: &Cli,
    interval_mins: u64,
    is_macos: bool,
    innerwarden_bin: Option<&str>,
    crontab_bin: &str,
) -> Result<()> {
    if is_macos {
        println!("On macOS, use a launchd plist instead of cron.");
        println!(
            "Create /Library/LaunchDaemons/com.innerwarden.watchdog.plist with an interval of {}s.",
            interval_mins * 60
        );
        println!("Or run: innerwarden watchdog --notify (manually, or via a scheduled job).");
        return Ok(());
    }

    let bin = innerwarden_bin
        .map(|p| p.to_string())
        .or_else(|| which_bin("innerwarden").map(|p| p.display().to_string()))
        .unwrap_or_else(|| "/usr/local/bin/innerwarden".to_string());
    let cron_line = build_watchdog_cron_line(interval_mins, &bin);

    if cli.dry_run {
        println!("[dry-run] would add to crontab:");
        println!("  {cron_line}");
        return Ok(());
    }

    let current = std::process::Command::new(crontab_bin)
        .arg("-l")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    if contains_watchdog_entry(&current) {
        println!("Watchdog cron is already installed:");
        for line in current
            .lines()
            .filter(|l| l.contains("innerwarden watchdog"))
        {
            println!("  {line}");
        }
        println!();
        println!("To update the interval, remove it first with 'crontab -e' and re-run.");
        return Ok(());
    }

    let new_crontab = append_cron_line(&current, &cron_line);

    let mut child = std::process::Command::new(crontab_bin)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to run crontab - is it installed?")?;
    if let Some(stdin) = child.stdin.take() {
        let mut stdin = stdin;
        stdin.write_all(new_crontab.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("crontab returned non-zero exit code");
    }

    println!("  [ok] cron entry added");
    println!();
    println!("Watchdog configured - checks every {interval_mins} minute(s).");
    println!("If the agent stops responding, you'll get a Telegram alert.");
    println!();
    println!("Cron entry:");
    println!("  {cron_line}");
    println!();
    println!("To remove:  crontab -e  (delete the innerwarden watchdog line)");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "watchdog".to_string(),
        parameters: serde_json::json!({ "interval_mins": interval_mins }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

fn which_bin(name: &str) -> Option<PathBuf> {
    std::env::var("PATH").ok()?.split(':').find_map(|dir| {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            Some(p)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_cli(tmp: &TempDir, dry_run: bool) -> Cli {
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        Cli {
            sensor_config: tmp.path().join("config.toml"),
            agent_config: tmp.path().join("agent.toml"),
            data_dir,
            dry_run,
            command: None,
        }
    }

    fn make_cli_without_data_dir(tmp: &TempDir) -> Cli {
        Cli {
            sensor_config: tmp.path().join("config.toml"),
            agent_config: tmp.path().join("agent.toml"),
            data_dir: tmp.path().join("missing-data-dir"),
            dry_run: false,
            command: None,
        }
    }

    fn noop_restart_agent(_cli: &Cli) {}

    fn read_audit_log(cli: &Cli) -> String {
        let path = std::fs::read_dir(&cli.data_dir)
            .expect("read data dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("admin-actions-"))
            })
            .expect("admin action log should exist");
        std::fs::read_to_string(path).expect("read audit log")
    }

    #[test]
    fn has_min_secret_length_enforces_minimum_length() {
        // Ensures API credential validation rejects obviously truncated secrets.
        assert!(has_min_secret_length("1234567890", 10));
        assert!(!has_min_secret_length("12345", 10));
    }

    #[test]
    fn parse_abuseipdb_threshold_input_accepts_numeric_values() {
        // Covers successful threshold parsing for valid integer user input.
        assert_eq!(parse_abuseipdb_threshold_input("0"), Some(0));
        assert_eq!(parse_abuseipdb_threshold_input("80"), Some(80));
        assert_eq!(parse_abuseipdb_threshold_input("100"), Some(100));
    }

    #[test]
    fn parse_abuseipdb_threshold_input_rejects_invalid_values() {
        // Guards fallback path so malformed thresholds trigger default handling upstream.
        assert_eq!(parse_abuseipdb_threshold_input(""), None);
        assert_eq!(parse_abuseipdb_threshold_input("abc"), None);
        assert_eq!(parse_abuseipdb_threshold_input("-1"), None);
    }

    #[test]
    fn parse_abuseipdb_threshold_input_keeps_u8_values_without_range_clamp() {
        // Documents current behavior: parser accepts any valid u8 and leaves policy range checks to callers.
        assert_eq!(parse_abuseipdb_threshold_input("200"), Some(200));
    }

    #[test]
    fn build_watchdog_cron_line_renders_expected_schedule() {
        // Verifies cron command generation remains deterministic for watchdog setup.
        let line = build_watchdog_cron_line(15, "/usr/local/bin/innerwarden");
        assert_eq!(
            line,
            "*/15 * * * * /usr/local/bin/innerwarden watchdog --notify"
        );
    }

    #[test]
    fn contains_watchdog_entry_detects_existing_installation() {
        // Ensures duplicate-installation guard triggers when a watchdog entry already exists.
        let current =
            "0 0 * * * backup\n*/5 * * * * /usr/local/bin/innerwarden watchdog --notify\n";
        assert!(contains_watchdog_entry(current));
        assert!(!contains_watchdog_entry("0 0 * * * backup\n"));
    }

    #[test]
    fn append_cron_line_handles_empty_and_existing_crontabs() {
        // Covers merge behavior for first install and append-to-existing installs.
        let cron_line = "*/10 * * * * /usr/local/bin/innerwarden watchdog --notify";
        let empty = append_cron_line("", cron_line);
        assert_eq!(empty, format!("{cron_line}\n"));

        let current = "0 0 * * * backup\n";
        let merged = append_cron_line(current, cron_line);
        assert_eq!(merged, format!("0 0 * * * backup\n{cron_line}\n"));
    }

    #[test]
    fn print_geoip_probe_status_handles_success_and_failure() {
        print_geoip_probe_status(|| true).expect("successful probe status should render");
        print_geoip_probe_status(|| false).expect("failed probe status should render");
    }

    #[test]
    fn cmd_configure_abuseipdb_dry_run_accepts_valid_key_and_threshold() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        cmd_configure_abuseipdb(&cli, Some("0123456789abcdef"), Some(90))
            .expect("dry-run abuseipdb config should pass");
    }

    #[test]
    fn cmd_configure_abuseipdb_rejects_short_key() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        let err = cmd_configure_abuseipdb(&cli, Some("short"), Some(80))
            .expect_err("short key should fail");

        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn cmd_configure_abuseipdb_writes_config_env_and_audit() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, false);

        cmd_configure_abuseipdb_with_restart(
            &cli,
            Some("0123456789abcdef"),
            Some(90),
            Some(noop_restart_agent),
        )
        .expect("abuseipdb config should write files");

        let env = std::fs::read_to_string(tmp.path().join("agent.env")).expect("read env");
        assert_eq!(env, "ABUSEIPDB_API_KEY=0123456789abcdef\n");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("[abuseipdb]"));
        assert!(agent.contains("enabled = true"));
        assert!(agent.contains("auto_block_threshold = 90"));

        let audit = read_audit_log(&cli);
        assert!(audit.contains("\"target\":\"abuseipdb\""));
        assert!(audit.contains("\"auto_block_threshold\":90"));
    }

    #[test]
    fn cmd_configure_abuseipdb_writes_zero_threshold() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, false);

        cmd_configure_abuseipdb_with_restart(&cli, Some("0123456789abcdef"), Some(0), None)
            .expect("abuseipdb zero threshold should write files");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("auto_block_threshold = 0"));
    }

    #[test]
    fn cmd_configure_geoip_dry_run_returns_ok() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        cmd_configure_geoip(&cli).expect("dry-run geoip should pass");
    }

    #[test]
    fn cmd_configure_geoip_writes_config_and_audit_without_probe() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, false);

        cmd_configure_geoip_with_options(&cli, Some(noop_restart_agent), false)
            .expect("geoip config should write files");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("[geoip]"));
        assert!(agent.contains("enabled = true"));

        let audit = read_audit_log(&cli);
        assert!(audit.contains("\"target\":\"geoip\""));
    }

    #[test]
    fn cmd_configure_geoip_tolerates_audit_write_failure() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli_without_data_dir(&tmp);

        cmd_configure_geoip_with_options(&cli, None, false)
            .expect("geoip config should not fail when audit write fails");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("[geoip]"));
        assert!(agent.contains("enabled = true"));
    }

    #[test]
    fn cmd_configure_geoip_writes_config_with_probe_enabled() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, false);

        cmd_configure_geoip_with_options(&cli, None, true)
            .expect("geoip config should write files when probe is enabled");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("[geoip]"));
        assert!(agent.contains("enabled = true"));
    }

    #[test]
    fn cmd_configure_cloudflare_dry_run_accepts_valid_inputs() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        cmd_configure_cloudflare(&cli, Some("zoneid0123456789"), Some("token0123456789"))
            .expect("dry-run cloudflare config should pass");
    }

    #[test]
    fn cmd_configure_cloudflare_rejects_short_zone_or_token() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        let zone_err = cmd_configure_cloudflare(&cli, Some("short"), Some("token0123456789"))
            .expect_err("short zone should fail");
        assert!(zone_err.to_string().contains("Zone ID looks too short"));

        let token_err = cmd_configure_cloudflare(&cli, Some("zoneid0123456789"), Some("short"))
            .expect_err("short token should fail");
        assert!(token_err.to_string().contains("API token looks too short"));
    }

    #[test]
    fn cmd_configure_cloudflare_writes_config_env_and_audit() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, false);

        cmd_configure_cloudflare_with_restart(
            &cli,
            Some("zoneid0123456789"),
            Some("token0123456789"),
            Some(noop_restart_agent),
        )
        .expect("cloudflare config should write files");

        let env = std::fs::read_to_string(tmp.path().join("agent.env")).expect("read env");
        assert_eq!(env, "CLOUDFLARE_API_TOKEN=token0123456789\n");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("[cloudflare]"));
        assert!(agent.contains("enabled = true"));
        assert!(agent.contains("zone_id = \"zoneid0123456789\""));
        assert!(agent.contains("auto_push_blocks = true"));

        let audit = read_audit_log(&cli);
        assert!(audit.contains("\"target\":\"cloudflare\""));
        assert!(audit.contains("\"zone_id\":\"zoneid0123456789\""));
    }

    #[test]
    fn cmd_configure_watchdog_for_os_documents_macos_path() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        cmd_configure_watchdog_for_os(&cli, 5, true).expect("macos watchdog guidance should pass");
    }

    #[test]
    fn cmd_configure_watchdog_for_os_dry_run_builds_cron_path() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        cmd_configure_watchdog_for_os(&cli, 5, false)
            .expect("non-macos dry-run watchdog cron should pass");
    }

    #[test]
    fn cmd_configure_watchdog_public_wrapper_returns_ok_in_dry_run() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(&tmp, true);

        cmd_configure_watchdog(&cli, 5).expect("watchdog wrapper should pass");
    }

    #[test]
    fn which_bin_finds_binary_on_path_and_returns_none_when_missing() {
        assert!(which_bin("sh").is_some() || which_bin("zsh").is_some());
        assert_eq!(which_bin("missing"), None);
    }

    #[test]
    fn cmd_configure_watchdog_for_os_installs_with_fake_crontab() {
        let tmp = TempDir::new().expect("tempdir");
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create fake bin dir");

        let innerwarden = bin_dir.join("innerwarden");
        std::fs::write(&innerwarden, "#!/bin/sh\nexit 0\n").expect("write fake innerwarden");
        let crontab_capture = tmp.path().join("captured-crontab");
        let crontab = bin_dir.join("crontab");
        std::fs::write(
            &crontab,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-l\" ]; then exit 1; fi\n/bin/cat > {}\n",
                crontab_capture.display()
            ),
        )
        .expect("write fake crontab");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&innerwarden, std::fs::Permissions::from_mode(0o755))
                .expect("chmod innerwarden");
            std::fs::set_permissions(&crontab, std::fs::Permissions::from_mode(0o755))
                .expect("chmod crontab");
        }

        let cli = make_cli(&tmp, false);
        cmd_configure_watchdog_with_bins(
            &cli,
            7,
            false,
            Some(innerwarden.to_str().expect("utf8 fake innerwarden")),
            crontab.to_str().expect("utf8 fake crontab"),
        )
        .expect("watchdog install should use fake crontab");

        let captured = std::fs::read_to_string(crontab_capture).expect("read captured crontab");
        assert!(captured.contains("*/7 * * * *"));
        assert!(captured.contains("innerwarden watchdog --notify"));

        let audit = read_audit_log(&cli);
        assert!(audit.contains("\"target\":\"watchdog\""));
        assert!(audit.contains("\"interval_mins\":7"));
    }
}
