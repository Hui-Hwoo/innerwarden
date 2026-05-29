use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::capability::CapabilityRegistry;
use crate::module_manifest::{is_module_enabled, scan_modules_dir};
use crate::{
    count_jsonl_lines, epoch_secs_to_date, make_opts, read_last_incident_summary, resolve_data_dir,
    systemd, today_date_string, unknown_cap_error, yesterday_date_string, Cli,
};

fn resolve_report_date(date_arg: &str, today: &str, yesterday: &str) -> String {
    match date_arg {
        "today" => today.to_string(),
        "yesterday" => yesterday.to_string(),
        other => other.to_string(),
    }
}

fn summary_dates_from_filenames(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("summary-")
                .and_then(|s| s.strip_suffix(".md"))
                .map(|d| d.to_string())
        })
        .collect()
}

pub(crate) fn cmd_status(cli: &Cli, registry: &CapabilityRegistry, id: &str) -> Result<()> {
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), false);
    let status = if cap.is_enabled(&opts) {
        "enabled"
    } else {
        "disabled"
    };
    println!("Capability:  {}", cap.name());
    println!("ID:          {}", cap.id());
    println!("Status:      {status}");
    println!("Description: {}", cap.description());
    Ok(())
}

pub(crate) fn cmd_status_global(
    cli: &Cli,
    registry: &CapabilityRegistry,
    modules_dir: &Path,
) -> Result<()> {
    println!("InnerWarden Status");
    println!("{}", "═".repeat(56));

    println!("\nServices");
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        let active = systemd::is_service_active(unit);
        let indicator = if active { "●" } else { "○" };
        let label = if active { "running" } else { "stopped" };
        println!("  {indicator} {unit:<28} {label}");
    }

    let data_dir: Option<PathBuf> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|doc| {
            doc.get("output")
                .and_then(|o| o.get("data_dir"))
                .and_then(|d| d.as_str())
                .map(PathBuf::from)
        })
        .or_else(|| Some(PathBuf::from("/var/lib/innerwarden")));

    if let Some(ref dir) = data_dir {
        let today = today_date_string();
        let events_count = count_jsonl_lines(&dir.join(format!("events-{today}.jsonl")));
        let incidents_count = count_jsonl_lines(&dir.join(format!("incidents-{today}.jsonl")));
        let last_incident =
            read_last_incident_summary(&dir.join(format!("incidents-{today}.jsonl")));

        println!("\nToday  ({})", today);
        println!("  Events logged:    {events_count}");
        println!("  Threats detected: {incidents_count}");
        if let Some((title, when)) = last_incident {
            println!("  Last threat:      {title}  [{when}]");
        } else if incidents_count == 0 {
            println!("  Last threat:      none - quiet day so far");
        }
    }

    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|a| a.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ai_provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|a| a.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();
    let responder_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("responder"))
        .and_then(|r| r.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dry_run = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("responder"))
        .and_then(|r| r.get("dry_run"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    println!("\nAI & Response");
    if ai_enabled {
        println!("  ● AI analysis     active  ({ai_provider})");
    } else {
        println!("  ○ AI analysis     disabled");
    }
    // Single source of truth for "is the agent actually acting?": the
    // posture headline + CTA are shared with the agent boot log and the
    // installer, so the operator reads the same sentence everywhere.
    let posture =
        innerwarden_core::policy::EnforcementPosture::from_responder(responder_enabled, dry_run);
    let indicator = if posture.is_enforcing() { "●" } else { "○" };
    println!("  {indicator} Responder       {}", posture.headline());
    if let Some(cta) = posture.cta() {
        println!("      {cta}");
    }

    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    for cap in registry.all() {
        let enabled = cap.is_enabled(&opts);
        let indicator = if enabled { "●" } else { "○" };
        let label = if enabled { "enabled " } else { "disabled" };
        println!(
            "  {indicator} {:<20} {}  {}",
            cap.id(),
            label,
            cap.description()
        );
    }

    println!("\nModules  ({})", modules_dir.display());
    let modules = scan_modules_dir(modules_dir);
    if modules.is_empty() {
        println!("  (none installed)");
    } else {
        for m in &modules {
            let enabled = is_module_enabled(&cli.sensor_config, &cli.agent_config, m);
            let indicator = if enabled { "●" } else { "○" };
            let label = if enabled { "enabled " } else { "disabled" };
            println!("  {indicator} {:<20} {}  {}", m.id, label, m.name);
        }
    }

    println!();
    Ok(())
}

pub(crate) fn cmd_report(cli: &Cli, date_arg: &str, data_dir: &Path) -> Result<()> {
    let effective_dir = if data_dir == Path::new("/var/lib/innerwarden") {
        cli.agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    };

    let date = resolve_report_date(date_arg, &today_date_string(), &yesterday_date_string());

    let summary_path = effective_dir.join(format!("summary-{date}.md"));

    if !summary_path.exists() {
        let entries: Vec<String> = std::fs::read_dir(&effective_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        let mut available = summary_dates_from_filenames(&entries);

        if available.is_empty() {
            println!("No summary found for {date}.");
            println!();
            println!("Summary files are generated by innerwarden-agent every 30 minutes.");
            println!("Make sure the agent is running:  innerwarden status");
        } else {
            available.sort();
            available.reverse();
            println!("No summary found for {date}.");
            println!();
            println!("Available dates:");
            for d in available.iter().take(7) {
                println!("  innerwarden report --date {d}");
            }
        }
        return Ok(());
    }

    let content = std::fs::read_to_string(&summary_path)
        .with_context(|| format!("failed to read {}", summary_path.display()))?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            println!("\n  {}", rest);
        } else if let Some(rest) = line.strip_prefix("## ") {
            println!("\n{}", rest.to_uppercase());
            println!("{}", "─".repeat(48));
        } else if let Some(rest) = line.strip_prefix("# ") {
            println!("{}", rest);
            println!("{}", "═".repeat(56));
        } else if line.starts_with("---") {
        } else {
            println!("{line}");
        }
    }

    println!();
    println!("Full report: {}", summary_path.display());
    Ok(())
}

pub(crate) fn cmd_navigator(output: Option<&str>) -> Result<()> {
    let layer = generate_navigator_layer();
    let json = serde_json::to_string_pretty(&layer)?;
    if let Some(path) = output {
        std::fs::write(path, &json)?;
        eprintln!("  ✓ Navigator layer written to {path}");
        eprintln!("  Open https://mitre-attack.github.io/attack-navigator/ and load the file.");
    } else {
        println!("{json}");
    }
    Ok(())
}

fn generate_navigator_layer() -> serde_json::Value {
    // All detector -> technique mappings (mirrors agent/mitre.rs)
    let techniques: Vec<(&str, &str, &str)> = vec![
        ("T1110.001", "Credential Access", "ssh_bruteforce"),
        ("T1110.004", "Credential Access", "credential_stuffing"),
        ("T1110", "Credential Access", "distributed_ssh"),
        ("T1003", "Credential Access", "credential_harvest"),
        ("T1078", "Initial Access", "suspicious_login"),
        ("T1595", "Reconnaissance", "port_scan"),
        (
            "T1595.002",
            "Reconnaissance",
            "web_scan, user_agent_scanner",
        ),
        ("T1499", "Impact", "search_abuse"),
        ("T1496", "Impact", "crypto_miner"),
        ("T1498", "Impact", "outbound_anomaly"),
        ("T1486", "Impact", "ransomware"),
        ("T1059", "Execution", "execution_guard, process_tree"),
        ("T1059.004", "Execution", "reverse_shell"),
        ("T1610", "Execution", "docker_anomaly"),
        ("T1620", "Defense Evasion", "fileless"),
        ("T1098", "Defense Evasion", "integrity_alert"),
        ("T1070", "Defense Evasion", "log_tampering"),
        ("T1014", "Defense Evasion", "rootkit"),
        ("T1055", "Defense Evasion", "process_injection"),
        ("T1505.003", "Persistence", "web_shell"),
        ("T1098.004", "Persistence", "ssh_key_injection"),
        ("T1547.006", "Persistence", "kernel_module_load"),
        ("T1053.003", "Persistence", "crontab_persistence"),
        ("T1543.002", "Persistence", "systemd_persistence"),
        ("T1136", "Persistence", "user_creation"),
        ("T1611", "Privilege Escalation", "container_escape"),
        ("T1068", "Privilege Escalation", "privesc"),
        ("T1548", "Privilege Escalation", "sudo_abuse"),
        ("T1548.001", "Privilege Escalation", "sudo_abuse"),
        ("T1071", "Command and Control", "c2_callback"),
        ("T1571", "Command and Control", "c2_callback"),
        ("T1048.001", "Exfiltration", "dns_tunneling"),
        (
            "T1041",
            "Exfiltration",
            "data_exfiltration, data_exfil_ebpf",
        ),
        ("T1021", "Lateral Movement", "lateral_movement"),
        ("T1546.004", "Persistence", "sensitive_write"),
        ("T1037.004", "Persistence", "sensitive_write"),
        ("T1574.006", "Persistence", "sensitive_write"),
        ("T1556", "Credential Access", "sensitive_write"),
        ("T1053.002", "Persistence", "at_job_persist"),
        ("T1222.002", "Defense Evasion", "file_permission_mod"),
        ("T1564.001", "Defense Evasion", "hidden_artifact"),
        ("T1219", "Command and Control", "remote_access_tool"),
        ("T1489", "Impact", "service_stop"),
        ("T1529", "Impact", "system_shutdown"),
        ("T1040", "Credential Access", "network_sniffing"),
        ("T1036.005", "Defense Evasion", "masquerading"),
        ("T1560", "Collection", "data_archive"),
        ("T1090", "Command and Control", "proxy_tunnel"),
        ("T1105", "Command and Control", "execution_guard"),
        ("T1140", "Defense Evasion", "execution_guard"),
        ("T1552.001", "Credential Access", "data_exfil_ebpf"),
        ("T1552.004", "Credential Access", "private_key_search"),
        ("T1562.001", "Defense Evasion", "sudo_abuse"),
        ("T1562.004", "Defense Evasion", "sudo_abuse"),
        ("T1485", "Impact", "sudo_abuse"),
    ];

    let tech_entries: Vec<serde_json::Value> = techniques
        .iter()
        .map(|(tid, _tactic, detectors)| {
            serde_json::json!({
                "techniqueID": tid,
                "score": 1,
                "color": "#00ff00",
                "comment": format!("Detectors: {detectors}"),
                "enabled": true,
                "showSubtechniques": true,
            })
        })
        .collect();

    serde_json::json!({
        "name": "InnerWarden Detection Coverage",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": format!(
            "InnerWarden: {} MITRE ATT&CK techniques covered by 49 detectors + 8 YARA + 8 Sigma rules",
            tech_entries.len()
        ),
        "gradient": {
            "colors": ["#ffe766", "#00ff00"],
            "minValue": 1,
            "maxValue": 3
        },
        "techniques": tech_entries,
    })
}

pub(crate) fn cmd_sensor_status(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let today = epoch_secs_to_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    let telemetry_path = effective_dir.join(format!("telemetry-{today}.jsonl"));
    let snapshot: Option<serde_json::Value> = std::fs::read_to_string(&telemetry_path)
        .ok()
        .and_then(|content| {
            content
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .and_then(|line| serde_json::from_str(line).ok())
        });

    println!("InnerWarden - sensor status  ({})\n", today);

    let Some(snap) = snapshot else {
        println!("  No telemetry data for today.");
        println!("  Is the agent running?  innerwarden status");
        return Ok(());
    };

    println!("Collectors (events today):");
    let by_collector = snap["events_by_collector"].as_object();
    match by_collector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (source, count) in &pairs {
                println!("  ● {:<30} {:>6} events", source, count);
            }
        }
        _ => println!("  (no events recorded yet today)"),
    }

    println!();
    println!("Detectors (incidents today):");
    let by_detector = snap["incidents_by_detector"].as_object();
    match by_detector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (detector, count) in &pairs {
                println!("  ⚠  {:<30} {:>6} incidents", detector, count);
            }
        }
        _ => println!("  (no incidents today)"),
    }

    let ai_sent = snap["ai_sent_count"].as_u64().unwrap_or(0);
    let ai_decided = snap["ai_decision_count"].as_u64().unwrap_or(0);
    let avg_ms = snap["avg_decision_latency_ms"].as_f64().unwrap_or(0.0);
    let real_exec = snap["real_execution_count"].as_u64().unwrap_or(0);
    let dry_exec = snap["dry_run_execution_count"].as_u64().unwrap_or(0);
    let gate_pass = snap["gate_pass_count"].as_u64().unwrap_or(0);

    println!();
    println!("AI & Response (today):");
    println!("  Passed algorithm gate:  {gate_pass}");
    println!("  Sent to AI:             {ai_sent}");
    println!("  AI decisions:           {ai_decided}  (avg {avg_ms:.0}ms)");
    if real_exec > 0 {
        println!("  Actions executed:       {real_exec}  (live)");
    }
    if dry_exec > 0 {
        println!("  Actions simulated:      {dry_exec}  (dry-run)");
    }

    let errors = snap["errors_by_component"].as_object();
    if let Some(map) = errors {
        if !map.is_empty() {
            println!();
            println!("Errors:");
            for (comp, count) in map {
                println!("  ✗ {comp}: {}", count.as_u64().unwrap_or(0));
            }
        }
    }

    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cli(temp: &TempDir) -> Cli {
        Cli {
            sensor_config: temp.path().join("sensor.toml"),
            agent_config: temp.path().join("agent.toml"),
            data_dir: temp.path().join("data"),
            dry_run: true,
            command: None,
        }
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("test should create parent directory");
        }
        std::fs::write(path, content).expect("test should write fixture");
    }

    fn today() -> String {
        epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }

    #[test]
    fn resolve_report_date_expands_relative_keywords() {
        // Ensures user-friendly date shortcuts map to concrete dates consistently.
        assert_eq!(
            resolve_report_date("today", "2026-04-16", "2026-04-15"),
            "2026-04-16"
        );
        assert_eq!(
            resolve_report_date("yesterday", "2026-04-16", "2026-04-15"),
            "2026-04-15"
        );
    }

    #[test]
    fn resolve_report_date_keeps_explicit_date_strings() {
        // Covers pass-through behavior for explicit date arguments.
        assert_eq!(
            resolve_report_date("2026-04-01", "2026-04-16", "2026-04-15"),
            "2026-04-01"
        );
    }

    #[test]
    fn summary_dates_from_filenames_extracts_only_summary_files() {
        // Verifies summary date discovery ignores unrelated files and keeps valid report dates.
        let names = vec![
            "summary-2026-04-16.md".to_string(),
            "summary-2026-04-15.md".to_string(),
            "events-2026-04-16.jsonl".to_string(),
            "summary-2026-04-14.txt".to_string(),
        ];
        let dates = summary_dates_from_filenames(&names);
        assert_eq!(dates, vec!["2026-04-16", "2026-04-15"]);
    }

    #[test]
    fn generate_navigator_layer_has_expected_metadata() {
        // Ensures exported ATT&CK layer preserves required metadata used by the Navigator UI.
        let layer = generate_navigator_layer();
        assert_eq!(
            layer["name"].as_str().expect("layer name"),
            "InnerWarden Detection Coverage"
        );
        assert_eq!(
            layer["domain"].as_str().expect("layer domain"),
            "enterprise-attack"
        );
        assert_eq!(
            layer["versions"]["layer"].as_str().expect("layer version"),
            "4.5"
        );
    }

    #[test]
    fn generate_navigator_layer_contains_known_techniques() {
        // Guards the detector-to-technique map so key ATT&CK IDs are not lost during refactors.
        let layer = generate_navigator_layer();
        let techniques = layer["techniques"]
            .as_array()
            .expect("techniques must be array");
        let ids: Vec<&str> = techniques
            .iter()
            .filter_map(|t| t["techniqueID"].as_str())
            .collect();
        assert!(ids.contains(&"T1110.001"));
        assert!(ids.contains(&"T1485"));
    }

    #[test]
    fn generate_navigator_layer_sets_visual_defaults_for_each_technique() {
        // Confirms each technique entry keeps score/color/display defaults expected by ATT&CK Navigator.
        let layer = generate_navigator_layer();
        let techniques = layer["techniques"]
            .as_array()
            .expect("techniques must be array");
        let first = techniques.first().expect("at least one technique");
        assert_eq!(first["score"].as_i64().expect("score"), 1);
        assert_eq!(first["color"].as_str().expect("color"), "#00ff00");
        assert_eq!(first["enabled"].as_bool().expect("enabled"), true);
        assert_eq!(
            first["showSubtechniques"]
                .as_bool()
                .expect("showSubtechniques"),
            true
        );
    }

    #[test]
    fn generate_navigator_layer_technique_count_matches_description() {
        // Ensures description count stays in sync with actual entries to avoid stale exported metadata.
        let layer = generate_navigator_layer();
        let techniques = layer["techniques"]
            .as_array()
            .expect("techniques must be array");
        let description = layer["description"].as_str().expect("description");
        assert!(description.contains(&techniques.len().to_string()));
        assert!(techniques.len() >= 40);
    }

    #[test]
    fn cmd_navigator_writes_layer_to_requested_file() {
        let temp = TempDir::new().expect("tempdir");
        let output = temp.path().join("navigator.json");

        cmd_navigator(output.to_str()).expect("navigator export should succeed");

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output).expect("navigator json"))
                .expect("valid navigator json");
        assert_eq!(written["name"], "InnerWarden Detection Coverage");
        assert!(written["techniques"].as_array().expect("techniques").len() >= 40);
    }

    #[test]
    fn cmd_report_handles_missing_summaries_and_lists_available_dates() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("reports");
        std::fs::create_dir_all(&data_dir).expect("reports dir");

        cmd_report(&cli, "today", &data_dir).expect("missing report without files is ok");

        write_file(&data_dir.join("summary-2026-04-16.md"), "# Daily\nbody\n");
        write_file(&data_dir.join("summary-2026-04-15.md"), "# Daily\nbody\n");
        cmd_report(&cli, "2026-04-14", &data_dir).expect("missing report with alternatives is ok");
    }

    #[test]
    fn cmd_report_reads_summary_from_agent_configured_data_dir() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("agent-data");
        write_file(
            &cli.agent_config,
            &format!("[output]\ndata_dir = \"{}\"\n", data_dir.display()),
        );
        write_file(
            &data_dir.join("summary-2026-04-16.md"),
            "# InnerWarden\n---\n## Highlights\n### Finding\nAll clear\n",
        );

        cmd_report(&cli, "2026-04-16", Path::new("/var/lib/innerwarden"))
            .expect("configured report should render");
    }

    #[test]
    fn cmd_status_global_reads_config_data_and_empty_modules() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("status-data");
        let today = today();
        write_file(
            &cli.agent_config,
            &format!(
                "[output]\ndata_dir = \"{}\"\n[ai]\nenabled = true\nprovider = \"ollama\"\n[responder]\nenabled = true\ndry_run = false\n",
                data_dir.display()
            ),
        );
        write_file(
            &cli.sensor_config,
            "[collectors.exec_audit]\nenabled = true\n",
        );
        write_file(&data_dir.join(format!("events-{today}.jsonl")), "{}\n{}\n");
        write_file(
            &data_dir.join(format!("incidents-{today}.jsonl")),
            "{\"title\":\"Suspicious login\",\"ts\":\"2026-04-16T10:00:00Z\"}\n",
        );
        let modules_dir = temp.path().join("modules");
        std::fs::create_dir_all(&modules_dir).expect("modules dir");

        let registry = CapabilityRegistry::default_all();
        cmd_status_global(&cli, &registry, &modules_dir).expect("global status should render");
    }

    #[test]
    fn cmd_status_global_renders_monitor_only_posture_when_responder_disabled() {
        // Exercises the non-enforcing branch (responder disabled -> the
        // posture CTA line is printed), the default a fresh install ships.
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("status-data");
        write_file(
            &cli.agent_config,
            &format!(
                "[output]\ndata_dir = \"{}\"\n[ai]\nenabled = false\nprovider = \"ollama\"\n[responder]\nenabled = false\ndry_run = true\n",
                data_dir.display()
            ),
        );
        write_file(
            &cli.sensor_config,
            "[collectors.exec_audit]\nenabled = true\n",
        );
        let modules_dir = temp.path().join("modules");
        std::fs::create_dir_all(&modules_dir).expect("modules dir");

        let registry = CapabilityRegistry::default_all();
        // Asserts the disabled-responder path renders without panicking; the
        // posture wording itself is unit-tested in innerwarden_core.
        cmd_status_global(&cli, &registry, &modules_dir)
            .expect("global status should render in monitor-only mode");
    }

    #[test]
    fn cmd_sensor_status_handles_missing_and_empty_telemetry() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("sensor-data");

        cmd_sensor_status(&cli, &data_dir).expect("missing telemetry is ok");

        write_file(
            &data_dir.join(format!("telemetry-{}.jsonl", today())),
            "{\"events_by_collector\":{},\"incidents_by_detector\":{},\"errors_by_component\":{}}\n",
        );
        cmd_sensor_status(&cli, &data_dir).expect("empty telemetry maps are ok");
    }

    #[test]
    fn cmd_sensor_status_renders_populated_snapshot_branches() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("sensor-data");
        write_file(
            &data_dir.join(format!("telemetry-{}.jsonl", today())),
            "{\"events_by_collector\":{\"exec\":5,\"nginx\":2},\"incidents_by_detector\":{\"sudo_abuse\":3},\"ai_sent_count\":4,\"ai_decision_count\":2,\"avg_decision_latency_ms\":123.4,\"real_execution_count\":1,\"dry_run_execution_count\":2,\"gate_pass_count\":7,\"errors_by_component\":{\"sensor\":1}}\n",
        );

        cmd_sensor_status(&cli, &data_dir).expect("populated telemetry should render");
    }

    #[test]
    fn cmd_metrics_reports_missing_empty_and_populated_telemetry() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("metrics-data");

        let missing = cmd_metrics(&cli, &data_dir).expect_err("missing telemetry should error");
        assert!(missing.to_string().contains("cannot read"));

        let telemetry = data_dir.join(format!("telemetry-{}.jsonl", today()));
        write_file(&telemetry, "\n\n");
        cmd_metrics(&cli, &data_dir).expect("empty telemetry file is reported");

        write_file(
            &telemetry,
            "{\"ts\":0}\n{\"events_by_collector\":{\"exec\":2,\"nginx\":8},\"incidents_by_detector\":{\"ssh\":1},\"decisions_by_action\":{\"block_ip\":1,\"ignore\":2},\"avg_decision_latency_ms\":45.6,\"ai_sent_count\":3,\"ai_decision_count\":2,\"gate_pass_count\":4,\"real_execution_count\":1,\"dry_run_execution_count\":5}\n",
        );
        cmd_metrics(&cli, &data_dir).expect("populated telemetry metrics should render");
    }

    /// Spec 044 Phase 2.3: `innerwarden get posture` reads the snapshot
    /// the agent writes and pretty-prints it. The hint message when the
    /// file is missing is the visible signal that the operator is on a
    /// pre-spec-044 binary or that the agent has not booted yet.
    #[test]
    fn cmd_posture_missing_file_emits_hint_and_returns_ok() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        // Function returns Ok even when the file is missing — the
        // operator sees the diagnostic via println, not via stderr.
        cmd_posture(&cli, &data_dir).expect("missing snapshot is not an error");
    }

    /// All four probe surfaces present + ok: exercises every branch
    /// of the pretty-printer (sshd directive lines, listener loop,
    /// sudo group lines, sudoers.d list, firewall backend list,
    /// allowed-ports list).
    #[test]
    fn cmd_posture_renders_full_snapshot_branches() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        let path = data_dir.join("posture.json");
        let snap = r#"{
          "captured_at": "2026-05-09T15:00:00Z",
          "sshd": {
            "probe_state": "ok",
            "password_authentication": "no",
            "kbd_interactive_authentication": "no",
            "permit_root_login": "no",
            "pubkey_authentication": "yes",
            "max_auth_tries": 6,
            "ports": [22, 2222]
          },
          "services": {
            "probe_state": "ok",
            "listeners": [
              {"proto": "tcp", "port": 22, "addr": "0.0.0.0", "comm": "sshd"},
              {"proto": "tcp", "port": 8787, "addr": "0.0.0.0", "comm": "innerwarden-age"}
            ]
          },
          "sudo": {
            "probe_state": "ok",
            "sudo_group_members": ["alice", "deploy"],
            "wheel_group_members": [],
            "admin_group_members": [],
            "sudoers_d_filenames": ["deploy", "zz-innerwarden-deny-bob"]
          },
          "firewall": {
            "probe_state": "ok",
            "active_backends": ["ufw"],
            "default_policy": "drop",
            "allowed_tcp_ports": [22, 8787]
          }
        }"#;
        write_file(&path, snap);
        cmd_posture(&cli, &data_dir).expect("full ok snapshot renders");
    }

    /// Failed / unavailable probes: exercises the error branch in each
    /// section. Anchors that the command does NOT panic when probe
    /// states are not Ok — the operator might have an agent running on
    /// a host without sshd / nft / sudo.
    #[test]
    fn cmd_posture_renders_failed_and_unavailable_probe_states() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        let path = data_dir.join("posture.json");
        let snap = r#"{
          "captured_at": "2026-05-09T15:00:00Z",
          "sshd": {"probe_state": "unavailable", "error": "sshd binary not found"},
          "services": {"probe_state": "failed", "listeners": [], "error": "ss exit 1"},
          "sudo": {"probe_state": "unavailable", "error": "getent: not found"},
          "firewall": {"probe_state": "unavailable"}
        }"#;
        write_file(&path, snap);
        cmd_posture(&cli, &data_dir).expect("error states render without panic");
    }

    #[test]
    fn cmd_posture_malformed_json_returns_err() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        let path = data_dir.join("posture.json");
        write_file(&path, "{not json");
        let err = cmd_posture(&cli, &data_dir).expect_err("malformed JSON must error");
        assert!(err.to_string().contains("malformed JSON"));
    }
}

pub(crate) fn cmd_metrics(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);

    let telemetry_path = effective_dir.join(format!("telemetry-{today}.jsonl"));
    let content = std::fs::read_to_string(&telemetry_path)
        .with_context(|| format!("cannot read {}", telemetry_path.display()))?;

    let first_line: Option<serde_json::Value> = content
        .lines()
        .find(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str(line).ok());

    let snapshot: Option<serde_json::Value> = content
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str(line).ok());

    let Some(snap) = snapshot else {
        println!("InnerWarden - metrics  ({})\n", today);
        println!("  No telemetry data for today.");
        println!("  Is the agent running?  innerwarden status");
        return Ok(());
    };

    println!("InnerWarden - metrics  ({})\n", today);

    println!("Events processed today:");
    let by_collector = snap["events_by_collector"].as_object();
    let mut total_events: u64 = 0;
    match by_collector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_events += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (source, count) in &pairs {
                println!("  {:<30} {:>6}", source, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_events);
        }
        _ => println!("  (no events recorded yet today)"),
    }

    println!();
    println!("Incidents detected today:");
    let by_detector = snap["incidents_by_detector"].as_object();
    let mut total_incidents: u64 = 0;
    match by_detector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_incidents += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (detector, count) in &pairs {
                println!("  {:<30} {:>6}", detector, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_incidents);
        }
        _ => println!("  (no incidents today)"),
    }

    println!();
    println!("Decisions made today:");
    let by_action = snap["decisions_by_action"].as_object();
    let mut total_decisions: u64 = 0;
    match by_action {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_decisions += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (action, count) in &pairs {
                println!("  {:<30} {:>6}", action, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_decisions);
        }
        _ => println!("  (no decisions today)"),
    }

    let avg_ms = snap["avg_decision_latency_ms"].as_f64().unwrap_or(0.0);
    let ai_sent = snap["ai_sent_count"].as_u64().unwrap_or(0);
    let ai_decided = snap["ai_decision_count"].as_u64().unwrap_or(0);
    let gate_pass = snap["gate_pass_count"].as_u64().unwrap_or(0);
    let real_exec = snap["real_execution_count"].as_u64().unwrap_or(0);
    let dry_exec = snap["dry_run_execution_count"].as_u64().unwrap_or(0);

    println!();
    println!("AI pipeline:");
    println!("  Passed algorithm gate:    {:>6}", gate_pass);
    println!("  Sent to AI:               {:>6}", ai_sent);
    println!("  AI decisions:             {:>6}", ai_decided);
    println!("  Avg decision latency:     {:>5.0} ms", avg_ms);
    println!("  Actions executed (live):  {:>6}", real_exec);
    println!("  Actions simulated (dry):  {:>6}", dry_exec);

    if let Some(ref first) = first_line {
        if let Some(first_ts) = first["ts"].as_u64().or_else(|| first["timestamp"].as_u64()) {
            let uptime_secs = now_secs.saturating_sub(first_ts);
            let hours = uptime_secs / 3600;
            let minutes = (uptime_secs % 3600) / 60;
            println!();
            println!("Agent uptime (approx):      {}h {}m", hours, minutes);
        }
    }

    println!();
    Ok(())
}

/// `innerwarden get posture` — pretty-print the host posture snapshot
/// the agent uses for severity downgrade decisions (spec 044 Phase 2).
///
/// Reads `data_dir/posture.json` written by the agent's slow loop. The
/// command is read-only — refreshing the snapshot is the agent's job
/// (10 min cadence + boot snapshot + fanotify-triggered refresh).
///
/// When the file is missing the operator gets a hint: usually means
/// the agent is on an older binary that pre-dates spec 044, or the
/// agent has not been running long enough for the boot snapshot to
/// land. Refusing to fabricate fields here is deliberate — the
/// downgrade engine reads the same JSON and a stale or fabricated
/// view here would mask divergence from what the agent actually sees.
pub(crate) fn cmd_posture(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let path = effective_dir.join("posture.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("InnerWarden - host posture\n");
            println!("  No snapshot at {}.", path.display());
            println!();
            println!("  Causes:");
            println!("    - agent has not booted since spec 044 deploy");
            println!("    - agent is on an older binary (pre-2026-05-09)");
            println!();
            println!("  The agent writes this file at boot and refreshes every 10 min.");
            return Ok(());
        }
        Err(e) => {
            anyhow::bail!("cannot read {}: {e}", path.display());
        }
    };

    let snap: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("malformed JSON at {}", path.display()))?;

    let captured_at = snap["captured_at"].as_str().unwrap_or("?");
    println!("InnerWarden - host posture\n");
    println!("  Snapshot taken: {captured_at}");
    println!();

    // SSHD ─────────────────────────────────────────────────────────────────
    let sshd = &snap["sshd"];
    let sshd_state = sshd["probe_state"].as_str().unwrap_or("?");
    println!("SSHD ({sshd_state}):");
    if sshd_state == "ok" {
        let pa = sshd["password_authentication"].as_str().unwrap_or("?");
        let kbd = sshd["kbd_interactive_authentication"]
            .as_str()
            .unwrap_or("?");
        let prl = sshd["permit_root_login"].as_str().unwrap_or("?");
        let pk = sshd["pubkey_authentication"].as_str().unwrap_or("?");
        let mat = sshd["max_auth_tries"].as_u64();
        println!("  PasswordAuthentication        : {pa}");
        println!("  KbdInteractiveAuthentication  : {kbd}");
        println!("  PermitRootLogin               : {prl}");
        println!("  PubkeyAuthentication          : {pk}");
        if let Some(n) = mat {
            println!("  MaxAuthTries                  : {n}");
        }
        if let Some(ports) = sshd["ports"].as_array() {
            let list: Vec<String> = ports
                .iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect();
            if !list.is_empty() {
                println!("  Listen ports                  : {}", list.join(", "));
            }
        }
    } else if let Some(err) = sshd["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    // Listening services ───────────────────────────────────────────────────
    let services = &snap["services"];
    let svc_state = services["probe_state"].as_str().unwrap_or("?");
    println!("Listening services ({svc_state}):");
    if svc_state == "ok" {
        if let Some(listeners) = services["listeners"].as_array() {
            if listeners.is_empty() {
                println!("  (no listeners)");
            } else {
                for l in listeners {
                    let proto = l["proto"].as_str().unwrap_or("?");
                    let port = l["port"].as_u64().unwrap_or(0);
                    let addr = l["addr"].as_str().unwrap_or("?");
                    let comm = l["comm"].as_str().unwrap_or("?");
                    println!("  {proto:<3} {addr}:{port}  {comm}");
                }
            }
        }
    } else if let Some(err) = services["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    // Sudo ─────────────────────────────────────────────────────────────────
    let sudo = &snap["sudo"];
    let sudo_state = sudo["probe_state"].as_str().unwrap_or("?");
    println!("Sudo ({sudo_state}):");
    if sudo_state == "ok" {
        for (key, label) in [
            ("sudo_group_members", "group sudo "),
            ("wheel_group_members", "group wheel"),
            ("admin_group_members", "group admin"),
        ] {
            if let Some(arr) = sudo[key].as_array() {
                let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                if !names.is_empty() {
                    println!("  {label}: {}", names.join(", "));
                }
            }
        }
        if let Some(arr) = sudo["sudoers_d_filenames"].as_array() {
            let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            if !names.is_empty() {
                println!("  /etc/sudoers.d/: {}", names.join(", "));
            }
        }
    } else if let Some(err) = sudo["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    // Firewall ─────────────────────────────────────────────────────────────
    let fw = &snap["firewall"];
    let fw_state = fw["probe_state"].as_str().unwrap_or("?");
    println!("Firewall ({fw_state}):");
    if fw_state == "ok" {
        if let Some(arr) = fw["active_backends"].as_array() {
            let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            if !names.is_empty() {
                println!("  Active backends   : {}", names.join(", "));
            }
        }
        let policy = fw["default_policy"].as_str().unwrap_or("?");
        println!("  Default INPUT     : {policy}");
        if let Some(ports) = fw["allowed_tcp_ports"].as_array() {
            let list: Vec<String> = ports
                .iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect();
            if !list.is_empty() {
                println!("  Allowed TCP ports : {}", list.join(", "));
            }
        }
    } else if let Some(err) = fw["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    Ok(())
}
