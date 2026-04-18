//! `innerwarden system calibrate` — discover host inventory for FP reduction.
//!
//! Scans the current system to discover:
//! - Local interface IPs
//! - Listening TCP ports and their owning processes
//! - Running services (systemd units in active state)
//! - Active outbound connections and their destinations
//!
//! Outputs a report the operator can review and optionally paste into
//! `[calibration]` in the sensor config to suppress known-good FPs.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

/// Entry point for `innerwarden system calibrate`.
pub fn cmd_calibrate() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          InnerWarden — Host Calibration             ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // 1. Own IPs
    let own_ips = discover_ips();
    println!("🔹 Local interface IPs ({}):", own_ips.len());
    for ip in &own_ips {
        println!("   {ip}");
    }
    println!();

    // 2. Listening ports
    let listeners = discover_listeners();
    println!("🔹 Listening TCP ports ({}):", listeners.len());
    for (port, procs) in &listeners {
        let proc_str = procs.iter().cloned().collect::<Vec<_>>().join(", ");
        println!("   :{port:<6} ({proc_str})");
    }
    println!();

    // 3. Running services
    let services = discover_services();
    println!("🔹 Active services ({}):", services.len());
    for svc in &services {
        println!("   {svc}");
    }
    println!();

    // 4. Outbound connections
    let outbound = discover_outbound();
    println!("🔹 Active outbound destinations ({}):", outbound.len());
    for (dst, procs) in &outbound {
        let proc_str = procs.iter().cloned().collect::<Vec<_>>().join(", ");
        println!("   {dst:<40} ({proc_str})");
    }
    println!();

    // 5. Suggested config
    println!("───────────────────────────────────────────────────────");
    println!("Suggested [calibration] for sensor config.toml:");
    println!();
    println!("[calibration]");

    let (svc_names, out_names) = generate_calibration_suggestions(&services, &outbound);

    println!("expected_services = [{}]", svc_names.join(", "));
    println!("expected_outbound = [{}]", out_names.join(", "));
    println!();
    println!("Review the above and paste into /etc/innerwarden/config.toml");
    println!("Only approved entries will be used — nothing is applied automatically.");

    Ok(())
}

fn generate_calibration_suggestions(
    services: &BTreeSet<String>,
    outbound: &BTreeMap<String, BTreeSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let svc_names: Vec<_> = services
        .iter()
        .filter(|s| !s.contains("innerwarden"))
        .map(|s| format!("\"{}\"", s.trim_end_matches(".service")))
        .collect();

    // Extract just the IP (without port) for the config suggestion
    let out_ips: BTreeSet<_> = outbound
        .keys()
        .filter_map(|d| d.rsplit(':').nth(1)) // "1.2.3.4:443" → "1.2.3.4"
        .filter(|ip| !ip.starts_with("127.") && !ip.starts_with("10.") && !ip.starts_with("172."))
        .collect();
    let out_names: Vec<_> = out_ips.iter().map(|ip| format!("\"{ip}\"")).collect();

    (svc_names, out_names)
}

/// Discover local interface IPs from /proc/net/fib_trie.
fn discover_ips() -> BTreeSet<String> {
    let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") else {
        return BTreeSet::new();
    };
    parse_fib_trie(&content)
}

fn parse_fib_trie(content: &str) -> BTreeSet<String> {
    let mut ips = BTreeSet::new();
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(ip_str) = trimmed.strip_prefix("|-- ") {
            if i + 1 < lines.len()
                && lines[i + 1].trim().contains("/32 host LOCAL")
                && !ip_str.starts_with("127.")
            {
                ips.insert(ip_str.to_string());
            }
        }
    }
    ips
}

/// Discover listening TCP ports and their owning processes.
fn discover_listeners() -> BTreeMap<u16, BTreeSet<String>> {
    let mut result: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();

    // Try ss first (more info), fall back to /proc/net/tcp
    if let Ok(output) = std::process::Command::new("ss").args(["-tlnp"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        result = parse_ss_listeners(&text);
    }

    if result.is_empty() {
        // Fallback: parse /proc/net/tcp
        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(content) = std::fs::read_to_string(path) {
                let parsed = parse_proc_net_tcp(&content);
                for (port, procs) in parsed {
                    result.entry(port).or_default().extend(procs);
                }
            }
        }
    }

    result
}

fn parse_ss_listeners(text: &str) -> BTreeMap<u16, BTreeSet<String>> {
    let mut result: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        // Local address:port is in column 3
        if let Some(port_str) = parts[3].rsplit(':').next() {
            if let Ok(port) = port_str.parse::<u16>() {
                // Process info in last column: users:(("sshd",pid=1234,...))
                let proc_name = parts
                    .last()
                    .and_then(|s| s.split('"').nth(1).map(|n| n.to_string()))
                    .unwrap_or_else(|| "?".to_string());
                result.entry(port).or_default().insert(proc_name);
            }
        }
    }
    result
}

fn parse_proc_net_tcp(content: &str) -> BTreeMap<u16, BTreeSet<String>> {
    let mut result: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 || parts[3] != "0A" {
            continue;
        }
        if let Some(port_hex) = parts[1].split(':').nth(1) {
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                if port > 0 {
                    result.entry(port).or_default().insert("?".to_string());
                }
            }
        }
    }
    result
}

/// Discover running systemd services.
fn discover_services() -> BTreeSet<String> {
    if let Ok(output) = std::process::Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_systemctl_services(&text);
    }
    BTreeSet::new()
}

fn parse_systemctl_services(text: &str) -> BTreeSet<String> {
    let mut services = BTreeSet::new();
    for line in text.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if !name.is_empty() {
                services.insert(name.to_string());
            }
        }
    }
    services
}

/// Discover active outbound connections and their destination IPs/domains.
fn discover_outbound() -> BTreeMap<String, BTreeSet<String>> {
    if let Ok(output) = std::process::Command::new("ss")
        .args(["-tnp", "state", "established"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_ss_outbound(&text);
    }

    BTreeMap::new()
}

fn parse_ss_outbound(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: Recv-Q Send-Q LocalAddr:Port PeerAddr:Port [Process]
        if parts.len() < 5 {
            continue;
        }
        let peer = parts[4].to_string();
        // Skip localhost connections
        if peer.starts_with("127.") || peer.starts_with("[::1]") {
            continue;
        }
        // Process info is in column 5+ (if running as root with -p)
        let proc_name = if parts.len() > 5 {
            parts[5..]
                .join(" ")
                .split('"')
                .nth(1)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string())
        } else {
            "?".to_string()
        };
        result.entry(peer).or_default().insert(proc_name);
    }
    result
}

/// Maps sensitivity levels to detector threshold overrides.
/// Returns a map of config keys to threshold values.
pub fn calculate_sensitivity_overrides(level: &str) -> Result<BTreeMap<String, i64>> {
    match level.to_lowercase().as_str() {
        "verbose" => {
            let mut m = BTreeMap::new();
            m.insert("detectors.ssh_bruteforce.threshold".to_string(), 2);
            m.insert("detectors.port_scan.threshold".to_string(), 2);
            m.insert("detectors.credential_stuffing.threshold".to_string(), 2);
            m.insert("detectors.packet_flood.syn_threshold".to_string(), 20);
            Ok(m)
        }
        "normal" => {
            let mut m = BTreeMap::new();
            m.insert("detectors.ssh_bruteforce.threshold".to_string(), 5);
            m.insert("detectors.port_scan.threshold".to_string(), 5);
            m.insert("detectors.credential_stuffing.threshold".to_string(), 3);
            m.insert("detectors.packet_flood.syn_threshold".to_string(), 100);
            Ok(m)
        }
        "quiet" => {
            let mut m = BTreeMap::new();
            m.insert("detectors.ssh_bruteforce.threshold".to_string(), 15);
            m.insert("detectors.port_scan.threshold".to_string(), 15);
            m.insert("detectors.credential_stuffing.threshold".to_string(), 10);
            m.insert("detectors.packet_flood.syn_threshold".to_string(), 500);
            Ok(m)
        }
        other => anyhow::bail!("Invalid sensitivity level: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fib_trie() {
        let content = r#"Main:
  |-- 0.0.0.0/0
     |-- 1.2.3.4
        |-- 1.2.3.4/32 host LOCAL
     |-- 127.0.0.1
        |-- 127.0.0.1/32 host LOCAL
"#;
        let ips = parse_fib_trie(content);
        assert!(ips.contains("1.2.3.4"));
        assert!(!ips.contains("127.0.0.1"));
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_parse_ss_listeners() {
        // Mock output without Netid column (index 3 is Local Address:Port)
        let stdout = r#"State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1234,fd=3))
LISTEN 0      100             *:80            *:*       users:(("nginx",pid=5678,fd=4))
"#;
        let listeners = parse_ss_listeners(stdout);
        assert_eq!(listeners.get(&22).unwrap().iter().next().unwrap(), "sshd");
        assert_eq!(listeners.get(&80).unwrap().iter().next().unwrap(), "nginx");
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000
"#;
        let listeners = parse_proc_net_tcp(content);
        assert!(listeners.contains_key(&22));
        assert!(listeners.contains_key(&80));
    }

    #[test]
    fn test_parse_systemctl_services() {
        let stdout = r#"dbus.service   loaded active running   D-Bus System Message Bus
nginx.service  loaded active running   nginx - high performance web server
sshd.service   loaded active running   OpenBSD Secure Shell server
"#;
        let services = parse_systemctl_services(stdout);
        assert!(services.contains("dbus.service"));
        assert!(services.contains("nginx.service"));
    }

    #[test]
    fn test_parse_ss_outbound() {
        // Mock output without Netid column (index 4 is Peer Address:Port)
        let stdout = r#"State      Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB      0      0      1.2.3.4:45678      8.8.8.8:443  users:(("curl",pid=999,fd=3))
"#;
        let outbound = parse_ss_outbound(stdout);
        assert!(outbound.contains_key("8.8.8.8:443"));
    }

    #[test]
    fn test_generate_calibration_suggestions() {
        let mut services = BTreeSet::new();
        services.insert("nginx.service".to_string());
        services.insert("innerwarden-agent.service".to_string());

        let mut outbound = BTreeMap::new();
        let mut procs = BTreeSet::new();
        procs.insert("curl".to_string());
        outbound.insert("8.8.8.8:443".to_string(), procs.clone());
        outbound.insert("10.0.0.1:80".to_string(), procs);

        let (svc_names, out_names) = generate_calibration_suggestions(&services, &outbound);

        assert!(svc_names.contains(&"\"nginx\"".to_string()));
        assert!(!svc_names.contains(&"\"innerwarden-agent\"".to_string()));
        assert!(out_names.contains(&"\"8.8.8.8\"".to_string()));
        assert!(!out_names.contains(&"\"10.0.0.1\"".to_string()));
    }

    #[test]
    fn test_calculate_sensitivity_overrides() {
        let verbose = calculate_sensitivity_overrides("verbose").unwrap();
        assert_eq!(
            verbose.get("detectors.ssh_bruteforce.threshold").unwrap(),
            &2
        );
        assert_eq!(
            verbose.get("detectors.packet_flood.syn_threshold").unwrap(),
            &20
        );

        let normal = calculate_sensitivity_overrides("normal").unwrap();
        assert_eq!(
            normal.get("detectors.ssh_bruteforce.threshold").unwrap(),
            &5
        );
        assert_eq!(
            normal.get("detectors.packet_flood.syn_threshold").unwrap(),
            &100
        );

        let quiet = calculate_sensitivity_overrides("quiet").unwrap();
        assert_eq!(
            quiet.get("detectors.ssh_bruteforce.threshold").unwrap(),
            &15
        );
        assert_eq!(
            quiet.get("detectors.packet_flood.syn_threshold").unwrap(),
            &500
        );
    }

    #[test]
    fn test_invalid_sensitivity_input() {
        let res = calculate_sensitivity_overrides("extreme");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Invalid sensitivity level"));
    }

    #[test]
    fn test_sensitivity_idempotence() {
        let first = calculate_sensitivity_overrides("normal").unwrap();
        let second = calculate_sensitivity_overrides("normal").unwrap();
        assert_eq!(first, second);
    }
}
