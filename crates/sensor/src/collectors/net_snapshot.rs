//! Process network snapshot collector.
//!
//! Periodically scans /proc/net/tcp{,6} and maps each socket to its owning
//! PID via /proc/[pid]/fd. Emits a snapshot of all active TCP connections
//! with process context.
//!
//! This provides STATE visibility ("who is connected to whom RIGHT NOW")
//! complementing eBPF's EVENT visibility ("someone just connected").
//!
//! When an incident fires, the agent can query the latest snapshot to know
//! exactly which process is talking to the C2 server.

use std::collections::HashMap;

use chrono::Utc;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::{debug, info};

/// A single TCP connection with process ownership.
#[derive(Debug, Clone)]
struct SocketEntry {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: &'static str,
    inode: u64,
    pid: Option<u32>,
    comm: Option<String>,
}

/// TCP connection states from /proc/net/tcp.
fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parse /proc/net/tcp into socket entries.
fn parse_proc_net_tcp(content: &str) -> Vec<SocketEntry> {
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        let state_hex = fields[3];
        let inode: u64 = fields[9].parse().unwrap_or(0);

        let (local_addr, local_port) = parse_hex_addr(local);
        let (remote_addr, remote_port) = parse_hex_addr(remote);

        entries.push(SocketEntry {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state: tcp_state(state_hex),
            inode,
            pid: None,
            comm: None,
        });
    }

    entries
}

/// Parse hex address:port from /proc/net/tcp format.
/// Format: "0100007F:0050" = 127.0.0.1:80
fn parse_hex_addr(s: &str) -> (String, u16) {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return ("0.0.0.0".into(), 0);
    }

    let addr_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    // IPv4: 4 bytes in little-endian hex
    if addr_hex.len() == 8 {
        let n = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
        let addr = format!(
            "{}.{}.{}.{}",
            n & 0xff,
            (n >> 8) & 0xff,
            (n >> 16) & 0xff,
            (n >> 24) & 0xff
        );
        (addr, port)
    } else {
        // IPv6: simplified
        (format!("ipv6:{}", addr_hex), port)
    }
}

/// Build a map of socket inode -> (pid, comm) by scanning /proc/[pid]/fd.
fn build_inode_pid_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };

        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        for fd_entry in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                if link_str.starts_with("socket:[") {
                    if let Some(inode_str) = link_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.insert(inode, (pid, comm.clone()));
                        }
                    }
                }
            }
        }
    }

    map
}

fn attach_pid_ownership(entries: &mut [SocketEntry], inode_map: &HashMap<u64, (u32, String)>) {
    for entry in entries {
        if let Some((pid, comm)) = inode_map.get(&entry.inode) {
            entry.pid = Some(*pid);
            entry.comm = Some(comm.clone());
        }
    }
}

fn is_interesting_socket(entry: &SocketEntry) -> bool {
    (entry.state == "ESTABLISHED" || entry.state == "LISTEN" || entry.state == "SYN_SENT")
        && (entry.remote_addr != "0.0.0.0" || entry.state == "LISTEN")
        && (!entry.local_addr.starts_with("127.") || entry.state == "LISTEN")
}

fn build_snapshot_event(
    host_id: &str,
    now: chrono::DateTime<Utc>,
    entries: &[SocketEntry],
) -> Event {
    let interesting: Vec<&SocketEntry> = entries
        .iter()
        .filter(|entry| is_interesting_socket(entry))
        .collect();

    let established: Vec<serde_json::Value> = interesting
        .iter()
        .filter(|entry| entry.state == "ESTABLISHED")
        .map(|entry| {
            serde_json::json!({
                "pid": entry.pid,
                "comm": entry.comm,
                "local": format!("{}:{}", entry.local_addr, entry.local_port),
                "remote": format!("{}:{}", entry.remote_addr, entry.remote_port),
                "state": entry.state,
            })
        })
        .collect();

    let listening: Vec<serde_json::Value> = interesting
        .iter()
        .filter(|entry| entry.state == "LISTEN")
        .map(|entry| {
            serde_json::json!({
                "pid": entry.pid,
                "comm": entry.comm,
                "addr": format!("{}:{}", entry.local_addr, entry.local_port),
            })
        })
        .collect();

    Event {
        ts: now,
        host: host_id.to_string(),
        source: "net_snapshot".into(),
        kind: "network.snapshot".into(),
        severity: Severity::Debug,
        summary: format!(
            "Network snapshot: {} established, {} listening",
            established.len(),
            listening.len()
        ),
        details: serde_json::json!({
            "established": established,
            "listening": listening,
            "established_count": established.len(),
            "listening_count": listening.len(),
        }),
        tags: vec!["snapshot".into(), "network".into()],
        entities: Vec::new(),
    }
}

/// Run the network snapshot collector.
pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("net_snapshot: starting (interval: {interval_secs}s)");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let now = Utc::now();

        // Parse /proc/net/tcp
        let tcp_content = match std::fs::read_to_string("/proc/net/tcp") {
            Ok(c) => c,
            Err(e) => {
                debug!("net_snapshot: cannot read /proc/net/tcp: {e}");
                continue;
            }
        };

        let mut entries = parse_proc_net_tcp(&tcp_content);

        // Also parse tcp6
        if let Ok(tcp6) = std::fs::read_to_string("/proc/net/tcp6") {
            entries.extend(parse_proc_net_tcp(&tcp6));
        }

        // Resolve PID ownership
        let inode_map = build_inode_pid_map();
        attach_pid_ownership(&mut entries, &inode_map);
        let event = build_snapshot_event(&host_id, now, &entries);

        let _ = tx.send(event).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr_ipv4() {
        // 0100007F:0050 = 127.0.0.1:80
        let (addr, port) = parse_hex_addr("0100007F:0050");
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:1F90 0100007F:C35A 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0\n";

        let entries = parse_proc_net_tcp(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].state, "LISTEN");
        assert_eq!(entries[0].local_port, 80);
        assert_eq!(entries[0].inode, 12345);
        assert_eq!(entries[1].state, "ESTABLISHED");
    }

    #[test]
    fn test_tcp_state() {
        assert_eq!(tcp_state("01"), "ESTABLISHED");
        assert_eq!(tcp_state("0A"), "LISTEN");
        assert_eq!(tcp_state("06"), "TIME_WAIT");
        assert_eq!(tcp_state("FF"), "UNKNOWN");
    }

    #[test]
    fn parse_proc_net_tcp_skips_short_lines() {
        let content = "header\nshort line";
        assert!(parse_proc_net_tcp(content).is_empty());
    }

    #[test]
    fn parse_proc_net_tcp_handles_missing_inode() {
        // Line with 10 fields but invalid inode
        let content = "header\n0: 0100007F:0050 00000000:0000 0A 0 0 0 0 0 invalid_inode 0";
        let entries = parse_proc_net_tcp(content);
        assert_eq!(entries[0].inode, 0);
    }

    #[test]
    fn test_parse_hex_addr_invalid_format() {
        // No colon
        let (addr, port) = parse_hex_addr("0100007F0050");
        assert_eq!(addr, "0.0.0.0");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_hex_addr_invalid_hex() {
        // Invalid hex in IP
        let (addr, port) = parse_hex_addr("XX00007F:0050");
        assert_eq!(addr, "0.0.0.0");
        assert_eq!(port, 80); // port parses ok
    }

    #[test]
    fn test_parse_hex_addr_ipv6() {
        let (addr, port) = parse_hex_addr("00000000000000000000000000000001:0050");
        assert_eq!(addr, "ipv6:00000000000000000000000000000001");
        assert_eq!(port, 80);
    }

    fn socket(local_addr: &str, remote_addr: &str, state: &'static str, inode: u64) -> SocketEntry {
        SocketEntry {
            local_addr: local_addr.to_string(),
            local_port: 8080,
            remote_addr: remote_addr.to_string(),
            remote_port: 443,
            state,
            inode,
            pid: None,
            comm: None,
        }
    }

    #[test]
    fn interesting_socket_filter_keeps_exposed_connections_only() {
        assert!(is_interesting_socket(&socket(
            "10.0.0.5",
            "8.8.8.8",
            "ESTABLISHED",
            1
        )));
        assert!(is_interesting_socket(&socket(
            "127.0.0.1",
            "0.0.0.0",
            "LISTEN",
            2
        )));
        assert!(!is_interesting_socket(&socket(
            "127.0.0.1",
            "8.8.8.8",
            "ESTABLISHED",
            3
        )));
        assert!(!is_interesting_socket(&socket(
            "10.0.0.5",
            "0.0.0.0",
            "TIME_WAIT",
            4
        )));
    }

    #[test]
    fn attach_pid_ownership_populates_matching_inodes_only() {
        let mut entries = vec![
            socket("10.0.0.5", "8.8.8.8", "ESTABLISHED", 77),
            socket("10.0.0.6", "1.1.1.1", "SYN_SENT", 88),
        ];
        let owners = HashMap::from([(77, (4242, "curl".to_string()))]);
        attach_pid_ownership(&mut entries, &owners);

        assert_eq!(entries[0].pid, Some(4242));
        assert_eq!(entries[0].comm.as_deref(), Some("curl"));
        assert_eq!(entries[1].pid, None);
        assert_eq!(entries[1].comm, None);
    }

    #[test]
    fn snapshot_event_counts_established_and_listening_connections() {
        let mut owned = socket("10.0.0.5", "8.8.8.8", "ESTABLISHED", 77);
        owned.pid = Some(42);
        owned.comm = Some("curl".to_string());
        let listen = socket("0.0.0.0", "0.0.0.0", "LISTEN", 88);
        let hidden = socket("127.0.0.1", "8.8.8.8", "ESTABLISHED", 99);

        let ev = build_snapshot_event("sensor-a", Utc::now(), &[owned, listen, hidden]);
        assert_eq!(ev.kind, "network.snapshot");
        assert_eq!(ev.details["established_count"], 1);
        assert_eq!(ev.details["listening_count"], 1);
        assert_eq!(ev.details["established"][0]["pid"], 42);
        assert!(ev.summary.contains("1 established, 1 listening"));
    }
}
