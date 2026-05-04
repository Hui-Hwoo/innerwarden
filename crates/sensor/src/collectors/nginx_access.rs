/// Nginx access log collector.
///
/// Tails a Combined Log Format (or Common Log Format) access log and emits
/// `http.request` events per line. Uses a byte-offset cursor for resume-on-restart.
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::log_state::{classify_open, log_instruction_for, LogInstruction, OpenLogState};

pub struct NginxAccessCollector {
    path: String,
    host: String,
    start_offset: u64,
}

impl NginxAccessCollector {
    pub fn new(path: impl Into<String>, host: impl Into<String>, start_offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            start_offset,
        }
    }

    pub async fn run(self, tx: mpsc::Sender<Event>, shared_offset: Arc<AtomicU64>) -> Result<()> {
        let path = self.path.clone();
        let host = self.host.clone();
        let mut offset = self.start_offset;

        // Wave 9f (AUDIT-010 anchor): suppress per-retry log spam. The
        // collector retries to open `path` every 5s when the file is
        // unreadable; pre-fix that emitted ~720 WARN entries per hour. The
        // state machine emits exactly one WARN per failure episode + one
        // INFO on recovery. See `super::log_state` for the contract.
        let mut open_log_state = OpenLogState::new();

        loop {
            // Open file and seek to last known offset.
            let open_result = std::fs::File::open(&path);
            let action = classify_open(
                &mut open_log_state,
                open_result.as_ref().err().map(|e| format!("{e:#}")),
            );
            let instruction = log_instruction_for(&action);
            let file = match open_result {
                Ok(f) => {
                    if instruction == LogInstruction::InfoRecovered {
                        info!(path = %path, "nginx_access: open recovered");
                    }
                    f
                }
                Err(e) => {
                    let err_str = format!("{e:#}");
                    match instruction {
                        LogInstruction::WarnCannotOpen => {
                            warn!(path = %path, error = %err_str, "nginx_access: cannot open");
                        }
                        LogInstruction::DebugSuppressed => {
                            debug!(path = %path, error = %err_str, "nginx_access: still cannot open (suppressed)");
                        }
                        // None / InfoRecovered are unreachable on the Err
                        // arm per classify_open's contract.
                        _ => debug_assert!(false, "unexpected instruction on Err: {instruction:?}"),
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut reader = BufReader::new(file);
            if let Err(e) = reader.seek(SeekFrom::Start(offset)) {
                warn!("nginx_access: seek failed: {e:#}");
            }

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        // End of file - wait and re-open to detect rotation
                        break;
                    }
                    Ok(n) => {
                        offset += n as u64;
                        shared_offset.store(offset, Ordering::Relaxed);

                        let line = line.trim_end();
                        if line.is_empty() {
                            continue;
                        }

                        if let Some(entry) = parse_line(line) {
                            let severity = http_severity(entry.status);
                            let event = Event {
                                ts: chrono::Utc::now(),
                                host: host.clone(),
                                source: "nginx_access".to_string(),
                                kind: "http.request".to_string(),
                                severity,
                                summary: format!(
                                    "{} {} {} {}",
                                    entry.ip, entry.method, entry.path, entry.status
                                ),
                                details: serde_json::json!({
                                    "ip": entry.ip,
                                    "method": entry.method,
                                    "path": entry.path,
                                    "status": entry.status,
                                    "bytes": entry.bytes,
                                    "user_agent": entry.user_agent,
                                }),
                                tags: {
                                    let mut t = vec!["http".to_string()];
                                    if is_known_good_bot(&entry.user_agent) {
                                        // Verify via rDNS for major bots that can be spoofed
                                        let ua = entry.user_agent.clone();
                                        let ip = entry.ip.clone();
                                        let verified = tokio::task::block_in_place(|| {
                                            verify_bot_rdns(&ua, &ip)
                                        });
                                        if verified {
                                            t.push("bot:known".to_string());
                                        } else {
                                            t.push("bot:spoofed".to_string());
                                        }
                                    }
                                    t
                                },
                                entities: vec![EntityRef::ip(&entry.ip)],
                            };
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("nginx_access: read error: {e:#}");
                        break;
                    }
                }
            }

            // Pause between tail iterations; also detects log rotation
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Known good bots - excluded from abuse detection
// ---------------------------------------------------------------------------

const KNOWN_GOOD_BOTS: &[&str] = &[
    "googlebot",
    "bingbot",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "slurp", // Yahoo
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "amazonbot",
    "applebot",
    "pinterestbot",
    "redditbot",
    "discordbot",
    "telegrambot",
    "whatsapp",
    "chatgpt-user",
    "gptbot",
    "claudebot",
    "anthropic-ai",
    "petalbot", // Ahrefs
    "semrushbot",
    "ahrefsbot",
    "mj12bot", // Majestic
    "dotbot",
    "rogerbot",
    "archive.org_bot",
    "ia_archiver",
];

fn is_known_good_bot(user_agent: &str) -> bool {
    let ua = user_agent.to_ascii_lowercase();
    KNOWN_GOOD_BOTS.iter().any(|bot| ua.contains(bot))
}

/// Known rDNS suffixes for legitimate bot IPs.
/// If a request claims to be Googlebot but the IP doesn't resolve to
/// *.googlebot.com, it's a fake.
const BOT_RDNS_PATTERNS: &[(&str, &[&str])] = &[
    ("googlebot", &[".googlebot.com", ".google.com"]),
    ("bingbot", &[".search.msn.com"]),
    ("yandexbot", &[".yandex.ru", ".yandex.net", ".yandex.com"]),
    ("baiduspider", &[".baidu.com", ".baidu.jp"]),
    ("duckduckbot", &[".duckduckgo.com"]),
    ("applebot", &[".apple.com", ".applebot.apple.com"]),
];

/// Verify a claimed bot identity via reverse DNS.
/// Returns true if the bot is verified or if verification is not applicable
/// (bot not in the rDNS check list - we give benefit of the doubt).
/// Returns false if the bot claims to be e.g. Googlebot but rDNS doesn't match.
fn verify_bot_rdns(user_agent: &str, ip: &str) -> bool {
    let ua = user_agent.to_ascii_lowercase();

    // Find which bot this claims to be
    let expected_suffixes = BOT_RDNS_PATTERNS
        .iter()
        .find(|(bot, _)| ua.contains(bot))
        .map(|(_, suffixes)| *suffixes);

    let Some(suffixes) = expected_suffixes else {
        // Bot not in rDNS check list - allow (benefit of the doubt)
        return true;
    };

    // Reverse DNS lookup with timeout
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };

    match dns_lookup_with_timeout(addr) {
        Some(hostname) => {
            let host = hostname.to_lowercase();
            suffixes.iter().any(|s| host.ends_with(s))
        }
        None => false, // DNS failed or timeout - don't trust the claim
    }
}

/// Blocking rDNS lookup with a 2-second timeout.
fn dns_lookup_with_timeout(addr: std::net::IpAddr) -> Option<String> {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
    let addr_clone = addr;
    std::thread::spawn(move || {
        let result = dns_lookup::lookup_addr(&addr_clone);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(hostname)) => Some(hostname),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Log parser
// ---------------------------------------------------------------------------

struct NginxLogEntry {
    ip: String,
    method: String,
    path: String,
    status: u16,
    bytes: u64,
    user_agent: String,
}

/// Parse one line of Nginx Combined or Common Log Format.
///
/// ```text
/// 1.2.3.4 - user [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 1234 "referer" "ua"
/// ```
fn parse_line(line: &str) -> Option<NginxLogEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Detect Nginx Proxy Manager format:
    //   [date] - status status - METHOD proto host "/path" [Client IP] [Length N] ... "UA" "ref"
    if line.starts_with('[') && line.contains("[Client ") {
        return parse_npm_line(line);
    }

    // Standard Combined/Common Log Format:
    //   IP - - [date] "METHOD /path HTTP/ver" status bytes "ref" "UA"
    let (ip, rest) = line.split_once(' ')?;
    let ip = ip.to_string();

    let quote_start = rest.find('"')?;
    let after_quote = &rest[quote_start + 1..];
    let quote_end = after_quote.find('"')?;
    let request = &after_quote[..quote_end];
    let after_request = after_quote[quote_end + 1..].trim_start();

    let mut req_parts = request.splitn(3, ' ');
    let method = req_parts.next().unwrap_or("").to_string();
    let path = req_parts.next().unwrap_or("/").to_string();

    let (status_str, after_status) = after_request.split_once(' ')?;
    let status: u16 = status_str.parse().ok()?;

    let after_status = after_status.trim_start();
    let (bytes_str, rest_str) = after_status.split_once(' ').unwrap_or((after_status, ""));
    let bytes: u64 = bytes_str.parse().unwrap_or(0);

    let user_agent = extract_last_quoted(rest_str.trim()).unwrap_or_default();

    Some(NginxLogEntry {
        ip,
        method,
        path,
        status,
        bytes,
        user_agent,
    })
}

/// Parse Nginx Proxy Manager log format:
/// [19/Mar/2026:04:49:01 +0000] - - 301 - GET http host.com "/path" [Client 1.2.3.4] [Length 166] [Gzip -] [Sent-to backend] "UA" "ref"
fn parse_npm_line(line: &str) -> Option<NginxLogEntry> {
    // Extract client IP from [Client X.X.X.X]
    let client_start = line.find("[Client ")? + 8;
    let client_end = line[client_start..].find(']')? + client_start;
    let ip = line[client_start..client_end].to_string();

    // Extract path from "..." (first quoted string after the hostname)
    let first_quote = line.find('"')?;
    let after_quote = &line[first_quote + 1..];
    let end_quote = after_quote.find('"')?;
    let path = after_quote[..end_quote].to_string();

    // Extract method - token before "http" or "https" before the hostname
    // Format: ... METHOD proto host "/path" ...
    let before_client = &line[..line.find("[Client")?];
    let tokens: Vec<&str> = before_client.split_whitespace().collect();

    // Find method (GET/POST/etc.) - it's the token before "http" or "https"
    let mut method = String::new();
    let mut status: u16 = 0;
    for (i, t) in tokens.iter().enumerate() {
        if (*t == "http" || *t == "https") && i > 0 {
            method = tokens[i - 1].to_string();
            break;
        }
    }

    // Extract status - first numeric 3-digit token after the date bracket
    for t in &tokens {
        if t.len() == 3 {
            if let Ok(s) = t.parse::<u16>() {
                if (100..600).contains(&s) {
                    status = s;
                    break;
                }
            }
        }
    }

    // Extract length from [Length N]
    let bytes = if let Some(len_start) = line.find("[Length ") {
        let after = &line[len_start + 8..];
        after
            .split(']')
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    } else {
        0
    };

    // User-agent from last quoted string
    let user_agent = extract_last_quoted(line).unwrap_or_default();

    if method.is_empty() || status == 0 {
        return None;
    }

    Some(NginxLogEntry {
        ip,
        method,
        path,
        status,
        bytes,
        user_agent,
    })
}

/// Extract the content of the last `"..."` pair in a string.
fn extract_last_quoted(s: &str) -> Option<String> {
    if s.is_empty() {
        return None;
    }
    let last_quote = s.rfind('"')?;
    let prev_quote = s[..last_quote].rfind('"')?;
    Some(s[prev_quote + 1..last_quote].to_string())
}

fn http_severity(status: u16) -> Severity {
    match status {
        200..=299 => Severity::Info,
        300..=399 => Severity::Debug,
        400..=499 => Severity::Low,
        500..=599 => Severity::Medium,
        _ => Severity::Debug,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_log_format() {
        let line = r#"1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /api/search?q=foo HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "1.2.3.4");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/api/search?q=foo");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 1234);
        assert_eq!(entry.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn parses_common_log_format() {
        let line =
            r#"10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "POST /api/search HTTP/1.0" 200 512"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "10.0.0.1");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/api/search");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 512);
        assert!(entry.user_agent.is_empty());
    }

    #[test]
    fn parses_dash_bytes() {
        let line = r#"5.5.5.5 - - [01/Jan/2025:00:00:00 +0000] "GET /health HTTP/1.1" 200 -"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.bytes, 0);
    }

    #[test]
    fn ignores_empty_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
    }

    #[test]
    fn ignores_malformed_lines() {
        assert!(parse_line("not a log line").is_none());
    }

    #[test]
    fn http_severity_mapping() {
        assert_eq!(http_severity(200), Severity::Info);
        assert_eq!(http_severity(301), Severity::Debug);
        assert_eq!(http_severity(404), Severity::Low);
        assert_eq!(http_severity(500), Severity::Medium);
    }

    #[test]
    fn extract_last_quoted_works() {
        assert_eq!(
            extract_last_quoted(r#""https://ref" "Mozilla/5.0""#),
            Some("Mozilla/5.0".to_string())
        );
        assert_eq!(extract_last_quoted(""), None);
    }

    #[test]
    fn parses_npm_format() {
        let line = r#"[19/Mar/2026:04:49:01 +0000] - - 301 - GET http n8n.example.com "/favicon.ico" [Client 104.22.17.224] [Length 166] [Gzip -] [Sent-to n8n] "Mozilla/5.0 Firefox/124.0" "-""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "104.22.17.224");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/favicon.ico");
        assert_eq!(entry.status, 301);
        assert_eq!(entry.bytes, 166);
    }

    #[test]
    fn parses_npm_format_200() {
        let line = r#"[18/Mar/2026:15:57:53 +0000] - 200 200 - POST https mygrowth.tools "/wp-login.php" [Client 172.68.193.204] [Length 2841] [Gzip -] [Sent-to wp_site] "Mozilla/5.0" "-""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "172.68.193.204");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/wp-login.php");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 2841);
    }

    #[test]
    fn npm_format_extracts_user_agent() {
        let line = r#"[19/Mar/2026:00:00:00 +0000] - - 404 - GET https site.com "/api/search?q=test" [Client 203.0.113.42] [Length 100] [Gzip -] [Sent-to back] "sqlmap/1.7" "-""#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.ip, "203.0.113.42");
        assert_eq!(entry.path, "/api/search?q=test");
        assert_eq!(entry.status, 404);
    }

    #[test]
    fn is_known_good_bot_detects_bots() {
        assert!(is_known_good_bot(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ));
        assert!(is_known_good_bot(
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ));
        assert!(is_known_good_bot("duckduckbot/1.0"));
        assert!(!is_known_good_bot("Mozilla/5.0 Firefox/124.0"));
    }

    #[test]
    fn verify_bot_rdns_not_in_list_returns_true() {
        // "anthropic-ai" is in KNOWN_GOOD_BOTS but not in BOT_RDNS_PATTERNS
        // It should get benefit of the doubt
        assert!(verify_bot_rdns("anthropic-ai", "127.0.0.1"));
    }

    #[test]
    fn verify_bot_rdns_invalid_ip_returns_false() {
        assert!(!verify_bot_rdns("googlebot", "not-an-ip"));
    }

    #[test]
    fn test_http_severity_edge_cases() {
        assert_eq!(http_severity(100), Severity::Debug); // _ arm
        assert_eq!(http_severity(599), Severity::Medium);
        assert_eq!(http_severity(0), Severity::Debug); // _ arm
    }

    #[test]
    fn test_extract_last_quoted_no_quotes() {
        assert_eq!(extract_last_quoted("hello world"), None);
    }

    #[test]
    fn test_extract_last_quoted_single_quote() {
        assert_eq!(extract_last_quoted("hello \"world"), None);
    }

    // ── Wave 9f integration anchors (AUDIT-010) ────────────────────────
    //
    // These exercise the actual `run` loop so the per-verdict log-level
    // branches (warn for first failure, debug for repeated failures, info
    // for recovery, plus the Ok-arm of the `match open_result`) get
    // covered by tarpaulin. Pure unit tests on `log_instruction_for`
    // already pin the verdict→level mapping; these add the collector
    // wiring on top.
    //
    // Time is mocked via `start_paused = true` so the 5-second retry
    // sleep is virtual; tests run in milliseconds while still exercising
    // multiple iterations of the retry loop.

    use std::io::Write;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn run_emits_event_for_existing_log_line() {
        // Ok arm of the match open_result. Pre-seed a tempfile with one
        // valid nginx access log line, run the collector against it, and
        // assert that the event lands on the channel. Anchors that the
        // refactor to `log_instruction_for` did not break the happy path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"203.0.113.10 - - [01/Jan/2026:00:00:00 +0000] "GET /healthz HTTP/1.1" 200 5 "-" "curl/8.0""#
        )
        .unwrap();
        drop(f);

        let (tx, mut rx) = mpsc::channel(16);
        let shared_offset = Arc::new(AtomicU64::new(0));
        let collector =
            NginxAccessCollector::new(path.to_str().unwrap(), "test-host".to_string(), 0);
        let handle = tokio::spawn(collector.run(tx, shared_offset));

        // Receive the parsed event. With paused time the inter-iteration
        // 500ms sleep is also virtual, but the collector emits the event
        // before the first such sleep.
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("should not time out")
            .expect("event channel must produce one event");

        assert_eq!(event.source, "nginx_access");
        assert_eq!(event.kind, "http.request");
        assert!(event.summary.contains("203.0.113.10"));

        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn run_retries_quietly_on_persistent_missing_file() {
        // Err arm of the match open_result. Path that does not exist:
        // the collector hits Err, calls log_instruction_for (which on
        // first hit returns WarnCannotOpen), sleeps 5s, retries. Subsequent
        // iterations get DebugSuppressed. The test does not assert on log
        // output (we trust log_instruction_for's unit tests for that) but
        // it DOES exercise the Err arm + the sleep + the continue path,
        // which is the bulk of the changed lines under codecov.
        let (tx, _rx) = mpsc::channel::<Event>(16);
        let shared_offset = Arc::new(AtomicU64::new(0));
        let collector = NginxAccessCollector::new(
            "/var/empty/_nonexistent_innerwarden_test_path/access.log".to_string(),
            "test-host".to_string(),
            0,
        );
        let handle = tokio::spawn(collector.run(tx, shared_offset));

        // Advance virtual time past several retry cadences. Each
        // tokio::time::advance hop wakes any sleeping task whose deadline
        // it passes, so the collector iterates the loop multiple times.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(5)).await;
            tokio::task::yield_now().await;
        }

        // Cancel the collector. Aborting from inside the test runtime is
        // safe: the task does not hold any externally-visible resource
        // that needs draining.
        handle.abort();
        let _ = handle.await; // resolve the JoinHandle (ignores AbortedError)
    }
}
