//! Cloud-metadata SSRF detector — flags outbound connections to
//! Instance Metadata Service (IMDS) endpoints from processes that have
//! no business querying them.
//!
//! ## Why this exists
//!
//! IMDS at `169.254.169.254` (and `fd00:ec2::254` for AWS IPv6) is the
//! cloud-provider endpoint that hands out short-lived IAM /
//! service-account credentials valid for the host. Every major cloud
//! (AWS, GCP, Azure, Oracle, Alibaba) uses the same link-local address.
//!
//! An attacker who lands SSRF in a webapp:
//!
//! ```text
//! GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
//! ```
//!
//! can lift those credentials and pivot from the compromised app to
//! the entire cloud account.
//!
//! ## Why the existing pipeline misses this
//!
//! The agent's `cloud_safelist.rs` explicitly permits the
//! `169.254.0.0/16` range so that legitimate cloud-init / SSM-agent /
//! kubelet IMDS traffic does not trip the regular outbound and C2
//! detectors. That choice is correct for those tools — and exactly
//! what an SSRF exploit hides behind. This detector is the targeted
//! exception: it specifically watches IMDS and fires when the
//! accessing process is NOT in the legitimate-tool allowlist.
//!
//! ## FP defences
//!
//! Three layers, applied in order:
//!
//! 1. `is_innerwarden_process(uid, comm)` — sensor / agent processes
//!    are skipped even if some future code path queries IMDS (none
//!    today; defensive symmetry with `data_exfil_ebpf`).
//! 2. `IMDS_LEGITIMATE_PROCESSES` — hard-coded list of cloud bootstrap
//!    and agent comms (cloud-init, amazon-ssm-agen, aws, gcloud, az,
//!    walinuxagent, kubelet, dockerd, containerd, …) that legitimately
//!    poll IMDS. Each entry uses the truncated 15-char form that
//!    Linux's `TASK_COMM_LEN` produces, so the actual comm seen in
//!    eBPF events matches.
//! 3. `allowlist_comms` (config) — operator extension for app-specific
//!    runtimes that legitimately use IAM (e.g. a Python service that
//!    calls boto3 against IMDS). Adding `python3` here silences the
//!    HIGH-tier alert for that comm only.
//!
//! After the three skips, the detector tiers severity:
//!
//! - `WEBSERVER_RUNTIME_PREFIXES` (`nginx`, `apache2`, `php-fpm`,
//!   `uwsgi`, `gunicorn`, `puma`, …) hitting IMDS = **Critical**. That
//!   shape IS the SSRF signature — webserver workers do not call IAM
//!   in normal life.
//! - Any other non-allowlisted comm = **High**. Suspicious but worth
//!   investigating before allowlisting.
//!
//! A per-(comm) cooldown of 10 minutes prevents alert floods when an
//! SSRF loop pokes IMDS continuously.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Default IMDS IPv4 endpoint shared by AWS, GCP, Azure, Oracle, Alibaba.
const IMDS_IPV4: &str = "169.254.169.254";

/// AWS IPv6 IMDS endpoint (RFC 7793 / ULA-style address that AWS reuses
/// for the same role as the IPv4 169.254.169.254).
const IMDS_IPV6: &str = "fd00:ec2::254";

/// Cooldown applied per accessing comm. Even an SSRF loop should not
/// emit more than one incident per (comm) per 10 minutes — the first
/// one is enough to wake the operator.
pub const DEFAULT_COOLDOWN_SECONDS: u64 = 600;

/// Comms that legitimately query IMDS. Entries are matched with
/// `starts_with`, so the Linux 15-char truncation (`TASK_COMM_LEN`) is
/// covered: `amazon-ssm-agent` becomes `amazon-ssm-agen` in eBPF
/// events, `ec2-instance-connect` becomes `ec2-instance-c`, etc.
///
/// Coverage rationale:
///
/// - AWS: cloud-init (first-boot configuration), amazon-ssm-agent
///   (Systems Manager), amazon-cloudwatch-agent, ec2-instance-connect,
///   awscli / aws (CLI), the various aws-c2c / aws-c2v helper daemons.
/// - GCP: cloud-init (yes, same binary on GCP), gcloud (CLI),
///   gke-metadata-server, google-osconfig-agent, google-fluentd,
///   google_oslogin_*, google-startup-scripts. All known to poll IMDS
///   on a schedule.
/// - Azure: az / azure-cli, walinuxagent + WaAppAgent (the Azure
///   provisioning daemons), omsagent (Log Analytics).
/// - Kubernetes / container runtimes: kubelet, dockerd, containerd,
///   runc, kube-proxy, cilium-agent. All call IMDS to discover the
///   node's IAM role for pulling private images, mounting EBS, etc.
const IMDS_LEGITIMATE_PROCESSES: &[&str] = &[
    // AWS
    "cloud-init",
    "cloud-init-l",
    "cloud-config",
    "cloud-final",
    "amazon-ssm-agen",
    "amazon-cloudwat",
    "aws",
    "awscli",
    "ec2-instance-c",
    // GCP
    "gcloud",
    "gke-metadata-",
    "google-fluentd",
    "google-osconfig",
    "google_oslogin_",
    "google-startup-",
    // Azure
    "az",
    "azure-cli",
    "walinuxagent",
    "WaAppAgent",
    "omsagent",
    // Kubernetes / container runtimes
    "kubelet",
    "dockerd",
    "containerd",
    "runc",
    "kube-proxy",
    "cilium-agent",
];

/// Comms whose IMDS access is treated as the canonical SSRF signature
/// and promoted to Critical. These are HTTP-serving frontends and
/// app-server workers — none of them call IAM as part of their job.
///
/// Deliberately conservative: this list does NOT include generic
/// language runtimes (`python`, `node`, `ruby`, `java`) because those
/// comms are also used for CLI tools and worker daemons that may
/// legitimately consume IAM via the cloud SDKs. Such processes still
/// fire a HIGH-tier alert (worth one human look) and the operator can
/// allowlist them per-comm if the access is legitimate.
const WEBSERVER_RUNTIME_PREFIXES: &[&str] = &[
    "nginx",
    "apache2",
    "apache",
    "httpd",
    "caddy",
    "lighttpd",
    "openresty",
    "php-fpm",
    "uwsgi",
    "gunicorn",
    "puma",
    "unicorn",
    "passenger",
];

pub struct ImdsSsrfDetector {
    host: String,
    /// Operator-extended allowlist on top of `IMDS_LEGITIMATE_PROCESSES`.
    allowlist_comms: Vec<String>,
    /// Cooldown gate: per-(comm) timestamp of last emitted incident.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl ImdsSsrfDetector {
    pub fn new(
        host: impl Into<String>,
        allowlist_comms: Vec<String>,
        cooldown_seconds: u64,
    ) -> Self {
        Self {
            host: host.into(),
            allowlist_comms,
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "network.outbound_connect" {
            return None;
        }
        let dst_ip = event.details.get("dst_ip").and_then(|v| v.as_str())?;
        if dst_ip != IMDS_IPV4 && dst_ip != IMDS_IPV6 {
            return None;
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);

        if super::allowlists::is_innerwarden_process(uid, comm) {
            return None;
        }
        if IMDS_LEGITIMATE_PROCESSES
            .iter()
            .any(|p| comm.starts_with(p))
        {
            return None;
        }
        if self
            .allowlist_comms
            .iter()
            .any(|p| comm.starts_with(p.as_str()))
        {
            return None;
        }

        let now = event.ts;
        if let Some(&last) = self.alerted.get(comm) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(comm.to_string(), now);

        // Memory bound — keep the cooldown map from growing unboundedly
        // if a long-running SSRF loop cycles through many synthetic
        // comm names. 4096 distinct comms is well beyond any realistic
        // host.
        if self.alerted.len() > 4096 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        let is_webserver = WEBSERVER_RUNTIME_PREFIXES
            .iter()
            .any(|p| comm.starts_with(p));
        let severity = if is_webserver {
            Severity::Critical
        } else {
            Severity::High
        };

        let title = if is_webserver {
            format!("Cloud metadata SSRF: webserver process {comm} (pid={pid}) reached IMDS at {dst_ip}")
        } else {
            format!("Cloud metadata access by unexpected process: {comm} (pid={pid}) reached IMDS at {dst_ip}")
        };

        let summary = format!(
            "{comm} (pid={pid}) made an outbound connection to the cloud \
             metadata endpoint {dst_ip}. IMDS hands out short-lived IAM / \
             service-account credentials valid for this host. {}",
            if is_webserver {
                "Webserver runtimes (nginx / apache / php-fpm / uwsgi / \
                 gunicorn) don't call IAM in normal operation, so this \
                 pattern is the canonical SSRF-to-cred-theft signature. \
                 Treat as a likely SSRF exploit against the webapp; check \
                 request logs for the URL that triggered the IMDS request \
                 and rotate any IAM credentials the metadata server returned."
            } else {
                "This process is not in the built-in cloud-tool allowlist \
                 (cloud-init / SSM-agent / kubelet / aws / gcloud / az / …). \
                 Investigate whether it should be allowlisted in \
                 `[detectors.imds_ssrf] allowlist_comms` or whether it \
                 indicates an attacker tool."
            }
        );

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("imds_ssrf:{pid}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title,
            summary,
            evidence: serde_json::json!([{
                "kind": "imds_ssrf",
                "detection": "metadata_endpoint_access",
                "comm": comm,
                "pid": pid,
                "dst_ip": dst_ip,
                "is_webserver_runtime": is_webserver,
            }]),
            recommended_checks: vec![
                format!(
                    "Identify the URL or input that caused {comm} (pid={pid}) to query IMDS"
                ),
                "Rotate any IAM / service-account credentials that may have been returned".to_string(),
                "Patch SSRF in the application — typically a request-forwarding or webhook feature".to_string(),
                format!(
                    "If legitimate, allowlist via `[detectors.imds_ssrf] allowlist_comms = [\"{comm}\"]`"
                ),
            ],
            tags: vec![
                "credential_access".to_string(),
                "imds".to_string(),
                "ssrf".to_string(),
                if is_webserver {
                    "webserver_runtime".to_string()
                } else {
                    "unexpected_process".to_string()
                },
            ],
            entities: vec![EntityRef::ip(dst_ip)],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn imds_connect(pid: u32, comm: &str, dst_ip: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: format!("connect {dst_ip}:80"),
            details: serde_json::json!({
                "pid": pid,
                "uid": 33, // www-data
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": 80,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn nginx_to_imds_fires_critical() {
        // The canonical SSRF signature: an HTTP-serving frontend
        // (nginx / php-fpm / uwsgi) makes an outbound connect to
        // 169.254.169.254. There is no legitimate reason for nginx
        // to call IAM — this IS the SSRF-to-cred-theft pattern.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9100, "nginx", IMDS_IPV4, Utc::now()))
            .expect("nginx → IMDS must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("SSRF"));
        assert!(inc.tags.contains(&"webserver_runtime".to_string()));
    }

    #[test]
    fn php_fpm_to_imds_fires_critical() {
        // PHP-FPM workers are the classic SSRF vector: a vulnerable
        // PHP app that takes URLs as input (avatar uploaders, SSRF
        // in image-proxy features) gets weaponised by appending
        // `http://169.254.169.254/latest/meta-data/iam/...`.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9101, "php-fpm", IMDS_IPV4, Utc::now()))
            .expect("php-fpm → IMDS must fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn unknown_runtime_to_imds_fires_high_not_critical() {
        // A non-allowlisted, non-webserver comm hitting IMDS is
        // suspicious but ambiguous — could be an attacker tool or a
        // legitimate app using boto3 from a worker daemon. Fire HIGH
        // (one human look) instead of Critical (page on-call).
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9102, "python3", IMDS_IPV4, Utc::now()))
            .expect("unknown comm → IMDS must fire");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.tags.contains(&"unexpected_process".to_string()));
    }

    #[test]
    fn cloud_init_to_imds_is_silent() {
        // cloud-init queries IMDS at every boot to pull the user-data
        // and instance identity document. Firing here would page
        // on-call for every reboot.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect(9103, "cloud-init", IMDS_IPV4, Utc::now()));
        assert!(inc.is_none(), "cloud-init must be allowlisted");
    }

    #[test]
    fn ssm_agent_truncated_comm_is_silent() {
        // Linux TASK_COMM_LEN truncates `amazon-ssm-agent` to
        // `amazon-ssm-agen`. Anchor pins that the allowlist entry
        // covers the truncated form — the form eBPF actually emits.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect(
            9104,
            "amazon-ssm-agen",
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(
            inc.is_none(),
            "amazon-ssm-agen (truncated 15-char comm) must be allowlisted"
        );
    }

    #[test]
    fn kubelet_to_imds_is_silent() {
        // kubelet queries IMDS on every node startup to discover the
        // IAM role for pulling private images and mounting EBS.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect(9105, "kubelet", IMDS_IPV4, Utc::now()));
        assert!(inc.is_none(), "kubelet must be allowlisted");
    }

    #[test]
    fn operator_allowlist_silences_otherwise_flagged_comm() {
        // Operator runs a Python service that legitimately uses
        // boto3 against IMDS. Default behaviour fires HIGH; adding
        // `python3` to the operator's `allowlist_comms` config
        // silences it.
        let mut det = ImdsSsrfDetector::new(
            "test",
            vec!["python3".to_string()],
            DEFAULT_COOLDOWN_SECONDS,
        );
        let inc = det.process(&imds_connect(9106, "python3", IMDS_IPV4, Utc::now()));
        assert!(inc.is_none(), "operator-allowlisted comm must be silenced");
    }

    #[test]
    fn cooldown_blocks_repeated_alerts_within_window() {
        // An SSRF loop hammering IMDS once a second would produce a
        // flood of identical alerts without a cooldown. Pin that the
        // second alert from the same comm within the cooldown
        // window is suppressed.
        let mut det = ImdsSsrfDetector::new("test", vec![], 600);
        let now = Utc::now();
        let first = det.process(&imds_connect(9200, "nginx", IMDS_IPV4, now));
        assert!(first.is_some());
        let second = det.process(&imds_connect(
            9200,
            "nginx",
            IMDS_IPV4,
            now + Duration::seconds(30),
        ));
        assert!(
            second.is_none(),
            "second alert within 30s must be suppressed"
        );
    }

    #[test]
    fn cooldown_expires_after_window() {
        // After the cooldown elapses, a fresh attack from the same
        // comm should fire again — otherwise an operator who acks an
        // alert and forgets to fix the SSRF would never get
        // re-paged when the attacker resumes the next day.
        let mut det = ImdsSsrfDetector::new("test", vec![], 60);
        let now = Utc::now();
        det.process(&imds_connect(9201, "nginx", IMDS_IPV4, now));
        let later = det.process(&imds_connect(
            9201,
            "nginx",
            IMDS_IPV4,
            now + Duration::seconds(61),
        ));
        assert!(later.is_some(), "alert after cooldown must fire");
    }

    #[test]
    fn ipv6_imds_endpoint_is_covered() {
        // AWS exposes IMDS at fd00:ec2::254 on IPv6-only instances.
        // Skipping IPv6 would let attackers bypass detection by
        // crafting a URL that uses the IPv6 endpoint.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9300, "nginx", IMDS_IPV6, Utc::now()))
            .expect("IMDS over IPv6 must fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn non_imds_outbound_is_ignored() {
        // Sanity check: an outbound connect to a non-IMDS address
        // must NOT enter the detector's hot path even when the
        // process is otherwise interesting. The whole point of this
        // detector being separate from c2_callback / outbound_anomaly
        // is that it ONLY watches IMDS.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect(9400, "nginx", "8.8.8.8", Utc::now()));
        assert!(inc.is_none());
    }

    #[test]
    fn innerwarden_own_process_is_silent() {
        // Defensive symmetry with data_exfil_ebpf: if some future
        // refactor of the agent's cloud_safelist init queries IMDS,
        // do not self-page.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let now = Utc::now();
        let ev = Event {
            ts: now,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: "connect".into(),
            details: serde_json::json!({
                "pid": 9500,
                "uid": 998, // innerwarden uid (see allowlists::is_innerwarden_process)
                "comm": "tokio-rt-worker",
                "dst_ip": IMDS_IPV4,
                "dst_port": 80,
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }
}
