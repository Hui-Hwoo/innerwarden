//! Environment profiling — detect cloud/VM, admin UIDs, services, crons.
//!
//! Bootstrap profiling runs once at first boot (or when profile is missing).
//! The profile is stored as JSON in data_dir and loaded at agent startup to
//! adjust notification thresholds and suppress known noise.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::EnvironmentConfig;

// ---------------------------------------------------------------------------
// Profile data
// ---------------------------------------------------------------------------

/// Operator-facing classification of a user observed in events.
///
/// Returned by `EnvironmentProfile::classify_user`. Graph detectors
/// use this to apply differentiated thresholds:
///
/// * `Root` — uid 0. Always-trusted (3x threshold by convention).
/// * `Human` — uid >= 1000 with a login shell (`bash`, `zsh`, etc.).
///   Real operators. 3x threshold.
/// * `Service` — uid >= 1000 with `nologin`/`false` shell. System
///   service accounts (`snap_daemon`, `_apt`, `systemd-resolve`,
///   `messagebus`, etc.) that the OS spawns to run package updates,
///   DNS resolution, dbus brokering, etc. They legitimately do
///   `socket + sensitive_read` and process bursts during routine
///   work. 5x threshold by default; `data_exfil` skips them
///   entirely because that detector is the noisiest.
/// * `Unknown` — anyone the agent does not recognise. Standard
///   threshold. Real attacker scenarios (compromised low-uid
///   service that doesn't appear in /etc/passwd, exec from a
///   chroot, etc.) end up here and get the strict treatment they
///   deserve.
///
/// **Threat model (2026-05-03):** classifying a user as Service
/// dampens noise but does NOT silence telemetry — every suppression
/// increments `innerwarden_graph_detector_suppressed_total{user_class}`
/// in the metrics so the operator can grep `/metrics` and see what
/// was hidden. If `snap_daemon` itself is ever compromised at uid
/// level, kill_chain detection in eBPF still fires (different code
/// path, untouchable enforcement applies); only the graph
/// behavioural detectors (which are inherently noisy on routine
/// service activity) are dampened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum UserClass {
    Root,
    Human,
    Service,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnvironmentProfile {
    /// "cloud_vps", "vm", or "bare_metal"
    pub platform: String,
    /// Cloud provider if detected (e.g., "oracle", "aws", "gcp", "azure", "digitalocean")
    pub provider: String,
    /// UIDs of human users (uid >= 1000, with login shell)
    pub human_uids: Vec<u32>,
    /// 2026-05-03: UIDs of system service accounts (uid >= 1000,
    /// `nologin`/`false` shell). Auto-detected from `/etc/passwd`.
    /// Distinct from `human_uids` so detectors can apply different
    /// thresholds (Service gets 5x, Human gets 3x).
    #[serde(default)]
    pub service_uids: Vec<u32>,
    /// 2026-05-03: names of those service accounts. Same length as
    /// `service_uids` and 1:1 indexed. Needed because graph events
    /// arrive with the user as a name (`snap_daemon`) more often
    /// than as `uid:NNNN`, so the classifier needs reverse lookup.
    #[serde(default)]
    pub service_user_names: Vec<String>,
    /// 2026-05-03: names of human user accounts. Same role as above
    /// (reverse lookup). 1:1 with `human_uids`.
    #[serde(default)]
    pub human_user_names: Vec<String>,
    /// Running systemd service names
    pub services: Vec<String>,
    /// Cron job descriptions
    pub crons: Vec<String>,
    /// When the profile was generated
    pub profiled_at: chrono::DateTime<chrono::Utc>,
}

impl Default for EnvironmentProfile {
    fn default() -> Self {
        Self {
            platform: "unknown".into(),
            provider: "unknown".into(),
            human_uids: vec![],
            service_uids: vec![],
            service_user_names: vec![],
            human_user_names: vec![],
            services: vec![],
            crons: vec![],
            profiled_at: chrono::Utc::now(),
        }
    }
}

impl EnvironmentProfile {
    pub fn is_cloud(&self) -> bool {
        self.platform == "cloud_vps" || self.platform == "vm"
    }

    #[allow(dead_code)]
    pub fn is_human_uid(&self, uid: u32) -> bool {
        self.human_uids.contains(&uid)
    }

    /// 2026-05-03: classify a user observed in graph events. Accepts
    /// either a numeric `uid:NNNN` form or a named user (`snap_daemon`,
    /// `ubuntu`, `root`).
    ///
    /// Mirrored on `CalibrationContext::classify_user` (which is what
    /// the graph detectors call after the boot path bridges the
    /// fields). Kept here so any code holding a `&EnvironmentProfile`
    /// directly can classify without first building a context.
    #[allow(dead_code)]
    pub fn classify_user(&self, name_or_uid: &str) -> UserClass {
        if name_or_uid == "root" {
            return UserClass::Root;
        }
        if let Some(uid_str) = name_or_uid.strip_prefix("uid:") {
            if let Ok(uid) = uid_str.parse::<u32>() {
                return self.classify_uid(uid);
            }
            return UserClass::Unknown;
        }
        // Named user — reverse lookup against the cached name lists
        // populated at boot from /etc/passwd.
        if self.service_user_names.iter().any(|n| n == name_or_uid) {
            return UserClass::Service;
        }
        if self.human_user_names.iter().any(|n| n == name_or_uid) {
            return UserClass::Human;
        }
        UserClass::Unknown
    }

    #[allow(dead_code)]
    fn classify_uid(&self, uid: u32) -> UserClass {
        if uid == 0 {
            return UserClass::Root;
        }
        if self.human_uids.contains(&uid) {
            return UserClass::Human;
        }
        if self.service_uids.contains(&uid) {
            return UserClass::Service;
        }
        UserClass::Unknown
    }

    /// 2026-05-03: extend the Service classification with operator-
    /// supplied user names from `[graph_detectors] service_users_extra`.
    /// Runs at boot after `bootstrap_profile`. Idempotent —
    /// duplicates are deduped, empty / whitespace entries skipped.
    /// Also accepts pure-uid extras via `service_uids_extra`.
    pub fn merge_operator_service_extras(
        &mut self,
        service_users_extra: &[String],
        service_uids_extra: &[u32],
    ) {
        for name in service_users_extra {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !self.service_user_names.iter().any(|n| n == trimmed) {
                self.service_user_names.push(trimmed.to_string());
            }
        }
        for uid in service_uids_extra {
            if !self.service_uids.contains(uid) {
                self.service_uids.push(*uid);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Profile file path
// ---------------------------------------------------------------------------

fn profile_path(data_dir: &Path) -> PathBuf {
    data_dir.join("environment-profile.json")
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load the environment profile from disk. Returns None if not found.
pub(crate) fn load_profile(data_dir: &Path) -> Option<EnvironmentProfile> {
    let path = profile_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(profile) => Some(profile),
            Err(e) => {
                warn!("failed to parse environment profile: {e:#}");
                None
            }
        },
        Err(_) => None,
    }
}

fn save_profile(data_dir: &Path, profile: &EnvironmentProfile) -> anyhow::Result<()> {
    let path = profile_path(data_dir);
    let json = serde_json::to_string_pretty(profile)?;
    std::fs::write(&path, json)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootstrap profiling
// ---------------------------------------------------------------------------

/// Generate and save the environment profile. Runs once at first boot.
pub(crate) fn bootstrap_profile(data_dir: &Path, _cfg: &EnvironmentConfig) -> EnvironmentProfile {
    let (platform, provider) = detect_platform();
    let UserAccountScan {
        human_uids,
        human_user_names,
        service_uids,
        service_user_names,
    } = scan_user_accounts();
    let services = detect_services();
    let crons = detect_crons();

    let profile = EnvironmentProfile {
        platform,
        provider,
        human_uids,
        service_uids,
        service_user_names,
        human_user_names,
        services,
        crons,
        profiled_at: chrono::Utc::now(),
    };

    if let Err(e) = save_profile(data_dir, &profile) {
        warn!("failed to save environment profile: {e:#}");
    } else {
        info!(
            platform = %profile.platform,
            provider = %profile.provider,
            human_uids = ?profile.human_uids,
            service_uids = ?profile.service_uids,
            services_count = profile.services.len(),
            crons_count = profile.crons.len(),
            "environment profile bootstrapped"
        );
    }

    profile
}

/// Load existing profile or bootstrap a new one.
pub(crate) fn load_or_bootstrap(data_dir: &Path, cfg: &EnvironmentConfig) -> EnvironmentProfile {
    if !cfg.auto_profile {
        return EnvironmentProfile::default();
    }

    if let Some(profile) = load_profile(data_dir) {
        info!(
            platform = %profile.platform,
            provider = %profile.provider,
            "loaded environment profile from disk"
        );
        return profile;
    }

    bootstrap_profile(data_dir, cfg)
}

// ---------------------------------------------------------------------------
// Platform detection (cloud/VM/bare metal)
// ---------------------------------------------------------------------------

fn detect_platform() -> (String, String) {
    // Read DMI product name — available on most Linux systems
    let product_name = read_dmi("product_name");
    let sys_vendor = read_dmi("sys_vendor");
    let bios_vendor = read_dmi("bios_vendor");

    // Check for known cloud/VM signatures
    let combined = format!(
        "{} {} {}",
        product_name.to_lowercase(),
        sys_vendor.to_lowercase(),
        bios_vendor.to_lowercase()
    );

    let (platform, provider) = if combined.contains("oracle") || combined.contains("oci") {
        ("cloud_vps", "oracle")
    } else if combined.contains("amazon") || combined.contains("aws") || combined.contains("ec2") {
        ("cloud_vps", "aws")
    } else if combined.contains("google") || combined.contains("gce") {
        ("cloud_vps", "gcp")
    } else if combined.contains("microsoft")
        || combined.contains("azure")
        || combined.contains("hyper-v")
    {
        ("cloud_vps", "azure")
    } else if combined.contains("digitalocean") {
        ("cloud_vps", "digitalocean")
    } else if combined.contains("hetzner") {
        ("cloud_vps", "hetzner")
    } else if combined.contains("linode") || combined.contains("akamai") {
        ("cloud_vps", "linode")
    } else if combined.contains("vultr") {
        ("cloud_vps", "vultr")
    } else if combined.contains("ovh") {
        ("cloud_vps", "ovh")
    } else if combined.contains("vmware")
        || combined.contains("virtualbox")
        || combined.contains("qemu")
        || combined.contains("kvm")
        || combined.contains("xen")
        || combined.contains("bhyve")
    {
        ("vm", "unknown")
    } else {
        ("bare_metal", "none")
    };

    (platform.into(), provider.into())
}

fn read_dmi(field: &str) -> String {
    let path = format!("/sys/class/dmi/id/{field}");
    std::fs::read_to_string(&path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// User account detection (humans + service accounts)
// ---------------------------------------------------------------------------

/// 2026-05-03: result of one `/etc/passwd` scan, partitioned into
/// the four classifications graph detectors care about. Names and
/// UIDs are kept in parallel slices (1:1 indexed) because graph
/// events arrive with the user as a name (`snap_daemon`) more often
/// than as `uid:NNNN`, and the classifier needs both directions.
pub(crate) struct UserAccountScan {
    pub human_uids: Vec<u32>,
    pub human_user_names: Vec<String>,
    pub service_uids: Vec<u32>,
    pub service_user_names: Vec<String>,
}

/// Parse `/etc/passwd` and partition entries into Human / Service.
///
/// Classification rules (2026-05-03 — anchored on the operator's
/// `snap_daemon = uid 584788` finding which the previous range
/// `1000..65534` silently dropped):
///
/// * uid 0 (root) → not classified here. Graph detectors handle
///   root via the `Root` arm of `UserClass`, not via this scan.
/// * uid 65534 (`nobody`) → skipped. Reserved for "no real user".
/// * any uid != 0 / 65534 with a `nologin` / `false` shell →
///   Service. Covers both low-uid system services (`_apt = 42`,
///   `systemd-resolve = 991`) AND high-uid mappings used by snap
///   subuid namespaces (`snap_daemon = 584788`, often beyond the
///   classical 16-bit range).
/// * uid >= 1000 with a real login shell → Human.
/// * uid 1-999 with a login shell → unclassified (rare; default
///   to the strict path so real attacker scenarios surface).
///
/// Pure function over file contents. Real I/O lives in
/// `scan_user_accounts`. Split so tests can drive synthetic input.
pub(crate) fn parse_passwd_for_user_classes(content: &str) -> UserAccountScan {
    const NOBODY_UID: u32 = 65534;
    let nologin_shells = ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"];
    let mut scan = UserAccountScan {
        human_uids: Vec::new(),
        human_user_names: Vec::new(),
        service_uids: Vec::new(),
        service_user_names: Vec::new(),
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            continue;
        }
        let name = parts[0];
        let Ok(uid) = parts[2].parse::<u32>() else {
            continue;
        };
        if uid == 0 || uid == NOBODY_UID {
            continue;
        }
        let shell = parts[6];
        let is_nologin = nologin_shells.iter().any(|s| shell.ends_with(s));
        if is_nologin {
            scan.service_uids.push(uid);
            scan.service_user_names.push(name.to_string());
        } else if uid >= 1000 {
            scan.human_uids.push(uid);
            scan.human_user_names.push(name.to_string());
        }
        // uid 1-999 with login shell: rare edge case (e.g. uid for
        // `mail`/`bin` but with /bin/sh by mistake). Leave
        // unclassified — falls into UserClass::Unknown so detectors
        // apply the strict standard threshold.
    }
    scan
}

fn scan_user_accounts() -> UserAccountScan {
    match std::fs::read_to_string("/etc/passwd") {
        Ok(content) => parse_passwd_for_user_classes(&content),
        Err(_) => UserAccountScan {
            human_uids: Vec::new(),
            human_user_names: Vec::new(),
            service_uids: Vec::new(),
            service_user_names: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Service detection
// ---------------------------------------------------------------------------

fn detect_services() -> Vec<String> {
    let output = match std::process::Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    if !output.status.success() {
        return vec![];
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            // Format: "unit.service loaded active running description..."
            line.split_whitespace()
                .next()
                .map(|unit| unit.strip_suffix(".service").unwrap_or(unit).to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Cron detection
// ---------------------------------------------------------------------------

/// Read a system crontab file for the cron-baseline scan, surfacing
/// genuine I/O failure via `warn!` while staying silent on `NotFound`
/// (some hosts do not ship a /etc/crontab; the cron.d scan still picks
/// up user cron jobs). Replaces the silent
/// `if let Ok(content) = read_to_string("/etc/crontab")` site
/// (Spec 037 I-13 follow-up #2).
///
/// On a real I/O error the operator's environment baseline misses
/// every system-cron entry, weakening the cron-based persistence
/// detection signal. The warn carries path + error so the operator
/// can recover the file or fix permissions.
fn read_crontab_file_or_warn(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "system crontab read failed (system-cron entries missing from environment baseline)"
            );
            None
        }
    }
}

fn detect_crons() -> Vec<String> {
    let mut crons = Vec::new();

    // System crontab
    if let Some(content) = read_crontab_file_or_warn(Path::new("/etc/crontab")) {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                crons.push(format!("system: {trimmed}"));
            }
        }
    }

    // User crontabs for root
    let output = std::process::Command::new("crontab").args(["-l"]).output();
    if let Ok(o) = output {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    crons.push(format!("root: {trimmed}"));
                }
            }
        }
    }

    // /etc/cron.d/
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                crons.push(format!("cron.d: {name}"));
            }
        }
    }

    crons
}

// ---------------------------------------------------------------------------
// Spec 005 Phase 6 — Periodic Census
// ---------------------------------------------------------------------------
//
// Every `census_interval_hours` the agent re-profiles the environment and
// diffs against the stored profile. Three kinds of diff are recorded:
//
//   - UidAdded / UidRemoved      — new or removed human UIDs
//   - ServiceAdded / ServiceRemoved — systemd service drift
//   - CronAdded / CronRemoved    — new or removed cron entries
//
// Each diff is appended as a line of JSON to
// `data_dir/census-YYYY-MM-DD.jsonl`. Diffs that are "suspicious" (new human
// UID not paired with an installer service; new cron job) also return an
// `Incident` so the caller can route them through the normal notification
// pipeline. Service additions are informational only — new services arrive
// legitimately during package installs and package-install drift fires its
// own detector.

use innerwarden_core::{
    entities::{EntityRef, EntityType},
    event::Severity,
    incident::Incident,
};

/// A single change observed between two environment profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CensusChange {
    UidAdded { uid: u32 },
    UidRemoved { uid: u32 },
    ServiceAdded { name: String },
    ServiceRemoved { name: String },
    CronAdded { entry: String },
    CronRemoved { entry: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CensusRecord {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub change: CensusChange,
}

/// Result of `run_census`: the incidents that should be surfaced through
/// the normal notification pipeline and the full diff list for audit.
#[derive(Debug, Default)]
#[allow(dead_code)] // `changes` is audit output (written to JSONL) — runtime path only reads `incidents` + `new_profile`.
pub(crate) struct CensusOutcome {
    pub incidents: Vec<Incident>,
    pub changes: Vec<CensusChange>,
    pub new_profile: Option<EnvironmentProfile>,
}

/// Diff two profiles and produce the list of changes.
pub(crate) fn diff_profiles(
    previous: &EnvironmentProfile,
    current: &EnvironmentProfile,
) -> Vec<CensusChange> {
    use std::collections::HashSet;

    let mut out = Vec::new();

    let prev_uids: HashSet<&u32> = previous.human_uids.iter().collect();
    let curr_uids: HashSet<&u32> = current.human_uids.iter().collect();
    for uid in curr_uids.difference(&prev_uids) {
        out.push(CensusChange::UidAdded { uid: **uid });
    }
    for uid in prev_uids.difference(&curr_uids) {
        out.push(CensusChange::UidRemoved { uid: **uid });
    }

    let prev_svcs: HashSet<&String> = previous.services.iter().collect();
    let curr_svcs: HashSet<&String> = current.services.iter().collect();
    for svc in curr_svcs.difference(&prev_svcs) {
        out.push(CensusChange::ServiceAdded {
            name: (*svc).clone(),
        });
    }
    for svc in prev_svcs.difference(&curr_svcs) {
        out.push(CensusChange::ServiceRemoved {
            name: (*svc).clone(),
        });
    }

    let prev_crons: HashSet<&String> = previous.crons.iter().collect();
    let curr_crons: HashSet<&String> = current.crons.iter().collect();
    for c in curr_crons.difference(&prev_crons) {
        out.push(CensusChange::CronAdded {
            entry: (*c).clone(),
        });
    }
    for c in prev_crons.difference(&curr_crons) {
        out.push(CensusChange::CronRemoved {
            entry: (*c).clone(),
        });
    }

    out
}

/// Classify which diffs warrant an incident. UID additions and cron
/// additions are suspicious; removals and service drift are informational.
pub(crate) fn incidents_for_changes(changes: &[CensusChange], host: &str) -> Vec<Incident> {
    let now = chrono::Utc::now();
    changes
        .iter()
        .filter_map(|c| match c {
            CensusChange::UidAdded { uid } => Some(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("env_census:uid_added:{uid}:{}", now.timestamp()),
                severity: Severity::Medium,
                title: format!("Census detected new human UID {uid}"),
                summary: "A human-shell UID was added to /etc/passwd since the last \
                     environment profile. Investigate: new operator, compromised \
                     host, or benign ops change?"
                    .to_string(),
                evidence: serde_json::json!({ "uid": uid, "kind": "uid_added" }),
                recommended_checks: vec![
                    "getent passwd <uid> — confirm the account".to_string(),
                    "Check /var/log/auth.log for recent useradd / adduser".to_string(),
                ],
                tags: vec!["env_census".to_string(), "uid".to_string()],
                entities: vec![EntityRef {
                    r#type: EntityType::User,
                    value: uid.to_string(),
                }],
            }),
            CensusChange::CronAdded { entry } => Some(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!(
                    "env_census:cron_added:{}:{}",
                    stable_hash(entry),
                    now.timestamp()
                ),
                severity: Severity::Medium,
                title: "Census detected a new cron entry".to_string(),
                summary: format!(
                    "A new cron job has appeared since the last profile: `{entry}`. \
                     Benign if it matches a recent install; otherwise investigate."
                ),
                evidence: serde_json::json!({ "entry": entry, "kind": "cron_added" }),
                recommended_checks: vec![
                    "Confirm via package manager whether this cron came from an install"
                        .to_string(),
                    "Inspect the cron command and who owns the target script".to_string(),
                ],
                tags: vec!["env_census".to_string(), "cron".to_string()],
                entities: vec![],
            }),
            _ => None,
        })
        .collect()
}

/// Stable, short identifier for free-text strings used in incident_id.
fn stable_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:x}", h.finish())
}

fn census_path(data_dir: &Path, date: chrono::NaiveDate) -> PathBuf {
    data_dir.join(format!("census-{}.jsonl", date.format("%Y-%m-%d")))
}

pub(crate) fn append_census(
    data_dir: &Path,
    changes: &[CensusChange],
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    use std::io::Write as _;
    let path = census_path(data_dir, now.date_naive());
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    for change in changes {
        let record = CensusRecord {
            ts: now,
            change: change.clone(),
        };
        let line = serde_json::to_string(&record)?;
        writeln!(f, "{line}")?;
    }
    Ok(())
}

/// Re-profile the environment and produce census results. The caller is
/// expected to persist `new_profile` and replace its in-memory copy, and to
/// route `incidents` through the normal notification pipeline.
pub(crate) fn run_census(
    data_dir: &Path,
    cfg: &EnvironmentConfig,
    previous: &EnvironmentProfile,
    host: &str,
) -> CensusOutcome {
    if !cfg.auto_profile {
        return CensusOutcome::default();
    }

    let scan = scan_user_accounts();
    let current = EnvironmentProfile {
        platform: previous.platform.clone(),
        provider: previous.provider.clone(),
        human_uids: scan.human_uids,
        human_user_names: scan.human_user_names,
        service_uids: scan.service_uids,
        service_user_names: scan.service_user_names,
        services: detect_services(),
        crons: detect_crons(),
        profiled_at: chrono::Utc::now(),
    };

    let changes = diff_profiles(previous, &current);
    let incidents = incidents_for_changes(&changes, host);

    if let Err(e) = append_census(data_dir, &changes, current.profiled_at) {
        warn!("census append failed: {e:#}");
    }
    if !changes.is_empty() {
        if let Err(e) = save_profile(data_dir, &current) {
            warn!("census profile save failed: {e:#}");
        }
    }

    if !changes.is_empty() {
        info!(
            changes = changes.len(),
            incidents = incidents.len(),
            "environment census ran"
        );
    }

    CensusOutcome {
        incidents,
        changes,
        new_profile: Some(current),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_unknown() {
        let p = EnvironmentProfile::default();
        assert_eq!(p.platform, "unknown");
        assert!(!p.is_cloud());
    }

    #[test]
    fn cloud_profile_is_detected() {
        let mut p = EnvironmentProfile::default();
        p.platform = "cloud_vps".into();
        assert!(p.is_cloud());
    }

    #[test]
    fn vm_profile_is_cloud() {
        let mut p = EnvironmentProfile::default();
        p.platform = "vm".into();
        assert!(p.is_cloud());
    }

    #[test]
    fn human_uid_check() {
        let mut p = EnvironmentProfile::default();
        p.human_uids = vec![1000, 1001];
        assert!(p.is_human_uid(1000));
        assert!(!p.is_human_uid(0));
    }

    #[test]
    fn save_and_load_profile() {
        let dir = tempfile::tempdir().unwrap();
        let profile = EnvironmentProfile {
            platform: "cloud_vps".into(),
            provider: "oracle".into(),
            human_uids: vec![1001],
            human_user_names: vec!["ubuntu".into()],
            service_uids: vec![],
            service_user_names: vec![],
            services: vec!["nginx".into()],
            crons: vec!["root: certbot renew".into()],
            profiled_at: chrono::Utc::now(),
        };

        save_profile(dir.path(), &profile).unwrap();
        let loaded = load_profile(dir.path()).unwrap();

        assert_eq!(loaded.platform, "cloud_vps");
        assert_eq!(loaded.provider, "oracle");
        assert_eq!(loaded.human_uids, vec![1001]);
        assert_eq!(loaded.services, vec!["nginx"]);
    }

    #[test]
    fn load_missing_profile_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_profile(dir.path()).is_none());
    }

    #[test]
    fn bootstrap_creates_profile_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EnvironmentConfig::default();
        let profile = bootstrap_profile(dir.path(), &cfg);

        // Profile should be saved to disk
        assert!(profile_path(dir.path()).exists());
        // Platform should be detected (at least not panic)
        assert!(!profile.platform.is_empty());
    }

    #[test]
    fn load_or_bootstrap_uses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EnvironmentConfig::default();

        // Bootstrap first
        let p1 = bootstrap_profile(dir.path(), &cfg);

        // Load should return existing
        let p2 = load_or_bootstrap(dir.path(), &cfg);
        assert_eq!(p1.platform, p2.platform);
        assert_eq!(p1.provider, p2.provider);
    }

    #[test]
    fn load_or_bootstrap_respects_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EnvironmentConfig {
            auto_profile: false,
            ..Default::default()
        };

        let profile = load_or_bootstrap(dir.path(), &cfg);
        assert_eq!(profile.platform, "unknown");
        // No file should be created
        assert!(!profile_path(dir.path()).exists());
    }

    // ─── Spec 005 Phase 6 — Periodic Census tests ──────────────────

    fn profile_with(uids: Vec<u32>, services: Vec<&str>, crons: Vec<&str>) -> EnvironmentProfile {
        EnvironmentProfile {
            platform: "bare_metal".into(),
            provider: "none".into(),
            human_uids: uids,
            human_user_names: vec![],
            service_uids: vec![],
            service_user_names: vec![],
            services: services.into_iter().map(String::from).collect(),
            crons: crons.into_iter().map(String::from).collect(),
            profiled_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn diff_profiles_detects_uid_add_and_remove() {
        let prev = profile_with(vec![1000], vec![], vec![]);
        let curr = profile_with(vec![1000, 1001], vec![], vec![]);
        let changes = diff_profiles(&prev, &curr);
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0], CensusChange::UidAdded { uid: 1001 }));

        let reverse = diff_profiles(&curr, &prev);
        assert_eq!(reverse.len(), 1);
        assert!(matches!(reverse[0], CensusChange::UidRemoved { uid: 1001 }));
    }

    #[test]
    fn diff_profiles_detects_service_and_cron_drift() {
        let prev = profile_with(vec![], vec!["nginx"], vec!["root: certbot"]);
        let curr = profile_with(
            vec![],
            vec!["nginx", "postgres"],
            vec!["root: certbot", "root: backup"],
        );
        let changes = diff_profiles(&prev, &curr);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| matches!(
            c,
            CensusChange::ServiceAdded { name } if name == "postgres"
        )));
        assert!(changes.iter().any(|c| matches!(
            c,
            CensusChange::CronAdded { entry } if entry == "root: backup"
        )));
    }

    #[test]
    fn diff_profiles_empty_when_identical() {
        let a = profile_with(vec![1000, 1001], vec!["nginx"], vec!["root: certbot"]);
        let b = a.clone();
        assert!(diff_profiles(&a, &b).is_empty());
    }

    #[test]
    fn incidents_for_changes_emits_uid_added_and_cron_added_only() {
        let changes = vec![
            CensusChange::UidAdded { uid: 1002 },
            CensusChange::UidRemoved { uid: 999 },
            CensusChange::ServiceAdded {
                name: "postgres".into(),
            },
            CensusChange::ServiceRemoved {
                name: "nginx".into(),
            },
            CensusChange::CronAdded {
                entry: "root: backup".into(),
            },
            CensusChange::CronRemoved {
                entry: "root: certbot".into(),
            },
        ];
        let incs = incidents_for_changes(&changes, "testhost");
        assert_eq!(incs.len(), 2, "only UidAdded + CronAdded produce incidents");
        assert!(incs.iter().any(|i| i.incident_id.contains("uid_added")));
        assert!(incs.iter().any(|i| i.incident_id.contains("cron_added")));
    }

    #[test]
    fn incidents_for_changes_produces_unique_incident_ids() {
        let changes = vec![
            CensusChange::CronAdded {
                entry: "root: backup".into(),
            },
            CensusChange::CronAdded {
                entry: "root: daily-report".into(),
            },
        ];
        let incs = incidents_for_changes(&changes, "h");
        assert_eq!(incs.len(), 2);
        assert_ne!(incs[0].incident_id, incs[1].incident_id);
    }

    #[test]
    fn append_census_writes_jsonl_per_date() {
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        let changes = vec![
            CensusChange::UidAdded { uid: 1002 },
            CensusChange::CronAdded {
                entry: "root: backup".into(),
            },
        ];
        append_census(dir.path(), &changes, now).unwrap();
        let path = census_path(dir.path(), now.date_naive());
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: CensusRecord = serde_json::from_str(lines[0]).unwrap();
        assert!(matches!(first.change, CensusChange::UidAdded { uid: 1002 }));
    }

    #[test]
    fn append_census_noop_for_empty_changes() {
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        append_census(dir.path(), &[], now).unwrap();
        let path = census_path(dir.path(), now.date_naive());
        assert!(!path.exists(), "empty census must not create an empty file");
    }

    #[test]
    fn run_census_disabled_when_auto_profile_off() {
        let dir = tempfile::tempdir().unwrap();
        let prev = profile_with(vec![1000], vec![], vec![]);
        let cfg = EnvironmentConfig {
            auto_profile: false,
            ..Default::default()
        };
        let outcome = run_census(dir.path(), &cfg, &prev, "h");
        assert!(outcome.incidents.is_empty());
        assert!(outcome.changes.is_empty());
        assert!(outcome.new_profile.is_none());
    }

    // Spec 037 I-13 follow-up #2: read_crontab_file_or_warn

    #[test]
    fn read_crontab_file_or_warn_returns_some_silently_on_existing_file() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crontab-fixture");
        std::fs::write(&path, b"* * * * * root /usr/bin/true\n").expect("seed crontab");

        let result = read_crontab_file_or_warn(&path);
        assert!(result.is_some(), "existing file must yield Some");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("system crontab read failed"),
            "happy path must not emit warn, got: {captured}"
        );
    }

    #[test]
    fn read_crontab_file_or_warn_returns_none_and_warns_on_io_failure() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("crontab-fixture");

        let result = read_crontab_file_or_warn(&path);
        assert!(result.is_none(), "io-failure must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("system crontab read failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }

    // ── 2026-05-03 (PR #418) anchors — trusted service accounts ──
    //
    // These pin the parse_passwd_for_user_classes contract +
    // EnvironmentProfile::classify_user behaviour so a future
    // refactor that mis-classifies snap_daemon (or breaks the
    // human/service split) is caught at build time.

    #[test]
    fn parse_passwd_splits_humans_and_service_accounts() {
        // Mix of real-world cases:
        //  - root: uid 0 → not classified (handled by Root arm).
        //  - daemon (uid 1): low-uid system service, nologin → Service.
        //  - ubuntu (uid 1000): real operator with login shell → Human.
        //  - maicon (uid 1001): another operator → Human.
        //  - snap_daemon (uid 584788): high-uid subuid mapping
        //    that the operator hit on the dashboard, /usr/bin/false
        //    shell → Service. The previous parser dropped this on
        //    the `1000..65534` range filter; this anchor pins the
        //    high-uid coverage.
        //  - _apt (uid 42): low-uid system, nologin → Service.
        //  - systemd-resolve (uid 991): nologin → Service.
        //  - sshd (uid 121): nologin → Service.
        //  - nobody-mark (uid 65534): the canonical "no user" → skip.
        let synthetic = "\
root:x:0:0::/root:/bin/bash\n\
daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n\
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n\
sshd:x:121:65534::/run/sshd:/usr/sbin/nologin\n\
systemd-resolve:x:991:993:::/usr/sbin/nologin\n\
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n\
maicon:x:1001:1001::/home/maicon:/bin/zsh\n\
snap_daemon:x:584788:584788::/nonexistent:/usr/bin/false\n\
nobody-mark:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
";
        let scan = parse_passwd_for_user_classes(synthetic);
        // Humans: uid >= 1000 + login shell, in file order.
        assert_eq!(scan.human_uids, vec![1000, 1001]);
        assert_eq!(scan.human_user_names, vec!["ubuntu", "maicon"]);
        // Services: any uid != 0/65534 with nologin shell, in file order.
        assert_eq!(scan.service_uids, vec![1, 42, 121, 991, 584788]);
        assert_eq!(
            scan.service_user_names,
            vec!["daemon", "_apt", "sshd", "systemd-resolve", "snap_daemon"]
        );
        // High-uid mapping (584788) MUST be picked up — that's the
        // exact case the operator's dashboard alert came from.
        assert!(scan.service_user_names.contains(&"snap_daemon".to_string()));
        assert!(scan.service_uids.contains(&584788));
        // root and nobody (65534) are skipped.
        assert!(!scan.human_uids.contains(&0));
        assert!(!scan.service_uids.contains(&65534));
    }

    #[test]
    fn classify_user_recognises_named_service_account() {
        let mut profile = EnvironmentProfile::default();
        profile.service_uids = vec![584788];
        profile.service_user_names = vec!["snap_daemon".to_string()];
        profile.human_uids = vec![1000];
        profile.human_user_names = vec!["ubuntu".to_string()];
        // The exact case the operator hit on the dashboard:
        // graph events arrive with `name=snap_daemon`, NOT
        // `uid:584788`, and the old `is_trusted_graph_user` would
        // have returned `false` for that. Now must return Service.
        assert_eq!(profile.classify_user("snap_daemon"), UserClass::Service);
        assert_eq!(profile.classify_user("ubuntu"), UserClass::Human);
        assert_eq!(profile.classify_user("root"), UserClass::Root);
        assert_eq!(profile.classify_user("attacker"), UserClass::Unknown);
    }

    #[test]
    fn classify_user_handles_uid_form() {
        let mut profile = EnvironmentProfile::default();
        profile.human_uids = vec![1000, 1001];
        profile.service_uids = vec![584788];
        assert_eq!(profile.classify_user("uid:0"), UserClass::Root);
        assert_eq!(profile.classify_user("uid:1000"), UserClass::Human);
        assert_eq!(profile.classify_user("uid:584788"), UserClass::Service);
        assert_eq!(profile.classify_user("uid:9999"), UserClass::Unknown);
        // Malformed UID strings fall through to Unknown.
        assert_eq!(profile.classify_user("uid:notanumber"), UserClass::Unknown);
    }

    #[test]
    fn merge_operator_service_extras_dedupes_and_trims() {
        let mut profile = EnvironmentProfile::default();
        profile.service_user_names = vec!["snap_daemon".to_string()];
        profile.service_uids = vec![584788];
        profile.merge_operator_service_extras(
            &[
                "puppet".to_string(),
                "  chef-client  ".to_string(),
                "snap_daemon".to_string(), // duplicate
                "".to_string(),            // empty
                "   ".to_string(),         // whitespace
            ],
            &[991, 584788, 992],
        );
        // Duplicates and empty entries skipped, whitespace trimmed.
        assert_eq!(
            profile.service_user_names,
            vec!["snap_daemon", "puppet", "chef-client"]
        );
        assert_eq!(profile.service_uids, vec![584788, 991, 992]);
        // Operator-added users are now classified as Service.
        assert_eq!(profile.classify_user("puppet"), UserClass::Service);
        assert_eq!(profile.classify_user("chef-client"), UserClass::Service);
    }

    #[test]
    fn classify_user_real_user_with_login_shell_is_not_service() {
        // Negative anchor: a regular user (uid 1000, /bin/bash)
        // must NOT slip into Service even after operator adds a
        // bunch of service extras. Compromise of `ubuntu` would
        // show up at standard threshold.
        //
        // puppet here has nologin shell so it parses as Service
        // automatically (uid 991, nologin /usr/bin/false). Note
        // that low-uid + nologin is now classified as Service per
        // the post-PR-#418 parser — covers the real /etc/passwd
        // shape on Ubuntu / Debian.
        let synthetic = "ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n\
puppet:x:991:991::/var/lib/puppet:/usr/bin/false\n";
        let scan = parse_passwd_for_user_classes(synthetic);
        let mut profile = EnvironmentProfile {
            human_uids: scan.human_uids,
            human_user_names: scan.human_user_names,
            service_uids: scan.service_uids,
            service_user_names: scan.service_user_names,
            ..EnvironmentProfile::default()
        };
        profile.merge_operator_service_extras(&["custom-svc".into()], &[]);
        assert_eq!(profile.classify_user("ubuntu"), UserClass::Human);
        assert_eq!(profile.classify_user("puppet"), UserClass::Service);
        assert_eq!(profile.classify_user("custom-svc"), UserClass::Service);
    }
}
