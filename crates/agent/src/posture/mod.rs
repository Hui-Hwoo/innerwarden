//! Host posture snapshot — what controls are already hardened.
//!
//! Spec 044 (`/.specify/features/044-posture-aware-alerting/spec.md`).
//!
//! The agent's severity downgrade engine (Phase 3, not yet implemented)
//! reads this snapshot to answer "would this attack have actually
//! worked given the host's current configuration". A SSH password
//! bruteforce against a host with `PasswordAuthentication no` hits the
//! sshd wall before reaching the kernel — the attempt is informational,
//! not a high-severity threat.
//!
//! **Cadence**: snapshot is taken at agent boot and refreshed every
//! 10 min by the slow loop (Phase 2.2). Operator changes (e.g. flipping
//! `PasswordAuthentication` for a debug session) are picked up within
//! one refresh window.
//!
//! **Source of truth**: each probe shells out to the canonical tool for
//! its surface (`sshd -T` for sshd, `ss -ltnp` for listeners, etc.)
//! rather than re-parsing config files. `sshd -T` already handles
//! `Include` directives, `Match` blocks, and effective defaults — much
//! safer than re-implementing that parser. If the canonical tool is
//! missing or fails, the probe records a `probe_failed` state and
//! the downgrade engine treats the surface as "permissive" (no
//! downgrade — bias toward keeping the alert).
//!
//! **What is NOT here**:
//!
//! - User account inventory (UIDs, names, login vs nologin shells) —
//!   `EnvironmentProfile` already covers this with bootstrap-once
//!   semantics. The downgrade engine reads both files.
//! - Active responses / dynamic blocklist — that is Decision state, not
//!   posture.
//! - Misconfiguration warnings — `innerwarden scan` / `innerwarden
//!   harden` own the "is this hardened enough" judgment. Posture is a
//!   read-only view.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub(crate) mod downgrade;
pub(crate) mod firewall;
pub(crate) mod services;
pub(crate) mod sshd;
pub(crate) mod sudo;

#[cfg(test)]
mod tests;

/// Top-level snapshot of host posture facts the severity engine cares about.
///
/// Each sub-struct carries a `probe_state` field describing whether the
/// underlying tool ran successfully, was missing, or failed — so the
/// downgrade engine can distinguish "we know SSH is hardened" from "we
/// have no idea, fall back to permissive".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostPosture {
    pub sshd: sshd::SshdPosture,
    pub services: services::ServicesPosture,
    pub sudo: sudo::SudoPosture,
    pub firewall: firewall::FirewallPosture,
    /// When this snapshot was taken (UTC). Used by the downgrade engine
    /// to refuse demotion when the snapshot is stale beyond a threshold.
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

impl HostPosture {
    /// Take a fresh snapshot by running every probe.
    ///
    /// Probes never panic and never fail the snapshot as a whole — each
    /// records its own `probe_state` and the snapshot always returns.
    pub fn take_snapshot() -> Self {
        Self {
            sshd: sshd::probe_sshd(),
            services: services::probe_services(),
            sudo: sudo::probe_sudo(),
            firewall: firewall::probe_firewall(),
            captured_at: chrono::Utc::now(),
        }
    }

    /// Age of the snapshot in seconds. The slow loop refresh cadence
    /// is 10 min; the downgrade engine treats anything older than ~30
    /// min as stale and refuses to demote based on it.
    #[allow(dead_code)]
    pub fn age_seconds(&self) -> i64 {
        (chrono::Utc::now() - self.captured_at).num_seconds()
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Path to the posture snapshot JSON file. Sibling to
/// `environment-profile.json` under `data_dir`.
pub fn posture_path(data_dir: &Path) -> PathBuf {
    data_dir.join("posture.json")
}

/// Write the snapshot to disk via temp-file + rename so a crash mid-write
/// does not leave a half-written file the dashboard would choke on.
/// Mirrors the pattern in `capped_log::write_atomic`.
pub fn save(data_dir: &Path, posture: &HostPosture) -> std::io::Result<()> {
    let path = posture_path(data_dir);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = parent.join(format!("posture.{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(posture)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    match std::fs::rename(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Load a previously-saved snapshot. Returns `None` when the file is
/// missing or unparseable — callers should re-snapshot in that case.
#[allow(dead_code)] // Used by `innerwarden get posture` (Phase 2.3) and tests.
pub fn load(data_dir: &Path) -> Option<HostPosture> {
    let path = posture_path(data_dir);
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<HostPosture>(&content) {
        Ok(p) => Some(p),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to parse posture.json");
            None
        }
    }
}

/// Render a Telegram-flavoured (HTML) summary of the snapshot.
/// Used by the `/posture` bot command (Phase 4). Mirrors the same
/// information as `innerwarden get posture` but with `<b>` markup
/// and per-section emoji so it reads as one coherent message in a
/// chat thread.
///
/// Probe sections that returned `Unavailable` / `Failed` render a
/// short "(probe failed)" line with the captured error rather than
/// fabricating data — the operator sees the truth: the agent has
/// no opinion on that surface, so the downgrade engine treated it
/// as permissive.
pub fn telegram_summary(posture: &HostPosture) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("\u{1f6e1}\u{fe0f} <b>Host posture</b>\n");
    s.push_str(&format!(
        "<i>Snapshot: {}</i>\n\n",
        posture.captured_at.format("%Y-%m-%d %H:%M UTC")
    ));

    // SSHD ────────────────────────────────────────────────────────────────
    s.push_str("\u{1f511} <b>SSHD</b>");
    match posture.sshd.probe_state {
        sshd::ProbeState::Ok => {
            s.push('\n');
            s.push_str(&format!(
                "  PasswordAuthentication: <b>{:?}</b>\n",
                posture.sshd.password_authentication
            ));
            s.push_str(&format!(
                "  KbdInteractiveAuthentication: <b>{:?}</b>\n",
                posture.sshd.kbd_interactive_authentication
            ));
            s.push_str(&format!(
                "  PermitRootLogin: <b>{:?}</b>\n",
                posture.sshd.permit_root_login
            ));
            s.push_str(&format!(
                "  PubkeyAuthentication: <b>{:?}</b>\n",
                posture.sshd.pubkey_authentication
            ));
            if let Some(n) = posture.sshd.max_auth_tries {
                s.push_str(&format!("  MaxAuthTries: <b>{n}</b>\n"));
            }
            if !posture.sshd.ports.is_empty() {
                let ports = posture
                    .sshd
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                s.push_str(&format!("  Ports: <b>{ports}</b>\n"));
            }
        }
        state => {
            s.push_str(&format!(" (probe {})\n", state.label()));
            if let Some(err) = posture.sshd.error.as_ref() {
                let trimmed = err.chars().take(120).collect::<String>();
                s.push_str(&format!(
                    "  <i>{}</i>\n",
                    crate::telegram::escape_html_pub(&trimmed)
                ));
            }
        }
    }

    // Listening services ──────────────────────────────────────────────────
    s.push_str("\n\u{1f4e1} <b>Listening services</b>");
    match posture.services.probe_state {
        sshd::ProbeState::Ok => {
            s.push_str(&format!(
                " ({} listeners)\n",
                posture.services.listeners.len()
            ));
            // Cap to 12 listeners in the Telegram message — the rest is
            // paginated via `innerwarden get posture` on the host.
            for l in posture.services.listeners.iter().take(12) {
                let proto = match l.proto {
                    services::Proto::Tcp => "tcp",
                    services::Proto::Udp => "udp",
                };
                let comm = if l.comm.is_empty() {
                    "?"
                } else {
                    l.comm.as_str()
                };
                s.push_str(&format!(
                    "  {proto} {addr}:{port}  <i>{comm}</i>\n",
                    addr = crate::telegram::escape_html_pub(&l.addr),
                    port = l.port,
                    comm = crate::telegram::escape_html_pub(comm),
                ));
            }
            if posture.services.listeners.len() > 12 {
                s.push_str(&format!(
                    "  <i>+{} more — see `innerwarden get posture`</i>\n",
                    posture.services.listeners.len() - 12
                ));
            }
        }
        state => {
            s.push_str(&format!(" (probe {})\n", state.label()));
        }
    }

    // Sudo ────────────────────────────────────────────────────────────────
    s.push_str("\n\u{1f6a8} <b>Sudo</b>");
    match posture.sudo.probe_state {
        sshd::ProbeState::Ok => {
            s.push('\n');
            for (label, members) in [
                ("group sudo", &posture.sudo.sudo_group_members),
                ("group wheel", &posture.sudo.wheel_group_members),
                ("group admin", &posture.sudo.admin_group_members),
            ] {
                if !members.is_empty() {
                    let names = members
                        .iter()
                        .map(|n| crate::telegram::escape_html_pub(n))
                        .collect::<Vec<_>>()
                        .join(", ");
                    s.push_str(&format!("  {label}: <b>{names}</b>\n"));
                }
            }
            if !posture.sudo.sudoers_d_filenames.is_empty() {
                let names = posture
                    .sudo
                    .sudoers_d_filenames
                    .iter()
                    .map(|n| crate::telegram::escape_html_pub(n))
                    .collect::<Vec<_>>()
                    .join(", ");
                s.push_str(&format!("  /etc/sudoers.d: <b>{names}</b>\n"));
            }
        }
        state => {
            s.push_str(&format!(" (probe {})\n", state.label()));
        }
    }

    // Firewall ────────────────────────────────────────────────────────────
    s.push_str("\n\u{1f6e1}\u{fe0f} <b>Firewall</b>");
    match posture.firewall.probe_state {
        sshd::ProbeState::Ok => {
            s.push('\n');
            if !posture.firewall.active_backends.is_empty() {
                let backends = posture
                    .firewall
                    .active_backends
                    .iter()
                    .map(|b| match b {
                        firewall::FirewallBackend::Ufw => "ufw",
                        firewall::FirewallBackend::Iptables => "iptables",
                        firewall::FirewallBackend::Nftables => "nftables",
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                s.push_str(&format!("  Backends: <b>{backends}</b>\n"));
            }
            s.push_str(&format!(
                "  Default INPUT: <b>{:?}</b>\n",
                posture.firewall.default_policy
            ));
            if !posture.firewall.allowed_tcp_ports.is_empty() {
                let ports = posture
                    .firewall
                    .allowed_tcp_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                s.push_str(&format!("  Allowed TCP: <b>{ports}</b>\n"));
            }
        }
        state => {
            s.push_str(&format!(" (probe {})\n", state.label()));
        }
    }

    let age = posture.age_seconds();
    if age >= 0 {
        s.push_str(&format!(
            "\n<i>Last refresh: {age}s ago (slow loop refreshes every 600s)</i>"
        ));
    }
    s
}

/// Compact, single-line host posture for the AI decide() prompt (spec 067
/// Phase 2b). The downgrade engine already uses posture to demote severity
/// (an `ssh_bruteforce` against a `PasswordAuthentication=no` host is Low, not
/// High); feeding the same facts to the LLM lets its reasoning match that
/// outcome instead of over-reacting. SSHD-only for now (the most decision-
/// relevant surface); `None` when the sshd probe did not succeed.
pub fn ai_context_line(p: &HostPosture) -> Option<String> {
    if !matches!(p.sshd.probe_state, sshd::ProbeState::Ok) {
        return None;
    }
    let max_tries = p
        .sshd
        .max_auth_tries
        .map(|n| n.to_string())
        .unwrap_or_else(|| "default".to_string());
    Some(format!(
        "sshd: PasswordAuthentication={:?}, PermitRootLogin={:?}, MaxAuthTries={max_tries}",
        p.sshd.password_authentication, p.sshd.permit_root_login,
    ))
}

/// Take a fresh snapshot, log a one-line summary, and persist. Called
/// at boot (Phase 2 wiring) and from the slow loop refresh tick (Phase
/// 2.2). Errors are logged but not propagated — posture is best-effort.
pub fn refresh_and_save(data_dir: &Path) -> HostPosture {
    let posture = HostPosture::take_snapshot();
    info!(
        sshd_probe = %posture.sshd.probe_state.label(),
        password_auth = ?posture.sshd.password_authentication,
        permit_root_login = ?posture.sshd.permit_root_login,
        services_probe = %posture.services.probe_state.label(),
        listener_count = posture.services.listeners.len(),
        sudo_probe = %posture.sudo.probe_state.label(),
        sudo_members = posture.sudo.sudo_group_members.len(),
        firewall_probe = %posture.firewall.probe_state.label(),
        firewall_default = ?posture.firewall.default_policy,
        firewall_allowed_count = posture.firewall.allowed_tcp_ports.len(),
        "host posture snapshot"
    );
    if let Err(e) = save(data_dir, &posture) {
        warn!(error = %e, "failed to save posture.json");
    }
    posture
}
