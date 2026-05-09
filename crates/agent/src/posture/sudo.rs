//! Sudoers membership probe.
//!
//! Two surfaces: group membership (`sudo`, `wheel`, `admin`) and
//! `/etc/sudoers.d/` filenames. Together they answer "could user X
//! escalate via sudo?" well enough for the downgrade engine.
//!
//! What this probe does NOT do:
//! - Parse `/etc/sudoers` content. The grammar (Cmnd_Alias,
//!   Defaults, Runas_List, NOPASSWD lines, host-restricted entries)
//!   is non-trivial; a wrong interpretation is dangerous because
//!   the downgrade engine would mis-classify a real sudo abuser as
//!   "harmless".
//! - Verify the `sudo` package is installed. If sudo is missing on
//!   the host, the agent's own response skills (block_ip_ufw etc.)
//!   are also broken and the operator already has bigger problems.
//!
//! When more granularity is needed in a later spec, replace the
//! group-membership heuristic with `sudo -l -U <user>` per user
//! observed in incidents. That is a per-incident probe and lives
//! outside the snapshot.

use serde::{Deserialize, Serialize};
use std::process::Command;

use super::sshd::ProbeState;

/// Sudo posture: who can sudo, and what fragments live in
/// `/etc/sudoers.d/`. The downgrade engine demotes `sudo_abuse` alerts
/// against users not in any of these surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SudoPosture {
    pub probe_state: ProbeState,
    /// Members of `group sudo` (Debian/Ubuntu convention). Empty when
    /// the group does not exist.
    #[serde(default)]
    pub sudo_group_members: Vec<String>,
    /// Members of `group wheel` (Red Hat / older BSD convention).
    #[serde(default)]
    pub wheel_group_members: Vec<String>,
    /// Members of `group admin` (older Ubuntu).
    #[serde(default)]
    pub admin_group_members: Vec<String>,
    /// Filenames under `/etc/sudoers.d/`. By convention each is named
    /// after the user or group it grants (`/etc/sudoers.d/deploy`,
    /// `/etc/sudoers.d/zz-innerwarden-deny-bob`). The downgrade engine
    /// uses these as a "maybe a sudoer" signal — never a definitive
    /// "is a sudoer" because the file content could grant other users.
    #[serde(default)]
    pub sudoers_d_filenames: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SudoPosture {
    /// True when the user appears in any of the well-known sudo
    /// groups OR in a sudoers.d filename. Conservative on purpose —
    /// the sudoers.d filename signal can be wrong, but it biases
    /// toward NOT demoting (kept alert wins over silenced alert).
    #[allow(dead_code)]
    pub fn user_might_have_sudo(&self, user: &str) -> bool {
        if self.probe_state != ProbeState::Ok {
            // Probe unavailable / failed → assume permissive (any user
            // might sudo). The downgrade engine never demotes in this
            // case; bias keeps alerts high.
            return true;
        }
        self.sudo_group_members.iter().any(|u| u == user)
            || self.wheel_group_members.iter().any(|u| u == user)
            || self.admin_group_members.iter().any(|u| u == user)
            || self.sudoers_d_filenames.iter().any(|f| f == user)
    }
}

pub fn probe_sudo() -> SudoPosture {
    let mut posture = SudoPosture::default();
    let mut errors: Vec<String> = Vec::new();
    let mut got_anything = false;

    for (group, target) in [
        ("sudo", &mut posture.sudo_group_members),
        ("wheel", &mut posture.wheel_group_members),
        ("admin", &mut posture.admin_group_members),
    ] {
        match read_group_members(group) {
            Ok(members) => {
                got_anything = true;
                *target = members;
            }
            Err(e) => errors.push(format!("getent group {group}: {e}")),
        }
    }

    match list_sudoers_d() {
        Ok(names) => {
            got_anything = true;
            posture.sudoers_d_filenames = names;
        }
        Err(e) => errors.push(format!("/etc/sudoers.d/: {e}")),
    }

    posture.probe_state = if got_anything {
        ProbeState::Ok
    } else {
        ProbeState::Unavailable
    };
    if !errors.is_empty() {
        posture.error = Some(errors.join("; "));
    }
    posture
}

/// Run `getent group <name>` and return the member list. Returns
/// `Ok(vec![])` when the group does not exist (`getent` exits 2);
/// returns `Err` when the binary is missing or another failure.
fn read_group_members(group: &str) -> Result<Vec<String>, String> {
    let output = Command::new("getent")
        .arg("group")
        .arg(group)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        // Exit 2 = "key not found" per getent(1) — group does not
        // exist on this system. Treat as empty membership rather than
        // an error.
        if output.status.code() == Some(2) {
            return Ok(Vec::new());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("getent exit {}", output.status)
        } else {
            stderr
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_getent_group_line(&stdout))
}

/// Parse `getent group sudo` output: `sudo:x:27:alice,bob,deploy`.
/// Returns the comma-separated member list (4th field). Empty when
/// the line is malformed or has no members.
pub(crate) fn parse_getent_group_line(line: &str) -> Vec<String> {
    let line = line.trim();
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 4 {
        return Vec::new();
    }
    fields[3]
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// List filenames under `/etc/sudoers.d/`. Returns `Err` on
/// permission denied (we are not running as root). Hidden files
/// (`.`-prefixed) and the canonical `README` file are excluded.
fn list_sudoers_d() -> Result<Vec<String>, String> {
    let dir = std::path::Path::new("/etc/sudoers.d");
    let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.') && n != "README")
        .collect();
    names.sort();
    Ok(names)
}
