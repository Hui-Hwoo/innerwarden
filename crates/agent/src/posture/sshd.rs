//! SSHD posture probe.
//!
//! Runs `sshd -T` and parses the effective config dump. `sshd -T` is
//! the only correct way to get the effective sshd configuration: it
//! resolves `Include` directives, applies `Match` blocks against the
//! current connection context (we run with no Match context, so the
//! global defaults are what we get), and emits the values sshd would
//! actually use, lowercased and one-per-line.
//!
//! This probe deliberately does NOT re-parse `/etc/ssh/sshd_config`.
//! That parser would have to handle:
//! - `Include /etc/ssh/sshd_config.d/*.conf`
//! - `Match` blocks with negation, AND/OR, host/address/user predicates
//! - implicit defaults when a directive is unset
//! - `Subsystem`, `AuthorizedKeysCommand`, etc.
//!
//! `sshd -T` already does all of that correctly. The cost is a
//! ~30 ms shell-out per refresh, which is acceptable at the 10 min
//! cadence.
//!
//! When `sshd -T` is not available (no sshd binary on PATH, e.g. a
//! container with sshd ripped out, or running on macOS where the
//! binary path differs), the probe records `ProbeState::Unavailable`
//! and the downgrade engine treats the SSH surface as "permissive"
//! (i.e. cannot demote any SSH-related alert based on this).

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::warn;

/// State of a probe run. Drives the downgrade engine's decision about
/// whether to trust the parsed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    /// `sshd -T` ran and we parsed at least one expected directive.
    Ok,
    /// `sshd -T` binary not found / not executable.
    Unavailable,
    /// `sshd -T` ran but exited non-zero (e.g. permission denied,
    /// malformed config that sshd itself rejects).
    Failed,
    /// Probe has not run yet on this snapshot.
    #[default]
    Pending,
}

impl ProbeState {
    pub fn label(&self) -> &'static str {
        match self {
            ProbeState::Ok => "ok",
            ProbeState::Unavailable => "unavailable",
            ProbeState::Failed => "failed",
            ProbeState::Pending => "pending",
        }
    }
}

/// Yes/No/Unset tri-state for sshd boolean directives. Distinguishes
/// "the operator explicitly set this to no" from "we did not observe
/// the directive in the dump" — the downgrade engine demands a
/// positive `No` before it demotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SshdToggle {
    Yes,
    No,
    /// Probe did not see the directive (or it carried a non-yes/no
    /// value like `prohibit-password` for `permit_root_login`).
    #[default]
    Unset,
}

impl SshdToggle {
    /// Returns true only when the directive is explicitly disabled.
    /// The "demote SSH bruteforce alerts" policy keys off this — never
    /// demote on `Unset`, only on a positive `No`.
    #[allow(dead_code)]
    pub fn is_disabled(&self) -> bool {
        matches!(self, SshdToggle::No)
    }

    fn from_yes_no(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "yes" => SshdToggle::Yes,
            "no" => SshdToggle::No,
            _ => SshdToggle::Unset,
        }
    }

    /// Specialised parser for `permit_root_login`, which has 4 valid
    /// values: `yes`, `no`, `prohibit-password`, `forced-commands-only`.
    /// For the downgrade decision we only care about a strict `no` —
    /// `prohibit-password` still allows root login via key, so we
    /// treat it as `Unset` (do not demote root-targeted alerts).
    fn from_permit_root_login(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "yes" => SshdToggle::Yes,
            "no" => SshdToggle::No,
            _ => SshdToggle::Unset,
        }
    }
}

/// Parsed sshd posture. Fields the severity downgrade engine reads:
///
/// - `password_authentication == No` → demote `ssh_bruteforce` alerts
///   that used `password` method to Low.
/// - `permit_root_login == No` → demote `ssh_bruteforce` against root
///   user to Low.
/// - `kbd_interactive_authentication == No` is a near-equivalent of
///   `password_authentication == No` on modern OpenSSH; both must be
///   No for the password-based downgrade to fire.
/// - `max_auth_tries` is informational; not used for downgrade in
///   Phase 3 but exposed in the snapshot for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshdPosture {
    pub probe_state: ProbeState,
    pub password_authentication: SshdToggle,
    pub kbd_interactive_authentication: SshdToggle,
    pub permit_root_login: SshdToggle,
    pub pubkey_authentication: SshdToggle,
    /// Numeric. None when the directive was not in the dump (defaults
    /// to 6 historically; we record None rather than fabricate).
    pub max_auth_tries: Option<u32>,
    /// Listen ports. Multiple `Port` directives are allowed; sshd dumps
    /// each on its own line. Empty when no `Port` was emitted.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// stderr from `sshd -T` when `probe_state != Ok`. Capped at 512
    /// bytes so a malformed config does not blow up the JSON snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SshdPosture {
    /// True when both password-based and keyboard-interactive auth are
    /// disabled. The downgrade engine demands BOTH because OpenSSH
    /// falls back to keyboard-interactive (PAM) when
    /// `PasswordAuthentication=no` but `KbdInteractiveAuthentication=yes`,
    /// and a brute-force tool can probe both endpoints.
    #[allow(dead_code)]
    pub fn password_login_effectively_disabled(&self) -> bool {
        self.probe_state == ProbeState::Ok
            && self.password_authentication.is_disabled()
            && self.kbd_interactive_authentication.is_disabled()
    }

    /// True only when root login is explicitly `No`. `prohibit-password`
    /// still allows key-based root login, so it is NOT enough to demote
    /// an alert (an attacker with a stolen key would still get in).
    #[allow(dead_code)]
    pub fn root_login_disabled(&self) -> bool {
        self.probe_state == ProbeState::Ok && self.permit_root_login.is_disabled()
    }
}

/// Run `sshd -T` and parse the effective configuration.
///
/// The shell-out runs synchronously. Acceptable because the boot
/// snapshot is one-shot and the slow-loop refresh is at the 10 min
/// cadence — neither is a hot path. If the future moves this to a
/// hotter cadence, wrap the call in `tokio::task::spawn_blocking`.
pub fn probe_sshd() -> SshdPosture {
    // `sshd -T` requires running as a user that can read the config —
    // typically root. The agent runs under the `innerwarden` user with
    // CAP_SYS_PTRACE and friends but not generally root, so the more
    // common form is `sudo sshd -T`. For now we try plain `sshd -T`
    // first and fall back to the `-f` explicit-path form if that
    // fails — which is the common case on Ubuntu where sshd lives
    // outside `$PATH` of non-root users.
    //
    // The deploy script gives the agent sudo NOPASSWD for a small
    // allowlist; if `sudo sshd -T` is in that allowlist (Phase 2.3
    // operator-side change), it works. If not, we fall back to a
    // direct `/usr/sbin/sshd -T` invocation under the agent's own
    // permissions and accept that some hosts will report
    // `Unavailable`.
    let candidates: [&[&str]; 3] = [
        &["sshd", "-T"],
        &["/usr/sbin/sshd", "-T"],
        &["sudo", "-n", "/usr/sbin/sshd", "-T"],
    ];
    for argv in candidates {
        match try_probe(argv) {
            Ok(posture) => return posture,
            Err(ProbeState::Unavailable) => {
                // Try next candidate when the binary is not on PATH /
                // not at the absolute path. Anything else is final.
                continue;
            }
            Err(_) => break,
        }
    }
    // None of the candidates produced a parseable dump. Record the
    // first failure mode we saw — Unavailable in nearly every case.
    SshdPosture {
        probe_state: ProbeState::Unavailable,
        error: Some("sshd binary not found or not executable".to_string()),
        ..Default::default()
    }
}

fn try_probe(argv: &[&str]) -> Result<SshdPosture, ProbeState> {
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..]);
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            // ENOENT / EACCES / EPERM — binary missing or not executable.
            // Caller will try the next candidate.
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(ProbeState::Unavailable);
            }
            warn!(argv = ?argv, error = %e, "sshd probe failed to spawn");
            return Err(ProbeState::Unavailable);
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let mut err = stderr.trim().to_string();
        if err.is_empty() {
            err = format!("sshd exited with status {}", output.status);
        }
        if err.len() > 512 {
            err.truncate(512);
            err.push('…');
        }
        return Ok(SshdPosture {
            probe_state: ProbeState::Failed,
            error: Some(err),
            ..Default::default()
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_sshd_dump(&stdout))
}

/// Parse the lowercased one-directive-per-line output of `sshd -T`.
///
/// Format example:
/// ```text
/// port 22
/// passwordauthentication no
/// kbdinteractiveauthentication no
/// permitrootlogin prohibit-password
/// pubkeyauthentication yes
/// maxauthtries 6
/// ```
///
/// Unknown directives are silently ignored — sshd emits dozens we do
/// not care about, and the set evolves between OpenSSH versions.
pub(crate) fn parse_sshd_dump(dump: &str) -> SshdPosture {
    let mut posture = SshdPosture {
        probe_state: ProbeState::Ok,
        ..Default::default()
    };
    let mut saw_directive = false;
    for line in dump.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        match key.as_str() {
            "passwordauthentication" => {
                posture.password_authentication = SshdToggle::from_yes_no(value);
                saw_directive = true;
            }
            "kbdinteractiveauthentication" => {
                posture.kbd_interactive_authentication = SshdToggle::from_yes_no(value);
                saw_directive = true;
            }
            "permitrootlogin" => {
                posture.permit_root_login = SshdToggle::from_permit_root_login(value);
                saw_directive = true;
            }
            "pubkeyauthentication" => {
                posture.pubkey_authentication = SshdToggle::from_yes_no(value);
                saw_directive = true;
            }
            "maxauthtries" => {
                posture.max_auth_tries = value.parse::<u32>().ok();
                saw_directive = true;
            }
            "port" => {
                if let Ok(p) = value.parse::<u16>() {
                    posture.ports.push(p);
                }
                saw_directive = true;
            }
            _ => {}
        }
    }
    if !saw_directive {
        // Got a successful exit but no directive we recognise. Probably
        // the binary returned help text or a non-config dump. Mark as
        // failed so the downgrade engine does not trust the defaults.
        posture.probe_state = ProbeState::Failed;
        posture.error = Some("sshd -T returned no recognised directives".to_string());
    }
    posture
}
