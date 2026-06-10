//! Explained-alerts catalog (spec 075).
//!
//! A single, plain-language source of "what is this + why it matters" per
//! detector kind, fused with the MITRE mapping from [`crate::mitre`]. It turns
//! a raw detector name in a notification into a sentence an operator
//! understands — so an alert reads as "InnerWarden saw this, knows what it is,
//! and is handling it" instead of `keylogger_bash_trap from shell_startup_write`.
//!
//! Design notes:
//! - Pure data + pure functions: no I/O, trivially testable.
//! - The MITRE layer is NOT duplicated here — it is read live from
//!   `mitre::map_detector` so the two never drift.
//! - Unknown detectors get a safe humanised fallback (never panics, never
//!   blank) so a new detector still produces a readable alert before it is
//!   curated here.

/// Plain-language explanation of a detector for operator-facing alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectorExplanation {
    /// What was observed, in plain words (no jargon).
    pub what: &'static str,
    /// Why InnerWarden watches for it — the attacker goal it maps to.
    pub why: &'static str,
}

/// Plain-language "what + why" for the detectors operators see most. Curated
/// for the common set; everything else falls back to a humanised default.
pub fn explain(detector: &str) -> DetectorExplanation {
    let e = |what, why| DetectorExplanation { what, why };
    match detector {
        "ssh_bruteforce" => e(
            "Repeated failed SSH logins from one source.",
            "Attackers guess passwords at scale to get their first foothold on the box.",
        ),
        "credential_stuffing" => e(
            "Many logins tried with leaked username/password pairs.",
            "Attackers replay stolen credentials hoping one still works here.",
        ),
        "port_scan" => e(
            "One source probed many ports/services in a short window.",
            "Reconnaissance — attackers map what is exposed before they pick a way in.",
        ),
        "web_scan" | "web_scanner" => e(
            "Automated probing of web paths/endpoints.",
            "Attackers hunt for vulnerable apps, admin panels, and known exploits.",
        ),
        "reverse_shell" => e(
            "A local process opened an interactive shell back out to a remote host.",
            "This is how an attacker gets hands-on control after they break in — rarely benign.",
        ),
        "web_shell" => e(
            "A web-servable script that can execute commands was written or hit.",
            "A backdoor planted in your web root for persistent remote control.",
        ),
        "rootkit" => e(
            "Signs of hidden processes/files or tampered kernel structures.",
            "Attackers hide their presence at the kernel level to survive and evade you.",
        ),
        "keylogger_bash_trap" => e(
            "Something wrote to a shell startup file (e.g. .bashrc / .profile).",
            "Attackers plant a trap there to capture every command typed on the host (a keylogger).",
        ),
        "auditd_disable" => e(
            "The host audit subsystem was stopped, disabled, or tampered with.",
            "Attackers blind logging before the loud part of an attack so you cannot see it.",
        ),
        "selinux_apparmor_disable" => e(
            "A mandatory-access-control system (SELinux/AppArmor) was disabled.",
            "Attackers tear down OS guardrails to move freely.",
        ),
        "privesc" => e(
            "A process gained or used root through a path its lineage does not justify.",
            "Privilege escalation — turning a limited foothold into full control of the host.",
        ),
        "data_exfiltration" | "data_exfil_ebpf" => e(
            "An unusual volume of data was staged or sent outbound.",
            "Attackers steal your data; this is the payday step of many breaches.",
        ),
        "dns_tunneling" => e(
            "Data smuggled inside DNS queries.",
            "Attackers use DNS as a covert channel to exfiltrate data or reach command-and-control.",
        ),
        "crypto_miner" => e(
            "A process matches cryptocurrency-mining behaviour.",
            "Attackers hijack your CPU/GPU to mine coins on your bill.",
        ),
        "process_injection" => e(
            "Code was injected into another running process.",
            "Attackers run inside a trusted process to hide and bypass defences.",
        ),
        "container_escape" => e(
            "A container did something consistent with breaking out to the host.",
            "Escaping the container turns one compromised app into a compromised server.",
        ),
        "ransomware" => e(
            "A burst of rapid file rewrites with high-entropy (encrypted) content.",
            "Ransomware encrypting your files for extortion — speed of detection is everything.",
        ),
        "reverse_shell_listener" | "c2_callback" => e(
            "A process is beaconing to a likely command-and-control server.",
            "The implant phoning home for instructions after a compromise.",
        ),
        _ => DetectorExplanation {
            // Never blank: humanise the raw name and give an honest generic line
            // so a freshly-added detector still reads sensibly until curated.
            what: "Suspicious activity matched one of InnerWarden's detectors.",
            why: "It fits a known attacker behaviour pattern worth flagging.",
        },
    }
}

/// A compact MITRE attribution line for a detector, e.g.
/// `MITRE T1110.001 · Brute Force: Password Guessing`. `None` when the detector
/// has no mapping (kept live from `mitre.rs`, never duplicated here).
pub fn mitre_line(detector: &str) -> Option<String> {
    crate::mitre::map_detector(detector)
        .map(|m| format!("MITRE {} · {}", m.technique_id, m.technique_name))
}

/// True when `explain` has a curated (non-fallback) entry for this detector.
/// Test-only for now; un-gate when a notification surface needs to branch on
/// it (Phase 2). Kept here so the fallback contract stays asserted.
#[cfg(test)]
fn is_curated(detector: &str) -> bool {
    explain(detector) != explain("__definitely_not_a_real_detector__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_detectors_have_nonblank_what_and_why() {
        for d in [
            "ssh_bruteforce",
            "reverse_shell",
            "keylogger_bash_trap",
            "auditd_disable",
            "privesc",
            "ransomware",
            "data_exfiltration",
        ] {
            let ex = explain(d);
            assert!(!ex.what.is_empty(), "{d} what empty");
            assert!(!ex.why.is_empty(), "{d} why empty");
            assert!(is_curated(d), "{d} should be curated");
        }
    }

    #[test]
    fn unknown_detector_falls_back_safely() {
        let ex = explain("some_brand_new_detector");
        assert!(!ex.what.is_empty());
        assert!(!ex.why.is_empty());
        assert!(!is_curated("some_brand_new_detector"));
    }

    #[test]
    fn mitre_line_reuses_mitre_map() {
        // ssh_bruteforce is mapped in mitre.rs -> must produce a line.
        let line = mitre_line("ssh_bruteforce").expect("ssh_bruteforce is mapped");
        assert!(line.starts_with("MITRE T"));
        assert!(line.contains("Brute Force"));
        // An unmapped name yields None (no fabricated technique).
        assert!(mitre_line("__unmapped__").is_none());
    }

    #[test]
    fn keylogger_explanation_matches_the_real_world_case() {
        // The 2026-06-09 rustup FP: the alert must read as a keylogger watch,
        // not a raw detector name.
        let ex = explain("keylogger_bash_trap");
        assert!(ex.what.to_lowercase().contains("shell startup"));
        assert!(ex.why.to_lowercase().contains("keylogger"));
    }
}
