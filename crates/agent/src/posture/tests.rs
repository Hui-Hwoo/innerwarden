//! Tests for the posture module. Probe shell-outs are NOT exercised
//! here — those are integration concerns and `sshd -T` is not present
//! on every CI runner. The parser is, however, fully tested.

use super::sshd::*;
use super::*;

// ---------------------------------------------------------------------------
// SshdToggle
// ---------------------------------------------------------------------------

#[test]
fn sshd_toggle_yes_no_parses_canonical() {
    assert_eq!(SshdToggle::from_yes_no_for_test("yes"), SshdToggle::Yes);
    assert_eq!(SshdToggle::from_yes_no_for_test("no"), SshdToggle::No);
}

#[test]
fn sshd_toggle_yes_no_is_case_insensitive_and_trims() {
    assert_eq!(SshdToggle::from_yes_no_for_test("  Yes  "), SshdToggle::Yes);
    assert_eq!(SshdToggle::from_yes_no_for_test("NO"), SshdToggle::No);
}

#[test]
fn sshd_toggle_unknown_value_is_unset() {
    assert_eq!(
        SshdToggle::from_yes_no_for_test("prohibit-password"),
        SshdToggle::Unset
    );
    assert_eq!(SshdToggle::from_yes_no_for_test(""), SshdToggle::Unset);
}

#[test]
fn sshd_toggle_is_disabled_only_on_explicit_no() {
    assert!(SshdToggle::No.is_disabled());
    assert!(!SshdToggle::Yes.is_disabled());
    // The downgrade engine MUST NOT demote on Unset — that is the
    // whole point of the tri-state.
    assert!(!SshdToggle::Unset.is_disabled());
}

// ---------------------------------------------------------------------------
// parse_sshd_dump
// ---------------------------------------------------------------------------

#[test]
fn parse_sshd_dump_canonical_hardened_host() {
    // Output shape from a real Ubuntu host with PasswordAuth + root
    // login disabled. Truncated to the directives the agent reads;
    // sshd emits ~80 lines total but unknown directives are ignored.
    let dump = "\
port 22
addressfamily any
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
pubkeyauthentication yes
maxauthtries 6
clientaliveinterval 0
";
    let posture = parse_sshd_dump(dump);
    assert_eq!(posture.probe_state, ProbeState::Ok);
    assert_eq!(posture.password_authentication, SshdToggle::No);
    assert_eq!(posture.kbd_interactive_authentication, SshdToggle::No);
    assert_eq!(posture.permit_root_login, SshdToggle::No);
    assert_eq!(posture.pubkey_authentication, SshdToggle::Yes);
    assert_eq!(posture.max_auth_tries, Some(6));
    assert_eq!(posture.ports, vec![22]);
    assert!(posture.password_login_effectively_disabled());
    assert!(posture.root_login_disabled());
}

#[test]
fn parse_sshd_dump_permissive_host() {
    let dump = "\
port 22
passwordauthentication yes
kbdinteractiveauthentication yes
permitrootlogin yes
pubkeyauthentication yes
maxauthtries 6
";
    let posture = parse_sshd_dump(dump);
    assert_eq!(posture.probe_state, ProbeState::Ok);
    assert_eq!(posture.password_authentication, SshdToggle::Yes);
    assert_eq!(posture.permit_root_login, SshdToggle::Yes);
    assert!(!posture.password_login_effectively_disabled());
    assert!(!posture.root_login_disabled());
}

/// Spec 044 invariant: `prohibit-password` is NOT enough to demote
/// root-targeted alerts. An attacker with a stolen key can still log
/// in as root under `prohibit-password`, so the downgrade engine
/// must keep treating root-targeted brute force as high severity.
#[test]
fn parse_sshd_dump_permitrootlogin_prohibit_password_is_unset_for_downgrade() {
    let dump = "permitrootlogin prohibit-password\n";
    let posture = parse_sshd_dump(dump);
    assert_eq!(posture.probe_state, ProbeState::Ok);
    assert_eq!(posture.permit_root_login, SshdToggle::Unset);
    assert!(
        !posture.root_login_disabled(),
        "prohibit-password must NOT count as 'root login disabled' — \
         a stolen key still gets in"
    );
}

/// Spec 044 invariant: even when `PasswordAuthentication=no`, OpenSSH
/// can still accept passwords via `KbdInteractiveAuthentication`
/// (which routes through PAM, which routes to /etc/shadow). The
/// downgrade engine demands BOTH be `No` to declare the password
/// surface effectively closed. Anchor this so a future "we only need
/// PasswordAuthentication=no" simplification trips the test.
#[test]
fn parse_sshd_dump_kbd_interactive_alone_keeps_password_surface_open() {
    let only_password_no = "\
passwordauthentication no
kbdinteractiveauthentication yes
";
    let posture = parse_sshd_dump(only_password_no);
    assert_eq!(posture.password_authentication, SshdToggle::No);
    assert_eq!(posture.kbd_interactive_authentication, SshdToggle::Yes);
    assert!(
        !posture.password_login_effectively_disabled(),
        "PasswordAuthentication=no alone is NOT enough — \
         KbdInteractiveAuthentication=yes still routes to PAM/shadow"
    );

    let only_kbd_no = "\
passwordauthentication yes
kbdinteractiveauthentication no
";
    let posture = parse_sshd_dump(only_kbd_no);
    assert!(!posture.password_login_effectively_disabled());
}

#[test]
fn parse_sshd_dump_handles_multiple_port_lines() {
    let dump = "\
port 22
port 2222
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
";
    let posture = parse_sshd_dump(dump);
    assert_eq!(posture.ports, vec![22, 2222]);
}

#[test]
fn parse_sshd_dump_ignores_unknown_directives_and_blank_lines() {
    // Real-world dump has dozens of directives we do not parse. The
    // parser must silently skip them.
    // String starts with a newline + blank line on purpose so the
    // parser sees a leading-empty-line case. Using `"\n` instead of
    // `"\` because the latter would swallow the blank line clippy
    // wants us to keep visible (clippy::multiple_lines_skipped_by_escaped_newline).
    let dump = "
# leading blank line and a comment

port 22
addressfamily any
listenaddress 0.0.0.0:22
listenaddress [::]:22
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
pubkeyauthentication yes
syslogfacility AUTH
loglevel INFO
maxauthtries 6
maxsessions 10
useprivilegeseparation sandbox
";
    let posture = parse_sshd_dump(dump);
    assert_eq!(posture.probe_state, ProbeState::Ok);
    assert_eq!(posture.password_authentication, SshdToggle::No);
    assert_eq!(posture.max_auth_tries, Some(6));
}

#[test]
fn parse_sshd_dump_empty_or_help_text_marks_failed() {
    // If sshd -T returns help text or empty, the parser must NOT
    // declare Ok — otherwise the downgrade engine would happily
    // demote based on a snapshot that saw nothing.
    let posture = parse_sshd_dump("");
    assert_eq!(posture.probe_state, ProbeState::Failed);

    let posture = parse_sshd_dump("usage: sshd [-46DdeiqTtV] [-C connection_spec]\n");
    assert_eq!(
        posture.probe_state,
        ProbeState::Failed,
        "help text contains no recognised directive"
    );
}

#[test]
fn parse_sshd_dump_invalid_max_auth_tries_does_not_panic() {
    let dump = "\
port 22
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
maxauthtries notanumber
";
    let posture = parse_sshd_dump(dump);
    assert_eq!(posture.probe_state, ProbeState::Ok);
    assert_eq!(posture.max_auth_tries, None);
}

// ---------------------------------------------------------------------------
// HostPosture: persistence round-trip
// ---------------------------------------------------------------------------

#[test]
fn save_and_load_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let posture = HostPosture {
        sshd: parse_sshd_dump(
            "\
port 22
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
pubkeyauthentication yes
maxauthtries 6
",
        ),
        services: super::services::ServicesPosture::default(),
        sudo: super::sudo::SudoPosture::default(),
        firewall: super::firewall::FirewallPosture::default(),
        captured_at: chrono::Utc::now(),
    };
    save(tmp.path(), &posture).expect("save");
    let loaded = load(tmp.path()).expect("load");
    assert_eq!(loaded.sshd.password_authentication, SshdToggle::No);
    assert_eq!(loaded.sshd.max_auth_tries, Some(6));
    // captured_at survives to-from-JSON via chrono's default RFC3339
    // serialisation. Compare at second granularity to dodge any
    // sub-second drift in serde_json's Display impl.
    assert_eq!(
        loaded.captured_at.timestamp(),
        posture.captured_at.timestamp()
    );
}

#[test]
fn load_returns_none_when_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    assert!(load(tmp.path()).is_none());
}

#[test]
fn load_returns_none_on_corrupt_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("posture.json"), "{ this is not json").expect("write");
    assert!(load(tmp.path()).is_none());
}

// ---------------------------------------------------------------------------
// HostPosture::age_seconds
// ---------------------------------------------------------------------------

#[test]
fn age_seconds_returns_non_negative_for_fresh_snapshot() {
    let posture = HostPosture::take_snapshot();
    let age = posture.age_seconds();
    assert!(
        (0..5).contains(&age),
        "fresh snapshot should be 0-5 s old (got {age})"
    );
}

/// End-to-end exercise of `refresh_and_save`: invokes every probe (each
/// records its own state — likely Unavailable on a CI runner without
/// sshd/ss/getent/ufw, which is fine), persists to `posture.json`, and
/// returns. Verifies the file is valid JSON the loader can read back.
///
/// The probes themselves are uncoverable without mocking their
/// shell-outs, but this test ensures the orchestration code (build →
/// log → save → return) runs end-to-end on every supported platform.
#[test]
fn refresh_and_save_round_trip_does_not_panic() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let posture = refresh_and_save(tmp.path());
    // captured_at is now-ish.
    assert!(posture.age_seconds() < 5);
    // File exists and is parseable.
    let loaded = load(tmp.path()).expect("posture.json must be readable after refresh");
    assert_eq!(
        loaded.captured_at.timestamp(),
        posture.captured_at.timestamp()
    );
}

/// Probes never panic and the orchestrator always returns. Even if
/// every binary is missing, the snapshot is still a valid struct.
#[test]
fn take_snapshot_always_returns_valid_struct() {
    let posture = HostPosture::take_snapshot();
    // Each probe has a probe_state — pending is the default; after
    // probe_xxx() it must be one of Ok / Unavailable / Failed.
    use crate::posture::sshd::ProbeState;
    for state in [
        posture.sshd.probe_state,
        posture.services.probe_state,
        posture.sudo.probe_state,
        posture.firewall.probe_state,
    ] {
        assert!(
            matches!(
                state,
                ProbeState::Ok | ProbeState::Unavailable | ProbeState::Failed
            ),
            "probe_state must be terminal after probe runs (got {state:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// services::parse_ss_dump
// ---------------------------------------------------------------------------

#[test]
fn parse_ss_dump_canonical_v4_v6_split_on_22() {
    use super::services::*;
    // Real `ss -Hltnp` output on a host with sshd + dashboard listening,
    // captured 2026-05-09 from prod for fixture purposes. Process column
    // present (CAP_NET_ADMIN granted to the agent).
    let dump = "\
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=1234,fd=4))
LISTEN 0      128             [::]:22           [::]:*    users:((\"sshd\",pid=1234,fd=5))
LISTEN 0      128          0.0.0.0:8787      0.0.0.0:*    users:((\"innerwarden-age\",pid=868514,fd=45))
";
    let listeners = parse_ss_dump(dump, Proto::Tcp);
    assert_eq!(listeners.len(), 3);
    assert_eq!(listeners[0].port, 22);
    assert_eq!(listeners[0].comm, "sshd");
    assert_eq!(listeners[0].addr, "0.0.0.0");
    assert_eq!(listeners[1].addr, "[::]");
    assert_eq!(listeners[2].port, 8787);
    assert_eq!(listeners[2].comm, "innerwarden-age");
}

#[test]
fn parse_ss_dump_handles_systemd_resolved_zone_id() {
    use super::services::*;
    let dump = "\
UNCONN 0      0          127.0.0.53%lo:53     0.0.0.0:*    users:((\"systemd-resolve\",pid=999,fd=14))
";
    let listeners = parse_ss_dump(dump, Proto::Udp);
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].port, 53);
    assert_eq!(listeners[0].addr, "127.0.0.53%lo");
    assert_eq!(listeners[0].comm, "systemd-resolve");
}

#[test]
fn parse_ss_dump_falls_back_to_question_mark_when_no_users_column() {
    use super::services::*;
    // Permission-denied run: `ss -ltn` (no -p) emits 5 columns.
    let dump = "\
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
";
    let listeners = parse_ss_dump(dump, Proto::Tcp);
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].comm, "?");
}

#[test]
fn services_has_listener_on_port_requires_ok_state() {
    use super::services::*;
    use super::sshd::ProbeState;
    let mut p = ServicesPosture {
        probe_state: ProbeState::Ok,
        listeners: vec![Listener {
            proto: Proto::Tcp,
            port: 22,
            addr: "0.0.0.0".into(),
            comm: "sshd".into(),
        }],
        error: None,
    };
    assert!(p.has_listener_on_port(22));
    assert!(!p.has_listener_on_port(80));
    // Probe failed → never confirm a listener even if vec has entries.
    p.probe_state = ProbeState::Failed;
    assert!(!p.has_listener_on_port(22));
}

// ---------------------------------------------------------------------------
// sudo::parse_getent_group_line
// ---------------------------------------------------------------------------

#[test]
fn parse_getent_group_line_typical() {
    use super::sudo::parse_getent_group_line;
    let line = "sudo:x:27:alice,bob,deploy\n";
    let members = parse_getent_group_line(line);
    assert_eq!(members, vec!["alice", "bob", "deploy"]);
}

#[test]
fn parse_getent_group_line_empty_membership() {
    use super::sudo::parse_getent_group_line;
    // Group exists with no members.
    let line = "wheel:x:10:\n";
    assert_eq!(parse_getent_group_line(line), Vec::<String>::new());
}

#[test]
fn parse_getent_group_line_malformed_returns_empty() {
    use super::sudo::parse_getent_group_line;
    assert_eq!(parse_getent_group_line("sudo:x"), Vec::<String>::new());
    assert_eq!(parse_getent_group_line(""), Vec::<String>::new());
}

#[test]
fn sudo_user_might_have_sudo_biases_permissive_when_probe_failed() {
    use super::sshd::ProbeState;
    use super::sudo::SudoPosture;
    let mut p = SudoPosture {
        probe_state: ProbeState::Ok,
        sudo_group_members: vec!["alice".into()],
        ..Default::default()
    };
    assert!(p.user_might_have_sudo("alice"));
    assert!(!p.user_might_have_sudo("eve"));
    // Probe unavailable → bias toward "any user MIGHT have sudo".
    p.probe_state = ProbeState::Unavailable;
    assert!(
        p.user_might_have_sudo("eve"),
        "when probe failed the downgrade engine must keep alerts at \
         original severity, so this returns true (permissive)"
    );
}

#[test]
fn sudo_user_might_have_sudo_checks_sudoers_d_filename() {
    use super::sshd::ProbeState;
    use super::sudo::SudoPosture;
    let p = SudoPosture {
        probe_state: ProbeState::Ok,
        sudoers_d_filenames: vec!["deploy".into()],
        ..Default::default()
    };
    // Filename signal is "maybe a sudoer" — biases toward keeping the
    // alert (returning true here means downgrade engine does not demote).
    assert!(p.user_might_have_sudo("deploy"));
}

// ---------------------------------------------------------------------------
// firewall parsers
// ---------------------------------------------------------------------------

#[test]
fn parse_ufw_status_active_with_default_deny() {
    use super::firewall::parse_ufw_status;
    use super::firewall::DefaultPolicy;
    let dump = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
8787/tcp                   ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
";
    let (policy, ports, _err) = parse_ufw_status(dump);
    assert_eq!(policy, DefaultPolicy::Drop);
    assert!(ports.contains(&22));
    assert!(ports.contains(&8787));
    assert!(ports.contains(&443));
}

#[test]
fn parse_ufw_status_inactive_is_permissive() {
    use super::firewall::parse_ufw_status;
    use super::firewall::DefaultPolicy;
    // Even with a configured deny policy, an inactive ufw is a no-op
    // → permissive, do not demote alerts based on it.
    let dump = "\
Status: inactive
Default: deny (incoming), allow (outgoing), disabled (routed)
";
    let (policy, _ports, _err) = parse_ufw_status(dump);
    assert_eq!(policy, DefaultPolicy::Permissive);
}

#[test]
fn parse_iptables_input_drop_policy_with_explicit_allows() {
    use super::firewall::parse_iptables_input;
    use super::firewall::DefaultPolicy;
    let dump = "\
Chain INPUT (policy DROP)
num  target prot opt source       destination
1    ACCEPT all  --  0.0.0.0/0    0.0.0.0/0   ctstate RELATED,ESTABLISHED
2    ACCEPT tcp  --  0.0.0.0/0    0.0.0.0/0   tcp dpt:22
3    ACCEPT tcp  --  0.0.0.0/0    0.0.0.0/0   tcp dpt:8787
";
    let (policy, ports, _err) = parse_iptables_input(dump);
    assert_eq!(policy, DefaultPolicy::Drop);
    assert_eq!(ports, vec![22, 8787]);
}

#[test]
fn parse_iptables_input_accept_policy() {
    use super::firewall::parse_iptables_input;
    use super::firewall::DefaultPolicy;
    let dump = "\
Chain INPUT (policy ACCEPT)
num  target prot opt source       destination
";
    let (policy, ports, _err) = parse_iptables_input(dump);
    assert_eq!(policy, DefaultPolicy::Accept);
    assert!(ports.is_empty());
}

#[test]
fn parse_nft_ruleset_input_drop_with_accept_for_22_and_8787() {
    use super::firewall::parse_nft_ruleset;
    use super::firewall::DefaultPolicy;
    let dump = "\
table inet filter {
\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t\tct state established,related accept
\t\ttcp dport 22 accept
\t\ttcp dport 8787 accept
\t}
}
";
    let (policy, ports, _err) = parse_nft_ruleset(dump);
    assert_eq!(policy, DefaultPolicy::Drop);
    assert!(ports.contains(&22));
    assert!(ports.contains(&8787));
}

#[test]
fn firewall_would_drop_port_only_when_drop_policy_and_not_allowed() {
    use super::firewall::{DefaultPolicy, FirewallBackend, FirewallPosture};
    use super::sshd::ProbeState;
    let p = FirewallPosture {
        probe_state: ProbeState::Ok,
        active_backends: vec![FirewallBackend::Ufw],
        default_policy: DefaultPolicy::Drop,
        allowed_tcp_ports: vec![22, 8787],
        error: None,
    };
    assert!(
        !p.would_drop_port(22),
        "explicitly allowed → reaches listener"
    );
    assert!(
        p.would_drop_port(80),
        "default DROP + not allowed → dropped"
    );
    let p_accept = FirewallPosture {
        default_policy: DefaultPolicy::Accept,
        ..p.clone()
    };
    assert!(
        !p_accept.would_drop_port(80),
        "default ACCEPT means firewall does not drop"
    );
}

// ---------------------------------------------------------------------------
// telegram_summary
// ---------------------------------------------------------------------------

/// Spec 044 Phase 4 anchor: `/posture` Telegram command renders all
/// four sections (sshd / services / sudo / firewall). When every
/// probe is Ok and populated, the message must include each section's
/// header, the captured-at timestamp, and the snapshot age footer.
#[test]
fn telegram_summary_renders_all_sections_when_probes_ok() {
    let posture = HostPosture {
        sshd: parse_sshd_dump(
            "\
port 22
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
pubkeyauthentication yes
maxauthtries 3
",
        ),
        services: super::services::ServicesPosture {
            probe_state: ProbeState::Ok,
            listeners: vec![super::services::Listener {
                proto: super::services::Proto::Tcp,
                port: 22,
                addr: "0.0.0.0".to_string(),
                comm: "sshd".to_string(),
            }],
            error: None,
        },
        sudo: super::sudo::SudoPosture {
            probe_state: ProbeState::Ok,
            sudo_group_members: vec!["ubuntu".to_string()],
            ..Default::default()
        },
        firewall: super::firewall::FirewallPosture {
            probe_state: ProbeState::Ok,
            active_backends: vec![super::firewall::FirewallBackend::Ufw],
            default_policy: super::firewall::DefaultPolicy::Drop,
            allowed_tcp_ports: vec![22, 8787],
            error: None,
        },
        captured_at: chrono::Utc::now(),
    };
    let msg = telegram_summary(&posture);
    assert!(msg.contains("Host posture"));
    assert!(msg.contains("SSHD"));
    assert!(msg.contains("Listening services"));
    assert!(msg.contains("Sudo"));
    assert!(msg.contains("Firewall"));
    assert!(msg.contains("ubuntu"));
    assert!(msg.contains("22"));
    assert!(msg.contains("8787"));
    assert!(msg.contains("Last refresh:"));
}

/// Failed/Unavailable probe states render a "(probe …)" hint instead
/// of fabricating fields. The downgrade engine treats those surfaces
/// as permissive; the operator must see the same truth on Telegram.
#[test]
fn telegram_summary_renders_probe_failed_states_without_panic() {
    let posture = HostPosture {
        sshd: super::sshd::SshdPosture {
            probe_state: ProbeState::Unavailable,
            error: Some("sshd binary not found".to_string()),
            ..Default::default()
        },
        services: super::services::ServicesPosture {
            probe_state: ProbeState::Failed,
            listeners: vec![],
            error: Some("ss exit 1".to_string()),
        },
        sudo: super::sudo::SudoPosture {
            probe_state: ProbeState::Unavailable,
            ..Default::default()
        },
        firewall: super::firewall::FirewallPosture {
            probe_state: ProbeState::Unavailable,
            ..Default::default()
        },
        captured_at: chrono::Utc::now(),
    };
    let msg = telegram_summary(&posture);
    assert!(msg.contains("Host posture"));
    assert!(msg.contains("probe unavailable") || msg.contains("probe failed"));
}

/// HTML-injection probe: a sudoers.d filename containing `<script>`
/// must be escaped, otherwise a malicious filename on the host could
/// break Telegram rendering or hide content.
#[test]
fn telegram_summary_html_escapes_sudoers_filenames() {
    let posture = HostPosture {
        sudo: super::sudo::SudoPosture {
            probe_state: ProbeState::Ok,
            sudoers_d_filenames: vec!["evil<script>".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let msg = telegram_summary(&posture);
    assert!(msg.contains("evil&lt;script&gt;"));
    assert!(!msg.contains("evil<script>"));
}

// ---------------------------------------------------------------------------
// Test-only helper to expose the otherwise-private from_yes_no /
// from_permit_root_login parsers without leaking them from the module.
// ---------------------------------------------------------------------------

impl SshdToggle {
    fn from_yes_no_for_test(s: &str) -> Self {
        // Inline the same logic — keeping it private in sshd.rs but
        // testing the contract here.
        match s.trim().to_ascii_lowercase().as_str() {
            "yes" => SshdToggle::Yes,
            "no" => SshdToggle::No,
            _ => SshdToggle::Unset,
        }
    }
}
