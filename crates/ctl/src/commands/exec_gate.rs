//! `innerwarden exec-gate` — operator CLI for the agent-scoped Execution Gate
//! (spec 083). ctl is aya-free, so the map writes go through `bpftool` (the same
//! tool ctl already uses to READ the gate in `doctor`). The SAFETY decision is
//! `innerwarden_core::execution_gate::plan_arm` (pure, unit-tested); this module
//! resolves the target cgroup, builds the plan, and translates it into bpftool
//! commands.
//!
//! Scope of this command today: `status`, `arm --observe`, `disarm`. Observe
//! never denies an exec, so it is the safe onboarding mode — arm observe, watch
//! what the agent would-block, build the allowlist, then enforce. `arm --enforce`
//! is intentionally gated behind a zero-would-deny rehearsal (a follow-up); it is
//! refused here so nobody flips enforce blind (the k7 brick lesson).

use innerwarden_core::execution_gate::{self as eg, GateMode};
use std::collections::BTreeSet;

/// Little-endian `0xNN` byte args for a bpftool map key/value of `n` bytes.
pub(crate) fn le_hex(v: u64, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("0x{:02x}", (v >> (8 * i)) & 0xff))
        .collect()
}

fn map_update(pin: &str, key: Vec<String>, val: Vec<String>) -> Vec<String> {
    let mut c = vec![
        "map".into(),
        "update".into(),
        "pinned".into(),
        pin.into(),
        "key".into(),
    ];
    c.extend(key);
    c.push("value".into());
    c.extend(val);
    c.push("any".into());
    c
}

fn map_delete(pin: &str, key: Vec<String>) -> Vec<String> {
    let mut c = vec![
        "map".into(),
        "delete".into(),
        "pinned".into(),
        pin.into(),
        "key".into(),
    ];
    c.extend(key);
    c
}

/// PURE translation of a vetted [`eg::ArmPlan`] into the ordered list of bpftool
/// commands that apply it. Order is host-safe: allowlist inserts, then removes,
/// then the scope cgroup id, then `LSM_POLICY` key 4 (scope) BEFORE key 3 (mode),
/// so the gate is scoped the instant it goes active.
pub(crate) fn arm_commands(plan: &eg::ArmPlan) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    for k in &plan.reconcile.to_insert {
        cmds.push(map_update(
            eg::EXEC_ALLOWLIST_PIN,
            le_hex(*k, 8),
            vec!["0x01".into()],
        ));
    }
    for k in &plan.reconcile.to_remove {
        cmds.push(map_delete(eg::EXEC_ALLOWLIST_PIN, le_hex(*k, 8)));
    }
    cmds.push(map_update(
        eg::EXEC_GATE_SCOPE_PIN,
        le_hex(plan.scope_cgroup_id, 8),
        vec!["0x01".into()],
    ));
    cmds.push(map_update(
        eg::LSM_POLICY_PIN,
        le_hex(eg::GATE_SCOPE_KEY as u64, 4),
        le_hex(1, 4),
    ));
    let mode_val: u64 = match plan.mode {
        GateMode::Enforce => 1,
        GateMode::Observe => 2,
        _ => 0,
    };
    cmds.push(map_update(
        eg::LSM_POLICY_PIN,
        le_hex(eg::GATE_MODE_KEY as u64, 4),
        le_hex(mode_val, 4),
    ));
    cmds
}

/// PURE: disarm commands — `LSM_POLICY` key 3 = 0 (stop denying) THEN key 4 = 0.
/// Leaves the allowlist + scope entries (harmless while inert).
pub(crate) fn disarm_commands() -> Vec<Vec<String>> {
    vec![
        map_update(
            eg::LSM_POLICY_PIN,
            le_hex(eg::GATE_MODE_KEY as u64, 4),
            le_hex(0, 4),
        ),
        map_update(
            eg::LSM_POLICY_PIN,
            le_hex(eg::GATE_SCOPE_KEY as u64, 4),
            le_hex(0, 4),
        ),
    ]
}

/// PURE: parse the u64 keys from a `bpftool map dump` of `EXEC_ALLOWLIST` (the
/// keys are 8 little-endian bytes on each `key:` line). Used to read the live
/// allowlist for the reconcile diff.
pub(crate) fn parse_bpftool_u64_keys(dump: &str) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for line in dump.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("key:") else {
            continue;
        };
        let bytes: Vec<u8> = rest
            .split_whitespace()
            .take(8)
            .filter_map(|b| u8::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .collect();
        if bytes.len() == 8 {
            let mut v = 0u64;
            for (i, b) in bytes.iter().enumerate() {
                v |= (*b as u64) << (8 * i);
            }
            out.insert(v);
        }
    }
    out
}

// ── I/O (real kernel + bpftool; exercised on a box, error-path only in CI) ────

fn resolve_cgroup_id(pid: u32) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = eg::parse_cgroup_v2_path(&raw)?;
    std::fs::metadata(format!("/sys/fs/cgroup{rel}"))
        .ok()
        .map(|m| m.ino())
}

fn bpftool(args: &[String]) -> anyhow::Result<()> {
    let out = std::process::Command::new("bpftool").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "bpftool {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn live_allowlist_keys() -> BTreeSet<u64> {
    match std::process::Command::new("bpftool")
        .args(["map", "dump", "pinned", eg::EXEC_ALLOWLIST_PIN])
        .output()
    {
        Ok(o) if o.status.success() => parse_bpftool_u64_keys(&String::from_utf8_lossy(&o.stdout)),
        _ => BTreeSet::new(),
    }
}

/// PURE decision + translation: vet an arm request and return the ordered bpftool
/// commands to apply it, or a human-readable refusal. No I/O — `cgid` and `live`
/// are resolved by the caller, so every branch is unit-testable. Observe-only
/// today (enforce is refused until the rehearsal lands).
pub(crate) fn arm_plan_for_cli(
    cgid: u64,
    observe: bool,
    paths: &[String],
    live: &BTreeSet<u64>,
) -> Result<Vec<Vec<String>>, String> {
    if !observe {
        return Err(
            "enforce is gated behind a zero-would-deny rehearsal (not yet available). \
             Run `arm --observe` first, watch the would-block events, build the allowlist, \
             then enforce once the rehearsal passes."
                .to_string(),
        );
    }
    if cgid == 0 {
        return Err(
            "could not resolve a cgroup-v2 id for the target pid (process gone, or a \
             cgroup-v1 host). The Execution Gate scopes on the unified cgroup."
                .to_string(),
        );
    }
    let target = eg::target_allowlist_keys(paths);
    let plan = eg::plan_arm(target, live, cgid, GateMode::Observe)
        .map_err(|r| format!("refused: {r:?}"))?;
    Ok(arm_commands(&plan))
}

/// `innerwarden exec-gate arm --pid <PID> --observe [--path P ...]`.
pub(crate) fn cmd_arm(pid: u32, observe: bool, paths: &[String]) -> anyhow::Result<()> {
    let cgid = resolve_cgroup_id(pid).unwrap_or(0);
    let cmds = arm_plan_for_cli(cgid, observe, paths, &live_allowlist_keys())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for cmd in cmds {
        bpftool(&cmd)?;
    }
    println!(
        "Execution Gate armed: OBSERVE, scoped to pid {pid} (cgroup id {cgid}), \
         {} binaries allowlisted. Observe never denies — it logs what it WOULD block. \
         Disarm with `innerwarden exec-gate disarm`.",
        paths.len()
    );
    Ok(())
}

fn bpftool_lookup_u32(pin: &str, key: u32) -> Option<u32> {
    let out = std::process::Command::new("bpftool")
        .args([
            "map",
            "lookup",
            "pinned",
            pin,
            "key",
            &key.to_string(),
            "0",
            "0",
            "0",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    eg::parse_bpftool_value_u32(&String::from_utf8_lossy(&out.stdout))
}

fn bpftool_dump_count(pin: &str) -> usize {
    match std::process::Command::new("bpftool")
        .args(["map", "dump", "pinned", pin])
        .output()
    {
        Ok(o) if o.status.success() => eg::count_bpftool_dump(&String::from_utf8_lossy(&o.stdout)),
        _ => 0,
    }
}

/// `innerwarden exec-gate status` — read-only summary of the live gate.
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    let mode = GateMode::from_policy_key(bpftool_lookup_u32(eg::LSM_POLICY_PIN, eg::GATE_MODE_KEY));
    let scoped = bpftool_lookup_u32(eg::LSM_POLICY_PIN, eg::GATE_SCOPE_KEY) == Some(1);
    let allow = bpftool_dump_count(eg::EXEC_ALLOWLIST_PIN);
    let scope = bpftool_dump_count(eg::EXEC_GATE_SCOPE_PIN);
    println!(
        "Execution Gate: mode={}, scope={}, allowlist={} binaries, scope_cgroups={}",
        mode.label(),
        if scoped { "agent-scoped" } else { "host-wide" },
        allow,
        scope
    );
    if mode == GateMode::Inert {
        println!("The gate is inert — it denies nothing. `arm --observe` to start.");
    }
    Ok(())
}

/// `innerwarden exec-gate disarm`.
pub(crate) fn cmd_disarm() -> anyhow::Result<()> {
    for cmd in disarm_commands() {
        bpftool(&cmd)?;
    }
    println!("Execution Gate disarmed (inert). The host and the agent are ungated.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_hex_is_little_endian() {
        assert_eq!(le_hex(0x04, 4), vec!["0x04", "0x00", "0x00", "0x00"]);
        // cgroup id 9772 = 0x262c -> LE 8 bytes
        assert_eq!(
            le_hex(9772, 8),
            vec!["0x2c", "0x26", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]
        );
    }

    #[test]
    fn arm_commands_order_and_content() {
        let plan = eg::ArmPlan {
            reconcile: eg::ReconcilePlan {
                to_insert: [0xaa].into_iter().collect(),
                to_remove: [0xbb].into_iter().collect(),
            },
            scope_cgroup_id: 9772,
            mode: GateMode::Observe,
        };
        let cmds = arm_commands(&plan);
        // insert, remove, scope, key4=1, key3=2 (observe) — in that order.
        assert_eq!(cmds.len(), 5);
        assert_eq!(cmds[0][1], "update"); // allowlist insert
        assert!(cmds[0].contains(&eg::EXEC_ALLOWLIST_PIN.to_string()));
        assert_eq!(cmds[1][1], "delete"); // allowlist remove
        assert!(cmds[2].contains(&eg::EXEC_GATE_SCOPE_PIN.to_string()));
        // key4 (scope) before key3 (mode)
        assert_eq!(
            cmds[3],
            map_update(eg::LSM_POLICY_PIN, le_hex(4, 4), le_hex(1, 4))
        );
        assert_eq!(
            cmds[4],
            map_update(eg::LSM_POLICY_PIN, le_hex(3, 4), le_hex(2, 4))
        );
    }

    #[test]
    fn disarm_sets_mode_then_scope_to_zero() {
        let cmds = disarm_commands();
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0],
            map_update(eg::LSM_POLICY_PIN, le_hex(3, 4), le_hex(0, 4))
        );
        assert_eq!(
            cmds[1],
            map_update(eg::LSM_POLICY_PIN, le_hex(4, 4), le_hex(0, 4))
        );
    }

    #[test]
    fn parse_bpftool_u64_keys_reads_le_8_bytes() {
        let dump = "key: 2c 26 00 00 00 00 00 00  value: 01\n\
                    key: aa bb 00 00 00 00 00 00  value: 01\n\
                    Found 2 elements";
        let keys = parse_bpftool_u64_keys(dump);
        assert!(keys.contains(&9772));
        assert!(keys.contains(&0xbbaa));
        assert_eq!(keys.len(), 2);
        // empty dump
        assert!(parse_bpftool_u64_keys("Found 0 elements").is_empty());
    }

    #[test]
    fn arm_plan_for_cli_refuses_enforce() {
        let live = BTreeSet::new();
        let err = arm_plan_for_cli(123, false, &[], &live).unwrap_err();
        assert!(err.contains("rehearsal"));
    }

    #[test]
    fn arm_plan_for_cli_refuses_zero_cgid() {
        let live = BTreeSet::new();
        let err = arm_plan_for_cli(0, true, &["/usr/bin/true".into()], &live).unwrap_err();
        assert!(err.contains("cgroup"));
    }

    #[test]
    fn arm_plan_for_cli_observe_empty_is_scope_and_policy_only() {
        // observe + no paths: no allowlist insert -> scope + key4 + key3 = 3 cmds.
        let live = BTreeSet::new();
        let cmds = arm_plan_for_cli(9772, true, &[], &live).expect("observe empty ok");
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains(&eg::EXEC_GATE_SCOPE_PIN.to_string()));
        // last is key3 = 2 (observe)
        assert_eq!(
            cmds[2],
            map_update(eg::LSM_POLICY_PIN, le_hex(3, 4), le_hex(2, 4))
        );
    }

    #[test]
    fn arm_plan_for_cli_observe_with_a_path_inserts_allowlist() {
        let live = BTreeSet::new();
        let cmds = arm_plan_for_cli(9772, true, &["/usr/bin/true".into()], &live).unwrap();
        // allowlist insert + scope + key4 + key3 = 4 cmds.
        assert_eq!(cmds.len(), 4);
        assert_eq!(cmds[0][1], "update");
        assert!(cmds[0].contains(&eg::EXEC_ALLOWLIST_PIN.to_string()));
    }

    // ── I/O fns: CI-safe failure / read paths. bpftool + the target /proc entry
    //    are absent in CI; these assertions also hold on a box (bogus pid, bad
    //    args, read-only) so they never mutate a real gate. ──────────────────────

    #[test]
    fn resolve_cgroup_id_none_for_bogus_pid() {
        assert!(resolve_cgroup_id(u32::MAX).is_none());
    }

    #[test]
    fn bpftool_errors_on_failure() {
        // CI: no bpftool -> spawn error. Box: unknown subcommand -> non-zero exit.
        assert!(bpftool(&["definitely-not-a-bpftool-subcommand".to_string()]).is_err());
    }

    #[test]
    fn live_allowlist_keys_is_callable() {
        // Read-only; empty in CI, possibly non-empty on a box. Just exercise it.
        let _ = live_allowlist_keys();
    }

    #[test]
    fn cmd_status_is_read_only_and_ok() {
        // status only READS + prints (inert when nothing is readable) — safe in CI
        // and on a box.
        assert!(cmd_status().is_ok());
    }

    #[test]
    fn cmd_arm_errors_on_unresolvable_pid() {
        // bogus pid -> cgid 0 -> refused BEFORE any write.
        assert!(cmd_arm(u32::MAX, true, &[]).is_err());
    }

    #[test]
    fn cmd_arm_errors_on_enforce() {
        // enforce is refused before any map write, regardless of the pid.
        assert!(cmd_arm(123, false, &[]).is_err());
    }

    #[test]
    fn cmd_disarm_errors_without_bpftool() {
        // Disarm WRITES, so only assert it where bpftool is ABSENT (CI): the first
        // map update fails -> Err, never mutating a real gate. Skipped on a box.
        if std::process::Command::new("bpftool")
            .arg("version")
            .output()
            .is_err()
        {
            assert!(cmd_disarm().is_err());
        }
    }
}
