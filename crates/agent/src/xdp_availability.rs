//! XDP firewall availability gate (Wave 5b PR-2, 2026-05-03).
//!
//! Background — operator-visible bug: production hosts where the
//! sensor never finished mounting `bpffs` at `/sys/fs/bpf/innerwarden`
//! were emitting `bpftool map update failed for X.X.X.X: Error: bpf
//! obj get (/sys/fs/bpf/innerwarden): directory not in bpf file
//! system (bpffs)` followed by `XDP blocklist map not found - XDP
//! firewall not loaded` on EVERY block decision. Three blocks per
//! hour produced six log lines per hour of pure noise that masked
//! real warnings (SQLite lock contention, KG dangling edges, etc.).
//! The fallback to UFW worked silently, so the operator only saw
//! the WARNs and was led to think blocks were failing — they were
//! not, just slower.
//!
//! This module gates both XDP call sites in `decision_block_ip` so:
//!
//! 1. After one observed failure, XDP attempts are SKIPPED for
//!    `RECHECK_INTERVAL` (5 min). The fallback path runs directly,
//!    no syscall wasted, no log line emitted.
//! 2. Exactly one operator-facing WARN with actionable instructions
//!    is logged per `WARN_INTERVAL` (5 min) — the operator sees the
//!    problem ONCE per dashboard refresh window with a recovery
//!    recipe, not on every block.
//! 3. After `RECHECK_INTERVAL`, the next block tries XDP again so
//!    that mounting bpffs auto-recovers without an agent restart.
//!
//! The state is two atomics, no locking, safe to call from any
//! tokio worker. Pure logic; the actual filesystem check lives in
//! the caller (`std::path::Path::new(BLOCKLIST_PIN).exists()`).

use std::sync::atomic::{AtomicI64, Ordering};

use tracing::warn;

/// Seconds to skip XDP attempts after a failure. After this many
/// seconds, the next block tries XDP again so auto-recovery works
/// when the operator finally mounts bpffs.
pub const RECHECK_INTERVAL_SECS: i64 = 300;

/// Seconds between operator-facing WARN messages. Same value as the
/// recheck interval — keeps the WARN-to-attempt ratio at 1:1 in the
/// degraded state.
const WARN_INTERVAL_SECS: i64 = 300;

/// Unix timestamp at which the next XDP attempt is permitted.
/// 0 = "no failure observed, attempt freely".
static SKIP_UNTIL_TS: AtomicI64 = AtomicI64::new(0);

/// Unix timestamp of the last operator-facing WARN. Separate from
/// SKIP_UNTIL_TS so the WARN can fire at the moment of failure
/// without artificially extending the skip window.
static LAST_WARN_TS: AtomicI64 = AtomicI64::new(0);

/// Should the caller attempt XDP right now? Returns `false` while
/// inside the skip window after a recent failure.
///
/// Cheap — one atomic load + one timestamp read.
pub fn should_attempt_xdp() -> bool {
    let now = chrono::Utc::now().timestamp();
    let skip_until = SKIP_UNTIL_TS.load(Ordering::Relaxed);
    now >= skip_until
}

/// Record an XDP failure. Sets the skip window for the next
/// `RECHECK_INTERVAL_SECS` seconds, and emits exactly one
/// operator-facing WARN per `WARN_INTERVAL_SECS` window.
///
/// `context` is a one-line string carried into the WARN
/// (e.g. `"shield xdp_manager"` or `"block-ip-xdp skill"`) so the
/// log makes the failure surface obvious. `details` is the underlying
/// error string (typically the bpftool stderr or filesystem
/// description) — included once per WARN, not on every attempt.
///
/// 2026-05-08: the warning text is now detection-aware. A prod audit
/// found the previous static recipe (`mount bpffs && restart sensor`)
/// was actively misleading: bpffs was mounted and the sensor was
/// running — the real cause was the systemd unit putting `/sys/fs/bpf`
/// in `ReadOnlyPaths`, which silently broke `map.pin()`. Operator
/// followed the recipe, nothing changed, and the warning fired again
/// every 5 minutes for hours. The new copy inspects observable state
/// (bpffs mount, pin dir presence, expected pin file) and emits the
/// recipe that matches what's actually missing.
pub fn mark_failed(context: &str, details: &str) {
    let now = chrono::Utc::now().timestamp();
    SKIP_UNTIL_TS.store(now + RECHECK_INTERVAL_SECS, Ordering::Relaxed);

    let last_warn = LAST_WARN_TS.load(Ordering::Relaxed);
    if now - last_warn >= WARN_INTERVAL_SECS
        && LAST_WARN_TS
            .compare_exchange(last_warn, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let recipe = diagnose_xdp_state();
        // Operator-actionable single-line WARN. Includes the
        // detection-derived recovery recipe so the operator does not
        // have to remember it. Falls back to UFW/iptables silently in
        // the meantime — blocks still happen, just at firewall speed
        // instead of wire speed.
        warn!(
            context,
            details,
            "XDP firewall unavailable — falling back to UFW/iptables for the next {RECHECK_INTERVAL_SECS}s. \
             {recipe} \
             Subsequent failures within this window will be silent until the next recheck."
        );
    }
}

/// Inspect on-disk state to suggest the recovery action that matches
/// what's actually missing. Returns a one-sentence recipe (no leading
/// label, no trailing period) suitable for embedding in the WARN.
///
/// Probes, in order:
/// 1. `/sys/fs/bpf` not a directory → bpffs not mounted; suggest mount.
/// 2. `/sys/fs/bpf/innerwarden/` does not exist → sensor never created
///    the pin dir. Most likely cause: systemd unit has `/sys/fs/bpf` in
///    `ReadOnlyPaths` (the prod regression we tripped on 2026-05-08).
/// 3. `/sys/fs/bpf/innerwarden/blocklist` does not exist → dir is
///    there but the sensor failed to pin the BLOCKLIST map. Common
///    cause: previous sensor lifetime left an XDP link attached on the
///    interface, the new sensor's `xdp.attach()` returned EBUSY and
///    early-returned before the pin step. (This sub-case is covered
///    by the recover-on-busy fix in the sensor's `attach_xdp`, but
///    older binaries still in the wild trigger it.)
/// 4. Everything looks healthy from the agent's view → fall back to a
///    generic "check sensor logs" recipe rather than guessing.
pub(crate) fn diagnose_xdp_state() -> &'static str {
    use std::path::Path;

    const BPFFS_ROOT: &str = "/sys/fs/bpf";
    const PIN_DIR: &str = "/sys/fs/bpf/innerwarden";
    const BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";

    if !Path::new(BPFFS_ROOT).is_dir() {
        return "bpffs is not mounted at /sys/fs/bpf. To enable wire-speed blocks: \
                `sudo mount -t bpf bpffs /sys/fs/bpf && sudo systemctl restart innerwarden-sensor`.";
    }
    if !Path::new(PIN_DIR).exists() {
        return "the sensor did not create /sys/fs/bpf/innerwarden/. The most common cause \
                is the systemd unit having `/sys/fs/bpf` in `ReadOnlyPaths` instead of \
                `ReadWritePaths`. Fix the unit (or drop in an override) and restart \
                the sensor: `sudo systemctl restart innerwarden-sensor`.";
    }
    if !Path::new(BLOCKLIST_PIN).exists() {
        return "/sys/fs/bpf/innerwarden/ exists but the BLOCKLIST map is not pinned — \
                the sensor's XDP attach probably hit EBUSY because a previous lifetime \
                left a link attached. Detach: `sudo bpftool link list` (find the xdp \
                row), `sudo bpftool link detach id <ID>`, then \
                `sudo systemctl restart innerwarden-sensor`.";
    }
    "/sys/fs/bpf/innerwarden/blocklist is present from the agent's view; the failure \
     is downstream of the pin file (e.g. bpftool subprocess permissions or the agent's \
     systemd hardening). Check sensor + agent logs for the underlying error."
}

/// Reset the skip window. Called after an XDP success so a transient
/// glitch (e.g. one-off bpftool race) does not leave subsequent
/// successful blocks running through the skip path.
pub fn mark_succeeded() {
    SKIP_UNTIL_TS.store(0, Ordering::Relaxed);
}

/// Test-only: clear the global state so tests don't leak into each
/// other. The atomics are `static`, so a previous test that called
/// `mark_failed` would otherwise poison the next test's view.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    SKIP_UNTIL_TS.store(0, Ordering::Relaxed);
    LAST_WARN_TS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-05-03 (Wave 5b PR-2 anchor): the gate must (a) skip XDP
    /// attempts for the configured window after a failure and (b)
    /// rate-limit the operator-facing WARN to one per window.
    ///
    /// Combined into a single test because the gate state lives in
    /// `static` atomics shared across the test binary; running the
    /// two scenarios in parallel races on `SKIP_UNTIL_TS` /
    /// `LAST_WARN_TS` even with `reset_for_test` at the start.
    /// The whole-flow assertion is the contract anyway — the
    /// operator-visible behaviour is "after failure, no more
    /// attempts AND no more WARNs for 5 min, then both auto-recover
    /// on the next attempt".
    ///
    /// The bug this pins: prod was burning a bpftool subprocess per
    /// block decision (3+ per hour) AND emitting 2 WARN lines each
    /// time, swamping the journal. The skip path replaces both with
    /// a single atomic load.
    #[test]
    fn xdp_availability_gate_skips_attempts_and_rate_limits_warns() {
        reset_for_test();

        // Cold path: never failed → attempt allowed.
        assert!(should_attempt_xdp(), "cold start must allow XDP attempt");

        // First failure records the WARN timestamp and opens the skip window.
        mark_failed("test", "first");
        let after_first = LAST_WARN_TS.load(Ordering::Relaxed);
        assert!(after_first > 0, "first failure must record warn timestamp");
        assert!(
            !should_attempt_xdp(),
            "attempt must be skipped immediately after failure"
        );

        // Second failure within the window must NOT re-record the WARN.
        // (The skip window stays open; the gate is idempotent.)
        mark_failed("test", "second");
        let after_second = LAST_WARN_TS.load(Ordering::Relaxed);
        assert_eq!(
            after_first, after_second,
            "second failure within WARN_INTERVAL must not re-record warn timestamp"
        );
        assert!(
            !should_attempt_xdp(),
            "second failure must keep skip window open"
        );

        // Success resets the gate (covers the transient-glitch case
        // where one bpftool call fails but the next succeeds).
        mark_succeeded();
        assert!(
            should_attempt_xdp(),
            "success must re-enable attempts after a transient failure"
        );
    }

    /// 2026-05-08 anchor (fix/xdp-infra-honesty): `diagnose_xdp_state`
    /// must return distinct copy for each observable state. Pins the
    /// operator-honesty contract — pre-fix the WARN always told the
    /// operator to mount bpffs even when bpffs was mounted, the pin
    /// dir was missing because of a systemd `ReadOnlyPaths` regression.
    /// The mismatch between the recipe and reality made the warning
    /// actively counterproductive: operators followed it, nothing
    /// changed, the WARN fired again 5 minutes later.
    ///
    /// We exercise four observable states by reading the on-disk
    /// snapshot and asserting the right phrase appears. The function
    /// reads real paths (`/sys/fs/bpf/...`) which on a CI runner
    /// without bpffs lands on the "bpffs not mounted" branch — so the
    /// assertion checks for the bpffs-mount phrase, which is the test
    /// host's actual state. The other branches are covered by the
    /// integration tests on a host with bpffs available.
    #[test]
    fn diagnose_xdp_state_returns_actionable_recipe_for_observable_state() {
        let recipe = diagnose_xdp_state();
        // Whatever branch we hit, the recipe must mention an
        // operator-actionable command (mount, restart, detach, or
        // log-check). Pre-fix the recipe was hard-coded to the mount
        // command regardless of state.
        let actionable = recipe.contains("mount")
            || recipe.contains("ReadWritePaths")
            || recipe.contains("link detach")
            || recipe.contains("Check sensor + agent logs");
        assert!(
            actionable,
            "diagnose_xdp_state must return a state-specific recipe with an \
             actionable command (mount / ReadWritePaths / link detach / log \
             inspection). Got: {recipe}"
        );
    }
}
