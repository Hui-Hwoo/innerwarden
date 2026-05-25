//! Tracing initialisation for the sensor binary.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR1 of the sensor decomposition
//! (see SESSION_LOG.md). Pure code motion — zero behaviour change. The three
//! functions and their existing four anchor tests moved verbatim; new
//! anchors below pin behaviour that was implicit before.
//!
//! ## Why a dedicated module
//!
//! Pre-extraction these three functions lived among 24 unrelated top-level
//! functions inside a 3451-line `main.rs`. Splitting them out lets the unit
//! tests live next to the code, makes the dependency surface (a single
//! `init_tracing()` entry called once at startup) explicit, and unblocks
//! the larger decomposition work (the upcoming `state_paths.rs`, `seccomp.rs`,
//! `incident_builders.rs`, `event_dispatch.rs` extractions).

use anyhow::Result;

/// Build the tracing env-filter shared by every tracing init path.
/// Pure so unit tests can compare its `Display` form without mutating
/// process-global subscriber state.
pub(crate) fn build_tracing_env_filter() -> Result<tracing_subscriber::EnvFilter> {
    Ok(tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("innerwarden_sensor=info".parse()?))
}

/// Wave 9f (AUDIT-009 root): true iff the process is being captured by
/// systemd's journal stream. systemd sets `JOURNAL_STREAM=<dev>:<inode>`
/// on services launched via a unit file, so the binary's stdout/stderr
/// goes into the journal. When this is set we route tracing through
/// `tracing-journald` so each record gets a real `PRIORITY=` field
/// (instead of letting journald guess priority off captured plain stdout).
///
/// Pure helper so tests pass the env value in as an argument and avoid
/// mutating process-global state. `cfg_attr` on the dead-code lint
/// because the only non-test caller is the Linux-cfg branch in
/// `init_tracing` — macOS / dev-shell builds never reach the call site
/// but the unit tests do exercise the function on every platform.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn use_journald_layer(journal_stream: Option<&str>) -> bool {
    journal_stream.is_some_and(|v| !v.is_empty())
}

/// Set up tracing for the sensor binary. Routes through `tracing-journald`
/// when running under systemd, plain stdout fmt subscriber otherwise.
pub(crate) fn init_tracing() -> Result<()> {
    let env_filter = build_tracing_env_filter()?;

    #[cfg(target_os = "linux")]
    {
        let journal_stream = std::env::var("JOURNAL_STREAM").ok();
        if use_journald_layer(journal_stream.as_deref()) {
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            match tracing_journald::layer() {
                Ok(layer) => {
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(layer)
                        .init();
                    return Ok(());
                }
                Err(e) => {
                    eprintln!(
                        "tracing-journald layer unavailable ({e}); falling back to stdout fmt subscriber"
                    );
                }
            }
        }
    }
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing anchors moved from main.rs ──────────────────────────────
    //
    // 2026-05-23 origin: the three `use_journald_layer_*` tests pin the
    // detection logic so a future refactor that breaks the env-var
    // contract is caught at test time rather than by the operator one
    // morning when their `journalctl -p warning` query goes silent.

    #[test]
    fn use_journald_layer_returns_true_when_journal_stream_is_set() {
        // The JOURNAL_STREAM=<dev>:<inode> shape that systemd documents.
        assert!(use_journald_layer(Some("8:42")));
    }

    #[test]
    fn use_journald_layer_returns_false_when_env_is_unset() {
        // Off-systemd dev shell + macOS dev: env var simply absent. We
        // must NOT try to write to a non-existent journal socket because
        // that fails the binary at startup on macOS where there is no
        // /run/systemd at all.
        assert!(!use_journald_layer(None));
    }

    #[test]
    fn use_journald_layer_returns_false_when_env_is_empty_string() {
        // Defensive: env vars set to empty string are common operator
        // mistakes (e.g. `JOURNAL_STREAM= cargo run`). Treat empty as
        // unset so the operator's foreground run does not silently start
        // attempting a journald write that will fail.
        assert!(!use_journald_layer(Some("")));
    }

    #[test]
    fn build_tracing_env_filter_includes_innerwarden_sensor_directive() {
        // Anchor for the env filter. Pins the directive so a future
        // contributor cannot accidentally drop the log routing for the
        // sensor namespace — which would silently turn off most logs.
        // The Display form is what tracing-subscriber shows on `--help`
        // output, so a missing directive shows up here.
        let f = build_tracing_env_filter().expect("env filter must build");
        let s = format!("{f}");
        assert!(
            s.contains("innerwarden_sensor"),
            "env filter must enable innerwarden_sensor; got: {s}"
        );
    }

    // ── New anchors added with the extraction ────────────────────────────
    //
    // 2026-05-25: extraction PR1 anchors. Pin behaviour that was implicit
    // before — the function was effectively untested as a unit and any
    // future refactor that drops the "innerwarden_sensor=info" default
    // would silently break the operator's `journalctl` filtering.

    #[test]
    fn build_tracing_env_filter_is_pure_and_repeatable() {
        // The Display form must be deterministic across calls so the
        // helper can be used safely inside boot-loop retries (e.g. the
        // watchdog respawning the sensor after a fault) without
        // accumulating duplicate directives or drifting between runs.
        let a = build_tracing_env_filter().expect("first build");
        let b = build_tracing_env_filter().expect("second build");
        assert_eq!(format!("{a}"), format!("{b}"));
    }

    #[test]
    fn build_tracing_env_filter_uses_info_level_for_sensor_namespace() {
        // Anchor: the default level for the sensor namespace MUST be
        // `info`, not `warn` or `debug`. A future refactor that changes
        // this — e.g. someone tightens to `warn` to reduce noise without
        // thinking about journald — would silently stop emitting the
        // detector-startup banner lines and the collector-spawn logs
        // that operators rely on to confirm the sensor came up clean.
        let f = build_tracing_env_filter().expect("env filter must build");
        let s = format!("{f}");
        assert!(
            s.contains("innerwarden_sensor=info"),
            "default level for innerwarden_sensor must stay `info`; got: {s}"
        );
    }

    #[test]
    fn use_journald_layer_treats_whitespace_only_as_present() {
        // 2026-05-25 anchor: the current `is_some_and(|v| !v.is_empty())`
        // check rejects only the literal empty string. A value of " "
        // counts as set, so it returns true. This is a deliberate
        // narrow interpretation of "empty" — anchor it so a future
        // refactor that switches to `v.trim().is_empty()` (which would
        // FLIP this case) triggers an explicit conversation about
        // whether systemd would ever actually emit a whitespace
        // JOURNAL_STREAM. (It would not — but pinning the current
        // behaviour rather than the speculative future change is safer.)
        assert!(use_journald_layer(Some(" ")));
    }
}
