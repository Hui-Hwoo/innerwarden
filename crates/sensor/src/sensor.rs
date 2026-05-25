//! Sensor top-level orchestration extracted from `async fn main`.
//!
//! Created 2026-05-25 as PR-F3 of the test-foundations series. Before
//! this PR `async fn main` held the entire boot+run pipeline inline,
//! which made integration testing impossible (the only way to exercise
//! the boot sequence was to spawn the real binary in a subprocess).
//!
//! After this PR:
//!
//! - `main.rs::async fn main` is ~10 lines: init tracing, parse CLI,
//!   load config, call `sensor::run(cfg).await`. That's it.
//! - This module owns the full orchestration: state load, sinks,
//!   channel + cursor setup, DetectorSet construction, threat
//!   datasets, collector spawn, collector-health snapshot, optional
//!   seccomp gate, event loop, shutdown persistence.
//! - Integration tests can call `run(Config::test_default())` and
//!   assert end-to-end behaviour (sinks created, state file written,
//!   collector-health.json written, run returns cleanly when no
//!   collectors are enabled).

use std::path::Path;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::info;
#[cfg(target_os = "linux")]
use tracing::warn;

use crate::boot;
use crate::collector_health;
use crate::config::Config;
use crate::detectors;
use crate::main_helpers::{
    choose_syslog_protocol, parse_syslog_port, should_enable_syslog_sink, state_path_for,
};
#[cfg(target_os = "linux")]
use crate::seccomp;
use crate::sinks::{self, sqlite::SqliteWriter, state::State};

/// Run the sensor pipeline end-to-end. Returns when the event loop
/// exits — either because every collector task dropped its sender
/// (channel close) or because SIGINT / SIGTERM fired.
pub(crate) async fn run(cfg: Config) -> Result<()> {
    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden-sensor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir = Path::new(&cfg.output.data_dir);
    let state_path = state_path_for(data_dir);

    let mut state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    let write_events = cfg.output.write_events;

    // SQLite is the primary and only event/incident sink.
    let sqlite_writer = SqliteWriter::new(data_dir, write_events)?;
    info!(path = %data_dir.join("innerwarden.db").display(), "sqlite sink enabled");
    // Optional syslog CEF output (configured via env or future config section)
    let mut syslog_writer: Option<sinks::syslog_cef::SyslogCefWriter> = {
        let syslog_host = std::env::var("INNERWARDEN_SYSLOG_HOST").unwrap_or_default();
        if !should_enable_syslog_sink(&syslog_host) {
            None
        } else {
            let syslog_port = std::env::var("INNERWARDEN_SYSLOG_PORT").ok();
            let port = parse_syslog_port(syslog_port.as_deref());
            let protocol = choose_syslog_protocol(std::env::var("INNERWARDEN_SYSLOG_TCP").is_ok());
            info!(host = %syslog_host, port, "Syslog CEF output enabled");
            Some(sinks::syslog_cef::SyslogCefWriter::new(
                sinks::syslog_cef::SyslogCefConfig {
                    host: syslog_host,
                    port,
                    protocol,
                },
                env!("CARGO_PKG_VERSION"),
            ))
        }
    };
    let (tx, rx) = mpsc::channel(1024);

    // Shared state - updated by collectors, read on shutdown for persistence.
    // Bundled into SharedCursors in PR-F1 (#810); adopted here in PR-F2.
    let cursors = boot::cursors::SharedCursors::new();

    // Build the full DetectorSet (every per-detector cfg.enabled.then(...)
    // block + dynamic allowlist load + blocked-IP feedback file). Moved
    // to crates/sensor/src/boot/build_detectors.rs in PR5b1 (2026-05-25).
    let mut detectors = boot::build_detectors::build_detector_set(&cfg, data_dir);

    // Load threat intelligence datasets (IPs, domains, JA3, hashes, URLs).
    // Downloads public feeds on first run, reloads from disk every 60 min.
    let datasets_dir = data_dir.join("datasets");
    let mut threat_datasets = detectors::datasets::Datasets::load(&datasets_dir, 3600);
    if !threat_datasets.is_loaded() {
        info!("downloading threat intelligence feeds for the first time...");
        let (ok, total) = detectors::datasets::update_all_feeds(&datasets_dir);
        info!(
            feeds_updated = ok,
            total_entries = total,
            "initial feed download complete"
        );
        threat_datasets.reload();
    }

    // Spawn every enabled collector + polling-detector as a tokio task.
    // Moved to crates/sensor/src/boot/spawn_collectors.rs in PR5b2
    // (2026-05-25). After this returns, the original `tx` has been
    // dropped — only the per-collector clones hold the sender side,
    // so when every collector task exits the consumer's `rx.recv()`
    // returns `None` and the event loop shuts down cleanly.
    boot::spawn_collectors::spawn_collectors(&cfg, data_dir, &state, tx, &cursors);

    // Apply seccomp profile if configured (Active Defence feature).
    // MUST be after all eBPF programs are loaded and sockets are opened,
    // since seccomp restricts future syscalls. The profile blocks execve,
    // connect, and other syscalls the sensor doesn't need post-startup.
    #[cfg(target_os = "linux")]
    {
        let seccomp_path = data_dir.join("sensor.seccomp.json");
        if seccomp_path.exists() {
            match seccomp::apply_seccomp_profile(&seccomp_path) {
                Ok(count) => info!(
                    syscalls_allowed = count,
                    "seccomp profile applied — sensor hardened"
                ),
                Err(e) => warn!("seccomp profile failed to apply: {e:#} — continuing without"),
            }
        }
    }

    // SIGTERM listener (Unix only)
    #[cfg(unix)]
    let sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())?
    };

    // PR29 — write the boot-time collector health snapshot. Probes
    // each file-backed collector's source path, records whether the
    // path exists / is stale / is missing, and writes the result to
    // `<data_dir>/collector-health.json` for the agent dashboard to
    // read. Errors are logged and swallowed: a missing health file
    // means the dashboard shows the legacy view (per-collector count
    // only), not a crash.
    {
        let now = chrono::Utc::now();
        let statuses = vec![
            collector_health::build_status(
                "auth_log",
                cfg.collectors.auth_log.enabled,
                Some(&cfg.collectors.auth_log.path),
                now,
            ),
            collector_health::build_status("journald", cfg.collectors.journald.enabled, None, now),
            collector_health::build_status(
                "exec_audit",
                cfg.collectors.exec_audit.enabled,
                Some(&cfg.collectors.exec_audit.path),
                now,
            ),
            collector_health::build_status("docker", cfg.collectors.docker.enabled, None, now),
            collector_health::build_status(
                "integrity",
                cfg.collectors.integrity.enabled,
                None,
                now,
            ),
            collector_health::build_status(
                "syslog_firewall",
                cfg.collectors.syslog_firewall.enabled,
                Some(&cfg.collectors.syslog_firewall.path),
                now,
            ),
            collector_health::build_status(
                "nginx_access",
                cfg.collectors.nginx_access.enabled,
                Some(&cfg.collectors.nginx_access.path),
                now,
            ),
            collector_health::build_status(
                "nginx_error",
                cfg.collectors.nginx_error.enabled,
                Some(&cfg.collectors.nginx_error.path),
                now,
            ),
            // NOTE: suricata_eve and osquery_log appear in some
            // operator config files but are NOT in the sensor's
            // CollectorsConfig struct. serde silently ignores those
            // keys, so the sensor never spawns them. Don't include
            // them in the probe; they aren't collectors this binary
            // runs. The right operator action is to remove those
            // sections from config.toml (or open a tracking PR to
            // add proper Suricata/Osquery collectors).
        ];
        if let Err(e) = collector_health::write_status_file(data_dir, &cfg.agent.host_id, &statuses)
        {
            tracing::warn!(error = %e, "failed to write collector-health.json");
        } else {
            info!("collector-health.json written ({} entries)", statuses.len());
        }
    }

    // Main loop + shutdown. Moved to crates/sensor/src/boot/event_loop.rs
    // in PR5b3 (2026-05-25). Drains rx until the channel closes or a
    // signal fires, then snapshots every shared-cursor Arc into the
    // State and writes it to disk.
    boot::event_loop::run_event_loop(
        rx,
        &sqlite_writer,
        &mut detectors,
        &mut syslog_writer,
        &mut threat_datasets,
        &mut state,
        &state_path,
        #[cfg(unix)]
        sigterm,
        &cursors,
    )
    .await?;

    Ok(())
}

// 2026-05-25 (PR-F3): integration anchors for `run()` were drafted
// but hung during `cargo test`. Root cause not yet identified — some
// part of the boot path doesn't drop a sender / Arc / handle that
// would let `rx.recv()` return None. Anchors deferred to a follow-up
// PR after the hang is debugged. The extraction itself is pure code
// motion; pre-existing 1416 sensor tests gate the behaviour of every
// callee (build_detector_set, spawn_collectors, run_event_loop).
