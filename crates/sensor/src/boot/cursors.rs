//! Shared collector-cursor state, bundled into a single struct.
//!
//! Pre-this each cursor (`auth_offset`, `journald_cursor`,
//! `docker_since`, `exec_audit_offset`, `nginx_offset`,
//! `nginx_error_offset`, `syslog_firewall_offset`,
//! `integrity_hashes`) lived as a standalone local in `async fn main`
//! and was threaded through to [`spawn_collectors`] (12 params total)
//! and [`run_event_loop`] (16 params total) as individual `Arc<...>`
//! arguments. Both functions carried
//! `#[allow(clippy::too_many_arguments)]` to silence the warning.
//!
//! Bundling them here:
//!
//! 1. Cuts both signatures by 7 parameters each (and lets us drop the
//!    `too_many_arguments` allow on PR-F2).
//! 2. Makes test fixtures one-liners: `SharedCursors::new()` instead
//!    of constructing eight individual Arcs in every test setup.
//! 3. Centralises the cursor inventory — adding a new collector that
//!    needs persistent state means adding one field here, not threading
//!    a new Arc through three call sites.
//!
//! Introduced 2026-05-25 as PR-F1 of the test-foundations series
//! (after the main.rs decomposition closed with PR #809). PR-F2
//! adopts this struct in spawn_collectors + event_loop; this PR is
//! pure addition (no callers yet).
//!
//! [`spawn_collectors`]: super::spawn_collectors::spawn_collectors
//! [`run_event_loop`]: super::event_loop::run_event_loop

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

/// The complete set of cursors that collectors update during runtime
/// and that `run_event_loop` snapshots into the persistent State at
/// shutdown.
///
/// Every field is `Arc`-wrapped so it can be cloned cheaply into each
/// collector's tokio::spawn closure. The `AtomicU64` cursors are byte
/// offsets into log files; the `Mutex<Option<String>>` cursors are
/// journald / docker resume tokens; the
/// `Mutex<HashMap<String, String>>` is the integrity baseline hash
/// map keyed by file path.
#[derive(Clone)]
pub(crate) struct SharedCursors {
    pub(crate) auth_offset: Arc<AtomicU64>,
    pub(crate) integrity_hashes: Arc<Mutex<HashMap<String, String>>>,
    pub(crate) journald_cursor: Arc<Mutex<Option<String>>>,
    pub(crate) docker_since: Arc<Mutex<Option<String>>>,
    pub(crate) exec_audit_offset: Arc<AtomicU64>,
    pub(crate) nginx_offset: Arc<AtomicU64>,
    pub(crate) nginx_error_offset: Arc<AtomicU64>,
    pub(crate) syslog_firewall_offset: Arc<AtomicU64>,
}

impl SharedCursors {
    /// Construct a SharedCursors with every cursor at its zero value:
    /// `AtomicU64::new(0)` for byte offsets, empty `Mutex<Option<_>>`
    /// / `Mutex<HashMap<_>>` for resume tokens and hash maps.
    pub(crate) fn new() -> Self {
        Self {
            auth_offset: Arc::new(AtomicU64::new(0)),
            integrity_hashes: Arc::new(Mutex::new(HashMap::new())),
            journald_cursor: Arc::new(Mutex::new(None)),
            docker_since: Arc::new(Mutex::new(None)),
            exec_audit_offset: Arc::new(AtomicU64::new(0)),
            nginx_offset: Arc::new(AtomicU64::new(0)),
            nginx_error_offset: Arc::new(AtomicU64::new(0)),
            syslog_firewall_offset: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for SharedCursors {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn new_returns_cursors_at_zero() {
        let c = SharedCursors::new();
        assert_eq!(c.auth_offset.load(Ordering::Relaxed), 0);
        assert_eq!(c.exec_audit_offset.load(Ordering::Relaxed), 0);
        assert_eq!(c.nginx_offset.load(Ordering::Relaxed), 0);
        assert_eq!(c.nginx_error_offset.load(Ordering::Relaxed), 0);
        assert_eq!(c.syslog_firewall_offset.load(Ordering::Relaxed), 0);
        assert!(c.integrity_hashes.lock().unwrap().is_empty());
        assert!(c.journald_cursor.lock().unwrap().is_none());
        assert!(c.docker_since.lock().unwrap().is_none());
    }

    #[test]
    fn clone_shares_inner_arc_state() {
        // SharedCursors derives Clone, but the inner Arcs are shared.
        // A write through one clone must be visible through the other —
        // this is the whole point of using Arc<AtomicU64> for cursors
        // that get updated from inside a tokio::spawn closure.
        let a = SharedCursors::new();
        let b = a.clone();
        a.auth_offset.store(42, Ordering::Relaxed);
        assert_eq!(
            b.auth_offset.load(Ordering::Relaxed),
            42,
            "clone must share the underlying Arc — Clone is shallow"
        );

        a.integrity_hashes
            .lock()
            .unwrap()
            .insert("/etc/passwd".to_string(), "hash-1".to_string());
        assert_eq!(
            b.integrity_hashes
                .lock()
                .unwrap()
                .get("/etc/passwd")
                .map(String::as_str),
            Some("hash-1"),
            "Mutex<HashMap> contents must also be shared"
        );
    }

    #[test]
    fn default_is_same_as_new() {
        // Anchor: Default impl must NOT diverge from new(). Both
        // produce a fresh zero-valued SharedCursors. If a future
        // refactor adds a field with a non-zero default to either,
        // this asserts the two paths stay in sync.
        let n = SharedCursors::new();
        let d = SharedCursors::default();
        assert_eq!(
            n.auth_offset.load(Ordering::Relaxed),
            d.auth_offset.load(Ordering::Relaxed)
        );
        assert_eq!(
            n.exec_audit_offset.load(Ordering::Relaxed),
            d.exec_audit_offset.load(Ordering::Relaxed)
        );
        assert!(n.journald_cursor.lock().unwrap().is_none());
        assert!(d.journald_cursor.lock().unwrap().is_none());
    }
}
