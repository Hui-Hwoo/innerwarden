//! SQLite sink for sensor events and incidents.
//!
//! Writes directly to `innerwarden.db` via the unified store crate.
//! Primary and only event/incident sink since spec 016 cleanup.
//! No buffering needed — SQLite WAL handles durability.

use std::path::Path;

use innerwarden_core::{event::Event, incident::Incident};
use innerwarden_store::Store;
use tracing::warn;

pub struct SqliteWriter {
    store: Store,
    write_events: bool,
}

impl SqliteWriter {
    /// Open or create the SQLite database at `data_dir/innerwarden.db`.
    /// When `write_events` is false, `write_event` is a no-op (incidents
    /// are always written).
    pub fn new(data_dir: &Path, write_events: bool) -> anyhow::Result<Self> {
        let store = Store::open(data_dir)?;
        Ok(Self {
            store,
            write_events,
        })
    }

    /// Returns the data directory path (used by the main loop for loading
    /// feedback files like blocked-ips.txt).
    pub fn data_dir(&self) -> &Path {
        self.store.data_dir()
    }

    /// Write an event to the events table.
    ///
    /// High-volume, low-value event kinds are skipped to prevent unbounded
    /// database growth. These events are still processed by detectors
    /// (in-memory) — they just aren't persisted to disk.
    pub fn write_event(&self, event: &Event) {
        if !self.write_events {
            return;
        }
        if is_high_volume_event(&event.kind) {
            return;
        }
        if let Err(e) = self.store.insert_event(event) {
            warn!(kind = %event.kind, "sqlite write_event failed: {e:#}");
        }
    }

    /// Write an incident to the incidents table.
    pub fn write_incident(&self, incident: &Incident) {
        if let Err(e) = self.store.insert_incident(incident) {
            warn!(incident_id = %incident.incident_id, "sqlite write_incident failed: {e:#}");
        }
    }
}

/// High-volume event kinds that are useful for in-memory detection but
/// not worth persisting to SQLite. These fire thousands of times per hour
/// on active servers and would grow the DB to gigabytes per day.
///
/// The detectors still see these events (they run before the sink).
/// The knowledge graph still ingests them (agent reads from graph, not DB).
/// Only the raw event audit trail skips them.
fn is_high_volume_event(kind: &str) -> bool {
    matches!(
        kind,
        "tcp_stream.flow"
            | "tcp_stream.http"
            | "process.exit"
            | "process.clone"
            | "process.fd_redirect"
            | "network.snapshot_connected"
            | "network.snapshot_listening"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_high_volume_event() {
        assert!(is_high_volume_event("tcp_stream.flow"));
        assert!(is_high_volume_event("tcp_stream.http"));
        assert!(is_high_volume_event("process.exit"));
        assert!(is_high_volume_event("process.clone"));
        assert!(is_high_volume_event("process.fd_redirect"));
        assert!(is_high_volume_event("network.snapshot_connected"));
        assert!(is_high_volume_event("network.snapshot_listening"));

        assert!(!is_high_volume_event("ssh.login_success"));
        assert!(!is_high_volume_event("sudo.command"));
        assert!(!is_high_volume_event("system.new_suid"));
        assert!(!is_high_volume_event("firmware.esp_modified"));
    }

    #[test]
    fn test_sqlite_writer_skips_events_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let writer = SqliteWriter::new(dir.path(), false).unwrap();

        let event = Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "test".to_string(),
            kind: "test.event".to_string(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "Test".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };

        writer.write_event(&event);

        // Count events in the DB
        let store = innerwarden_store::Store::open(dir.path()).unwrap();
        let count = store
            .conn()
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_sqlite_writer_skips_high_volume_events() {
        let dir = tempfile::tempdir().unwrap();
        let writer = SqliteWriter::new(dir.path(), true).unwrap();

        let event = Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "test".to_string(),
            kind: "tcp_stream.flow".to_string(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "Flow".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };

        writer.write_event(&event);

        let store = innerwarden_store::Store::open(dir.path()).unwrap();
        let count = store
            .conn()
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_sqlite_writer_writes_normal_events_and_incidents() {
        let dir = tempfile::tempdir().unwrap();
        let writer = SqliteWriter::new(dir.path(), true).unwrap();

        let event = Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "test".to_string(),
            kind: "ssh.login_success".to_string(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "Login".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };

        writer.write_event(&event);

        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-1".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "Test".to_string(),
            summary: "Summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };

        writer.write_incident(&incident);

        let store = innerwarden_store::Store::open(dir.path()).unwrap();
        let event_count = store
            .conn()
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(event_count, 1);

        let incident_count = store
            .conn()
            .unwrap()
            .query_row("SELECT count(*) FROM incidents", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(incident_count, 1);
    }
}
