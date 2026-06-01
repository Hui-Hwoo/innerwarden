//! Data-retention config section.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Data retention
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRetentionConfig {
    /// Keep daily events JSONL for N days (default: 7)
    #[serde(default = "default_data_events_keep_days")]
    pub events_keep_days: usize,

    /// Keep daily incidents JSONL for N days (default: 30)
    #[serde(default = "default_data_incidents_keep_days")]
    pub incidents_keep_days: usize,

    /// Keep daily decisions JSONL for N days - audit trail (default: 90)
    #[serde(default = "default_data_decisions_keep_days")]
    pub decisions_keep_days: usize,

    /// Keep daily telemetry JSONL for N days (default: 14)
    #[serde(default = "default_data_telemetry_keep_days")]
    pub telemetry_keep_days: usize,

    /// Keep trial-report-*.{json,md} for N days (default: 30)
    #[serde(default = "default_data_reports_keep_days")]
    pub reports_keep_days: usize,

    /// Spec 030: keep `graph-snapshot-YYYY-MM-DD.json` files for N
    /// days. Only the most recent snapshot is needed for recovery;
    /// older ones pile up at ~40 MB/day if not pruned. (default: 3)
    #[serde(default = "default_data_graph_snapshot_keep_days")]
    pub graph_snapshot_keep_days: usize,

    /// Spec 030: compress warm-tier JSONL files (events, incidents,
    /// decisions, telemetry, admin-actions, agent-guard-events) with
    /// gzip once they are older than this many days. The reader
    /// transparently decompresses `.jsonl.gz` so downstream callers
    /// do not have to know the difference. Set to 0 to disable
    /// compression. (default: 7)
    #[serde(default = "default_data_warm_gzip_days")]
    pub warm_gzip_days: usize,

    /// Retention for `filestore/extracted/<shard>/<sha256>.<ext>`
    /// files captured by the sensor's HTTP body extractor. These
    /// dedup-by-hash forensic artifacts have no pruning path of
    /// their own and grow unbounded (observed 6 GB / 44k files on
    /// prod). Uses mtime rather than filename-date since filenames
    /// are content hashes. Set to 0 to disable age-based pruning.
    /// (default: 30)
    #[serde(default = "default_data_filestore_keep_days")]
    pub filestore_keep_days: usize,

    /// Hard size cap for the entire `filestore/extracted/` tree in
    /// megabytes. After the age-based pass runs, oldest files are
    /// pruned until the total is under this cap. Protects against
    /// bursty captures overrunning disk between retention ticks.
    /// Set to 0 to disable the size cap. (default: 2048)
    #[serde(default = "default_data_filestore_max_size_mb")]
    pub filestore_max_size_mb: u64,
}

impl Default for DataRetentionConfig {
    fn default() -> Self {
        Self {
            events_keep_days: default_data_events_keep_days(),
            incidents_keep_days: default_data_incidents_keep_days(),
            decisions_keep_days: default_data_decisions_keep_days(),
            telemetry_keep_days: default_data_telemetry_keep_days(),
            reports_keep_days: default_data_reports_keep_days(),
            graph_snapshot_keep_days: default_data_graph_snapshot_keep_days(),
            warm_gzip_days: default_data_warm_gzip_days(),
            filestore_keep_days: default_data_filestore_keep_days(),
            filestore_max_size_mb: default_data_filestore_max_size_mb(),
        }
    }
}
